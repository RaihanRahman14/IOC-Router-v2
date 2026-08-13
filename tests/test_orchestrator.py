"""Tests for the parallel provider orchestration in core.orchestrator."""
import time
import unittest
from unittest.mock import patch

from config import Settings
from core.orchestrator import PROVIDER_KEYS, RESULT_KEYS, run_provider_lookups


ALL_OFF = {key: False for key in PROVIDER_KEYS}


def _payload_for(_provider: str) -> list[tuple[str, str, bool]]:
    """Default payload builder — one IOC for every provider."""
    return [("8.8.8.8", "ip", False)]


def _run(provider_flags: dict, payload_for=_payload_for, settings=None):
    """Invoke the orchestrator with the given flags and sensible defaults."""
    return run_provider_lookups(
        settings=settings or Settings(),
        provider_flags=provider_flags,
        payload_for=payload_for,
        allow_urlscan_submit=False,
    )


class TestProviderKeyMapping(unittest.TestCase):
    def test_every_provider_key_has_a_result_key(self):
        for key in PROVIDER_KEYS:
            with self.subTest(provider=key):
                self.assertIn(key, RESULT_KEYS)

    def test_dnsdumpster_is_the_only_renamed_key(self):
        """The UI toggle is "dns" but every consumer reads run_results["dnsd"]."""
        renamed = {k: v for k, v in RESULT_KEYS.items() if k != v}
        self.assertEqual(renamed, {"dns": "dnsd"})

    def test_results_always_carry_every_result_key(self):
        """A disabled provider still gets an entry, so consumers never KeyError."""
        results, _ = _run(ALL_OFF)
        self.assertEqual(set(results), set(RESULT_KEYS.values()))
        for key, value in results.items():
            with self.subTest(result_key=key):
                self.assertEqual(value, {})


class TestDispatch(unittest.TestCase):
    def test_only_enabled_providers_are_called(self):
        flags = {**ALL_OFF, "vt": True}
        with patch("core.orchestrator.vt_cached", return_value={"8.8.8.8": {"hit": 1}}) as vt, \
             patch("core.orchestrator.abuse_cached", return_value={}) as abuse:
            results, _ = _run(flags)

        vt.assert_called_once()
        abuse.assert_not_called()
        self.assertEqual(results["vt"], {"8.8.8.8": {"hit": 1}})
        self.assertEqual(results["abuse"], {})

    def test_dns_flag_publishes_under_dnsd(self):
        flags = {**ALL_OFF, "dns": True}
        with patch("core.orchestrator.dnsd_cached", return_value={"evil.test": {"a": 1}}):
            results, timings = _run(flags)

        self.assertEqual(results["dnsd"], {"evil.test": {"a": 1}})
        # Timings stay keyed by the provider key the UI labels map uses.
        self.assertEqual(timings["providers"]["dns"]["n"], 1)

    def test_api_keys_are_forwarded_from_settings(self):
        """Regression: a key resolved in the app must reach the provider call.

        Hybrid Analysis previously ignored its argument and re-read the
        environment, which silently discarded a key typed into the API drawer.
        """
        settings = Settings(hybrid_analysis_key="drawer-key")
        with patch("core.orchestrator.ha_cached", return_value={}) as ha:
            _run({**ALL_OFF, "ha": True}, settings=settings)

        self.assertEqual(ha.call_args[0][1], "drawer-key")

    def test_no_enabled_providers_starts_no_work(self):
        with patch("core.orchestrator.vt_cached") as vt:
            results, timings = _run(ALL_OFF)

        vt.assert_not_called()
        self.assertEqual(timings["providers_total"], 0.0)
        self.assertTrue(all(v == {} for v in results.values()))

    def test_missing_flag_is_treated_as_disabled(self):
        """A flags dict that omits a provider must not raise."""
        with patch("core.orchestrator.vt_cached", return_value={"x": {}}) as vt:
            results, _ = _run({"vt": True})

        vt.assert_called_once()
        self.assertEqual(results["abuse"], {})


class TestFailureIsolation(unittest.TestCase):
    def test_one_failing_provider_does_not_sink_the_run(self):
        flags = {**ALL_OFF, "vt": True, "abuse": True}
        with patch("core.orchestrator.vt_cached", side_effect=RuntimeError("boom")), \
             patch("core.orchestrator.abuse_cached", return_value={"8.8.8.8": {"score": 90}}), \
             self.assertLogs("core.orchestrator", level="ERROR") as logged:
            results, _ = _run(flags)

        self.assertEqual(results["vt"], {})
        self.assertEqual(results["abuse"], {"8.8.8.8": {"score": 90}})
        self.assertIn("provider vt lookup failed", logged.output[0])


class TestParallelism(unittest.TestCase):
    def test_providers_run_concurrently(self):
        """Three 150ms providers must finish in well under their 450ms sum."""
        delay = 0.15
        flags = {**ALL_OFF, "vt": True, "abuse": True, "shodan": True}

        def _slow(*_args, **_kwargs):
            time.sleep(delay)
            return {}

        with patch("core.orchestrator.vt_cached", side_effect=_slow), \
             patch("core.orchestrator.abuse_cached", side_effect=_slow), \
             patch("core.orchestrator.shodan_cached", side_effect=_slow):
            start = time.perf_counter()
            _, timings = _run(flags)
            elapsed = time.perf_counter() - start

        self.assertLess(elapsed, delay * 3)
        # providers_total is wall time of the block, not the sum of the
        # per-provider times — those overlap once the calls run in parallel.
        self.assertLess(timings["providers_total"], delay * 3)
        summed = sum(v["time"] for v in timings["providers"].values())
        self.assertGreater(summed, timings["providers_total"])


class TestTimings(unittest.TestCase):
    def test_disabled_providers_record_zero(self):
        with patch("core.orchestrator.vt_cached", return_value={}):
            _, timings = _run({**ALL_OFF, "vt": True})

        self.assertEqual(timings["providers"]["abuse"], {"time": 0.0, "n": 0})
        self.assertGreaterEqual(timings["providers"]["vt"]["time"], 0.0)

    def test_ioc_count_comes_from_the_payload_builder(self):
        def _two_for_vt(provider: str) -> list[tuple[str, str, bool]]:
            return [("a", "ip", False), ("b", "ip", False)] if provider == "vt" else []

        with patch("core.orchestrator.vt_cached", return_value={}):
            _, timings = _run({**ALL_OFF, "vt": True}, payload_for=_two_for_vt)

        self.assertEqual(timings["providers"]["vt"]["n"], 2)

    def test_every_provider_key_appears_in_timings(self):
        _, timings = _run(ALL_OFF)
        self.assertEqual(set(timings["providers"]), set(PROVIDER_KEYS))


if __name__ == "__main__":
    unittest.main()
