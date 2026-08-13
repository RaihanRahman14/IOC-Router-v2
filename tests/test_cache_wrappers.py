"""Tests for the provider cache wrappers in core.cache.

These cover the seam between the orchestrator and the provider clients: the
wrappers must forward the API key they are handed, and every wrapper must take
``cache_rev`` so bumping ``CACHE_REV`` invalidates all of them together.
"""
import inspect
import unittest
from unittest.mock import patch

from core import cache
from core.orchestrator import PROVIDER_KEYS


# Wrapper -> the Settings attribute it is expected to populate.
_WRAPPERS = {
    "vt_cached": "vt_key",
    "abuse_cached": "abuse_key",
    "tf_cached": "threatfox_key",
    "mb_cached": "malwarebazaar_key",
    "shodan_cached": "shodan_key",
    "dnsd_cached": "dnsdumpster_key",
    "ha_cached": "hybrid_analysis_key",
    "mxtoolbox_cached": "mxtoolbox_key",
    "whoxy_cached": "whoxy_key",
    "ransomware_live_cached": "ransomware_live_key",
}

# Wrapper -> the provider batch function it delegates to.
_BATCH_FN = {
    "vt_cached": "vt_lookup_batch",
    "abuse_cached": "abuseipdb_lookup_batch",
    "tf_cached": "threatfox_lookup_batch",
    "mb_cached": "malwarebazaar_lookup_batch",
    "shodan_cached": "shodan_lookup_batch",
    "dnsd_cached": "dnsdumpster_lookup_batch",
    "ha_cached": "hybrid_analysis_lookup_batch",
    "mxtoolbox_cached": "mxtoolbox_lookup_batch",
    "whoxy_cached": "whoxy_lookup_batch",
    "ransomware_live_cached": "ransomware_live_lookup_batch",
}

_ALL_WRAPPERS = tuple(_WRAPPERS) + ("urlscan_cached",)


class TestCacheRevCoverage(unittest.TestCase):
    def test_every_wrapper_takes_cache_rev(self):
        """A wrapper without cache_rev survives a CACHE_REV bump — stale forever."""
        for name in _ALL_WRAPPERS:
            with self.subTest(wrapper=name):
                params = inspect.signature(getattr(cache, name)).parameters
                self.assertIn("cache_rev", params)

    def test_there_is_one_wrapper_per_provider(self):
        self.assertEqual(len(_ALL_WRAPPERS), len(PROVIDER_KEYS))


class TestKeyForwarding(unittest.TestCase):
    def test_each_wrapper_forwards_its_api_key(self):
        """Regression: ha_cached accepted a key and then dropped it on the floor.

        The provider fell back to reading the environment, so a key typed into
        the API drawer was silently ignored for that provider only.
        """
        payload = [("1.2.3.4", "ip", False)]
        for wrapper_name, settings_attr in _WRAPPERS.items():
            with self.subTest(wrapper=wrapper_name):
                target = f"core.cache.{_BATCH_FN[wrapper_name]}"
                # cache_rev doubles as the cache key here: a value unique per
                # wrapper keeps a memoized result from masking the next call.
                with patch(target, return_value={}) as batch_fn:
                    getattr(cache, wrapper_name)(
                        payload, "forwarded-key", f"test-{wrapper_name}"
                    )

                batch_fn.assert_called_once()
                sent_settings = batch_fn.call_args[0][1]
                self.assertEqual(getattr(sent_settings, settings_attr), "forwarded-key")

    def test_urlscan_forwards_key_and_submit_flag(self):
        payload = [("http://evil.test/", "url", False)]
        with patch("core.cache.urlscan_lookup_batch", return_value={}) as batch_fn:
            cache.urlscan_cached(payload, "forwarded-key", False, "test-urlscan")

        sent_settings = batch_fn.call_args[0][1]
        self.assertEqual(sent_settings.urlscan_key, "forwarded-key")
        self.assertFalse(batch_fn.call_args[1]["allow_submit"])


if __name__ == "__main__":
    unittest.main()
