"""Tests for the shared HTTP session and fan-out helpers in core.http."""
import threading
import time
import unittest

import requests

from core.http import DEFAULT_MAX_WORKERS, get_session, run_parallel


class TestGetSession(unittest.TestCase):
    def test_returns_a_requests_session(self):
        self.assertIsInstance(get_session(), requests.Session)

    def test_same_thread_reuses_one_session(self):
        """Reuse is the point — a fresh session per call would keep re-handshaking."""
        self.assertIs(get_session(), get_session())

    def test_each_thread_gets_its_own_session(self):
        """requests.Session is not documented thread-safe, so they must not be shared."""
        seen: list[requests.Session] = []
        lock = threading.Lock()

        def _capture():
            with lock:
                seen.append(get_session())

        threads = [threading.Thread(target=_capture) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(seen), 4)
        self.assertEqual(len({id(s) for s in seen}), 4)
        self.assertNotIn(id(get_session()), {id(s) for s in seen})

    def test_adapters_are_mounted_for_both_schemes(self):
        session = get_session()
        for scheme in ("https://", "http://"):
            with self.subTest(scheme=scheme):
                adapter = session.get_adapter(scheme + "example.test")
                self.assertIsInstance(adapter, requests.adapters.HTTPAdapter)


class TestRunParallel(unittest.TestCase):
    def test_empty_job_map_returns_empty(self):
        self.assertEqual(run_parallel({}), {})

    def test_results_are_keyed_by_job_key(self):
        jobs = {"a": lambda: 1, "b": lambda: 2, "c": lambda: 3}
        self.assertEqual(run_parallel(jobs), {"a": 1, "b": 2, "c": 3})

    def test_single_job_runs_on_the_calling_thread(self):
        """One job needs no pool; staying inline keeps tracebacks readable."""
        caller = threading.get_ident()
        result = run_parallel({"only": lambda: threading.get_ident()})
        self.assertEqual(result["only"], caller)

    def test_failing_job_is_omitted_and_logged(self):
        def _boom():
            raise ValueError("nope")

        jobs = {"ok": lambda: "fine", "bad": _boom}
        with self.assertLogs("core.http", level="ERROR") as logged:
            out = run_parallel(jobs, label="probe")

        self.assertEqual(out, {"ok": "fine"})
        self.assertIn("probe 'bad' failed", logged.output[0])

    def test_single_failing_job_is_also_isolated(self):
        def _boom():
            raise ValueError("nope")

        with self.assertLogs("core.http", level="ERROR"):
            self.assertEqual(run_parallel({"bad": _boom}), {})

    def test_jobs_actually_overlap(self):
        delay = 0.12
        jobs = {n: (lambda: time.sleep(delay)) for n in range(4)}

        start = time.perf_counter()
        run_parallel(jobs)
        elapsed = time.perf_counter() - start

        self.assertLess(elapsed, delay * 4)

    def test_worker_count_is_bounded(self):
        """More jobs than the cap must not open a thread per job."""
        seen: set[int] = set()
        lock = threading.Lock()
        job_count = DEFAULT_MAX_WORKERS * 3

        def _work():
            with lock:
                seen.add(threading.get_ident())
            time.sleep(0.01)

        run_parallel({n: _work for n in range(job_count)})

        self.assertLessEqual(len(seen), DEFAULT_MAX_WORKERS)

    def test_max_workers_argument_is_honoured(self):
        seen: set[int] = set()
        lock = threading.Lock()

        def _work():
            with lock:
                seen.add(threading.get_ident())
            time.sleep(0.01)

        run_parallel({n: _work for n in range(8)}, max_workers=2)

        self.assertLessEqual(len(seen), 2)


if __name__ == "__main__":
    unittest.main()
