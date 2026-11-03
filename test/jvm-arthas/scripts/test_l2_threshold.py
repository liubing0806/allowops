"""Tests of l2_threshold.jobs(). Run from the repository root:
  python3 -m unittest discover -s test/jvm-arthas/scripts -p 'test_*.py'
"""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import l2_threshold  # noqa: E402


def req(action, open_ms, close_ms, command=None):
    r = {"action": action, "open": open_ms, "close": close_ms}
    if command:
        r["command"] = command
    return r


def jvm_arthas_row(start, end, requests):
    return {"kind": "jvm_arthas", "start": start, "end": end, "steps": {"requests": requests}}


class JobsTest(unittest.TestCase):
    def test_pull_results_do_not_end_the_job(self):
        # The requests of stage-3D smoke run l2func/jdk17/guard (a watch call stopped by the guard): the product sends
        # pull_results every 0.1 to 2 s on new connections after async_exec; the job ends with interrupt_job.
        watch = "watch demo.HotService work {params,returnObj} #cost>10000 -n 5 -x 1 -m 1 --timeout 30"
        reqs = [
            req("init_session", 6500.15, 6626.434),
            req("exec", 6633.633, 6768.768, "options disable-sub-class true"),
            req("exec", 6773.593, 6879.625, "options object-size-limit 8192"),
            req("async_exec", 6885.236, 6897.079, watch),
            req("pull_results", 6902.371, 8127.18),
            req("pull_results", 8132.885, 10157.232),
            req("pull_results", 10263.526, 11880.52),
            req("interrupt_job", 11887.563, 11897.718),
            req("close_session", 11903.04, 11907.293),
            req("exec", 11912.688, 12041.367, "reset"),
            req("exec", 12046.902, 12153.928, "reset"),
            req("exec", 12159.197, 12175.792, "stop"),
        ]
        spans, other, reset = l2_threshold.jobs([jvm_arthas_row(1000.0, 1014.414, reqs)])
        self.assertEqual(len(spans), 1)
        start, end, command = spans[0]
        self.assertEqual(command, watch)
        self.assertAlmostEqual(start, 1000.0 + 6.885236, places=6)
        self.assertAlmostEqual(end - start, 11.887563 - 6.885236, places=6)  # 5.0 s
        self.assertAlmostEqual(reset, 1000.0 + 11.912688, places=6)
        self.assertEqual(len(other), 2)

    def test_retried_async_exec_does_not_end_the_job(self):
        reqs = [
            req("init_session", 100, 200),
            req("async_exec", 300, 310, "trace demo.HotService work -n 5"),
            req("async_exec", 400, 410, "trace demo.HotService work -n 5"),
            req("pull_results", 500, 1500),
            req("interrupt_job", 3000, 3010),
            req("close_session", 3020, 3030),
        ]
        spans, _, _ = l2_threshold.jobs([jvm_arthas_row(50.0, 54.0, reqs)])
        self.assertAlmostEqual(spans[0][1] - spans[0][0], 3.0 - 0.3, places=6)

    def test_job_without_following_request_ends_at_its_own_close(self):
        reqs = [req("init_session", 100, 200), req("async_exec", 300, 4300, "stack demo.HotService work")]
        spans, _, _ = l2_threshold.jobs([jvm_arthas_row(0.0, 5.0, reqs)])
        self.assertAlmostEqual(spans[0][1] - spans[0][0], 4.0, places=6)

    def test_bench_rows_are_jobs_and_other_calls(self):
        calls = [{"kind": "job", "start": 10.0, "end": 20.0, "cmd": "watch x y"},
                 {"kind": "reset", "start": 21.0, "end": 22.0}]
        spans, other, reset = l2_threshold.jobs(calls)
        self.assertEqual(spans, [(10.0, 20.0, "watch x y")])
        self.assertEqual(other, [(21.0, 22.0)])
        self.assertEqual(reset, 21.0)


if __name__ == "__main__":
    unittest.main()
