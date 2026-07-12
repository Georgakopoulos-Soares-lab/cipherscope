"""Clock-envelope and Linux process-memory sanity checks."""

from __future__ import annotations

import resource
import time
import unittest
from pathlib import Path

import cipherscope

from . import support


@unittest.skipUnless(
    support.fhe is not None,
    "OpenFHE Python is unavailable; fake-backend results are not integration evidence",
)
class ResourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = support.basic_fixture()

    def test_res_01_event_clocks_fit_external_envelope(self) -> None:
        """RES-01: event wall/CPU timings are nonnegative and externally bounded."""

        left = self.fixture.encrypt(self.fixture.a)
        right = self.fixture.encrypt(self.fixture.b)
        outer_wall_start = time.perf_counter_ns()
        outer_cpu_start = time.process_time_ns()
        thread_clock = getattr(time, "thread_time_ns", None)
        outer_thread_start = thread_clock() if callable(thread_clock) else None
        with cipherscope.trace(self.fixture.context) as session:
            session.context.EvalMult(left, right)
        outer_wall = time.perf_counter_ns() - outer_wall_start
        outer_cpu = time.process_time_ns() - outer_cpu_start
        outer_thread = (
            thread_clock() - outer_thread_start
            if callable(thread_clock) and outer_thread_start is not None
            else None
        )
        timing = session.to_trace()["events"][0]["timing"]
        self.assertGreaterEqual(timing["wall_duration_ns"], 0)
        self.assertLessEqual(timing["wall_duration_ns"], outer_wall)
        self.assertGreaterEqual(timing["process_cpu_duration_ns"], 0)
        self.assertLessEqual(timing["process_cpu_duration_ns"], outer_cpu)
        if outer_thread is not None:
            self.assertGreaterEqual(timing["thread_cpu_duration_ns"], 0)
            self.assertLessEqual(timing["thread_cpu_duration_ns"], outer_thread)
        support.record(
            "RES-01",
            event=timing,
            outer_wall_duration_ns=outer_wall,
            outer_process_cpu_duration_ns=outer_cpu,
            outer_thread_cpu_duration_ns=outer_thread,
        )

    def test_res_02_linux_rss_and_hwm_are_positive(self) -> None:
        """RES-02: /proc and getrusage memory samples use explicit units."""

        status_path = Path("/proc/self/status")
        if not status_path.is_file():
            self.skipTest("/proc/self/status is required for the Linux evidence lane")
        values: dict[str, int] = {}
        for line in status_path.read_text(encoding="utf-8").splitlines():
            if line.startswith(("VmRSS:", "VmHWM:")):
                name, amount, unit = line.split()
                self.assertEqual(unit, "kB")
                values[name.rstrip(":")] = int(amount) * 1024
        self.assertGreater(values.get("VmRSS", 0), 0)
        self.assertGreaterEqual(values.get("VmHWM", 0), values["VmRSS"])
        usage_kib = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        self.assertGreater(usage_kib, 0)
        support.record(
            "RES-02",
            proc_rss_bytes=values["VmRSS"],
            proc_hwm_bytes=values["VmHWM"],
            getrusage_maxrss_kib=usage_kib,
        )


if __name__ == "__main__":
    unittest.main()
