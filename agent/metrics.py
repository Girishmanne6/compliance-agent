from __future__ import annotations

import threading
import time
from typing import Any

from agent.database import load_metrics, save_metrics

_lock = threading.Lock()


def record_scan(
    violations: list[dict[str, Any]],
    duration_ms: int,
    step_timings: dict[str, int] | None = None,
) -> None:
    with _lock:
        metrics = load_metrics()
        metrics["total_scans"] += 1
        metrics["total_violations"] += len(violations)
        metrics["total_scan_time_ms"] += duration_ms
        for violation in violations:
            severity = violation.get("severity", "low")
            counts = metrics["violations_by_severity"]
            counts[severity] = counts.get(severity, 0) + 1
        if step_timings:
            for step, ms in step_timings.items():
                metrics["step_times_ms"][step] = metrics["step_times_ms"].get(step, 0) + ms
                metrics["step_counts"][step] = metrics["step_counts"].get(step, 0) + 1
        save_metrics(metrics)


def get_stats() -> dict[str, Any]:
    with _lock:
        metrics = load_metrics()
        total_scans = metrics["total_scans"]
        avg_scan_time_ms = (
            round(metrics["total_scan_time_ms"] / total_scans) if total_scans else 0
        )
        step_averages: dict[str, int] = {}
        for step, total_ms in metrics["step_times_ms"].items():
            count = metrics["step_counts"].get(step, 0)
            step_averages[step] = round(total_ms / count) if count else 0
        return {
            "total_scans": total_scans,
            "total_violations": metrics["total_violations"],
            "violations_by_severity": dict(metrics["violations_by_severity"]),
            "average_scan_time_ms": avg_scan_time_ms,
            "average_step_time_ms": step_averages,
        }


class StepTimer:
    """Context manager that records elapsed milliseconds for a pipeline step."""

    def __init__(self) -> None:
        self.timings: dict[str, int] = {}
        self._start: float = 0.0
        self._step: str = ""

    def start(self, step: str) -> StepTimer:
        self._step = step
        self._start = time.perf_counter()
        return self

    def stop(self) -> int:
        elapsed_ms = int((time.perf_counter() - self._start) * 1000)
        self.timings[self._step] = elapsed_ms
        return elapsed_ms
