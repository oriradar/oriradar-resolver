"""Dedicated scan worker for Redis-backed deployments."""

from __future__ import annotations

import os
import time

from oritypo_solver.services.scan_engine import run_scan
from oritypo_solver.store import mark_worker_heartbeat, pop_scan_job, queue_enabled, update_scan


def worker_name() -> str:
    return os.environ.get("ORI_WORKER_NAME", "scan-worker")


def main() -> int:
    if not queue_enabled():
        raise RuntimeError("Worker requires REDIS_URL / queue mode.")

    name = worker_name()
    while True:
        mark_worker_heartbeat(name)
        job = pop_scan_job()
        if job is None:
            continue

        scan_id, apex = job
        mark_worker_heartbeat(name)
        try:
            run_scan(scan_id, apex)
        except Exception as e:  # noqa: BLE001
            update_scan(scan_id, status="failed", error=str(e))
        finally:
            mark_worker_heartbeat(name)
            time.sleep(0.01)


if __name__ == "__main__":
    raise SystemExit(main())
