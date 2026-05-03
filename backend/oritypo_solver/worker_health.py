"""Healthcheck for the Redis-backed scan worker."""

from __future__ import annotations

import os

from oritypo_solver.store import worker_heartbeat_fresh


def main() -> int:
    worker_name = os.environ.get("ORI_WORKER_NAME", "scan-worker")
    return 0 if worker_heartbeat_fresh(worker_name) else 1


if __name__ == "__main__":
    raise SystemExit(main())
