"""Recurring digest worker for Redis-backed deployments."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import time

from oritypo_solver.services.oridigest import (
    build_digest_payload,
    digest_interval_seconds_from_env,
    digest_lookback_since,
    send_digest_payload,
)
from oritypo_solver.store import get_state, list_scans, mark_worker_heartbeat, queue_enabled, set_state


def worker_name() -> str:
    return os.environ.get("ORI_WORKER_NAME", "oridigest-worker")


def main() -> int:
    if not queue_enabled():
        raise RuntimeError("oridigest worker requires REDIS_URL / queue mode.")

    name = worker_name()
    state_key = "oridigest:last_run"

    while True:
        mark_worker_heartbeat(name)
        last_run_raw = get_state(state_key)
        since = digest_lookback_since()
        if last_run_raw:
            try:
                since = datetime.fromisoformat(last_run_raw)
            except ValueError:
                since = digest_lookback_since()

        scans = list_scans(status="completed", updated_since=since)
        payload = build_digest_payload(scans=scans)
        delivery = send_digest_payload(payload)
        if not delivery.get("enabled"):
            print(json.dumps(payload, sort_keys=True))
        set_state(state_key, datetime.now(timezone.utc).isoformat())
        mark_worker_heartbeat(name)
        time.sleep(digest_interval_seconds_from_env())


if __name__ == "__main__":
    raise SystemExit(main())
