"""Lightweight crawl worker for Redis-backed deployments."""

from __future__ import annotations

import os

from oritypo_solver.services.oricrawl import crawl_site
from oritypo_solver.services.scan_engine import recompute_scan_derived_state
from oritypo_solver.store import mark_worker_heartbeat, pop_crawl_job, queue_enabled, update_finding


def worker_name() -> str:
    return os.environ.get("ORI_WORKER_NAME", "oricrawl-worker")


def main() -> int:
    if not queue_enabled():
        raise RuntimeError("oricrawl worker requires REDIS_URL / queue mode.")

    name = worker_name()
    while True:
        mark_worker_heartbeat(name)
        job = pop_crawl_job()
        if job is None:
            continue

        scan_id = job["scan_id"]
        fqdn = job["fqdn"]
        requested_url = job["requested_url"]
        update_finding(
            scan_id,
            fqdn,
            crawl={
                "status": "running",
                "requested_url": requested_url,
            },
        )
        mark_worker_heartbeat(name)
        try:
            result = crawl_site(target=fqdn, start_url=requested_url)
        except Exception as exc:  # noqa: BLE001
            result = {
                "status": "failed",
                "requested_url": requested_url,
                "error": exc.__class__.__name__,
            }
        update_finding(scan_id, fqdn, crawl=result)
        recompute_scan_derived_state(scan_id)


if __name__ == "__main__":
    raise SystemExit(main())
