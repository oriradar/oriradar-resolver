"""Screenshot worker for Redis-backed deployments."""

from __future__ import annotations

from datetime import datetime, timezone
import os

from playwright.sync_api import sync_playwright

from oritypo_solver.services.oriframe import build_screenshot_path, capture_screenshot, screenshot_public_url
from oritypo_solver.services.scan_engine import recompute_scan_derived_state
from oritypo_solver.store import (
    mark_worker_heartbeat,
    pop_screenshot_job,
    queue_enabled,
    update_finding,
)


def worker_name() -> str:
    return os.environ.get("ORI_WORKER_NAME", "oriframe-worker")


def main() -> int:
    if not queue_enabled():
        raise RuntimeError("oriframe worker requires REDIS_URL / queue mode.")

    name = worker_name()
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage"],
        )
        try:
            while True:
                mark_worker_heartbeat(name)
                job = pop_screenshot_job()
                if job is None:
                    continue

                scan_id = job["scan_id"]
                fqdn = job["fqdn"]
                requested_url = job["requested_url"]
                update_finding(
                    scan_id,
                    fqdn,
                    screenshot={
                        "status": "running",
                        "requested_url": requested_url,
                    },
                )
                mark_worker_heartbeat(name)
                try:
                    out_path, rel_path, filename = build_screenshot_path(scan_id, fqdn)
                    details = capture_screenshot(browser, url=requested_url, out_path=out_path)
                    update_finding(
                        scan_id,
                        fqdn,
                        screenshot={
                            "status": "completed",
                            "requested_url": details["requested_url"],
                            "final_url": details["final_url"],
                            "status_code": details["status_code"],
                            "width": details["width"],
                            "height": details["height"],
                            "path": rel_path,
                            "url": screenshot_public_url(scan_id, filename),
                            "captured_at": datetime.now(timezone.utc).isoformat(),
                        },
                    )
                except Exception as exc:  # noqa: BLE001
                    update_finding(
                        scan_id,
                        fqdn,
                        screenshot={
                            "status": "failed",
                            "requested_url": requested_url,
                            "error": exc.__class__.__name__,
                        },
                    )
                recompute_scan_derived_state(scan_id)
        finally:
            browser.close()


if __name__ == "__main__":
    raise SystemExit(main())
