"""Outbound events for completed scans (**oristream**)."""

from __future__ import annotations

import logging
import os

import httpx

from oritypo_solver.services.settings import env_float

logger = logging.getLogger(__name__)


def emit_scan_completed(
    *,
    scan_id: str,
    target: str,
    summary: dict,
    findings: list[dict],
) -> dict | None:
    webhook_url = os.environ.get("ORI_WEBHOOK_URL", "").strip()
    if not webhook_url:
        return None

    payload = {
        "event": "scan.completed",
        "scan_id": scan_id,
        "target": target,
        "summary": summary,
        "top_findings": findings[:10],
    }
    timeout = env_float("ORI_WEBHOOK_TIMEOUT", default=5.0, minimum=0.5, maximum=30.0)
    try:
        response = httpx.post(
            webhook_url,
            json=payload,
            timeout=timeout,
            headers={"User-Agent": "oristream/0.1 (+https://github.com/your-org/oriradar)"},
        )
        return {
            "enabled": True,
            "delivered": response.status_code < 400,
            "status_code": response.status_code,
        }
    except httpx.HTTPError as exc:
        logger.warning("oristream delivery failed: %s", exc)
        return {
            "enabled": True,
            "delivered": False,
            "error": exc.__class__.__name__,
        }
