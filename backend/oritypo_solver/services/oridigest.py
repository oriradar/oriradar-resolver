"""Digest helpers for recurring monitoring summaries (**oridigest**)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os

import httpx

from oritypo_solver.services.settings import env_float, env_int


def digest_interval_seconds_from_env(default: int = 3600) -> int:
    return env_int("ORI_DIGEST_INTERVAL_S", default=default, minimum=60, maximum=86_400)


def digest_lookback_hours_from_env(default: int = 24) -> int:
    return env_int("ORI_DIGEST_LOOKBACK_HOURS", default=default, minimum=1, maximum=24 * 30)


def digest_top_n_from_env(default: int = 20) -> int:
    return env_int("ORI_DIGEST_TOP_N", default=default, minimum=1, maximum=500)


def digest_timeout_from_env(default: float = 10.0) -> float:
    return env_float("ORI_DIGEST_TIMEOUT", default=default, minimum=1.0, maximum=60.0)


def digest_webhook_url() -> str:
    return os.environ.get("ORI_DIGEST_WEBHOOK_URL", "").strip()


def digest_lookback_since() -> datetime:
    return datetime.now(timezone.utc) - timedelta(hours=digest_lookback_hours_from_env())


def build_digest_payload(*, scans: list) -> dict:
    top_findings: list[dict] = []
    critical_count = 0
    high_count = 0
    screenshot_completed_count = 0
    crawl_completed_count = 0
    login_like_count = 0
    for scan in scans:
        for finding in scan.findings:
            if finding.get("risk_level") == "critical":
                critical_count += 1
            elif finding.get("risk_level") == "high":
                high_count += 1
            screenshot = finding.get("screenshot") or {}
            crawl = finding.get("crawl") or {}
            http_result = finding.get("http") or {}
            if screenshot.get("status") == "completed":
                screenshot_completed_count += 1
            if crawl.get("status") == "completed":
                crawl_completed_count += 1
            if http_result.get("login_page"):
                login_like_count += 1
            top_findings.append(
                {
                    "scan_id": scan.id,
                    "target": scan.target,
                    "fqdn": finding.get("fqdn"),
                    "score": finding.get("score"),
                    "prediction_score": finding.get("prediction_score"),
                    "risk_level": finding.get("risk_level"),
                    "prediction_level": finding.get("prediction_level"),
                }
            )
    top_findings.sort(
        key=lambda item: (
            -(item.get("score") or 0),
            -(item.get("prediction_score") or 0),
            item.get("fqdn") or "",
        )
    )
    return {
        "event": "digest.completed",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scans_count": len(scans),
        "critical_findings_count": critical_count,
        "high_findings_count": high_count,
        "login_like_count": login_like_count,
        "screenshot_completed_count": screenshot_completed_count,
        "crawl_completed_count": crawl_completed_count,
        "top_findings": top_findings[: digest_top_n_from_env()],
    }


def send_digest_payload(payload: dict) -> dict:
    webhook = digest_webhook_url()
    if not webhook:
        return {"enabled": False, "delivered": False}
    try:
        response = httpx.post(
            webhook,
            json=payload,
            timeout=digest_timeout_from_env(),
            headers={"User-Agent": "oridigest/0.1 (+https://github.com/your-org/oriradar)"},
        )
        return {
            "enabled": True,
            "delivered": response.status_code < 400,
            "status_code": response.status_code,
        }
    except httpx.HTTPError as exc:
        return {
            "enabled": True,
            "delivered": False,
            "error": exc.__class__.__name__,
        }
