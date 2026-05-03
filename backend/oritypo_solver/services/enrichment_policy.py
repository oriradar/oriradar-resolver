"""Policies deciding when to trigger heavy enrichments."""

from __future__ import annotations

from oritypo_solver.services.settings import env_bool, env_int


def screenshots_enabled() -> bool:
    return env_bool("ORI_ENABLE_SCREENSHOTS", default=True)


def crawl_enabled() -> bool:
    return env_bool("ORI_ENABLE_CRAWL", default=True)


def screenshot_limit_from_env(default: int = 5) -> int:
    return env_int("ORI_SCREENSHOT_MAX_JOBS", default=default, minimum=0, maximum=10_000)


def crawl_limit_from_env(default: int = 8) -> int:
    return env_int("ORI_CRAWL_MAX_JOBS", default=default, minimum=0, maximum=10_000)


def screenshot_score_threshold(default: int = 75) -> int:
    return env_int("ORI_SCREENSHOT_SCORE_THRESHOLD", default=default, minimum=0, maximum=100)


def screenshot_prediction_threshold(default: int = 80) -> int:
    return env_int("ORI_SCREENSHOT_PREDICTION_THRESHOLD", default=default, minimum=0, maximum=100)


def screenshot_parking_prediction_threshold(default: int = 85) -> int:
    return env_int(
        "ORI_SCREENSHOT_PARKING_PREDICTION_THRESHOLD",
        default=default,
        minimum=0,
        maximum=100,
    )


def crawl_score_threshold(default: int = 55) -> int:
    return env_int("ORI_CRAWL_SCORE_THRESHOLD", default=default, minimum=0, maximum=100)


def crawl_prediction_threshold(default: int = 65) -> int:
    return env_int("ORI_CRAWL_PREDICTION_THRESHOLD", default=default, minimum=0, maximum=100)


def enrichment_url_for_finding(finding: dict) -> str | None:
    http_result = finding.get("http") or {}
    for key in ("final_url", "requested_url"):
        value = http_result.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    fqdn = str(finding.get("fqdn", "")).strip()
    if fqdn:
        return f"https://{fqdn}"
    return None


def screenshot_priority(finding: dict) -> str:
    http_result = finding.get("http") or {}
    if (
        int(finding.get("score", 0)) >= 85
        or bool(http_result.get("login_page"))
        or http_result.get("final_host_matches_input") is False
    ):
        return "high"
    return "normal"


def should_capture_screenshot(finding: dict) -> bool:
    if not screenshots_enabled():
        return False
    http_result = finding.get("http") or {}
    if not http_result.get("reachable"):
        return False
    score = int(finding.get("score", 0))
    prediction_score = int(finding.get("prediction_score", 0))
    if http_result.get("parking_page") and prediction_score < screenshot_parking_prediction_threshold():
        return False
    return any(
        [
            score >= screenshot_score_threshold(),
            prediction_score >= screenshot_prediction_threshold(),
            bool(http_result.get("login_page")),
            http_result.get("final_host_matches_input") is False,
            int(http_result.get("redirects", 0) or 0) >= 2,
        ]
    )


def crawl_priority(finding: dict) -> str:
    http_result = finding.get("http") or {}
    if bool(http_result.get("login_page")) or int(finding.get("prediction_score", 0)) >= 80:
        return "high"
    return "normal"


def should_crawl_finding(finding: dict) -> bool:
    if not crawl_enabled():
        return False
    http_result = finding.get("http") or {}
    if not http_result.get("reachable"):
        return False
    score = int(finding.get("score", 0))
    prediction_score = int(finding.get("prediction_score", 0))
    return any(
        [
            score >= crawl_score_threshold(),
            prediction_score >= crawl_prediction_threshold(),
            bool(http_result.get("login_page")),
            http_result.get("final_host_matches_input") is False,
            int(http_result.get("redirects", 0) or 0) >= 1,
            bool(http_result.get("parking_page")),
        ]
    )
