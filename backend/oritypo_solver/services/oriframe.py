"""Screenshot capture helpers for **oriframe**."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from playwright.sync_api import Browser

from oritypo_solver.services.settings import env_bool, env_int


def screenshot_dir_from_env() -> Path:
    raw = Path(env_string("ORI_SCREENSHOT_DIR", "/data/screenshots"))
    raw.mkdir(parents=True, exist_ok=True)
    return raw


def screenshot_timeout_ms_from_env(default: int = 15_000) -> int:
    return env_int("ORI_SCREENSHOT_TIMEOUT_MS", default=default, minimum=1000, maximum=120_000)


def screenshot_width_from_env(default: int = 1366) -> int:
    return env_int("ORI_SCREENSHOT_WIDTH", default=default, minimum=320, maximum=4096)


def screenshot_height_from_env(default: int = 900) -> int:
    return env_int("ORI_SCREENSHOT_HEIGHT", default=default, minimum=240, maximum=4096)


def screenshot_full_page_from_env(default: bool = True) -> bool:
    return env_bool("ORI_SCREENSHOT_FULL_PAGE", default=default)


def env_string(name: str, default: str) -> str:
    import os

    value = os.environ.get(name, "").strip()
    return value or default


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip().lower())
    return slug.strip("-._") or "capture"


def screenshot_filename(scan_id: str, fqdn: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{_slug(fqdn)}-{stamp}.png"


def build_screenshot_path(scan_id: str, fqdn: str) -> tuple[Path, str, str]:
    root = screenshot_dir_from_env()
    scan_dir = root / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    filename = screenshot_filename(scan_id, fqdn)
    full_path = scan_dir / filename
    rel_path = f"{scan_id}/{filename}"
    return full_path, rel_path, filename


def screenshot_public_url(scan_id: str, filename: str) -> str:
    return f"/v1/scans/{scan_id}/screenshots/{filename}"


def capture_screenshot(browser: Browser, *, url: str, out_path: Path) -> dict:
    context = browser.new_context(
        viewport={
            "width": screenshot_width_from_env(),
            "height": screenshot_height_from_env(),
        }
    )
    page = context.new_page()
    try:
        response = page.goto(url, wait_until="domcontentloaded", timeout=screenshot_timeout_ms_from_env())
        page.screenshot(path=str(out_path), full_page=screenshot_full_page_from_env())
        return {
            "requested_url": url,
            "final_url": page.url,
            "status_code": response.status if response else None,
            "width": screenshot_width_from_env(),
            "height": screenshot_height_from_env(),
        }
    finally:
        context.close()
