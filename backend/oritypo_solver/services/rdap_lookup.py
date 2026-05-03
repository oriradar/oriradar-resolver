"""RDAP lookups for candidate domains (**orirdap**)."""

from __future__ import annotations

import httpx

from oritypo_solver.services.settings import env_bool, env_float, env_int

RDAP_BASE_URL = "https://rdap.org/domain/"
USER_AGENT = "orirdap/0.1 (+https://github.com/your-org/oriradar)"


def rdap_enabled() -> bool:
    return env_bool("ORI_ENABLE_RDAP", default=False)


def rdap_timeout_from_env(default: float = 4.0) -> float:
    return env_float("ORI_RDAP_TIMEOUT", default=default, minimum=0.5, maximum=30.0)


def rdap_limit_from_env(default: int = 10) -> int:
    return env_int("ORI_RDAP_MAX_LOOKUPS", default=default, minimum=0, maximum=1_000)


def _extract_vcard_name(entity: dict) -> str | None:
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return None
    for item in vcard[1]:
        if not isinstance(item, list) or len(item) < 4:
            continue
        if item[0] in {"fn", "org"} and isinstance(item[3], str) and item[3].strip():
            return item[3].strip()
    return None


def _extract_event_date(data: dict, event_action: str) -> str | None:
    for event in data.get("events", []):
        if event.get("eventAction") == event_action:
            value = event.get("eventDate")
            if isinstance(value, str) and value.strip():
                return value
    return None


def lookup_domain_rdap(fqdn: str, timeout: float | None = None) -> dict:
    timeout = timeout if timeout is not None else rdap_timeout_from_env()
    try:
        response = httpx.get(
            f"{RDAP_BASE_URL}{fqdn}",
            timeout=timeout,
            follow_redirects=True,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/rdap+json, application/json",
            },
        )
    except httpx.HTTPError as exc:
        return {"available": False, "error": exc.__class__.__name__}

    if response.status_code >= 400:
        return {"available": False, "status_code": response.status_code}

    try:
        data = response.json()
    except ValueError:
        return {"available": False, "error": "invalid_json"}

    registrar = None
    for entity in data.get("entities", []):
        roles = set(entity.get("roles") or [])
        if "registrar" in roles:
            registrar = _extract_vcard_name(entity) or entity.get("handle")
            break

    return {
        "available": True,
        "ldh_name": data.get("ldhName") or fqdn,
        "handle": data.get("handle"),
        "status": data.get("status") or [],
        "registrar": registrar,
        "registered_at": _extract_event_date(data, "registration"),
        "expires_at": _extract_event_date(data, "expiration"),
        "port43": data.get("port43"),
    }
