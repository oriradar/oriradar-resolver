"""HTTP probing for candidate domains (**oriprobe**)."""

from __future__ import annotations

import asyncio
import hashlib
import html
import logging
import re
import ssl
from urllib.parse import urljoin, urlparse

import httpx

from oritypo_solver.services.settings import env_float, env_int

logger = logging.getLogger(__name__)

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
USER_AGENT = "oriprobe/0.1 (+https://github.com/your-org/oriradar)"
MAX_BODY_BYTES = 65_536
LOGIN_KEYWORDS = (
    "login",
    "sign in",
    "signin",
    "secure",
    "verify",
    "account",
    "password",
    "wallet",
    "checkout",
    "auth",
)
PARKING_KEYWORDS = (
    "domain for sale",
    "this website is for sale",
    "buy this domain",
    "parked domain",
    "sedo",
    "hugedomains",
    "afternic",
    "parkingcrew",
    "parklogic",
)
CHALLENGE_KEYWORDS = ("just a moment", "attention required", "verify you are human")


def http_probe_timeout_from_env(default: float = 4.0) -> float:
    return env_float("ORI_HTTP_TIMEOUT", default=default, minimum=0.5, maximum=30.0)


def http_probe_limit_from_env(default: int = 25) -> int:
    return env_int("ORI_HTTP_MAX_PROBES", default=default, minimum=0, maximum=5_000)


def http_probe_concurrency_from_env(default: int = 25) -> int:
    return env_int("ORI_HTTP_CONCURRENCY", default=default, minimum=1, maximum=5_000)


def http_connect_timeout_from_env(default: float = 1.5) -> float:
    return env_float("ORI_HTTP_CONNECT_TIMEOUT", default=default, minimum=0.2, maximum=10.0)


def http_read_timeout_from_env(default: float = 3.5) -> float:
    return env_float("ORI_HTTP_READ_TIMEOUT", default=default, minimum=0.2, maximum=30.0)


def _extract_title(content_type: str, body: bytes, encoding: str | None) -> str | None:
    if "html" not in content_type.lower():
        return None
    text = body.decode(encoding or "utf-8", errors="replace")
    match = TITLE_RE.search(text)
    if not match:
        return None
    title = " ".join(match.group(1).split())
    if not title:
        return None
    return html.unescape(title)[:200]


def _build_timeout(timeout: float | None = None) -> httpx.Timeout:
    if timeout is not None:
        return httpx.Timeout(timeout)
    total = http_probe_timeout_from_env()
    connect = min(http_connect_timeout_from_env(), total)
    read = min(http_read_timeout_from_env(), total)
    return httpx.Timeout(timeout=total, connect=connect, read=read, write=total, pool=total)


def _extract_keyword_hits(text: str, keywords: tuple[str, ...]) -> list[str]:
    lowered = text.lower()
    return [keyword for keyword in keywords if keyword in lowered]


def _host_matches_input(final_host: str, fqdn: str) -> bool:
    if not final_host:
        return True
    return final_host == fqdn or final_host.endswith(f".{fqdn}")


def _extract_favicon_url(body: bytes, base_url: str) -> str | None:
    text = body.decode("utf-8", errors="replace")[:MAX_BODY_BYTES]
    match = re.search(
        r'<link[^>]+rel=["\'](?:shortcut )?icon["\'][^>]+href=["\']([^"\']+)["\']',
        text,
        re.IGNORECASE,
    )
    if match:
        return urljoin(base_url, match.group(1))
    return urljoin(base_url, "/favicon.ico")


def _hash_favicon(data: bytes) -> str | None:
    """MurmurHash3-style favicon hash (Shodan-compatible via mmh3, fallback to md5)."""
    if not data or len(data) < 16:
        return None
    try:
        import mmh3
        import base64
        b64 = base64.encodebytes(data)
        return str(mmh3.hash(b64))
    except ImportError:
        return "md5:" + hashlib.md5(data).hexdigest()


async def _fetch_favicon_hash(
    client: httpx.AsyncClient, fqdn: str, body: bytes, final_url: str, timeout: float | None
) -> str | None:
    favicon_url = _extract_favicon_url(body, final_url)
    if not favicon_url:
        return None
    try:
        resp = await client.get(favicon_url, timeout=_build_timeout(timeout))
        if resp.status_code == 200 and len(resp.content) >= 16:
            return _hash_favicon(resp.content)
    except httpx.HTTPError:
        pass
    return None


def _extract_cert_sans(fqdn: str) -> list[str]:
    """Extract Subject Alternative Names from the TLS certificate."""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            __import__("socket").create_connection((fqdn, 443), timeout=3.0),
            server_hostname=fqdn,
        ) as sock:
            cert = sock.getpeercert()
            if not cert:
                return []
            sans: list[str] = []
            for entry_type, value in cert.get("subjectAltName", ()):
                if entry_type == "DNS":
                    sans.append(value.lower())
            return sans
    except Exception:
        return []


def _analyze_page(fqdn: str, final_url: str, server: str | None, title: str | None, body: bytes) -> dict:
    final_host = (urlparse(final_url).hostname or "").lower()
    text = body.decode("utf-8", errors="replace")[:4096]
    server_text = server or ""
    title_text = title or ""
    combined = "\n".join([title_text, text, final_url, server_text])
    login_hits = _extract_keyword_hits(combined, LOGIN_KEYWORDS)
    parking_hits = _extract_keyword_hits(combined, PARKING_KEYWORDS)
    challenge_hits = _extract_keyword_hits(combined, CHALLENGE_KEYWORDS)
    return {
        "final_host": final_host,
        "final_host_matches_input": _host_matches_input(final_host, fqdn),
        "login_page": bool(login_hits),
        "parking_page": bool(parking_hits),
        "challenge_page": bool(challenge_hits),
        "login_indicators": login_hits[:5],
        "parking_indicators": parking_hits[:5],
        "challenge_indicators": challenge_hits[:5],
    }


async def _fetch(client: httpx.AsyncClient, fqdn: str, url: str, timeout: float | None) -> dict:
    async with client.stream("GET", url, timeout=_build_timeout(timeout)) as response:
        body = b""
        async for chunk in response.aiter_bytes():
            if not chunk or len(body) >= MAX_BODY_BYTES:
                break
            body += chunk[: MAX_BODY_BYTES - len(body)]
            if len(body) >= MAX_BODY_BYTES:
                break

        content_type = response.headers.get("content-type", "")
        title = _extract_title(content_type, body, response.encoding)
        analysis = _analyze_page(
            fqdn=fqdn,
            final_url=str(response.url),
            server=response.headers.get("server"),
            title=title,
            body=body,
        )

        favicon_hash: str | None = None
        if response.url.scheme == "https" or "html" in content_type.lower():
            favicon_hash = await _fetch_favicon_hash(
                client, fqdn, body, str(response.url), timeout
            )

        cert_sans: list[str] = []
        if response.url.scheme == "https":
            cert_sans = await asyncio.to_thread(_extract_cert_sans, fqdn)

        return {
            "reachable": True,
            "scheme": response.url.scheme,
            "requested_url": url,
            "final_url": str(response.url),
            "status_code": response.status_code,
            "redirects": len(response.history),
            "server": response.headers.get("server"),
            "content_type": content_type,
            "content_length": response.headers.get("content-length"),
            "title": title,
            "favicon_hash": favicon_hash,
            "cert_sans": cert_sans,
            **analysis,
        }


async def _probe_host_async(client: httpx.AsyncClient, fqdn: str, timeout: float | None = None) -> dict:
    errors: list[str] = []
    for url in (f"https://{fqdn}", f"http://{fqdn}"):
        try:
            return await _fetch(client, fqdn, url, timeout=timeout)
        except httpx.HTTPError as exc:
            errors.append(f"{url}: {exc.__class__.__name__}")
    return {"reachable": False, "errors": errors}


async def _probe_hosts_async(fqdns: list[str], timeout: float | None = None) -> dict[str, dict]:
    if not fqdns:
        return {}
    concurrency = http_probe_concurrency_from_env()
    semaphore = asyncio.Semaphore(concurrency)
    limits = httpx.Limits(
        max_connections=concurrency,
        max_keepalive_connections=concurrency,
    )
    async with httpx.AsyncClient(
        follow_redirects=True,
        headers={"User-Agent": USER_AGENT},
        limits=limits,
    ) as client:
        async def worker(hostname: str) -> tuple[str, dict]:
            async with semaphore:
                return hostname, await _probe_host_async(client, hostname, timeout=timeout)

        results = await asyncio.gather(*(worker(fqdn) for fqdn in fqdns))
    return dict(results)


def probe_hosts(fqdns: list[str], timeout: float | None = None) -> dict[str, dict]:
    normalized = list(dict.fromkeys(fqdn.strip().lower().strip(".") for fqdn in fqdns if fqdn.strip()))
    if not normalized:
        return {}
    return asyncio.run(_probe_hosts_async(normalized, timeout=timeout))


def probe_host(fqdn: str, timeout: float | None = None) -> dict:
    key = fqdn.strip().lower().strip(".")
    return probe_hosts([fqdn], timeout=timeout).get(key, {"reachable": False, "errors": ["probe_failed"]})
