"""Lightweight content crawl for suspicious domains (**oricrawl**)."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import re
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from oritypo_solver.services.settings import env_bool, env_float, env_int

LOGIN_HINTS = ("login", "signin", "sign-in", "auth", "account", "verify", "password", "checkout")
PAYMENT_HINTS = ("payment", "pay", "billing", "invoice", "wallet", "card")


def crawl_timeout_from_env(default: float = 5.0) -> float:
    return env_float("ORI_CRAWL_TIMEOUT", default=default, minimum=0.5, maximum=60.0)


def crawl_max_pages_from_env(default: int = 5) -> int:
    return env_int("ORI_CRAWL_MAX_PAGES", default=default, minimum=1, maximum=100)


def crawl_max_depth_from_env(default: int = 1) -> int:
    return env_int("ORI_CRAWL_MAX_DEPTH", default=default, minimum=0, maximum=5)


def crawl_max_links_per_page_from_env(default: int = 25) -> int:
    return env_int("ORI_CRAWL_MAX_LINKS_PER_PAGE", default=default, minimum=1, maximum=500)


def crawl_max_html_bytes_from_env(default: int = 200_000) -> int:
    return env_int("ORI_CRAWL_MAX_HTML_BYTES", default=default, minimum=10_000, maximum=5_000_000)


def crawl_snippet_chars_from_env(default: int = 1200) -> int:
    return env_int("ORI_CRAWL_SNIPPET_CHARS", default=default, minimum=200, maximum=20_000)


def crawl_follow_query_strings(default: bool = False) -> bool:
    return env_bool("ORI_CRAWL_FOLLOW_QUERY_STRINGS", default=default)


@dataclass
class CrawlPage:
    url: str
    depth: int


def _brand_terms(target: str) -> set[str]:
    label = target.split(".", 1)[0].lower()
    return {piece for piece in re.split(r"[-._]+", label) if len(piece) >= 3}


def _interesting_path(url: str, hints: tuple[str, ...]) -> bool:
    lowered = url.lower()
    return any(hint in lowered for hint in hints)


def _same_host(target_host: str, candidate_url: str) -> bool:
    parsed = urlparse(candidate_url)
    host = (parsed.hostname or "").lower()
    return host == target_host


def _external_http_links(
    page_host: str, base_url: str, soup: BeautifulSoup, *, limit: int
) -> list[str]:
    out: list[str] = []
    for tag in soup.find_all("a", href=True):
        if len(out) >= limit:
            break
        normalized = _normalize_link(base_url, tag["href"])
        if not normalized:
            continue
        host = (urlparse(normalized).hostname or "").lower()
        if host and host != page_host:
            out.append(normalized)
    return out


def _meta_description(soup: BeautifulSoup) -> str:
    tag = soup.find("meta", attrs={"name": re.compile("^description$", re.I)})
    if tag and tag.get("content"):
        return " ".join(str(tag["content"]).split())[:600]
    og = soup.find("meta", attrs={"property": re.compile("^og:description$", re.I)})
    if og and og.get("content"):
        return " ".join(str(og["content"]).split())[:600]
    return ""


def _og_title(soup: BeautifulSoup) -> str:
    og = soup.find("meta", attrs={"property": re.compile("^og:title$", re.I)})
    if og and og.get("content"):
        return " ".join(str(og["content"]).split())[:200]
    return ""


def _heading_samples(soup: BeautifulSoup, *, limit: int = 8) -> list[str]:
    out: list[str] = []
    for tag in soup.find_all(["h1", "h2"]):
        if len(out) >= limit:
            break
        text = " ".join(tag.get_text(" ", strip=True).split())
        if text:
            out.append(text[:240])
    return out


def _normalize_snippet(text: str, max_chars: int) -> str:
    collapsed = " ".join(text.split())
    return collapsed[:max_chars]


def _normalize_link(base_url: str, href: str) -> str | None:
    if not href or href.startswith(("mailto:", "javascript:", "tel:")):
        return None
    absolute = urljoin(base_url, href)
    parsed = urlparse(absolute)
    if parsed.scheme not in {"http", "https"}:
        return None
    if not crawl_follow_query_strings():
        absolute = parsed._replace(query="", fragment="").geturl()
    else:
        absolute = parsed._replace(fragment="").geturl()
    return absolute


def crawl_site(*, target: str, start_url: str) -> dict:
    brand_terms = _brand_terms(target)
    start_host = (urlparse(start_url).hostname or "").lower()
    queue = deque([CrawlPage(url=start_url, depth=0)])
    seen: set[str] = set()
    visited_pages: list[dict] = []
    forms_count = 0
    password_forms_count = 0
    login_urls: list[str] = []
    payment_urls: list[str] = []
    titles: list[str] = []
    og_titles: list[str] = []
    meta_descriptions: list[str] = []
    heading_samples: list[str] = []
    brand_term_hits = 0
    meta_brand_hits = 0
    scripts_total = 0
    external_http_urls: list[str] = []
    snippet_parts: list[str] = []
    html_limit = crawl_max_html_bytes_from_env()
    snippet_budget = crawl_snippet_chars_from_env()

    with httpx.Client(
        follow_redirects=True,
        timeout=crawl_timeout_from_env(),
        headers={"User-Agent": "oricrawl/0.1 (+https://github.com/your-org/oriradar)"},
    ) as client:
        while queue and len(visited_pages) < crawl_max_pages_from_env():
            page = queue.popleft()
            if page.url in seen:
                continue
            seen.add(page.url)

            try:
                response = client.get(page.url)
            except httpx.HTTPError:
                continue

            if "html" not in response.headers.get("content-type", "").lower():
                continue

            text = response.text[:html_limit]
            soup = BeautifulSoup(text, "html.parser")
            page_host = (urlparse(str(response.url)).hostname or "").lower() or start_host

            title = " ".join((soup.title.get_text(" ", strip=True) if soup.title else "").split())[:200]
            if title:
                titles.append(title)

            meta_desc = _meta_description(soup)
            if meta_desc:
                meta_descriptions.append(meta_desc)
                meta_lower = meta_desc.lower()
                meta_brand_hits += sum(meta_lower.count(term) for term in brand_terms)

            og_title = _og_title(soup)
            if og_title:
                og_titles.append(og_title)

            for line in _heading_samples(soup):
                heading_samples.append(line)

            scripts = soup.find_all("script")
            scripts_total += len(scripts)

            forms = soup.find_all("form")
            forms_count += len(forms)
            password_forms_count += sum(1 for form in forms if form.find("input", {"type": "password"}))

            body_text = soup.get_text(" ", strip=True).lower()
            brand_term_hits += sum(body_text.count(term) for term in brand_terms)

            if _interesting_path(str(response.url), LOGIN_HINTS):
                login_urls.append(str(response.url))
            if _interesting_path(str(response.url), PAYMENT_HINTS):
                payment_urls.append(str(response.url))

            external = _external_http_links(
                page_host,
                str(response.url),
                soup,
                limit=crawl_max_links_per_page_from_env(),
            )
            external_http_urls.extend(external)

            raw_snippet = soup.get_text(" ", strip=True)
            if raw_snippet:
                snippet_parts.append(_normalize_snippet(raw_snippet, max(snippet_budget // max(1, crawl_max_pages_from_env()), 200)))

            visited_pages.append(
                {
                    "url": str(response.url),
                    "depth": page.depth,
                    "status_code": response.status_code,
                    "title": title or None,
                    "meta_description": meta_desc or None,
                    "og_title": og_title or None,
                    "headings": _heading_samples(soup, limit=4),
                    "forms_count": len(forms),
                    "scripts_count": len(scripts),
                    "external_links_sample": external[:8],
                }
            )

            if page.depth >= crawl_max_depth_from_env():
                continue

            link_count = 0
            for tag in soup.find_all("a", href=True):
                if link_count >= crawl_max_links_per_page_from_env():
                    break
                normalized = _normalize_link(str(response.url), tag["href"])
                if not normalized or normalized in seen:
                    continue
                if not _same_host(start_host, normalized):
                    continue
                queue.append(CrawlPage(url=normalized, depth=page.depth + 1))
                link_count += 1

    combined_snippet = _normalize_snippet(" ".join(snippet_parts), snippet_budget)
    unique_external = list(dict.fromkeys(external_http_urls))[:40]

    return {
        "status": "completed",
        "requested_url": start_url,
        "pages_visited": len(visited_pages),
        "pages": visited_pages,
        "forms_count": forms_count,
        "password_forms_count": password_forms_count,
        "login_urls": login_urls[:10],
        "payment_urls": payment_urls[:10],
        "titles": titles[:10],
        "og_titles": og_titles[:10],
        "meta_descriptions": meta_descriptions[:10],
        "heading_samples": heading_samples[:20],
        "brand_term_hits": brand_term_hits,
        "meta_brand_hits": meta_brand_hits,
        "scripts_total": scripts_total,
        "external_http_urls": unique_external,
        "content_snippet": combined_snippet or None,
        "interesting_urls": list(dict.fromkeys(login_urls + payment_urls))[:15],
    }
