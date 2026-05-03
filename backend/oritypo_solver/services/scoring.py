"""Risk scoring for candidate domains (**oriscore**)."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

HIGH_SIGNAL_KINDS = {
    "orifold:Bitsquatting",
    "orifold:CommonMisspelling",
    "orifold:Homoglyph",
    "orifold:Homophones",
    "orifold:Mapped",
    "orifold:NumeralSwap",
    "orifold:Replacement",
    "orifold:Insertion",
    "orifold:Transposition",
    "orifold:Subdomain",
    "orifold:WrongSld",
    "orifold:MultiOmission",
    "orifold:PermutationCrossTld",
    "orifold:ReverseWord",
    "orifold:CountryCodeAffix",
    # oricert:CT = domaine reellement enregistre + certifie (signal externe fort)
    "oricert:CT",
}
MEDIUM_SIGNAL_KINDS = {
    "orifold:Addition",
    "orifold:AddTld",
    "orifold:ChangeDotDash",
    "orifold:DoubleVowelInsertion",
    "orifold:FauxTld",
    "orifold:Omission",
    "orifold:MissingDot",
    "orifold:Hyphenation",
    "orifold:Repetition",
    "orifold:SingularPluralize",
    "orifold:StripDash",
    "orifold:Tld",
    "orifold:Keyword",
    "orifold:VowelSwap",
    "orifold:VowelShuffle",
}
PARKING_HINTS = (
    "parked",
    "parking",
    "domain for sale",
    "this website is for sale",
    "buy this domain",
    "sedo",
    "afternic",
    "hugedomains",
    "parkingcrew",
    "parklogic",
)


def risk_level_for_score(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def prediction_level_for_score(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 55:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def _normalize_text(value: str | None) -> str:
    return (value or "").strip().lower()


def _meaningful_mx_records(mx_records: list[str]) -> list[str]:
    meaningful: list[str] = []
    for record in mx_records:
        lowered = " ".join(_normalize_text(record).split())
        if lowered in {"", ".", "0", "0 .", "0 localhost", "localhost"}:
            continue
        target = lowered.split()[-1]
        if target in {"", ".", "localhost"}:
            continue
        meaningful.append(record)
    return meaningful


def _looks_like_parking_host(value: str) -> bool:
    lowered = _normalize_text(value)
    return any(hint in lowered for hint in PARKING_HINTS)


def _registered_age_days(rdap_result: dict | None) -> int | None:
    if not rdap_result:
        return None
    registered_at = rdap_result.get("registered_at")
    if not isinstance(registered_at, str) or not registered_at.strip():
        return None
    try:
        parsed = datetime.fromisoformat(registered_at.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return max(0, int((datetime.now(timezone.utc) - parsed).total_seconds() // 86_400))


def _brand_label(target: str) -> str:
    return target.split(".", 1)[0].lower()


def _cert_mentions_brand(cert_sans: list[str], target: str) -> bool:
    brand = _brand_label(target)
    if len(brand) < 3:
        return False
    for san in cert_sans:
        cleaned = san.lstrip("*.")
        if brand in cleaned:
            return True
    return False


def _cert_is_generic_wildcard(cert_sans: list[str]) -> bool:
    return any(san.startswith("*.") for san in cert_sans) and len(cert_sans) <= 2


def score_finding(
    *,
    distance: int,
    kind: str,
    dns_records: dict[str, list[str]],
    http_result: dict | None = None,
    rdap_result: dict | None = None,
    crawl_result: dict | None = None,
    reference_data: dict | None = None,
) -> tuple[int, list[str], str]:
    score = 0
    reasons: list[str] = []
    meaningful_mx = _meaningful_mx_records(dns_records.get("MX") or [])
    ref = reference_data or {}

    if distance <= 1:
        score += 25
        reasons.append("very close to the target")
    elif distance == 2:
        score += 18
        reasons.append("close to the target")
    elif distance == 3:
        score += 8
        reasons.append("moderately close to the target")
    else:
        score -= 10
        reasons.append("far from the target")

    if kind in HIGH_SIGNAL_KINDS:
        score += 18
        reasons.append(f"high-signal permutation type ({kind})")
    elif kind in MEDIUM_SIGNAL_KINDS:
        score += 10
        reasons.append(f"common typosquat permutation ({kind})")

    if dns_records.get("A") or dns_records.get("AAAA"):
        score += 15
        reasons.append("resolves to an IP address")
    if meaningful_mx:
        score += 8
        reasons.append("has mail infrastructure")
    elif dns_records.get("MX"):
        score += 2
        reasons.append("publishes placeholder mail exchange records")
    if dns_records.get("NS"):
        score += 4
        reasons.append("has delegated name servers")
    if dns_records.get("CNAME"):
        cname_values = dns_records.get("CNAME") or []
        if any(_looks_like_parking_host(value) for value in cname_values):
            score -= 12
            reasons.append("aliases a parking-like host")
        else:
            score += 6
            reasons.append("aliases another hostname")
    if (
        dns_records.get("NS")
        and not dns_records.get("A")
        and not dns_records.get("AAAA")
        and not meaningful_mx
        and not dns_records.get("CNAME")
    ):
        score -= 4
        reasons.append("only exposes name servers")

    if http_result and http_result.get("reachable"):
        score += 10
        reasons.append("serves HTTP content")
        status_code = int(http_result.get("status_code", 0) or 0)
        if 200 <= status_code < 400:
            score += 5
            reasons.append("returns a successful or redirecting status")
        elif status_code >= 400:
            score -= 12
            reasons.append("returns an error status code")
        if http_result.get("scheme") == "https":
            score += 3
            reasons.append("responds over HTTPS")
        if http_result.get("title"):
            score += 2
            reasons.append("has an HTML title")
        if http_result.get("login_page"):
            score += 8
            reasons.append("looks like a login or account page")
        if http_result.get("redirects", 0) >= 2:
            score += 3
            reasons.append("uses a multi-step redirect chain")
        if http_result.get("final_host_matches_input") is False:
            score += 4
            reasons.append("redirects to a different host")
        if http_result.get("challenge_page"):
            score -= 6
            reasons.append("is protected by a challenge or interstitial page")
        if http_result.get("parking_page"):
            score -= 32
            reasons.append("looks like a parked or for-sale domain")

        favicon_hash = http_result.get("favicon_hash")
        ref_favicon = ref.get("favicon_hash")
        if favicon_hash and ref_favicon and favicon_hash == ref_favicon:
            score += 10
            reasons.append("favicon matches the official site")

        cert_sans = http_result.get("cert_sans") or []
        if cert_sans:
            target = ref.get("target", "")
            is_wildcard = _cert_is_generic_wildcard(cert_sans)
            mentions_brand = bool(target and _cert_mentions_brand(cert_sans, target))
            if is_wildcard:
                score -= 8
                reasons.append("generic wildcard certificate (likely shared host)")
            elif mentions_brand:
                score += 6
                reasons.append("TLS certificate references the brand name")

    if rdap_result and rdap_result.get("available"):
        score += 5
        reasons.append("has RDAP registration metadata")
        if rdap_result.get("registrar"):
            score += 3
            reasons.append("exposes registrar information")
        age_days = _registered_age_days(rdap_result)
        if age_days is not None:
            if age_days <= 30:
                score += 10
                reasons.append("was registered recently")
            elif age_days <= 180:
                score += 6
                reasons.append("is a relatively new registration")
            elif age_days >= 3650:
                score -= 4
                reasons.append("is an old registration")

    if crawl_result and crawl_result.get("status") == "completed":
        if int(crawl_result.get("password_forms_count", 0) or 0) > 0:
            score += 8
            reasons.append("password forms were found during crawl")
        if int(crawl_result.get("forms_count", 0) or 0) > 0:
            score += 4
            reasons.append("forms were found during crawl")
        if crawl_result.get("login_urls"):
            score += 6
            reasons.append("login-like URLs were found during crawl")
        if crawl_result.get("payment_urls"):
            score += 5
            reasons.append("payment-related URLs were found during crawl")
        if int(crawl_result.get("meta_brand_hits", 0) or 0) > 0:
            score += 4
            reasons.append("brand-like terms appear in page metadata")
        if crawl_result.get("external_http_urls"):
            score += 2
            reasons.append("external hyperlinks were observed during crawl")

        snippet = crawl_result.get("content_snippet") or ""
        if snippet and len(snippet) < 50:
            score -= 3
            reasons.append("minimal content found during crawl")

    similarity = (crawl_result or {}).get("similarity")
    has_reference = bool(ref.get("content_embedding"))
    if isinstance(similarity, (int, float)) and has_reference:
        if similarity >= 0.85:
            score += 15
            reasons.append("content closely resembles the official site")
        elif similarity >= 0.65:
            score += 8
            reasons.append("content moderately resembles the official site")
        elif similarity >= 0.45:
            score -= 5
            reasons.append("content shows limited overlap with the official site")
        elif similarity >= 0.30:
            score -= 12
            reasons.append("content has little overlap with the official site")
        else:
            score -= 20
            reasons.append("content bears no resemblance to the official site")

    legitimacy_deductions = 0

    age_days = _registered_age_days(rdap_result)
    if age_days is not None:
        if age_days >= 3650:
            legitimacy_deductions += 12
        elif age_days >= 1825:
            legitimacy_deductions += 6

    no_malicious_signals = (
        not (http_result or {}).get("login_page")
        and not (crawl_result or {}).get("login_urls")
        and not (crawl_result or {}).get("payment_urls")
        and int((crawl_result or {}).get("password_forms_count", 0) or 0) == 0
    )
    if isinstance(similarity, (int, float)) and similarity < 0.30 and no_malicious_signals:
        legitimacy_deductions += 10

    ref_fav = ref.get("favicon_hash")
    http_fav = (http_result or {}).get("favicon_hash")
    if ref_fav and http_fav and ref_fav != http_fav:
        legitimacy_deductions += 5

    if legitimacy_deductions > 0:
        score -= legitimacy_deductions
        reasons.append(f"legitimacy signals reduce risk (-{legitimacy_deductions})")

    score = max(0, min(score, 100))
    return score, reasons, risk_level_for_score(score)


def score_prediction_finding(
    *,
    distance: int,
    kind: str,
    dns_records: dict[str, list[str]],
    http_result: dict | None = None,
    rdap_result: dict | None = None,
    crawl_result: dict | None = None,
    reference_data: dict | None = None,
) -> tuple[int, list[str], str]:
    score = 0
    reasons: list[str] = []
    meaningful_mx = _meaningful_mx_records(dns_records.get("MX") or [])
    ref = reference_data or {}

    if distance <= 1:
        score += 35
        reasons.append("very close brand distance")
    elif distance == 2:
        score += 24
        reasons.append("close brand distance")
    elif distance == 3:
        score += 12
        reasons.append("moderately close brand distance")
    else:
        score += 0

    if kind in HIGH_SIGNAL_KINDS:
        score += 18
        reasons.append(f"high-signal permutation family ({kind})")
    elif kind in MEDIUM_SIGNAL_KINDS:
        score += 10
        reasons.append(f"relevant predictive permutation family ({kind})")

    if dns_records.get("A") or dns_records.get("AAAA"):
        score += 5
        reasons.append("already resolves")
    if dns_records.get("NS"):
        score += 3
        reasons.append("has delegated name servers")
    if meaningful_mx:
        score += 5
        reasons.append("has real mail infrastructure")
    elif dns_records.get("MX"):
        score += 2
        reasons.append("publishes placeholder mail exchange records")
    if dns_records.get("CNAME"):
        score += 3
        reasons.append("aliases another host")

    if http_result:
        if http_result.get("reachable"):
            score += 5
            reasons.append("already serves content")
        if http_result.get("login_page"):
            score += 8
            reasons.append("looks like a credential or account page")
        if http_result.get("parking_page"):
            score += 5
            reasons.append("appears monetized or parked")
        if http_result.get("challenge_page"):
            score += 2
            reasons.append("is already fronted by a protection layer")
        if http_result.get("final_host_matches_input") is False:
            score += 5
            reasons.append("redirects to another controlled host")

        favicon_hash = http_result.get("favicon_hash")
        ref_favicon = ref.get("favicon_hash")
        if favicon_hash and ref_favicon and favicon_hash == ref_favicon:
            score += 8
            reasons.append("favicon matches the official site")

        cert_sans = http_result.get("cert_sans") or []
        if cert_sans:
            target = ref.get("target", "")
            if target and _cert_mentions_brand(cert_sans, target):
                score += 5
                reasons.append("TLS certificate references the brand name")

    age_days = _registered_age_days(rdap_result)
    has_infrastructure = bool(
        dns_records.get("A")
        or dns_records.get("AAAA")
        or meaningful_mx
        or (http_result or {}).get("reachable")
    )
    if rdap_result and rdap_result.get("available"):
        score += 2
        reasons.append("has RDAP registration metadata")
        if age_days is not None:
            if age_days <= 30:
                score += 12 if has_infrastructure else 6
                reasons.append("was registered very recently")
            elif age_days <= 180:
                score += 7 if has_infrastructure else 3
                reasons.append("is a relatively new registration")
            elif age_days >= 3650:
                score -= 3
                reasons.append("is an old registration")

    if crawl_result and crawl_result.get("status") == "completed":
        if int(crawl_result.get("brand_term_hits", 0) or 0) > 0:
            score += 6
            reasons.append("brand terms were found across crawled pages")
        if int(crawl_result.get("meta_brand_hits", 0) or 0) > 0:
            score += 5
            reasons.append("brand-like terms appear in metadata or social previews")
        if crawl_result.get("login_urls"):
            score += 6
            reasons.append("login-like URLs were found during crawl")
        if crawl_result.get("payment_urls"):
            score += 5
            reasons.append("payment-related URLs were found during crawl")
        if int(crawl_result.get("password_forms_count", 0) or 0) > 0:
            score += 8
            reasons.append("password forms were found during crawl")
        if crawl_result.get("external_http_urls"):
            score += 3
            reasons.append("outbound links suggest a more elaborate site")

    similarity = (crawl_result or {}).get("similarity")
    has_reference = bool(ref.get("content_embedding"))
    if isinstance(similarity, (int, float)) and has_reference:
        if similarity >= 0.85:
            score += 12
            reasons.append("content closely resembles the official site")
        elif similarity >= 0.65:
            score += 6
            reasons.append("content moderately resembles the official site")
        elif similarity < 0.30:
            score -= 10
            reasons.append("content bears no resemblance to the official site")
        elif similarity < 0.45:
            score -= 5
            reasons.append("content is very different from the official site")

    score = max(0, min(score, 100))
    return score, reasons, prediction_level_for_score(score)


def build_summary(
    *,
    total_variants: int,
    findings: list[dict],
    http_probed: int,
    rdap_lookups: int,
) -> dict:
    level_counts = Counter(finding["risk_level"] for finding in findings)
    prediction_counts = Counter(finding["prediction_level"] for finding in findings)
    live_http = sum(1 for finding in findings if (finding.get("http") or {}).get("reachable"))
    parking_count = sum(1 for finding in findings if (finding.get("http") or {}).get("parking_page"))
    login_like_count = sum(1 for finding in findings if (finding.get("http") or {}).get("login_page"))
    screenshot_queued_count = sum(
        1 for finding in findings if (finding.get("screenshot") or {}).get("status") == "queued"
    )
    screenshot_completed_count = sum(
        1 for finding in findings if (finding.get("screenshot") or {}).get("status") == "completed"
    )
    crawl_queued_count = sum(1 for finding in findings if (finding.get("crawl") or {}).get("status") == "queued")
    crawl_completed_count = sum(
        1 for finding in findings if (finding.get("crawl") or {}).get("status") == "completed"
    )
    cross_host_redirect_count = sum(
        1
        for finding in findings
        if (finding.get("http") or {}).get("reachable")
        and (finding.get("http") or {}).get("final_host_matches_input") is False
    )
    max_score = max((finding["score"] for finding in findings), default=0)
    return {
        "total_variants": total_variants,
        "registered_count": len(findings),
        "http_probed_count": http_probed,
        "live_http_count": live_http,
        "parking_count": parking_count,
        "login_like_count": login_like_count,
        "screenshot_queued_count": screenshot_queued_count,
        "screenshot_completed_count": screenshot_completed_count,
        "crawl_queued_count": crawl_queued_count,
        "crawl_completed_count": crawl_completed_count,
        "cross_host_redirect_count": cross_host_redirect_count,
        "rdap_lookup_count": rdap_lookups,
        "max_score": max_score,
        "max_prediction_score": max((finding["prediction_score"] for finding in findings), default=0),
        "risk_counts": {
            "critical": level_counts.get("critical", 0),
            "high": level_counts.get("high", 0),
            "medium": level_counts.get("medium", 0),
            "low": level_counts.get("low", 0),
        },
        "prediction_counts": {
            "critical": prediction_counts.get("critical", 0),
            "high": prediction_counts.get("high", 0),
            "medium": prediction_counts.get("medium", 0),
            "low": prediction_counts.get("low", 0),
        },
    }
