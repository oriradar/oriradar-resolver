"""Orchestrates the Ori scan stack into ranked findings."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from oritypo_solver.services.enrichment_policy import (
    crawl_limit_from_env,
    crawl_priority,
    enrichment_url_for_finding,
    screenshot_limit_from_env,
    screenshot_priority,
    should_capture_screenshot,
    should_crawl_finding,
)
from oritypo_solver.services.permutations import Variant
from oritypo_solver.services.dns_resolve import is_registered, resolve_records_batch
from oritypo_solver.services.http_probe import http_probe_limit_from_env, probe_host, probe_hosts
from oritypo_solver.services.oricert import (
    ct_enabled,
    discover_ct_candidates,
)
from oritypo_solver.services.oricrawl import crawl_site
from oritypo_solver.services.orisim import (
    build_reference_text,
    compute_similarity,
    encode_text,
    similarity_enabled,
)
from oritypo_solver.services.oristream import emit_scan_completed
from oritypo_solver.services.permutations import generate_variants, max_variants_from_env
from oritypo_solver.services.rdap_lookup import lookup_domain_rdap, rdap_enabled, rdap_limit_from_env
from oritypo_solver.services.scoring import (
    HIGH_SIGNAL_KINDS,
    MEDIUM_SIGNAL_KINDS,
    build_summary,
    score_prediction_finding,
    score_finding,
)
from oritypo_solver.store import (
    enqueue_crawl_job,
    enqueue_screenshot_job,
    get_scan,
    queue_enabled,
    update_scan,
)

logger = logging.getLogger(__name__)


def _rescore_finding(finding: dict, reference_data: dict | None = None) -> None:
    score, reasons, risk_level = score_finding(
        distance=finding["distance"],
        kind=finding["kind"],
        dns_records=finding["dns"],
        http_result=finding.get("http"),
        rdap_result=finding.get("rdap"),
        crawl_result=finding.get("crawl"),
        reference_data=reference_data,
    )
    prediction_score, prediction_reasons, prediction_level = score_prediction_finding(
        distance=finding["distance"],
        kind=finding["kind"],
        dns_records=finding["dns"],
        http_result=finding.get("http"),
        rdap_result=finding.get("rdap"),
        crawl_result=finding.get("crawl"),
        reference_data=reference_data,
    )
    finding["score"] = score
    finding["reasons"] = reasons
    finding["risk_level"] = risk_level
    finding["prediction_score"] = prediction_score
    finding["prediction_reasons"] = prediction_reasons
    finding["prediction_level"] = prediction_level


def _sort_findings(findings: list[dict]) -> None:
    findings.sort(
        key=lambda finding: (
            -finding["score"],
            -finding["prediction_score"],
            finding["distance"],
            finding["fqdn"],
        )
    )


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _kind_priority(kind: str) -> int:
    if kind in HIGH_SIGNAL_KINDS:
        return 0
    if kind in MEDIUM_SIGNAL_KINDS:
        return 1
    return 2


def _dedupe_variants(variants: list[Variant]) -> list[Variant]:
    deduped: dict[str, Variant] = {}
    for variant in variants:
        previous = deduped.get(variant.fqdn)
        if previous is None or (
            variant.distance,
            _kind_priority(variant.kind),
            variant.kind,
        ) < (
            previous.distance,
            _kind_priority(previous.kind),
            previous.kind,
        ):
            deduped[variant.fqdn] = variant
    return list(deduped.values())


def _rebuild_summary(existing_summary: dict | None, findings: list[dict]) -> dict:
    existing_summary = existing_summary or {}
    return build_summary(
        total_variants=int(existing_summary.get("total_variants", len(findings))),
        findings=findings,
        http_probed=int(existing_summary.get("http_probed_count", 0)),
        rdap_lookups=int(existing_summary.get("rdap_lookup_count", 0)),
    )


def recompute_scan_derived_state(scan_id: str) -> None:
    rec = get_scan(scan_id)
    if not rec:
        return
    ref = rec.reference_data
    ref_embedding = (ref or {}).get("content_embedding")

    findings = list(rec.findings or [])
    for finding in findings:
        crawl = finding.get("crawl")
        if (
            ref_embedding
            and crawl
            and crawl.get("status") == "completed"
            and finding.get("similarity") is None
        ):
            sim = compute_similarity(ref_embedding, crawl)
            if sim is not None:
                finding["similarity"] = sim
                crawl["similarity"] = sim

                ref_favicon = (ref or {}).get("favicon_hash")
                http_res = finding.get("http") or {}
                finding["favicon_match"] = bool(
                    ref_favicon and http_res.get("favicon_hash") == ref_favicon
                )

        _rescore_finding(finding, reference_data=ref)
    _sort_findings(findings)
    summary = _rebuild_summary(rec.summary, findings)
    update_scan(scan_id, findings=findings, summary=summary)


def _queue_screenshot_jobs(scan_id: str, findings: list[dict]) -> list[dict]:
    jobs: list[dict] = []
    for finding in findings[: screenshot_limit_from_env()]:
        if not should_capture_screenshot(finding):
            continue
        requested_url = enrichment_url_for_finding(finding)
        if not requested_url:
            continue
        priority = screenshot_priority(finding)
        finding["screenshot"] = {
            "status": "queued",
            "requested_url": requested_url,
            "queued_at": _utcnow_iso(),
            "priority": priority,
        }
        jobs.append(
            {
                "scan_id": scan_id,
                "fqdn": finding["fqdn"],
                "requested_url": requested_url,
                "priority": priority,
            }
        )
    return jobs


def _queue_crawl_jobs(scan_id: str, findings: list[dict]) -> list[dict]:
    jobs: list[dict] = []
    for finding in findings[: crawl_limit_from_env()]:
        if not should_crawl_finding(finding):
            continue
        requested_url = enrichment_url_for_finding(finding)
        if not requested_url:
            continue
        priority = crawl_priority(finding)
        finding["crawl"] = {
            "status": "queued",
            "requested_url": requested_url,
            "queued_at": _utcnow_iso(),
            "priority": priority,
        }
        jobs.append(
            {
                "scan_id": scan_id,
                "fqdn": finding["fqdn"],
                "requested_url": requested_url,
                "priority": priority,
            }
        )
    return jobs


def _fetch_reference_data(apex: str) -> dict:
    """Collect reference signals from the official site for comparison."""
    ref: dict = {"target": apex}
    try:
        http_ref = probe_host(apex, timeout=6.0)
        ref["favicon_hash"] = http_ref.get("favicon_hash")
        ref["cert_sans"] = http_ref.get("cert_sans") or []
    except Exception:
        logger.debug("Reference HTTP probe failed for %s", apex, exc_info=True)
        ref["favicon_hash"] = None
        ref["cert_sans"] = []

    if similarity_enabled():
        try:
            crawl_ref = crawl_site(target=apex, start_url=f"https://{apex}")
            content_text = build_reference_text(crawl_ref)
            ref["content_text"] = content_text
            ref["content_embedding"] = encode_text(content_text)
        except Exception:
            logger.debug("Reference crawl failed for %s", apex, exc_info=True)
            ref["content_text"] = ""
            ref["content_embedding"] = None
    else:
        ref["content_text"] = ""
        ref["content_embedding"] = None

    return ref


def _augment_with_ct_candidates(apex: str, variants: list[Variant]) -> list[Variant]:
    """Complete les variantes orifold avec les decouvertes Certificate Transparency.

    Les candidats CT sont des typosquats deja **enregistres et certifies** par des
    autorites de certification publiques. Ils couvrent les cas que l'enumeration
    pure ne peut pas generer (mots-cles arbitraires, restructurations).
    """
    if not ct_enabled():
        return variants
    try:
        ct_candidates = discover_ct_candidates(apex)
    except Exception:
        logger.exception("oricert discovery failed for %s", apex)
        return variants

    if not ct_candidates:
        return variants

    existing_fqdns = {variant.fqdn for variant in variants}
    new_variants = list(variants)
    for fqdn, kind, distance in ct_candidates:
        if fqdn in existing_fqdns:
            continue
        existing_fqdns.add(fqdn)
        new_variants.append(Variant(fqdn=fqdn, kind=kind, distance=distance))
    return new_variants


def run_scan(scan_id: str, apex: str) -> None:
    cap = max_variants_from_env()
    variants = _dedupe_variants(generate_variants(apex, max_variants=cap))
    variants = _augment_with_ct_candidates(apex, variants)
    total = len(variants)
    update_scan(
        scan_id,
        status="running",
        progress_done=0,
        progress_total=total,
        error=None,
        summary=None,
    )

    reference_data = _fetch_reference_data(apex)
    update_scan(scan_id, reference_data=reference_data)

    candidate_variants = [variant for variant in variants if variant.fqdn != apex]
    dns_by_fqdn = resolve_records_batch([variant.fqdn for variant in candidate_variants])

    findings: list[dict] = []
    for i, variant in enumerate(variants):
        if variant.fqdn == apex:
            update_scan(scan_id, progress_done=i + 1)
            continue

        dns_records = dns_by_fqdn.get(variant.fqdn, {})
        if is_registered(dns_records):
            finding = {
                "fqdn": variant.fqdn,
                "kind": variant.kind,
                "distance": variant.distance,
                "registered": True,
                "dns": dns_records,
                "http": None,
                "rdap": None,
            }
            _rescore_finding(finding, reference_data=reference_data)
            findings.append(finding)
        update_scan(scan_id, progress_done=i + 1)

    _sort_findings(findings)

    http_targets = findings[: http_probe_limit_from_env()]
    progress_done = total
    progress_total = total + len(http_targets)
    update_scan(scan_id, progress_done=progress_done, progress_total=progress_total)

    http_results = probe_hosts([finding["fqdn"] for finding in http_targets]) if http_targets else {}
    for finding in http_targets:
        finding["http"] = http_results.get(
            finding["fqdn"],
            {"reachable": False, "errors": ["http_probe_missing"]},
        )

        ref_favicon = reference_data.get("favicon_hash")
        http_res = finding["http"]
        if ref_favicon and http_res.get("favicon_hash") == ref_favicon:
            finding["favicon_match"] = True

        _rescore_finding(finding, reference_data=reference_data)
        progress_done += 1
        update_scan(scan_id, progress_done=progress_done, progress_total=progress_total)

    _sort_findings(findings)

    rdap_targets: list[dict] = []
    if rdap_enabled():
        rdap_targets = findings[: rdap_limit_from_env()]
        progress_total += len(rdap_targets)
        update_scan(scan_id, progress_done=progress_done, progress_total=progress_total)

        for finding in rdap_targets:
            result = lookup_domain_rdap(finding["fqdn"])
            if result.get("available"):
                finding["rdap"] = result
                _rescore_finding(finding, reference_data=reference_data)
            progress_done += 1
            update_scan(scan_id, progress_done=progress_done, progress_total=progress_total)

    _sort_findings(findings)

    screenshot_jobs: list[dict] = []
    crawl_jobs: list[dict] = []
    if queue_enabled():
        screenshot_jobs = _queue_screenshot_jobs(scan_id, findings)
        crawl_jobs = _queue_crawl_jobs(scan_id, findings)

    summary = build_summary(
        total_variants=total,
        findings=findings,
        http_probed=len(http_targets),
        rdap_lookups=len(rdap_targets),
    )

    update_scan(
        scan_id,
        status="completed",
        findings=findings,
        summary=summary,
        progress_done=progress_total,
        progress_total=progress_total,
    )

    if queue_enabled():
        for job in screenshot_jobs:
            enqueue_screenshot_job(**job)
        for job in crawl_jobs:
            enqueue_crawl_job(**job)

    stream = emit_scan_completed(
        scan_id=scan_id,
        target=apex,
        summary=summary,
        findings=findings,
    )
    if stream is not None:
        update_scan(scan_id, summary={**summary, "stream": stream})
