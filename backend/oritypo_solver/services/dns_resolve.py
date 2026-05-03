"""
DNS **oriseek** — resolve core records for candidate hostnames.

Primary path: Rust **oriseek** batch CLI for throughput and concurrency.
Fallback: Python `dnspython` lookups when the binary is not installed.
"""

from __future__ import annotations

import json
import math
import os
import shutil
import subprocess

import dns.exception
import dns.resolver

from oritypo_solver.services.settings import env_float, env_int

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "CNAME")


def _normalize_value(value: str) -> str:
    return value.strip().rstrip(".")


def _oriseek_binary() -> str | None:
    env = os.environ.get("ORISEEK_PATH", "").strip()
    if env:
        return env
    return shutil.which("oriseek")


def dns_batch_concurrency_from_env(default: int = 256) -> int:
    return env_int("ORI_DNS_CONCURRENCY", default=default, minimum=1, maximum=10_000)


def dns_timeout_ms_from_env(default: int = 2_000) -> int:
    return env_int("ORI_DNS_TIMEOUT_MS", default=default, minimum=100, maximum=30_000)


def dns_batch_size_from_env(default: int = 128) -> int:
    return env_int("ORI_DNS_BATCH_SIZE", default=default, minimum=1, maximum=10_000)


def dns_rust_min_batch_from_env(default: int = 32) -> int:
    return env_int("ORI_DNS_RUST_MIN_BATCH", default=default, minimum=1, maximum=10_000)


def dns_process_timeout_s_from_env(default: float = 0.0) -> float:
    return env_float("ORI_DNS_PROCESS_TIMEOUT_S", default=default, minimum=0.0, maximum=3600.0)


def _resolve_one(fqdn: str, record_type: str, lifetime: float) -> list[str]:
    try:
        answer = dns.resolver.resolve(
            fqdn,
            record_type,
            lifetime=lifetime,
            raise_on_no_answer=False,
        )
        if answer.rrset is None:
            return []
        values = [_normalize_value(str(item)) for item in answer]
        return [value for value in values if value]
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
        dns.resolver.LifetimeTimeout,
    ):
        return []
    except Exception:
        return []


def resolve_records(fqdn: str, lifetime: float = 2.0) -> dict[str, list[str]]:
    """Return a compact DNS snapshot for the hostname."""
    return {record_type: _resolve_one(fqdn, record_type, lifetime) for record_type in RECORD_TYPES}


def resolve_records_batch(
    fqdns: list[str],
    lifetime: float = 2.0,
) -> dict[str, dict[str, list[str]]]:
    """Resolve many hostnames, preferring the Rust batch engine when available."""
    hosts = list(dict.fromkeys(fqdn.strip().lower().strip(".") for fqdn in fqdns if fqdn.strip()))
    if not hosts:
        return {}

    binary = _oriseek_binary()
    if binary and len(hosts) >= dns_rust_min_batch_from_env():
        out: dict[str, dict[str, list[str]]] = {}
        batch_size = dns_batch_size_from_env()
        for chunk in _chunked(hosts, batch_size):
            chunk_result = _resolve_records_batch_rust(binary, chunk, lifetime=lifetime)
            if chunk_result is None:
                chunk_result = {fqdn: resolve_records(fqdn, lifetime=lifetime) for fqdn in chunk}
            elif len(chunk_result) < len(chunk):
                missing = [fqdn for fqdn in chunk if fqdn not in chunk_result]
                chunk_result.update({fqdn: resolve_records(fqdn, lifetime=lifetime) for fqdn in missing})
            out.update(chunk_result)
        return out

    return {fqdn: resolve_records(fqdn, lifetime=lifetime) for fqdn in hosts}


def _chunked(items: list[str], chunk_size: int) -> list[list[str]]:
    return [items[i : i + chunk_size] for i in range(0, len(items), chunk_size)]


def _estimated_process_timeout_seconds(batch_len: int, concurrency: int, timeout_ms: int) -> float:
    override = dns_process_timeout_s_from_env()
    if override > 0:
        return override
    wave_count = max(1, math.ceil(batch_len / max(1, concurrency)))
    per_wave_s = (timeout_ms / 1000.0) * len(RECORD_TYPES)
    return max(10.0, min(600.0, (wave_count * per_wave_s * 1.5) + 5.0))


def _resolve_records_batch_rust(
    binary: str,
    hosts: list[str],
    lifetime: float,
) -> dict[str, dict[str, list[str]]] | None:
    timeout_ms = dns_timeout_ms_from_env(default=max(100, int(lifetime * 1000)))
    concurrency = dns_batch_concurrency_from_env()
    input_payload = "".join(f"{fqdn}\n" for fqdn in hosts)
    try:
        proc = subprocess.run(
            [
                binary,
                "resolve",
                "--stdin",
                "--concurrency",
                str(concurrency),
                "--timeout-ms",
                str(timeout_ms),
            ],
            input=input_payload,
            capture_output=True,
            text=True,
            timeout=_estimated_process_timeout_seconds(len(hosts), concurrency, timeout_ms),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    if proc.returncode != 0:
        return None

    out: dict[str, dict[str, list[str]]] = {}
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        dns = obj.get("dns") or {}
        out[obj["fqdn"]] = {
            record_type: [_normalize_value(value) for value in dns.get(record_type, [])]
            for record_type in RECORD_TYPES
        }
    return out


def is_registered(records: dict[str, list[str]]) -> bool:
    return any(records.get(record_type) for record_type in ("A", "AAAA", "MX", "NS", "CNAME"))


def resolve_a(fqdn: str, lifetime: float = 2.0) -> tuple[bool, list[str]]:
    """Backward-compatible helper used by earlier code paths."""
    records = resolve_records(fqdn, lifetime=lifetime)
    ips = [*records.get("A", []), *records.get("AAAA", [])]
    return bool(ips), ips
