"""
Domain variant generation.

Primary path: **orifold** (Rust, `crates/orifold`) — JSON lines on stdout.
Fallback: bounded Python heuristics when `orifold` is not installed or `ORIFOLD_PATH` is unset.

Set `ORIFOLD_PATH` to the `orifold` binary, or install it on `PATH`, for production-quality permutations.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)
COMMON_MULTI_SUFFIXES = (
    "ac.uk",
    "co.uk",
    "gov.uk",
    "ltd.uk",
    "me.uk",
    "net.uk",
    "org.uk",
    "plc.uk",
    "sch.uk",
    "ac.jp",
    "co.jp",
    "go.jp",
    "ne.jp",
    "or.jp",
    "com.au",
    "net.au",
    "org.au",
    "edu.au",
    "gov.au",
    "asn.au",
    "id.au",
    "co.nz",
    "net.nz",
    "org.nz",
    "govt.nz",
    "ac.nz",
    "co.in",
    "firm.in",
    "net.in",
    "org.in",
    "gen.in",
    "ind.in",
    "com.br",
    "com.mx",
    "com.tr",
    "com.pl",
    "com.sg",
    "com.ar",
    "com.co",
    "co.za",
    "co.il",
)
NUMERAL_GROUPS = (
    ("0", "zero"),
    ("1", "one", "first"),
    ("2", "two", "second"),
    ("3", "three", "third"),
    ("4", "four", "fourth", "for"),
    ("5", "five", "fifth"),
    ("6", "six", "sixth"),
    ("7", "seven", "seventh"),
    ("8", "eight", "eighth"),
    ("9", "nine", "ninth"),
)


@dataclass(frozen=True)
class Variant:
    fqdn: str
    kind: str
    distance: int


def _split_apex(host: str) -> tuple[str, str]:
    host = host.lower().strip(".")
    if not host or "." not in host:
        return host, ""
    for suffix in COMMON_MULTI_SUFFIXES:
        suffix_with_dot = f".{suffix}"
        if host.endswith(suffix_with_dot):
            domain = host[: -len(suffix_with_dot)]
            if domain:
                return domain, suffix
    parts = host.rsplit(".", 1)
    return parts[0], parts[1]


def _suffix_family(tld: str) -> tuple[str, ...]:
    families = {
        "ac.uk": ("ac.uk", "co.uk", "gov.uk", "ltd.uk", "me.uk", "net.uk", "org.uk", "plc.uk", "sch.uk"),
        "co.uk": ("ac.uk", "co.uk", "gov.uk", "ltd.uk", "me.uk", "net.uk", "org.uk", "plc.uk", "sch.uk"),
        "gov.uk": ("ac.uk", "co.uk", "gov.uk", "ltd.uk", "me.uk", "net.uk", "org.uk", "plc.uk", "sch.uk"),
        "ltd.uk": ("ac.uk", "co.uk", "gov.uk", "ltd.uk", "me.uk", "net.uk", "org.uk", "plc.uk", "sch.uk"),
        "me.uk": ("ac.uk", "co.uk", "gov.uk", "ltd.uk", "me.uk", "net.uk", "org.uk", "plc.uk", "sch.uk"),
        "net.uk": ("ac.uk", "co.uk", "gov.uk", "ltd.uk", "me.uk", "net.uk", "org.uk", "plc.uk", "sch.uk"),
        "org.uk": ("ac.uk", "co.uk", "gov.uk", "ltd.uk", "me.uk", "net.uk", "org.uk", "plc.uk", "sch.uk"),
        "plc.uk": ("ac.uk", "co.uk", "gov.uk", "ltd.uk", "me.uk", "net.uk", "org.uk", "plc.uk", "sch.uk"),
        "sch.uk": ("ac.uk", "co.uk", "gov.uk", "ltd.uk", "me.uk", "net.uk", "org.uk", "plc.uk", "sch.uk"),
        "ac.jp": ("ac.jp", "co.jp", "go.jp", "ne.jp", "or.jp"),
        "co.jp": ("ac.jp", "co.jp", "go.jp", "ne.jp", "or.jp"),
        "go.jp": ("ac.jp", "co.jp", "go.jp", "ne.jp", "or.jp"),
        "ne.jp": ("ac.jp", "co.jp", "go.jp", "ne.jp", "or.jp"),
        "or.jp": ("ac.jp", "co.jp", "go.jp", "ne.jp", "or.jp"),
        "com.au": ("com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au"),
        "net.au": ("com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au"),
        "org.au": ("com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au"),
        "edu.au": ("com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au"),
        "gov.au": ("com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au"),
        "asn.au": ("com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au"),
        "id.au": ("com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au"),
    }
    return families.get(tld, ())


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return _levenshtein(b, a)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        cur = [i + 1]
        for j, cb in enumerate(b):
            cur.append(
                min(prev[j + 1] + 1, cur[j] + 1, prev[j] + (ca != cb))
            )
        prev = cur
    return prev[-1]


def normalize_target(raw: str) -> str:
    """Accept https://example.com/ or example.com → apex hostname."""
    s = raw.strip()
    if not s:
        return ""
    if "://" in s:
        from urllib.parse import urlparse

        u = urlparse(s)
        host = u.hostname or ""
    else:
        host = s.split("/")[0].split(":")[0]
    host = host.lower().strip(".")
    if not host or not re.match(r"^[a-z0-9.-]+$", host):
        return ""
    return host


def _orifold_binary() -> str | None:
    env = os.environ.get("ORIFOLD_PATH", "").strip()
    if env and Path(env).is_file():
        return env
    w = shutil.which("orifold")
    return w


def _generate_via_orifold(binary: str, apex: str, max_variants: int) -> list[Variant]:
    proc = subprocess.run(
        [binary, "enumerate", apex, "--max", str(max_variants)],
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    if proc.returncode != 0:
        err = (proc.stderr or "").strip() or f"exit {proc.returncode}"
        raise RuntimeError(f"orifold failed: {err}")
    out: list[Variant] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        fqdn = obj["fqdn"]
        kind = str(obj.get("kind", "Permutation"))
        label_a, _ = _split_apex(apex)
        label_b, _ = _split_apex(fqdn)
        d = _levenshtein(label_a, label_b) if label_a and label_b else 0
        out.append(Variant(fqdn=fqdn, kind=f"orifold:{kind}", distance=d))
    return out


def generate_variants(apex: str, max_variants: int = 200) -> list[Variant]:
    """Build a bounded list of typo / TLD-style variants for the apex domain."""
    binary = _orifold_binary()
    if binary:
        try:
            return _generate_via_orifold(binary, apex, max_variants)
        except Exception as e:
            logger.warning(
                "orifold unavailable or failed (%s); using Python fallback",
                e,
            )

    return _generate_variants_python(apex, max_variants)


def _generate_variants_python(apex: str, max_variants: int = 200) -> list[Variant]:
    """Reference implementation when Rust **orifold** is not used."""
    label, tld = _split_apex(apex)
    if not label or not tld:
        return [Variant(fqdn=apex, kind="Original", distance=0)]

    seen: set[str] = set()
    out: list[Variant] = []

    def push(fqdn: str, kind: str, ref: str) -> None:
        if fqdn in seen or len(out) >= max_variants:
            return
        seen.add(fqdn)
        d = _levenshtein(ref.split(".")[0], fqdn.split(".")[0])
        out.append(Variant(fqdn=fqdn, kind=kind, distance=d))

    push(apex, "Original", apex)

    if len(label) > 3:
        for i in range(len(label)):
            nl = label[:i] + label[i + 1 :]
            if len(nl) >= 2:
                push(f"{nl}.{tld}", "Omission", apex)

    for i in range(len(label) - 1):
        chars = list(label)
        chars[i], chars[i + 1] = chars[i + 1], chars[i]
        nl = "".join(chars)
        if nl != label:
            push(f"{nl}.{tld}", "Transposition", apex)

    for i in range(1, len(label)):
        nl = label[:i] + "-" + label[i:]
        push(f"{nl}.{tld}", "Hyphenation", apex)

    for i in range(len(label)):
        nl = label[:i] + label[i] + label[i] + label[i + 1 :]
        push(f"{nl}.{tld}", "Repetition", apex)

    extra_tlds = ("net", "org", "io", "co", "app", "dev", "info")
    for et in extra_tlds:
        if et != tld:
            push(f"{label}.{et}", "Tld", apex)

    for p in ("my", "secure", "login", "www"):
        push(f"{p}-{label}.{tld}", "Keyword", apex)
        push(f"{label}-{p}.{tld}", "Keyword", apex)

    for group in NUMERAL_GROUPS:
        for source in group:
            if source not in label:
                continue
            for target in group:
                if target != source:
                    push(f"{label.replace(source, target)}.{tld}", "NumeralSwap", apex)

    for suffix in _suffix_family(tld):
        if suffix != tld:
            push(f"{label}.{suffix}", "WrongSld", apex)

    return out[:max_variants]


def max_variants_from_env(default: int = 200) -> int:
    raw = os.environ.get("ORI_MAX_VARIANTS", "").strip()
    if not raw:
        return default
    try:
        v = int(raw)
        return max(1, min(v, 50_000))
    except ValueError:
        return default
