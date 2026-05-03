"""Certificate Transparency lookup (**oricert**).

Interroge les logs publics de Certificate Transparency (via `crt.sh`) pour
decouvrir les domaines actifs contenant la marque cible. Cela couvre les
typosquats qui ne peuvent PAS etre generes par enumeration pure (mots-cles
arbitraires, restructurations semantiques) mais qui ont ete enregistres et
ont obtenu un certificat TLS dans la nature.

Exemples couverts :
- mizuno-chaussures.fr (mot-cle sectoriel)
- celiofrancecelio.fr (duplication marque + pays)
- voyagesncf.fr (restructuration semantique)

Le module retourne une liste de candidats `(fqdn, kind, distance)` injectes
dans le meme pipeline que les variantes orifold.
"""

from __future__ import annotations

import json
import logging
from typing import Iterable

import httpx

from oritypo_solver.services.permutations import _levenshtein, _split_apex
from oritypo_solver.services.settings import env_bool, env_float, env_int

logger = logging.getLogger(__name__)

CRT_SH_URL = "https://crt.sh/"
USER_AGENT = "oricert/0.1 (+https://github.com/your-org/oriradar)"
DEFAULT_RETRIES = 4
RETRYABLE_STATUSES = {429, 500, 502, 503, 504}


def ct_enabled() -> bool:
    return env_bool("ORI_ENABLE_CT", default=True)


def ct_timeout_from_env(default: float = 30.0) -> float:
    """Timeout par requete crt.sh.

    crt.sh est notoirement lent (Postgres backend public), un timeout
    genereux est necessaire. La valeur par defaut est volontairement haute
    et configurable via `ORI_CT_TIMEOUT`.
    """
    return env_float("ORI_CT_TIMEOUT", default=default, minimum=1.0, maximum=120.0)


def ct_max_results_from_env(default: int = 500) -> int:
    return env_int("ORI_CT_MAX_RESULTS", default=default, minimum=10, maximum=10_000)


def ct_min_label_length_from_env(default: int = 3) -> int:
    """Longueur minimale du label de marque pour eviter le bruit (ex: 'a', 'go')."""
    return env_int("ORI_CT_MIN_LABEL_LEN", default=default, minimum=2, maximum=20)


def ct_retries_from_env(default: int = DEFAULT_RETRIES) -> int:
    return env_int("ORI_CT_RETRIES", default=default, minimum=0, maximum=5)


def _brand_label(apex: str) -> str:
    """Extrait le label principal de l'apex (ex: 'mizuno' depuis 'mizuno.com')."""
    label, _ = _split_apex(apex)
    return label.lower()


def _build_search_term(label: str) -> str:
    """Construit le terme de recherche crt.sh.

    Note : `%mizuno%` (LIKE pattern) est tres souvent rejete en 502 par le backend
    crt.sh (Postgres public surcharge). En revanche, `q=mizuno` (full-text via
    Identity) est traite plus efficacement par crt.sh et matche les SAN/CN
    contenant le terme. On combine avec `exclude=expired` pour reduire le bruit.
    """
    return label


def _normalize_fqdn(raw: str) -> str:
    """Nettoie un FQDN brut depuis crt.sh (peut contenir wildcards, espaces, ports)."""
    candidate = raw.strip().strip(".").lower()
    candidate = candidate.lstrip("*.")
    if not candidate or " " in candidate or candidate.startswith("-"):
        return ""
    if "/" in candidate or ":" in candidate or candidate.startswith("xn--"):
        # garde les IDN ASCII (xn--) qui sont des homographes leges
        if candidate.startswith("xn--"):
            return candidate if "." in candidate else ""
        return ""
    return candidate if "." in candidate else ""


def _split_san_field(value: str) -> Iterable[str]:
    """Un champ SAN dans crt.sh peut contenir plusieurs domaines separes par '\\n'."""
    for piece in value.replace("\r", "\n").split("\n"):
        cleaned = _normalize_fqdn(piece)
        if cleaned:
            yield cleaned


def _fetch_crt_sh(label: str, *, timeout: float, retries: int | None = None) -> list[dict]:
    """Requete brute crt.sh avec retries + backoff ; [] sur erreur.

    crt.sh est instable (Postgres public, frequents 502/504). On retente jusqu'a
    `retries+1` fois avec un backoff exponentiel doux (1s, 2s, 4s, ...).
    Les erreurs reseau et les codes HTTP retryables (429/5xx) declenchent un retry.
    Tout est silencieux : un echec CT ne bloque jamais le scan.
    """
    import time

    params = {
        "q": _build_search_term(label),
        "output": "json",
        "exclude": "expired",
    }
    attempts = (retries if retries is not None else ct_retries_from_env()) + 1
    last_error: str | None = None

    for attempt in range(attempts):
        attempt_timeout = timeout * (1.0 + 0.25 * attempt)
        try:
            response = httpx.get(
                CRT_SH_URL,
                params=params,
                timeout=attempt_timeout,
                follow_redirects=True,
                headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            )
        except httpx.HTTPError as exc:
            last_error = exc.__class__.__name__
            logger.debug(
                "crt.sh attempt %d/%d failed for %s: %s",
                attempt + 1,
                attempts,
                label,
                last_error,
            )
            if attempt < attempts - 1:
                time.sleep(min(2 ** attempt, 8))
            continue

        if response.status_code == 200:
            try:
                data = response.json()
            except (ValueError, json.JSONDecodeError):
                last_error = "invalid JSON"
                continue
            if isinstance(data, list):
                return data
            last_error = "non-list payload"
            continue

        last_error = f"HTTP {response.status_code}"
        logger.debug(
            "crt.sh attempt %d/%d non-200 for %s: %s",
            attempt + 1,
            attempts,
            label,
            last_error,
        )
        if response.status_code in RETRYABLE_STATUSES and attempt < attempts - 1:
            time.sleep(min(2 ** attempt, 8))
            continue
        # Code non retryable (404, 400) -> on s'arrete
        break

    if last_error:
        logger.info("oricert: crt.sh gave up for %s (%s)", label, last_error)
    return []


def _label_for_fqdn(fqdn: str) -> str:
    label, _ = _split_apex(fqdn)
    return label.lower()


def discover_ct_candidates(
    apex: str,
    *,
    timeout: float | None = None,
    max_results: int | None = None,
) -> list[tuple[str, str, int]]:
    """Decouvre des candidats via Certificate Transparency.

    Retourne une liste de tuples (fqdn, kind, distance) ou :
    - `kind` est toujours 'oricert:CT' (signal externe)
    - `distance` est la distance de Levenshtein entre labels apex et candidat

    Le filtrage applique :
    - le label de marque doit faire au moins `ORI_CT_MIN_LABEL_LEN` caracteres
    - le FQDN doit etre different de l'apex (pas l'original)
    - le FQDN doit etre un domaine valide (pas d'espaces, pas d'IP, pas de wildcards
      a part les xn--)
    - le label du FQDN doit contenir la marque OU avoir une distance <= 4 avec elle

    Note : on ne renvoie pas les sous-domaines de l'apex officiel (ex: si apex=mizuno.com,
    on ignore www.mizuno.com, support.mizuno.com). On garde par contre les domaines
    qui sont sous d'autres apex (mizuno-chaussures.fr).
    """
    label = _brand_label(apex)
    min_len = ct_min_label_length_from_env()
    if len(label) < min_len:
        logger.debug("CT skip: brand label '%s' too short (< %d chars)", label, min_len)
        return []

    timeout_value = timeout if timeout is not None else ct_timeout_from_env()
    cap = max_results if max_results is not None else ct_max_results_from_env()

    raw_entries = _fetch_crt_sh(label, timeout=timeout_value)
    if not raw_entries:
        return []

    apex_normalized = apex.strip().strip(".").lower()
    seen_fqdns: set[str] = set()
    candidates: list[tuple[str, str, int]] = []

    for entry in raw_entries:
        if len(candidates) >= cap:
            break
        common_name = entry.get("common_name") if isinstance(entry, dict) else None
        name_value = entry.get("name_value") if isinstance(entry, dict) else None

        sources: list[str] = []
        if isinstance(common_name, str):
            cleaned = _normalize_fqdn(common_name)
            if cleaned:
                sources.append(cleaned)
        if isinstance(name_value, str):
            sources.extend(_split_san_field(name_value))

        for fqdn in sources:
            if fqdn in seen_fqdns:
                continue
            seen_fqdns.add(fqdn)

            if fqdn == apex_normalized:
                continue
            # Ignore les sous-domaines de l'apex (www.brand.com, api.brand.com)
            if fqdn.endswith(f".{apex_normalized}"):
                continue

            candidate_label = _label_for_fqdn(fqdn)
            if len(candidate_label) < 2:
                continue

            # Le label doit contenir la marque, ou en etre tres proche
            if label not in candidate_label:
                d = _levenshtein(label, candidate_label)
                if d > 4:
                    continue
                distance = d
            else:
                # Quand la marque est contenue, la distance reflete l'ecart d'expansion
                # (ex: mizuno-chaussures vs mizuno = 11)
                distance = max(0, len(candidate_label) - len(label))

            candidates.append((fqdn, "oricert:CT", distance))
            if len(candidates) >= cap:
                break

    logger.info(
        "oricert: %d candidates discovered for %s (label='%s')",
        len(candidates),
        apex,
        label,
    )
    return candidates
