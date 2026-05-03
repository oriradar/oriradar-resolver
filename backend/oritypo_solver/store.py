"""Scan store, queues and worker state backend.

Memory mode is kept for local development and tests.
Redis mode is used for Docker / VPS deployments to persist scans and queue jobs.
"""

from __future__ import annotations

import json
import os
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from oritypo_solver.services.settings import env_int

try:
    import redis
except ImportError:  # pragma: no cover - optional at import time
    redis = None

SCAN_KEY_PREFIX = "oriradar:scan:"
SCAN_QUEUE_KEY = "oriradar:scan_jobs"
SCREENSHOT_QUEUE_KEY = "oriradar:screenshot_jobs"
CRAWL_QUEUE_KEY = "oriradar:crawl_jobs"
WORKER_HEARTBEAT_KEY_PREFIX = "oriradar:worker:"
STATE_KEY_PREFIX = "oriradar:state:"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class ScanRecord:
    id: str
    target: str
    status: str  # pending | running | completed | failed
    progress_done: int = 0
    progress_total: int = 0
    findings: list[dict[str, Any]] = field(default_factory=list)
    summary: dict[str, Any] | None = None
    reference_data: dict[str, Any] | None = None
    error: str | None = None
    created_at: datetime = field(default_factory=_utcnow)
    updated_at: datetime = field(default_factory=_utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target,
            "status": self.status,
            "progress_done": self.progress_done,
            "progress_total": self.progress_total,
            "findings": self.findings,
            "summary": self.summary,
            "reference_data": self.reference_data,
            "error": self.error,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ScanRecord":
        return cls(
            id=payload["id"],
            target=payload["target"],
            status=payload["status"],
            progress_done=int(payload.get("progress_done", 0)),
            progress_total=int(payload.get("progress_total", 0)),
            findings=list(payload.get("findings") or []),
            summary=payload.get("summary"),
            reference_data=payload.get("reference_data"),
            error=payload.get("error"),
            created_at=datetime.fromisoformat(payload["created_at"]),
            updated_at=datetime.fromisoformat(payload["updated_at"]),
        )


_lock = threading.Lock()
_scans: dict[str, ScanRecord] = {}
_redis_client = None


def redis_enabled() -> bool:
    return bool(os.environ.get("REDIS_URL", "").strip()) and redis is not None


def queue_enabled() -> bool:
    return redis_enabled()


def _scan_key(scan_id: str) -> str:
    return f"{SCAN_KEY_PREFIX}{scan_id}"


def _worker_heartbeat_key(worker_name: str) -> str:
    return f"{WORKER_HEARTBEAT_KEY_PREFIX}{worker_name}:heartbeat"


def _state_key(name: str) -> str:
    return f"{STATE_KEY_PREFIX}{name}"


def worker_heartbeat_ttl_from_env(default: int = 120) -> int:
    return env_int("ORI_WORKER_HEARTBEAT_TTL", default=default, minimum=10, maximum=3600)


def queue_pop_timeout_from_env(default: int = 5) -> int:
    return env_int("ORI_QUEUE_POP_TIMEOUT", default=default, minimum=1, maximum=60)


def _get_redis():
    global _redis_client
    if not redis_enabled():
        return None
    if _redis_client is None:
        _redis_client = redis.Redis.from_url(os.environ["REDIS_URL"], decode_responses=True)
    return _redis_client


def _save_record(rec: ScanRecord) -> None:
    client = _get_redis()
    if client is not None:
        client.set(_scan_key(rec.id), json.dumps(rec.to_dict()))
        return
    with _lock:
        _scans[rec.id] = rec


def _load_record(scan_id: str) -> ScanRecord | None:
    client = _get_redis()
    if client is not None:
        raw = client.get(_scan_key(scan_id))
        if not raw:
            return None
        return ScanRecord.from_dict(json.loads(raw))
    with _lock:
        return _scans.get(scan_id)


def create_scan(target: str) -> ScanRecord:
    sid = str(uuid.uuid4())
    rec = ScanRecord(id=sid, target=target, status="pending")
    _save_record(rec)
    return rec


def get_scan(scan_id: str) -> ScanRecord | None:
    return _load_record(scan_id)


def list_scans(
    *,
    status: str | None = None,
    updated_since: datetime | None = None,
    limit: int | None = None,
) -> list[ScanRecord]:
    client = _get_redis()
    if client is not None:
        records = []
        for key in client.scan_iter(match=f"{SCAN_KEY_PREFIX}*"):
            raw = client.get(key)
            if not raw:
                continue
            records.append(ScanRecord.from_dict(json.loads(raw)))
    else:
        with _lock:
            records = list(_scans.values())

    if status is not None:
        records = [record for record in records if record.status == status]
    if updated_since is not None:
        records = [record for record in records if record.updated_at >= updated_since]
    records.sort(key=lambda record: record.updated_at, reverse=True)
    if limit is not None:
        records = records[:limit]
    return records


def update_scan(scan_id: str, **kwargs: Any) -> None:
    rec = _load_record(scan_id)
    if not rec:
        return
    for key, value in kwargs.items():
        setattr(rec, key, value)
    rec.updated_at = _utcnow()
    _save_record(rec)


def update_finding(scan_id: str, fqdn: str, **kwargs: Any) -> bool:
    rec = _load_record(scan_id)
    if not rec:
        return False
    for finding in rec.findings:
        if finding.get("fqdn") == fqdn:
            for key, value in kwargs.items():
                finding[key] = value
            rec.updated_at = _utcnow()
            _save_record(rec)
            return True
    return False


def _enqueue_job(queue_key: str, payload: dict[str, Any], *, high_priority: bool = False) -> None:
    client = _get_redis()
    if client is None:
        return
    encoded = json.dumps(payload)
    if high_priority:
        client.lpush(queue_key, encoded)
    else:
        client.rpush(queue_key, encoded)


def _pop_job(queue_key: str, timeout_seconds: int | None = None) -> dict[str, Any] | None:
    client = _get_redis()
    if client is None:
        return None
    result = client.blpop(queue_key, timeout=timeout_seconds or queue_pop_timeout_from_env())
    if not result:
        return None
    _, payload = result
    return json.loads(payload)


def enqueue_scan_job(scan_id: str, target: str) -> None:
    _enqueue_job(SCAN_QUEUE_KEY, {"scan_id": scan_id, "target": target})


def pop_scan_job(timeout_seconds: int | None = None) -> tuple[str, str] | None:
    job = _pop_job(SCAN_QUEUE_KEY, timeout_seconds=timeout_seconds)
    if not job:
        return None
    return job["scan_id"], job["target"]


def enqueue_screenshot_job(
    *,
    scan_id: str,
    fqdn: str,
    requested_url: str,
    priority: str = "normal",
) -> None:
    _enqueue_job(
        SCREENSHOT_QUEUE_KEY,
        {
            "scan_id": scan_id,
            "fqdn": fqdn,
            "requested_url": requested_url,
            "priority": priority,
        },
        high_priority=priority == "high",
    )


def pop_screenshot_job(timeout_seconds: int | None = None) -> dict[str, Any] | None:
    return _pop_job(SCREENSHOT_QUEUE_KEY, timeout_seconds=timeout_seconds)


def enqueue_crawl_job(
    *,
    scan_id: str,
    fqdn: str,
    requested_url: str,
    priority: str = "normal",
) -> None:
    _enqueue_job(
        CRAWL_QUEUE_KEY,
        {
            "scan_id": scan_id,
            "fqdn": fqdn,
            "requested_url": requested_url,
            "priority": priority,
        },
        high_priority=priority == "high",
    )


def pop_crawl_job(timeout_seconds: int | None = None) -> dict[str, Any] | None:
    return _pop_job(CRAWL_QUEUE_KEY, timeout_seconds=timeout_seconds)


def set_state(name: str, value: str) -> None:
    client = _get_redis()
    if client is None:
        return
    client.set(_state_key(name), value)


def get_state(name: str) -> str | None:
    client = _get_redis()
    if client is None:
        return None
    return client.get(_state_key(name))


def mark_worker_heartbeat(worker_name: str) -> None:
    client = _get_redis()
    if client is None:
        return
    client.setex(
        _worker_heartbeat_key(worker_name),
        worker_heartbeat_ttl_from_env(),
        _utcnow().isoformat(),
    )


def worker_heartbeat_fresh(worker_name: str, max_age_seconds: int | None = None) -> bool:
    client = _get_redis()
    if client is None:
        return False
    raw = client.get(_worker_heartbeat_key(worker_name))
    if not raw:
        return False
    try:
        timestamp = datetime.fromisoformat(raw)
    except ValueError:
        return False
    age = (_utcnow() - timestamp).total_seconds()
    limit = max_age_seconds or worker_heartbeat_ttl_from_env()
    return age <= limit
