"""Scan endpoints — oritypo-solver API."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from oritypo_solver.services.permutations import normalize_target
from oritypo_solver.services.oriframe import screenshot_dir_from_env
from oritypo_solver.services.scan_engine import run_scan
from oritypo_solver.store import create_scan, enqueue_scan_job, get_scan, queue_enabled, update_scan

router = APIRouter(prefix="/v1/scans", tags=["scans"])


class ScanCreate(BaseModel):
    target: str = Field(..., description="URL or hostname, e.g. https://example.com/ or example.com")


class ScanOut(BaseModel):
    id: str
    target: str
    status: str
    progress_done: int
    progress_total: int
    findings: list | None = None
    summary: dict | None = None
    error: str | None = None


def _to_out(rec) -> ScanOut:
    return ScanOut(
        id=rec.id,
        target=rec.target,
        status=rec.status,
        progress_done=rec.progress_done,
        progress_total=rec.progress_total,
        findings=rec.findings if rec.status == "completed" else None,
        summary=rec.summary if rec.status == "completed" else None,
        error=rec.error,
    )


def _run_scan_job(scan_id: str, apex: str) -> None:
    try:
        run_scan(scan_id, apex)
    except Exception as e:  # noqa: BLE001
        update_scan(scan_id, status="failed", error=str(e))


@router.post("", response_model=ScanOut)
async def create_scan_endpoint(body: ScanCreate, background_tasks: BackgroundTasks):
    apex = normalize_target(body.target)
    if not apex:
        raise HTTPException(status_code=400, detail="Invalid target hostname or URL.")

    rec = create_scan(apex)
    if queue_enabled():
        try:
            enqueue_scan_job(rec.id, apex)
        except Exception as e:  # noqa: BLE001
            update_scan(rec.id, status="failed", error=f"Queue enqueue failed: {e}")
            raise HTTPException(status_code=503, detail="Scan queue unavailable.") from e
    else:
        background_tasks.add_task(_run_scan_job, rec.id, apex)
    return _to_out(rec)


@router.get("/{scan_id}", response_model=ScanOut)
async def get_scan_endpoint(scan_id: str):
    rec = get_scan(scan_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return _to_out(rec)


@router.get("/{scan_id}/screenshots/{filename}")
async def get_screenshot_endpoint(scan_id: str, filename: str):
    rec = get_scan(scan_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Scan not found.")
    base_dir = screenshot_dir_from_env().resolve()
    file_path = (base_dir / scan_id / filename).resolve()
    if not str(file_path).startswith(str(base_dir)):
        raise HTTPException(status_code=400, detail="Invalid screenshot path.")
    if not Path(file_path).is_file():
        raise HTTPException(status_code=404, detail="Screenshot not found.")
    return FileResponse(file_path)
