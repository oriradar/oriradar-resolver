"""FastAPI entrypoint for **oritypo-solver**."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from oritypo_solver.routers.scans import router as scans_router
from oritypo_solver.store import queue_enabled

app = FastAPI(
    title="oritypo-solver",
    description="Oriradar — typosquat scan API (orifold permutations, oriseek DNS, oriprobe HTTP, oriscore ranking, optional orirdap/oristream).",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5173",
        "http://localhost:5173",
        "http://127.0.0.1:4173",
        "http://localhost:4173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scans_router)


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "oritypo-solver",
        "execution_mode": "redis-worker" if queue_enabled() else "in-process",
    }
