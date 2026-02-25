"""
HunterAI — REST API (FastAPI)
==============================
Exposes scan management, session queries, and report downloads.
Consumed by the React web dashboard and CLI status checks.
"""
from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# ── In-memory task store (replace with DB for production) ─────────
_tasks: dict[str, dict] = {}


# ── Pydantic Models ───────────────────────────────────────────────

class ScanRequest(BaseModel):
    target:  str
    mode:    str = "standard"
    output:  str = "/tmp/hunterai_reports"


class ScanStatus(BaseModel):
    task_id:     str
    target:      str
    mode:        str
    status:      str
    session:     Optional[dict]  = None
    findings:    list[dict]      = []
    created_at:  str


# ── App lifespan ──────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("HunterAI API starting up")
    yield
    logger.info("HunterAI API shutting down")


app = FastAPI(
    title="HunterAI API",
    description="AI-Driven Penetration Testing Platform — AlfaNet Organization",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Background scan runner ────────────────────────────────────────

async def _run_scan(task_id: str, target: str, mode: str, output: str) -> None:
    _tasks[task_id]["status"] = "running"
    try:
        from hunterai.core.engine         import HunterEngine
        from hunterai.llm.router          import LLMRouter
        from hunterai.agents.orchestrator import OrchestratorAgent
        from hunterai.modules.recon.recon         import ReconModule
        from hunterai.modules.vulnscan.scanner    import VulnScanModule
        from hunterai.modules.apifuzz.fuzzer      import APIFuzzModule
        from hunterai.modules.auth.tester         import AuthModule
        from hunterai.modules.exploit.chain       import ExploitChainModule
        from hunterai.modules.postexploit.module  import PostExploitModule
        from hunterai.modules.cloud.scanner       import CloudScanModule
        from hunterai.modules.report.report       import ReportModule

        llm    = LLMRouter()
        engine = HunterEngine(target=target, profile=mode)

        engine.register(ReconModule(engine.bus, engine.session))
        engine.register(VulnScanModule(engine.bus, engine.session))
        engine.register(APIFuzzModule(engine.bus, engine.session))
        engine.register(AuthModule(engine.bus, engine.session, llm))
        engine.register(ExploitChainModule(engine.bus, engine.session, llm))
        engine.register(PostExploitModule(engine.bus, engine.session, llm))
        engine.register(CloudScanModule(engine.bus, engine.session))
        engine.register(ReportModule(engine.bus, engine.session, llm, out_dir=output))

        orchestrator = OrchestratorAgent(engine, llm)
        engine.set_orchestrator(orchestrator)

        session = await engine.run()
        _tasks[task_id].update({
            "status":   "complete",
            "session":  session.snapshot(),
            "findings": session.findings,
        })
    except Exception as e:
        logger.error("Scan %s failed: %s", task_id, e)
        _tasks[task_id]["status"] = "failed"
        _tasks[task_id]["error"]  = str(e)


# ── Endpoints ─────────────────────────────────────────────────────

@app.get("/healthz")
async def healthz():
    return {"status": "ok", "service": "hunterai", "version": "1.0.0"}


@app.get("/api/v1/scans", response_model=list[ScanStatus])
async def list_scans():
    return [
        ScanStatus(
            task_id    = tid,
            target     = t["target"],
            mode       = t["mode"],
            status     = t["status"],
            session    = t.get("session"),
            findings   = t.get("findings", []),
            created_at = t["created_at"],
        )
        for tid, t in sorted(_tasks.items(),
                              key=lambda x: x[1]["created_at"], reverse=True)
    ]


@app.post("/api/v1/scans", status_code=202)
async def create_scan(req: ScanRequest, bg: BackgroundTasks):
    import uuid
    task_id = str(uuid.uuid4())
    _tasks[task_id] = {
        "target":     req.target,
        "mode":       req.mode,
        "output":     req.output,
        "status":     "pending",
        "created_at": datetime.utcnow().isoformat(),
        "session":    None,
        "findings":   [],
    }
    bg.add_task(_run_scan, task_id, req.target, req.mode, req.output)
    return {"task_id": task_id, "status": "pending"}


@app.get("/api/v1/scans/{task_id}", response_model=ScanStatus)
async def get_scan(task_id: str):
    t = _tasks.get(task_id)
    if not t:
        raise HTTPException(404, f"Scan {task_id} not found")
    return ScanStatus(
        task_id    = task_id,
        target     = t["target"],
        mode       = t["mode"],
        status     = t["status"],
        session    = t.get("session"),
        findings   = t.get("findings", []),
        created_at = t["created_at"],
    )


@app.delete("/api/v1/scans/{task_id}", status_code=204)
async def delete_scan(task_id: str):
    if task_id not in _tasks:
        raise HTTPException(404, f"Scan {task_id} not found")
    del _tasks[task_id]


@app.get("/api/v1/scans/{task_id}/report/{fmt}")
async def download_report(task_id: str, fmt: str):
    t = _tasks.get(task_id)
    if not t:
        raise HTTPException(404, "Scan not found")
    if t["status"] != "complete":
        raise HTTPException(409, "Report not ready yet")

    out_dir = t.get("output", "/tmp/hunterai_reports")
    sid     = t["session"]["session_id"] if t.get("session") else task_id
    path    = f"{out_dir}/{sid}.{fmt}"

    if not os.path.exists(path):
        raise HTTPException(404, f"Report file not found: {path}")

    media = {
        "html": "text/html",
        "json": "application/json",
        "md":   "text/markdown",
    }.get(fmt, "application/octet-stream")

    return FileResponse(path, media_type=media,
                        filename=f"hunterai_{task_id[:8]}_{fmt}.{fmt}")


@app.get("/api/v1/llm/health")
async def llm_health():
    try:
        from hunterai.llm.router import LLMRouter
        return LLMRouter().health_report()
    except Exception as e:
        raise HTTPException(503, str(e))
