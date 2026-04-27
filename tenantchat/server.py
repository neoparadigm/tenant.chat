"""FastAPI server — serves web UI and REST API."""

from __future__ import annotations

import asyncio
import os
from dotenv import load_dotenv
load_dotenv()
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from rich.console import Console

console = Console()
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="tenant.chat", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
_UI_DIR = Path(__file__).parent.parent / "ui"

# ── Models ────────────────────────────────────────────────────────────────────

class ChatRequest(BaseModel):
    message:   str
    tenant_id: str = ""

class ChatResponse(BaseModel):
    response:  str
    intent:    str = ""

class AssessRequest(BaseModel):
    baseline: str = "all"

class AuthStatusResponse(BaseModel):
    authenticated: bool
    account:       str = ""
    tenant_id:     str = ""

# ── State ─────────────────────────────────────────────────────────────────────

_state: dict[str, Any] = {
    "tenant_state": None,
    "assessment":   None,
    "agent":        None,
    "memory":       None,
    "tenant_id":    "",
}

# ── Startup ───────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup() -> None:
    from tenantchat.auth import AuthManager
    from tenantchat.agent import Agent
    from tenantchat.memory import Memory

    auth  = AuthManager()
    state = auth.status()

    if state.authenticated:
        _state["tenant_id"]     = state.tenant_id
        _state["account"]       = state.account
        _state["authenticated"] = True
        _state["memory"]        = Memory(tenant_id=state.tenant_id)
        token = auth.get_token()
        if token:
            _state["token"] = token

    _state["agent"] = Agent()
# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/", include_in_schema=False)
async def root() -> FileResponse:
    index = _UI_DIR / "index.html"
    if not index.exists():
        return JSONResponse(
            {"message": "UI not found. Run: tenantchat serve"},
            status_code=404,
        )
    return FileResponse(index)

@app.get("/api/auth/status", response_model=AuthStatusResponse)
async def auth_status() -> AuthStatusResponse:
    from tenantchat.auth import AuthManager
    state = AuthManager().status()
    return AuthStatusResponse(
        authenticated=state.authenticated,
        account=state.account,
        tenant_id=state.tenant_id,
    )

@app.post("/api/auth/login")
async def auth_login(
    client_id: str | None = None,
    tenant_id: str | None = None,
) -> JSONResponse:
    """Trigger browser-based PKCE login."""
    from tenantchat.auth import AuthManager
    import threading

    cid = client_id or os.environ.get("TENANTCHAT_CLIENT_ID", "")
    tid = tenant_id or os.environ.get("TENANTCHAT_TENANT_ID", "organizations")

    if not cid:
        return JSONResponse(
            {"status": "error", "message": "No client ID. Set TENANTCHAT_CLIENT_ID environment variable."},
            status_code=400,
        )

    def _login() -> None:
        try:
            auth  = AuthManager(client_id=cid, tenant_id=tid)
            state = auth.login()
            if state.authenticated:
                _state["tenant_id"] = state.tenant_id
                _state["authenticated"] = True
                _state["account"] = state.account
                from tenantchat.memory import Memory
                _state["memory"] = Memory(tenant_id=state.tenant_id)
        except Exception as e:
            _state["auth_error"] = str(e)

    thread = threading.Thread(target=_login, daemon=True)
    thread.start()
    return JSONResponse({"status": "login_initiated"})


@app.get("/api/auth/poll")
async def auth_poll() -> JSONResponse:
    """Poll for auth completion — UI calls this after login_initiated."""
    if _state.get("authenticated"):
        return JSONResponse({
            "authenticated": True,
            "account":    _state.get("account", ""),
            "tenant_id":  _state.get("tenant_id", ""),
        })
    if _state.get("auth_error"):
        return JSONResponse({
            "authenticated": False,
            "error": _state.get("auth_error"),
        })
    return JSONResponse({"authenticated": False, "pending": True})


@app.post("/api/auth/login")
async def auth_login() -> JSONResponse:
    """Trigger browser-based login."""
    from tenantchat.auth import AuthManager
    import threading

    def _login() -> None:
        auth  = AuthManager()
        state = auth.login()
        if state.authenticated:
            _state["tenant_id"] = state.tenant_id
            from tenantchat.memory import Memory
            _state["memory"] = Memory(tenant_id=state.tenant_id)

    thread = threading.Thread(target=_login, daemon=True)
    thread.start()
    return JSONResponse({"status": "login_initiated"})

@app.post("/api/assess")
async def assess(req: AssessRequest) -> JSONResponse:
    """Run full assessment against tenant."""
    from tenantchat.assessor import Assessor
    from tenantchat.auth import AuthManager
    from tenantchat.collector import Collector
    from tenantchat.memory import Memory
    from tenantchat.scrubber import Scrubber

    auth = AuthManager()
    if not auth.status().authenticated:
        raise HTTPException(status_code=401, detail="Not authenticated")

    collector = Collector(auth)
    state     = await collector.collect()
    scrubber  = Scrubber()
    state.users  = scrubber.scrub_list(state.users, "user")
    state.guests = scrubber.scrub_list(state.guests, "user")
    state.managed_devices = scrubber.scrub_list(
        state.managed_devices, "device"
    )
    state.mfa_registration = scrubber.scrub_list(
        state.mfa_registration, "user"
    )

    frameworks = {
        "all":        None,
        "microsoft":  ["Microsoft Baseline Security Mode"],
        "cis":        ["CIS Microsoft 365 v3.1"],
        "zero-trust": ["Microsoft Zero Trust RaMP"],
    }.get(req.baseline)

    assessor = Assessor()
    assessor.load_baselines(frameworks=frameworks)
    result = assessor.assess(state)

    _state["tenant_state"] = state
    _state["assessment"]   = result
    _state["tenant_id"]    = state.tenant_id

    memory = Memory(tenant_id=state.tenant_id)
    memory.save_assessment(
        tenant_id=state.tenant_id,
        score=result.posture_score,
        critical=result.critical_count,
        high=result.high_count,
        frameworks=result.frameworks,
        finding_count=result.total_controls,
    )
    _state["memory"] = memory

    from tenantchat.models import CheckStatus
    return JSONResponse({
        "tenant":    state.tenant_domain,
        "score":     result.posture_score,
        "critical":  result.critical_count,
        "high":      result.high_count,
        "medium":    result.medium_count,
        "pass":      result.pass_count,
        "total":     result.total_controls,
        "frameworks": result.frameworks,
        "findings": [
            {
                "control_id":    f.control_id,
                "framework":     f.framework,
                "title":         f.title,
                "status":        f.status.value,
                "severity":      f.severity.value,
                "effort":        f.effort,
                "delta":         f.delta,
                "drift_score":   f.drift_score,
                "affected_count":f.affected_count,
                "blast_radius":  f.blast_radius,
                "community_ref": f.community_ref,
            }
            for f in result.findings
        ],
    })

@app.post("/api/chat", response_model=ChatResponse)
async def chat(req: ChatRequest) -> ChatResponse:
    """Send a message to the agent."""
    agent = _state.get("agent")
    if not agent:
        from tenantchat.agent import Agent
        _state["agent"] = Agent()
        agent = _state["agent"]

    response = await agent.chat(
        message=req.message,
        tenant_state=_state.get("tenant_state"),
        assessment=_state.get("assessment"),
        memory=_state.get("memory"),
        tenant_id=_state.get("tenant_id", ""),
    )

    intent = agent._detect_intent(req.message)

    return ChatResponse(response=response, intent=intent)

@app.get("/api/blast")
async def blast(change: str) -> JSONResponse:
    """Get blast radius analysis for a proposed change."""
    from tenantchat.blast import BlastAnalyzer
    from tenantchat.models import TenantState
    from datetime import datetime, timezone

    analyzer = BlastAnalyzer()
    state    = _state.get("tenant_state") or TenantState(
        tenant_id="",
        tenant_domain="",
        collected_at=datetime.now(tz=timezone.utc),
    )
    result = analyzer.analyze(change, state)
    return JSONResponse({
        "change":          result.change_description,
        "risk_level":      result.risk_level,
        "affected_objects":result.affected_objects,
        "fix_first":       result.fix_first,
        "sequence":        result.sequence,
    })

@app.get("/api/history")
async def history() -> JSONResponse:
    """Get assessment history for the current tenant."""
    memory    = _state.get("memory")
    tenant_id = _state.get("tenant_id", "")
    if not memory or not tenant_id:
        return JSONResponse({"history": []})
    return JSONResponse({
        "history": memory.get_assessment_history(tenant_id),
        "trend":   memory.get_score_trend(tenant_id),
    })

@app.post("/api/report")
async def generate_report(report_type: str = "technical") -> JSONResponse:
    """Generate a PDF report."""
    from tenantchat.reporter import Reporter
    from datetime import datetime

    result = _state.get("assessment")
    state  = _state.get("tenant_state")
    if not result or not state:
        raise HTTPException(
            status_code=400,
            detail="No assessment data. Run /api/assess first."
        )

    reporter  = Reporter()
    out_path  = (
        f"tenantchat-{report_type}-"
        f"{state.tenant_domain}-"
        f"{datetime.now().strftime('%Y%m%d')}.pdf"
    )
    reporter.generate(result, state, report_type, out_path)
    return JSONResponse({"path": out_path, "status": "generated"})
