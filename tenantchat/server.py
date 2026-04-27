"""FastAPI server — serves web UI and REST API."""

from __future__ import annotations

import asyncio
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from rich.console import Console

load_dotenv()

console = Console()

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
    response: str
    intent:   str = ""

class AssessRequest(BaseModel):
    baseline: str = "all"

class AuthStatusResponse(BaseModel):
    authenticated: bool
    account:       str = ""
    tenant_id:     str = ""

# ── State ─────────────────────────────────────────────────────────────────────

_state: dict[str, Any] = {
    "tenant_state":  None,
    "assessment":    None,
    "agent":         None,
    "memory":        None,
    "tenant_id":     "",
    "account":       "",
    "authenticated": False,
    "token":         None,
    "auth_error":    None,
}

# ── Startup ───────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup() -> None:
    from tenantchat.agent import Agent
    from tenantchat.auth import AuthManager
    from tenantchat.memory import Memory

    try:
        auth  = AuthManager()
        state = auth.status()
        if state.authenticated:
            token = auth.get_token()
            if token:
                _state["authenticated"] = True
                _state["tenant_id"]     = state.tenant_id
                _state["account"]       = state.account
                _state["token"]         = token
                _state["memory"]        = Memory(tenant_id=state.tenant_id)
                console.print(
                    f"[green]Auto-authenticated[/green] as "
                    f"{state.account}"
                )
    except Exception as e:
        console.print(f"[dim]Auth startup: {e}[/dim]")

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

# ── Auth ──────────────────────────────────────────────────────────────────────

@app.get("/api/auth/status", response_model=AuthStatusResponse)
async def auth_status() -> AuthStatusResponse:
    # Return from in-memory state first (fastest)
    if _state.get("authenticated"):
        return AuthStatusResponse(
            authenticated=True,
            account=_state.get("account", ""),
            tenant_id=_state.get("tenant_id", ""),
        )
    # Fall back to keychain check
    from tenantchat.auth import AuthManager
    state = AuthManager().status()
    if state.authenticated:
        _state["authenticated"] = True
        _state["account"]       = state.account
        _state["tenant_id"]     = state.tenant_id
    return AuthStatusResponse(
        authenticated=state.authenticated,
        account=state.account,
        tenant_id=state.tenant_id,
    )

@app.post("/api/auth/login")
async def auth_login() -> JSONResponse:
    """Trigger browser-based PKCE login."""
    from tenantchat.auth import AuthManager

    cid = os.environ.get("TENANTCHAT_CLIENT_ID", "")
    tid = os.environ.get("TENANTCHAT_TENANT_ID", "organizations")

    if not cid:
        return JSONResponse(
            {
                "status":  "error",
                "message": "No client ID. Set TENANTCHAT_CLIENT_ID in .env file.",
            },
            status_code=400,
        )

    # Reset error state
    _state["auth_error"] = None

    def _login() -> None:
        try:
            auth  = AuthManager(client_id=cid, tenant_id=tid)
            state = auth.login()
            if state.authenticated:
                _state["authenticated"] = True
                _state["tenant_id"]     = state.tenant_id
                _state["account"]       = state.account
                token = auth.get_token()
                if token:
                    _state["token"] = token
                from tenantchat.memory import Memory
                _state["memory"] = Memory(tenant_id=state.tenant_id)
        except Exception as e:
            _state["auth_error"] = str(e)

    threading.Thread(target=_login, daemon=True).start()
    return JSONResponse({"status": "login_initiated"})

@app.get("/api/auth/poll")
async def auth_poll() -> JSONResponse:
    """Poll for auth completion after login_initiated."""
    if _state.get("authenticated"):
        return JSONResponse({
            "authenticated": True,
            "account":       _state.get("account", ""),
            "tenant_id":     _state.get("tenant_id", ""),
        })
    if _state.get("auth_error"):
        return JSONResponse({
            "authenticated": False,
            "error":         _state["auth_error"],
        })
    return JSONResponse({"authenticated": False, "pending": True})

@app.post("/api/auth/logout")
async def auth_logout() -> JSONResponse:
    from tenantchat.auth import AuthManager
    try:
        AuthManager().logout()
    except Exception:
        pass
    _state["authenticated"] = False
    _state["tenant_id"]     = ""
    _state["account"]       = ""
    _state["token"]         = None
    _state["tenant_state"]  = None
    _state["assessment"]    = None
    return JSONResponse({"status": "logged_out"})

# ── Assessment ────────────────────────────────────────────────────────────────

@app.post("/api/assess")
async def assess(req: AssessRequest) -> JSONResponse:
    from tenantchat.assessor import Assessor
    from tenantchat.auth import AuthManager
    from tenantchat.collector import Collector
    from tenantchat.memory import Memory
    from tenantchat.scrubber import Scrubber

    if not _state.get("authenticated"):
        raise HTTPException(status_code=401, detail="Not authenticated")

    auth      = AuthManager()
    collector = Collector(auth)
    state     = await collector.collect()
    scrubber  = Scrubber()

    state.users            = scrubber.scrub_list(state.users, "user")
    state.guests           = scrubber.scrub_list(state.guests, "user")
    state.managed_devices  = scrubber.scrub_list(state.managed_devices, "device")
    state.mfa_registration = scrubber.scrub_list(state.mfa_registration, "user")

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
                "control_id":     f.control_id,
                "framework":      f.framework,
                "title":          f.title,
                "status":         f.status.value,
                "severity":       f.severity.value,
                "effort":         f.effort,
                "delta":          f.delta,
                "drift_score":    f.drift_score,
                "affected_count": f.affected_count,
                "blast_radius":   f.blast_radius,
                "community_ref":  f.community_ref,
            }
            for f in result.findings
        ],
    })

# ── Chat ──────────────────────────────────────────────────────────────────────

@app.post("/api/chat", response_model=ChatResponse)
async def chat(req: ChatRequest) -> ChatResponse:
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
    return ChatResponse(
        response=response,
        intent=agent._detect_intent(req.message),
    )

# ── Blast ─────────────────────────────────────────────────────────────────────

@app.get("/api/blast")
async def blast(change: str) -> JSONResponse:
    from tenantchat.blast import BlastAnalyzer
    from tenantchat.models import TenantState

    analyzer = BlastAnalyzer()
    state    = _state.get("tenant_state") or TenantState(
        tenant_id="",
        tenant_domain="",
        collected_at=datetime.now(tz=timezone.utc),
    )
    result = analyzer.analyze(change, state)
    return JSONResponse({
        "change":           result.change_description,
        "risk_level":       result.risk_level,
        "affected_objects": result.affected_objects,
        "fix_first":        result.fix_first,
        "sequence":         result.sequence,
    })

# ── History ───────────────────────────────────────────────────────────────────

@app.get("/api/history")
async def history() -> JSONResponse:
    memory    = _state.get("memory")
    tenant_id = _state.get("tenant_id", "")
    if not memory or not tenant_id:
        return JSONResponse({"history": [], "trend": ""})
    return JSONResponse({
        "history": memory.get_assessment_history(tenant_id),
        "trend":   memory.get_score_trend(tenant_id),
    })

# ── Report ────────────────────────────────────────────────────────────────────

@app.post("/api/report")
async def generate_report(report_type: str = "technical") -> JSONResponse:
    from tenantchat.reporter import Reporter

    result = _state.get("assessment")
    state  = _state.get("tenant_state")
    if not result or not state:
        raise HTTPException(
            status_code=400,
            detail="No assessment data. Run /assess first.",
        )

    reporter = Reporter()
    out_path = (
        f"tenantchat-{report_type}-"
        f"{state.tenant_domain}-"
        f"{datetime.now().strftime('%Y%m%d')}.pdf"
    )
    reporter.generate(result, state, report_type, out_path)
    return JSONResponse({"path": out_path, "status": "generated"})
