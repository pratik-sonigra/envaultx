from __future__ import annotations

import time
import uuid
from typing import Any

from mcp.server.fastmcp import FastMCP

from .envault import Envault
from .vault import Vault

mcp = FastMCP("envault")

# session_id -> (envault, vault, created_at)
_sessions: dict[str, tuple[Envault, Vault, float]] = {}

SESSION_TTL = 3600  # 1 hour


def _cleanup_expired() -> None:
    now = time.time()
    expired = [sid for sid, (_, _, ts) in _sessions.items() if now - ts > SESSION_TTL]
    for sid in expired:
        del _sessions[sid]


def _get_session(session_id: str) -> tuple[Envault, Vault] | None:
    _cleanup_expired()
    entry = _sessions.get(session_id)
    if not entry:
        return None
    ev, vault, ts = entry
    if time.time() - ts > SESSION_TTL:
        del _sessions[session_id]
        return None
    return ev, vault


@mcp.tool()
def redact_text(
    text: str,
    session_id: str | None = None,
    threshold: float = 0.5,
    categories: list[str] | None = None,
    exclude_categories: list[str] | None = None,
) -> dict[str, Any]:
    """Redact secrets and PII from text, returning the redacted text and a session_id for restoration."""
    _cleanup_expired()
    ev = Envault(threshold=threshold, categories=categories, exclude_categories=exclude_categories)
    if session_id and session_id in _sessions:
        _, vault, _ = _sessions[session_id]
    else:
        session_id = str(uuid.uuid4())
        vault = Vault()

    redacted, vault = ev.redact(text, vault=vault, threshold=threshold,
                                 categories=categories, exclude_categories=exclude_categories)
    _sessions[session_id] = (ev, vault, time.time())
    return {
        "redacted_text": redacted,
        "session_id": session_id,
        "secrets_found": vault.count,
        "categories": list(vault.categories),
    }


@mcp.tool()
def scan_text(text: str, threshold: float = 0.5) -> dict[str, Any]:
    """Scan text for secrets and PII without redacting."""
    ev = Envault(threshold=threshold)
    result = ev.scan(text)
    return {
        "has_secrets": result.has_secrets,
        "risk_level": result.risk_level,
        "summary": result.summary,
        "detections": [
            {
                "category": d.category,
                "confidence": d.confidence,
                "span": list(d.span),
            }
            for d in result.detections
        ],
    }


@mcp.tool()
def scan_external_content(
    text: str,
    source_url: str = "",
    threshold: float = 0.4,
) -> dict[str, Any]:
    """Scan externally-sourced content for secrets and prompt injection."""
    ev = Envault(threshold=threshold)
    result = ev.scan_external(text, source=source_url)
    return {
        "has_secrets": result.has_secrets,
        "risk_level": result.risk_level,
        "summary": result.summary,
        "prompt_injection_detected": "PROMPT_INJECTION" in result.summary,
        "detections": [
            {
                "category": d.category,
                "confidence": d.confidence,
                "span": list(d.span),
            }
            for d in result.detections
        ],
    }


@mcp.tool()
def restore_text(text: str, session_id: str) -> dict[str, Any]:
    """Restore a previously redacted text using its session vault."""
    entry = _get_session(session_id)
    if entry is None:
        return {"error": f"Session '{session_id}' not found or expired", "restored_text": text}
    ev, vault = entry
    restored = ev.restore(text, vault)
    return {"restored_text": restored}


@mcp.tool()
def list_vault_sessions() -> dict[str, Any]:
    """List all active vault sessions."""
    _cleanup_expired()
    now = time.time()
    sessions = []
    for sid, (_, vault, ts) in _sessions.items():
        sessions.append({
            "session_id": sid,
            "secrets_count": vault.count,
            "categories": list(vault.categories),
            "age_seconds": int(now - ts),
            "expires_in_seconds": max(0, int(SESSION_TTL - (now - ts))),
        })
    return {"sessions": sessions, "total": len(sessions)}


@mcp.tool()
def clear_vault_session(session_id: str) -> dict[str, Any]:
    """Clear a specific vault session."""
    if session_id in _sessions:
        del _sessions[session_id]
        return {"cleared": True, "session_id": session_id}
    return {"cleared": False, "session_id": session_id, "error": "Session not found"}
