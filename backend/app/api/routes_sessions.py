"""
Sessions API Router.
Provides sortable, filterable session list and deep-dive session details.
"""
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query
from app.core.schemas import SessionModel
from app.api.routes_captures import SESSIONS_STORE

router = APIRouter(prefix="/api/captures/{capture_id}/sessions", tags=["Sessions"])

@router.get("", response_model=List[SessionModel])
async def list_sessions(
    capture_id: str,
    protocol: Optional[str] = Query(None, description="Filter by protocol: SMTP, IMAP, POP3"),
    risk_class: Optional[str] = Query(None, description="Filter by risk tier: Critical, High, Medium, Secure"),
    starttls_state: Optional[str] = Query(None, description="Filter by STARTTLS state"),
    search: Optional[str] = Query(None, description="Search IP, host, or cipher")
):
    """
    Returns filtered and sorted reconstructed sessions for a given capture.
    """
    if capture_id not in SESSIONS_STORE:
        raise HTTPException(status_code=404, detail="Capture not found")

    sessions = SESSIONS_STORE[capture_id]

    # Filtering
    if protocol:
        sessions = [s for s in sessions if protocol.lower() in s.protocol.lower()]

    if risk_class:
        sessions = [s for s in sessions if s.score_trace.risk_class.lower() == risk_class.lower()]

    if starttls_state:
        sessions = [s for s in sessions if s.starttls_state.lower() == starttls_state.lower()]

    if search:
        q = search.lower()
        sessions = [
            s for s in sessions
            if q in s.id.lower() or
               q in s.src_ip.lower() or
               q in s.dst_ip.lower() or
               (s.banner and q in s.banner.lower()) or
               (s.tls_summary and s.tls_summary.negotiated_cipher and q in s.tls_summary.negotiated_cipher.lower()) or
               (s.tls_summary and s.tls_summary.negotiated_version and q in s.tls_summary.negotiated_version.lower())
        ]

    return sessions

@router.get("/{session_id}", response_model=SessionModel)
async def get_session_detail(capture_id: str, session_id: str):
    """
    Returns complete details, SCoRE trace, certificate hierarchy, and evidence frames for a single session.
    """
    if capture_id not in SESSIONS_STORE:
        raise HTTPException(status_code=404, detail="Capture not found")

    for s in SESSIONS_STORE[capture_id]:
        if s.id == session_id:
            return s

    raise HTTPException(status_code=404, detail="Session not found")
