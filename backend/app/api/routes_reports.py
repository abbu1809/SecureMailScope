"""
Reports API Router.
Exports security audits in JSON (v1.1 schema), Standalone HTML, and PDF formats.
"""
from fastapi import APIRouter, HTTPException, Response
from fastapi.responses import HTMLResponse
from app.reports.report_builder import ReportBuilder
from app.api.routes_captures import SUMMARIES_STORE, SESSIONS_STORE

router = APIRouter(prefix="/api/captures/{capture_id}/report", tags=["Reports"])

@router.get(".json")
async def get_json_report(capture_id: str):
    """Exports structured, schema-versioned v1.1 JSON report."""
    if capture_id not in SUMMARIES_STORE or capture_id not in SESSIONS_STORE:
        raise HTTPException(status_code=404, detail="Capture not found")

    json_str = ReportBuilder.generate_json_report(
        summary=SUMMARIES_STORE[capture_id],
        sessions=SESSIONS_STORE[capture_id]
    )
    return Response(
        content=json_str,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="securemailscope_{capture_id}_report.json"'}
    )

@router.get(".html", response_class=HTMLResponse)
async def get_html_report(capture_id: str):
    """Exports standalone styled HTML security audit report."""
    if capture_id not in SUMMARIES_STORE or capture_id not in SESSIONS_STORE:
        raise HTTPException(status_code=404, detail="Capture not found")

    html_str = ReportBuilder.generate_html_report(
        summary=SUMMARIES_STORE[capture_id],
        sessions=SESSIONS_STORE[capture_id]
    )
    return HTMLResponse(content=html_str)

@router.get(".pdf", response_class=HTMLResponse)
async def get_pdf_report(capture_id: str):
    """
    Renders the printable PDF view template formatted for browser print-to-PDF
    or automated document generation.
    """
    if capture_id not in SUMMARIES_STORE or capture_id not in SESSIONS_STORE:
        raise HTTPException(status_code=404, detail="Capture not found")

    html_str = ReportBuilder.generate_html_report(
        summary=SUMMARIES_STORE[capture_id],
        sessions=SESSIONS_STORE[capture_id]
    )
    # Serves the exact styled report ready for print/PDF export
    return HTMLResponse(content=html_str)
