"""
Analytics API Router.
Returns posture scores, compliance matrices, anomaly listings, and dashboard charts.
"""
from typing import List, Dict, Any
from fastapi import APIRouter, HTTPException
from app.core.schemas import PostureSummaryModel, AnomalyItemModel
from app.api.routes_captures import SUMMARIES_STORE, SESSIONS_STORE

router = APIRouter(prefix="/api/captures/{capture_id}/analytics", tags=["Analytics"])

@router.get("/summary", response_model=PostureSummaryModel)
async def get_posture_summary(capture_id: str):
    """Returns the overall posture assessment, KPIs, and charts data for a capture."""
    if capture_id not in SUMMARIES_STORE:
        raise HTTPException(status_code=404, detail="Capture not found")
    return SUMMARIES_STORE[capture_id]

@router.get("/anomalies", response_model=List[AnomalyItemModel])
async def get_capture_anomalies(capture_id: str):
    """Returns AI Isolation Forest anomaly list with JA3 and SHAP explainability traces."""
    if capture_id not in SESSIONS_STORE:
        raise HTTPException(status_code=404, detail="Capture not found")

    sessions = SESSIONS_STORE[capture_id]
    anomalies: List[AnomalyItemModel] = []

    for s in sessions:
        if s.is_anomaly or s.score_trace.anomaly_boost_ab > 0:
            ja3_val = s.tls_summary.ja3 if s.tls_summary else None
            ja3s_val = s.tls_summary.ja3s if s.tls_summary else None
            factors = [f.get("factor", "") for f in s.score_trace.top_contributing_factors]
            anomalies.append(AnomalyItemModel(
                session_id=s.id,
                src_dst=f"{s.src_ip}:{s.src_port} -> {s.dst_ip}:{s.dst_port}",
                protocol=s.protocol,
                ja3=ja3_val,
                ja3s=ja3s_val,
                anomaly_score=round(s.score_trace.anomaly_boost_ab / 25.0, 3),
                reason=s.anomaly_reason or "Anomalous TLS fingerprint & parameter distribution flagged by Isolation Forest.",
                shap_factors=factors,
                risk_class=s.score_trace.risk_class
            ))

    return anomalies
