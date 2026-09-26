"""
Captures API Router.
Handles PCAP file uploads, synthetic scenario preloading, and capture management.
"""
import uuid
import time
from typing import List, Dict, Optional
from fastapi import APIRouter, UploadFile, File, HTTPException, Query
from app.core.schemas import CaptureModel, PostureSummaryModel, SessionModel
from app.engine.pcap_parser import PCAPParserPipeline
from app.generator.synthetic_pcap import generate_all_synthetic_pcaps

router = APIRouter(prefix="/api/captures", tags=["Captures"])

# In-memory storage of captures and sessions for the single-node prototype
CAPTURES_STORE: Dict[str, CaptureModel] = {}
SUMMARIES_STORE: Dict[str, PostureSummaryModel] = {}
SESSIONS_STORE: Dict[str, List[SessionModel]] = {}
RAW_PCAP_STORE: Dict[str, bytes] = {}

def initialize_demo_captures():
    """Generates and indexes the full suite of 8 synthetic test captures."""
    synthetic_pcaps = generate_all_synthetic_pcaps()
    for filename, (pcap_bytes, desc) in synthetic_pcaps.items():
        cap_id = "cap-" + hashlib_short(filename)
        summary, sessions = PCAPParserPipeline.process_pcap_bytes(
            pcap_data=pcap_bytes,
            capture_id=cap_id,
            filename=filename,
            use_ml=True
        )

        crit_cnt = summary.risk_distribution.get("Critical", 0)
        high_cnt = summary.risk_distribution.get("High", 0)
        med_cnt = summary.risk_distribution.get("Medium", 0)
        sec_cnt = summary.risk_distribution.get("Secure", 0)

        cap_model = CaptureModel(
            id=cap_id,
            filename=filename,
            uploaded_at=summary.analyzed_at,
            packet_count=summary.total_packets,
            session_count=summary.total_sessions,
            size_bytes=len(pcap_bytes),
            overall_score=summary.overall_score,
            overall_grade=summary.overall_grade,
            critical_count=crit_cnt,
            high_count=high_cnt,
            medium_count=med_cnt,
            secure_count=sec_cnt,
            is_synthetic=True,
            scenario_description=desc
        )

        CAPTURES_STORE[cap_id] = cap_model
        SUMMARIES_STORE[cap_id] = summary
        SESSIONS_STORE[cap_id] = sessions
        RAW_PCAP_STORE[cap_id] = pcap_bytes

def hashlib_short(name: str) -> str:
    import hashlib
    return hashlib.md5(name.encode('utf-8')).hexdigest()[:8]

@router.get("", response_model=List[CaptureModel])
async def list_captures():
    """Lists all available PCAP captures (both synthetic test cases and uploaded files)."""
    return list(CAPTURES_STORE.values())

@router.get("/{capture_id}", response_model=CaptureModel)
async def get_capture(capture_id: str):
    """Retrieves metadata for a specific capture."""
    if capture_id not in CAPTURES_STORE:
        raise HTTPException(status_code=404, detail="Capture not found")
    return CAPTURES_STORE[capture_id]

@router.post("/upload", response_model=CaptureModel)
async def upload_pcap(
    file: UploadFile = File(...),
    use_ml: bool = Query(True, description="Enable ML scoring and Isolation Forest anomaly detection")
):
    """
    Accepts multipart PCAP/PCAPNG file upload, parses TCP streams,
    evaluates cryptographic posture, and returns the analyzed capture record.
    """
    if not file.filename.lower().endswith(('.pcap', '.pcapng', '.cap')):
        raise HTTPException(status_code=400, detail="Only .pcap and .pcapng files are supported")

    content = await file.read()
    if not content or len(content) < 24:
        raise HTTPException(status_code=400, detail="Invalid or truncated PCAP file")

    cap_id = "cap-" + uuid.uuid4().hex[:8]
    summary, sessions = PCAPParserPipeline.process_pcap_bytes(
        pcap_data=content,
        capture_id=cap_id,
        filename=file.filename,
        use_ml=use_ml
    )

    cap_model = CaptureModel(
        id=cap_id,
        filename=file.filename,
        uploaded_at=summary.analyzed_at,
        packet_count=summary.total_packets,
        session_count=summary.total_sessions,
        size_bytes=len(content),
        overall_score=summary.overall_score,
        overall_grade=summary.overall_grade,
        critical_count=summary.risk_distribution.get("Critical", 0),
        high_count=summary.risk_distribution.get("High", 0),
        medium_count=summary.risk_distribution.get("Medium", 0),
        secure_count=summary.risk_distribution.get("Secure", 0),
        is_synthetic=False,
        scenario_description="User uploaded network capture."
    )

    CAPTURES_STORE[cap_id] = cap_model
    SUMMARIES_STORE[cap_id] = summary
    SESSIONS_STORE[cap_id] = sessions
    RAW_PCAP_STORE[cap_id] = content

    return cap_model

from fastapi.responses import Response

@router.get("/{capture_id}/download")
async def download_pcap(capture_id: str):
    """Downloads the raw binary PCAP file for inspection in Wireshark or external tools."""
    if capture_id not in CAPTURES_STORE:
        raise HTTPException(status_code=404, detail="Capture not found")
    
    cap = CAPTURES_STORE[capture_id]
    pcap_data = RAW_PCAP_STORE.get(capture_id)
    if not pcap_data:
        raise HTTPException(status_code=404, detail="Raw PCAP bytes not stored")

    return Response(
        content=pcap_data,
        media_type="application/vnd.tcpdump.pcap",
        headers={
            "Content-Disposition": f'attachment; filename="{cap.filename}"',
            "Content-Length": str(len(pcap_data))
        }
    )

@router.get("/benchmark/run")
async def run_benchmark():
    """Executes an in-process live validation & performance benchmark over all synthetic PCAPs."""
    import time
    synthetic_pcaps = generate_all_synthetic_pcaps()
    results = []
    total_packets = 0
    total_sessions = 0
    start_all = time.perf_counter()

    for idx, (filename, (pcap_bytes, desc)) in enumerate(synthetic_pcaps.items(), 1):
        t0 = time.perf_counter()
        summary, sessions = PCAPParserPipeline.process_pcap_bytes(
            pcap_data=pcap_bytes,
            capture_id=f"bench-{idx}",
            filename=filename,
            use_ml=True
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        total_packets += summary.total_packets
        total_sessions += summary.total_sessions

        findings_count = sum(len(s.findings) for s in sessions)
        results.append({
            "filename": filename,
            "packets": summary.total_packets,
            "sessions": summary.total_sessions,
            "score": summary.overall_score,
            "grade": summary.overall_grade,
            "findings_count": findings_count,
            "latency_ms": round(elapsed_ms, 2)
        })

    total_time_ms = (time.perf_counter() - start_all) * 1000.0
    pps = (total_packets / (total_time_ms / 1000.0)) if total_time_ms > 0 else 0
    fps = (total_sessions / (total_time_ms / 1000.0)) if total_time_ms > 0 else 0

    return {
        "captures_tested": len(results),
        "total_packets": total_packets,
        "total_sessions": total_sessions,
        "total_time_ms": round(total_time_ms, 2),
        "avg_latency_per_capture_ms": round(total_time_ms / len(results), 2),
        "packets_per_second": round(pps, 1),
        "flows_per_second": round(fps, 1),
        "results": results
    }

@router.post("/reset-samples")
async def reset_demo_samples():
    """Reloads the 8 official synthetic test scenarios."""
    initialize_demo_captures()
    return {"status": "success", "count": len(CAPTURES_STORE)}

