"""
Pydantic data models for SecureMailScope.
"""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime

class CertificateModel(BaseModel):
    subject: str = "Unknown"
    issuer: str = "Unknown"
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    is_expired: bool = False
    is_not_yet_valid: bool = False
    is_self_signed: bool = False
    key_algo: str = "RSA"
    key_bits: int = 2048
    sig_algo: str = "sha256WithRSAEncryption"
    san_list: List[str] = []
    days_until_expiry: int = 90
    observable: bool = True  # Explicitly false for encrypted TLS 1.3 handshakes
    fingerprint_sha256: Optional[str] = None

class TLSSummaryModel(BaseModel):
    negotiated_version: Optional[str] = None
    client_offered_versions: List[str] = []
    negotiated_cipher: Optional[str] = None
    client_offered_ciphers: List[str] = []
    key_exchange: Optional[str] = None
    sni: Optional[str] = None
    alpn: Optional[str] = None
    ja3: Optional[str] = None
    ja3_string: Optional[str] = None
    ja3s: Optional[str] = None
    ja3s_string: Optional[str] = None
    has_extended_master_secret: bool = False
    is_tls13: bool = False
    handshake_encrypted: bool = False

class FindingModel(BaseModel):
    id: str
    rule_id: str
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str
    evidence: str
    compliance_refs: List[str] = []
    remediation: str
    fix_effort: str = "Low"  # Low, Medium, High
    frame_numbers: List[int] = []

class ScoreTraceModel(BaseModel):
    raw_score: float
    score: int
    risk_class: str  # Critical, High, Medium, Secure
    deterministic_penalty_dp: float
    ml_probability_pml: float
    ml_confidence_blend: float
    anomaly_boost_ab: float
    urgency_boost_ub: float
    formula_trace: str
    top_contributing_factors: List[Dict[str, Any]] = []

class SessionModel(BaseModel):
    id: str
    capture_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str  # SMTP, IMAP, POP3, Other
    starttls_state: str  # OFFERED, REQUESTED, COMPLETED, NOT_APPLICABLE, STRIPPING_SUSPECTED
    banner: Optional[str] = None
    commands_observed: List[str] = []
    tls_summary: Optional[TLSSummaryModel] = None
    certificate: Optional[CertificateModel] = None
    findings: List[FindingModel] = []
    score_trace: ScoreTraceModel
    is_anomaly: bool = False
    anomaly_reason: Optional[str] = None
    packet_count: int = 0
    start_time: Optional[str] = None
    duration_ms: float = 0.0
    evidence_frames: List[Dict[str, Any]] = []

class AnomalyItemModel(BaseModel):
    session_id: str
    src_dst: str
    protocol: str
    ja3: Optional[str] = None
    ja3s: Optional[str] = None
    anomaly_score: float
    reason: str
    shap_factors: List[str] = []
    risk_class: str

class RemediationItemModel(BaseModel):
    rule_id: str
    title: str
    severity: str
    affected_sessions_count: int
    priority_score: float
    affected_hosts: List[str] = []
    remediation_snippet: str
    service_target: str  # Postfix, Dovecot, Exim, General

class ComplianceStandardPosture(BaseModel):
    standard_id: str
    title: str
    passed_checks: int
    total_checks: int
    compliance_percentage: float
    violations: List[str] = []

class PostureSummaryModel(BaseModel):
    capture_id: str
    filename: str
    total_sessions: int
    total_packets: int
    analyzed_at: str
    overall_score: int
    overall_grade: str  # A+, A, B, C, D, F
    risk_distribution: Dict[str, int] = {}  # Critical, High, Medium, Secure
    protocol_distribution: Dict[str, int] = {}
    tls_version_distribution: Dict[str, int] = {}
    cipher_heatmap: List[Dict[str, Any]] = []
    cert_expiry_timeline: List[Dict[str, Any]] = []
    starttls_stripping_count: int = 0
    deprecated_tls_count: int = 0
    weak_cert_count: int = 0
    critical_findings_count: int = 0
    anomalies_count: int = 0
    compliance_matrix: List[ComplianceStandardPosture] = []
    top_remediations: List[RemediationItemModel] = []

class CaptureModel(BaseModel):
    id: str
    filename: str
    uploaded_at: str
    packet_count: int
    session_count: int
    size_bytes: int
    overall_score: int
    overall_grade: str
    critical_count: int
    high_count: int
    medium_count: int
    secure_count: int
    is_synthetic: bool = False
    scenario_description: Optional[str] = None

class RuleDefinitionModel(BaseModel):
    rule_id: str
    title: str
    severity: str
    category: str
    description: str
    compliance_refs: List[str]
    remediation: str
    weight: float
    default_fix_effort: str
