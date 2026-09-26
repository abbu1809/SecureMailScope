export interface Certificate {
  subject: string;
  issuer: string;
  not_before?: string;
  not_after?: string;
  is_expired: boolean;
  is_not_yet_valid: boolean;
  is_self_signed: boolean;
  key_algo: string;
  key_bits: number;
  sig_algo: string;
  san_list: string[];
  days_until_expiry: number;
  observable: boolean;
  fingerprint_sha256?: string;
}

export interface TLSSummary {
  negotiated_version?: string;
  client_offered_versions: string[];
  negotiated_cipher?: string;
  client_offered_ciphers: string[];
  key_exchange?: string;
  sni?: string;
  alpn?: string;
  ja3?: string;
  ja3_string?: string;
  ja3s?: string;
  ja3s_string?: string;
  has_extended_master_secret: boolean;
  is_tls13: boolean;
  handshake_encrypted: boolean;
}

export interface Finding {
  id: string;
  rule_id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  category: string;
  evidence: string;
  compliance_refs: string[];
  remediation: string;
  fix_effort: string;
  frame_numbers: number[];
}

export interface ScoreTrace {
  raw_score: number;
  score: number;
  risk_class: 'Critical' | 'High' | 'Medium' | 'Secure';
  deterministic_penalty_dp: number;
  ml_probability_pml: number;
  ml_confidence_blend: number;
  anomaly_boost_ab: number;
  urgency_boost_ub: number;
  formula_trace: string;
  top_contributing_factors: { factor: string; impact: string; weight: number }[];
}

export interface FrameEvidence {
  frame_number: number;
  timestamp: number;
  length: number;
  direction: string;
  summary: string;
}

export interface Session {
  id: string;
  capture_id: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  protocol: 'SMTP' | 'IMAP' | 'POP3' | 'Other';
  starttls_state: 'OFFERED' | 'REQUESTED' | 'COMPLETED' | 'NOT_APPLICABLE' | 'STRIPPING_SUSPECTED';
  banner?: string;
  commands_observed: string[];
  tls_summary?: TLSSummary;
  certificate?: Certificate;
  findings: Finding[];
  score_trace: ScoreTrace;
  is_anomaly: boolean;
  anomaly_reason?: string;
  packet_count: number;
  start_time?: string;
  duration_ms: number;
  evidence_frames: FrameEvidence[];
}

export interface AnomalyItem {
  session_id: string;
  src_dst: string;
  protocol: string;
  ja3?: string;
  ja3s?: string;
  anomaly_score: number;
  reason: string;
  shap_factors: string[];
  risk_class: string;
}

export interface RemediationItem {
  rule_id: string;
  title: string;
  severity: string;
  affected_sessions_count: number;
  priority_score: number;
  affected_hosts: string[];
  remediation_snippet: string;
  service_target: string;
}

export interface ComplianceStandardPosture {
  standard_id: string;
  title: string;
  passed_checks: number;
  total_checks: number;
  compliance_percentage: number;
  violations: string[];
}

export interface PostureSummary {
  capture_id: string;
  filename: string;
  total_sessions: number;
  total_packets: number;
  analyzed_at: string;
  overall_score: number;
  overall_grade: string;
  risk_distribution: {
    Critical?: number;
    High?: number;
    Medium?: number;
    Secure?: number;
  };
  protocol_distribution: Record<string, number>;
  tls_version_distribution: Record<string, number>;
  cipher_heatmap: { cipher: string; count: number; is_secure: boolean }[];
  cert_expiry_timeline: {
    subject: string;
    issuer: string;
    days_until_expiry: number;
    is_expired: boolean;
    key_algo: string;
    key_bits: number;
  }[];
  starttls_stripping_count: number;
  deprecated_tls_count: number;
  weak_cert_count: number;
  critical_findings_count: number;
  anomalies_count: number;
  compliance_matrix: ComplianceStandardPosture[];
  top_remediations: RemediationItem[];
}

export interface Capture {
  id: string;
  filename: string;
  uploaded_at: string;
  packet_count: number;
  session_count: number;
  size_bytes: number;
  overall_score: number;
  overall_grade: string;
  critical_count: number;
  high_count: number;
  medium_count: number;
  secure_count: number;
  is_synthetic: boolean;
  scenario_description?: string;
}

export interface RuleDefinition {
  rule_id: string;
  title: string;
  severity: string;
  category: string;
  description: string;
  compliance_refs: string[];
  remediation: string;
  weight: number;
  default_fix_effort: string;
}
