"""
Authoritative SCoRE (Session Cryptographic Overall Risk Evaluator) Algorithm Engine.
Implements the exact mathematical specification from SRS §4.1 and PRD §3.5.
"""
import math
from typing import List, Dict, Any, Tuple, Optional
from app.core.config import SEVERITY_WEIGHTS, FIX_EFFORT_MAP
from app.core.schemas import FindingModel, ScoreTraceModel, CertificateModel
from app.engine.ml_scorer import ml_scorer_instance

class SCoREEvaluator:
    """
    Computes deterministic penalties, ML fusion blends, anomaly boosts, and urgency boosts.
    """

    @classmethod
    def evaluate(
        cls,
        findings: List[FindingModel],
        tls_summary: Optional[Dict[str, Any]],
        cert: Optional[CertificateModel],
        starttls_state: str,
        scope_counts: Optional[Dict[str, int]] = None,
        use_ml: bool = True
    ) -> ScoreTraceModel:
        """
        Executes SCoRE formula:
        DP = Σ w_i × min(1 + log2(scope_i + 1) / 4, 1.5)
        Blend = DP × (1 + 0.4 × (p_ml - 0.5))
        AB = anomaly_score × 25
        UB = urgency_factor × 10
        Score = clamp(100 - Blend - AB - UB, 0, 100)
        """
        scope_counts = scope_counts or {}

        # 1. Deterministic Penalty (DP)
        dp = 0.0
        for f in findings:
            w_i = SEVERITY_WEIGHTS.get(f.severity.upper(), 10.0)
            scope_i = scope_counts.get(f.rule_id, 1)
            scale = min(1.0 + math.log2(scope_i + 1) / 4.0, 1.5)
            dp += (w_i * scale)

        # 2. Urgency Factor (UB)
        # e.g., cert expiry proximity
        urgency_factor = 0.0
        if cert and cert.observable:
            if cert.is_expired:
                urgency_factor = 1.0
            elif 0 <= cert.days_until_expiry <= 7:
                urgency_factor = 0.9
            elif 7 < cert.days_until_expiry <= 14:
                urgency_factor = 0.6
            elif 14 < cert.days_until_expiry <= 30:
                urgency_factor = 0.3
        elif starttls_state == "STRIPPING_SUSPECTED":
            urgency_factor = 0.85

        ub = urgency_factor * 10.0

        # 3. ML Confidence Fusion & Anomaly Boost
        p_ml = 0.5
        anomaly_score = 0.0
        top_factors = []

        if use_ml:
            try:
                cert_dict = cert.model_dump() if cert else None
                vec, _ = ml_scorer_instance.extract_features(
                    tls_summary=tls_summary,
                    cert=cert_dict,
                    starttls_state=starttls_state,
                    findings_count=len(findings)
                )
                p_ml, anomaly_score, is_anom, reason, top_factors = ml_scorer_instance.predict_risk_and_anomaly(
                    vec=vec,
                    tls_summary=tls_summary,
                    cert=cert_dict,
                    findings_count=len(findings),
                    is_stripping=(starttls_state == "STRIPPING_SUSPECTED")
                )
            except Exception:
                # Graceful degradation
                p_ml = 0.5
                anomaly_score = 0.0
        else:
            # Graceful degradation requirement (SRS §4.1 box)
            p_ml = 0.5
            anomaly_score = 0.0

        # Blend = DP × (1 + 0.4 × (p_ml - 0.5))
        blend = dp * (1.0 + 0.4 * (p_ml - 0.5))
        ab = anomaly_score * 25.0

        # Raw Score & Clamping
        raw_score = 100.0 - blend - ab - ub
        clamped_score = max(0, min(100, int(round(raw_score))))

        # Class Assignment: 0-39 Critical | 40-69 High | 70-89 Medium | 90-100 Secure
        if clamped_score <= 39:
            risk_class = "Critical"
        elif clamped_score <= 69:
            risk_class = "High"
        elif clamped_score <= 89:
            risk_class = "Medium"
        else:
            risk_class = "Secure"

        formula_trace = (
            f"Score = clamp(100 - Blend({blend:.1f}) - AB({ab:.1f}) - UB({ub:.1f})) = {clamped_score} | "
            f"DP={dp:.1f}, p_ml={p_ml:.2f}, anomaly={anomaly_score:.2f}, urgency={urgency_factor:.2f}"
        )

        return ScoreTraceModel(
            raw_score=round(raw_score, 2),
            score=clamped_score,
            risk_class=risk_class,
            deterministic_penalty_dp=round(dp, 2),
            ml_probability_pml=round(p_ml, 3),
            ml_confidence_blend=round(blend, 2),
            anomaly_boost_ab=round(ab, 2),
            urgency_boost_ub=round(ub, 2),
            formula_trace=formula_trace,
            top_contributing_factors=top_factors
        )

    @classmethod
    def calculate_priority(cls, severity: str, exposure: int, fix_effort_str: str) -> float:
        """
        priority = severity_weight × exposure × (1 / fix_effort)
        """
        w = SEVERITY_WEIGHTS.get(severity.upper(), 10.0)
        effort_divisor = 1.5
        if fix_effort_str.lower() == "low":
            effort_divisor = 1.0
        elif fix_effort_str.lower() == "medium":
            effort_divisor = 2.0
        elif fix_effort_str.lower() == "high":
            effort_divisor = 3.0

        return round(w * max(1, exposure) * (1.0 / effort_divisor), 2)
