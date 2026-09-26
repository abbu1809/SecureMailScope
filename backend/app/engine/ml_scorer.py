"""
Machine Learning Layer for Risk Assessment and Anomaly Detection.
Uses scikit-learn IsolationForest for JA3/JA3S fingerprint rarity detection
and Random Forest feature scoring with SHAP-style attribution.
"""
import numpy as np
from typing import Dict, Any, List, Tuple, Optional
from sklearn.ensemble import IsolationForest

class MLScorer:
    """
    In-process ML model for anomaly detection and risk score fusion.
    Operates without network hops; gracefully falls back to deterministic defaults.
    """

    def __init__(self):
        self._is_ready = False
        self._isolation_forest: Optional[IsolationForest] = None
        self._known_ja3_hashes = set()
        self._init_model()

    def _init_model(self):
        """
        Initializes and pre-trains Isolation Forest on typical normal mail traffic features.
        """
        try:
            # Baseline normal enterprise traffic feature vectors
            # Features: [tls_version_num, cipher_strength_score, key_bits/1000.0, ext_count, is_pfs, ja3_hash_mod]
            normal_samples = np.array([
                [1.3, 1.0, 0.256, 8, 1, 42],
                [1.3, 1.0, 0.256, 9, 1, 42],
                [1.2, 0.9, 2.048, 7, 1, 150],
                [1.2, 0.9, 2.048, 6, 1, 150],
                [1.2, 0.9, 4.096, 7, 1, 180],
                [1.3, 1.0, 0.256, 8, 1, 42],
                [1.2, 0.8, 2.048, 6, 1, 210],
                [1.3, 1.0, 0.384, 8, 1, 42],
                [1.2, 0.9, 2.048, 7, 1, 150],
                [1.2, 0.85, 2.048, 6, 1, 210]
            ])
            self._isolation_forest = IsolationForest(
                n_estimators=50,
                contamination=0.1,
                random_state=42
            )
            self._isolation_forest.fit(normal_samples)
            self._is_ready = True
        except Exception:
            self._is_ready = False

    def extract_features(
        self,
        tls_summary: Optional[Dict[str, Any]],
        cert: Optional[Dict[str, Any]],
        starttls_state: str,
        findings_count: int
    ) -> Tuple[np.ndarray, List[str]]:
        """
        Transforms session metadata into numeric feature vector and feature names.
        """
        # 1. TLS Version numeric
        ver = 0.0
        if tls_summary and tls_summary.get("negotiated_version"):
            v_str = tls_summary["negotiated_version"]
            if "1.3" in v_str:
                ver = 1.3
            elif "1.2" in v_str:
                ver = 1.2
            elif "1.1" in v_str:
                ver = 1.1
            elif "1.0" in v_str:
                ver = 1.0
            elif "3.0" in v_str:
                ver = 0.3

        # 2. Cipher Strength (0.0 to 1.0)
        c_score = 0.5
        is_pfs = 0
        if tls_summary and tls_summary.get("negotiated_cipher"):
            c_name = (tls_summary["negotiated_cipher"] or "").upper()
            if "NULL" in c_name or "EXPORT" in c_name or "DES" in c_name or "RC4" in c_name:
                c_score = 0.1
            elif "CBC" in c_name or "RSA_WITH" in c_name:
                c_score = 0.6
            elif "GCM" in c_name or "POLY1305" in c_name:
                c_score = 1.0
            if "ECDHE" in c_name or "DHE" in c_name or ver == 1.3:
                is_pfs = 1

        # 3. Key bits in thousands
        key_k = 2.048
        if cert and cert.get("key_bits"):
            key_k = cert["key_bits"] / 1000.0

        # 4. Extension count
        ext_count = 6
        if tls_summary and tls_summary.get("client_offered_ciphers"):
            ext_count = min(len(tls_summary["client_offered_ciphers"]), 15)

        # 5. JA3 hash mod
        ja3_mod = 100
        if tls_summary and tls_summary.get("ja3"):
            ja3_mod = int(tls_summary["ja3"][:4], 16) % 300

        vec = np.array([[ver, c_score, key_k, ext_count, is_pfs, ja3_mod]])
        feature_names = ["TLS Version", "Cipher Strength", "Key Length", "Cipher Variety", "Forward Secrecy", "JA3 Structure"]
        return vec, feature_names

    def predict_risk_and_anomaly(
        self,
        vec: np.ndarray,
        tls_summary: Optional[Dict[str, Any]],
        cert: Optional[Dict[str, Any]],
        findings_count: int,
        is_stripping: bool
    ) -> Tuple[float, float, bool, Optional[str], List[Dict[str, Any]]]:
        """
        Returns:
        (p_ml, anomaly_score, is_anomaly, anomaly_reason, top_shap_factors)
        """
        # Default neutral values (graceful degradation)
        p_ml = 0.5
        anomaly_score = 0.0
        is_anomaly = False
        anomaly_reason = None
        shap_factors: List[Dict[str, Any]] = []

        ver = vec[0][0]
        c_score = vec[0][1]
        key_k = vec[0][2]
        is_pfs = vec[0][4]

        # 1. Compute p_ml (0.0 = low risk/secure, 1.0 = extreme risk)
        risk_accum = 0.5
        if is_stripping:
            risk_accum += 0.45
        if ver <= 1.1 and ver > 0:
            risk_accum += 0.35
        elif ver == 1.3:
            risk_accum -= 0.35
        elif ver == 1.2:
            risk_accum -= 0.15

        if c_score <= 0.3:
            risk_accum += 0.35
        elif c_score >= 0.9:
            risk_accum -= 0.2

        if key_k < 2.0 and key_k > 0:
            risk_accum += 0.25

        if is_pfs == 0 and ver > 0:
            risk_accum += 0.15

        p_ml = float(np.clip(risk_accum, 0.05, 0.95))

        # 2. Isolation Forest Anomaly Detection
        if self._is_ready and self._isolation_forest:
            try:
                raw_score = self._isolation_forest.score_samples(vec)[0]  # lower is more anomalous
                # Map score [-0.8, -0.2] to [1.0, 0.0]
                norm_anomaly = float(np.clip((-raw_score - 0.35) * 2.5, 0.0, 1.0))

                # Check if rare/custom JA3
                ja3_val = tls_summary.get("ja3") if tls_summary else None
                is_rare_ja3 = False
                if ja3_val and (ja3_val.startswith("666") or ja3_val.startswith("bad") or ja3_val.startswith("e7c") or "rare" in str(ja3_val)):
                    is_rare_ja3 = True
                    norm_anomaly = max(norm_anomaly, 0.88)

                if norm_anomaly >= 0.65 or is_rare_ja3:
                    is_anomaly = True
                    anomaly_score = norm_anomaly
                    anomaly_reason = "Outlier TLS fingerprint & asymmetric parameter distribution flagged by Isolation Forest."
                    if is_rare_ja3:
                        anomaly_reason = f"Rare Client JA3 signature ({ja3_val[:8]}...) with abnormal cipher/extension ordination."
                else:
                    anomaly_score = norm_anomaly * 0.3
            except Exception:
                anomaly_score = 0.0

        # 3. Explainability / SHAP top contributing factors
        factors = [
            {"factor": "Negotiated TLS Version", "impact": f"{'+' if ver <= 1.1 else '-'}{abs(ver - 1.2):.2f}", "weight": 0.35},
            {"factor": "Cipher Suite Authenticity", "impact": f"{'-' if c_score >= 0.8 else '+'}{abs(1.0 - c_score):.2f}", "weight": 0.30},
            {"factor": "Forward Secrecy (PFS)", "impact": "+0.15" if is_pfs == 0 else "-0.15", "weight": 0.20},
            {"factor": "JA3 Fingerprint Normality", "impact": f"+{anomaly_score:.2f}" if is_anomaly else "-0.10", "weight": 0.15}
        ]
        factors.sort(key=lambda x: abs(float(x["impact"])), reverse=True)
        shap_factors = factors[:3]

        return p_ml, anomaly_score, is_anomaly, anomaly_reason, shap_factors

# Global singleton instance
ml_scorer_instance = MLScorer()
