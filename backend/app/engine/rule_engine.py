"""
Deterministic Cryptographic Weakness Rule Engine.
Evaluates sessions against 30+ vulnerability rules independently of ML layer.
"""
import uuid
from typing import List, Dict, Any, Optional
from app.core.schemas import FindingModel, TLSSummaryModel, CertificateModel
from app.engine.rules_data import RULES_BY_ID

class RuleEngine:
    """
    Evaluates protocol state, TLS handshakes, and certificate properties
    against deterministic security rules.
    """

    @classmethod
    def evaluate_session(
        cls,
        protocol: str,
        starttls_state: str,
        tls_summary: Optional[TLSSummaryModel],
        cert: Optional[CertificateModel],
        plaintext_creds: bool,
        evidence_frames: List[Dict[str, Any]]
    ) -> List[FindingModel]:
        findings: List[FindingModel] = []
        frame_nums = [f.get("frame_number", 1) for f in evidence_frames]

        def add_finding(rule_id: str, evidence: str, fix_effort_override: Optional[str] = None):
            rule = RULES_BY_ID.get(rule_id)
            if not rule:
                return
            findings.append(FindingModel(
                id=str(uuid.uuid4())[:8],
                rule_id=rule["rule_id"],
                title=rule["title"],
                severity=rule["severity"],
                category=rule["category"],
                evidence=evidence,
                compliance_refs=rule.get("compliance_refs", []),
                remediation=rule["remediation"],
                fix_effort=fix_effort_override or rule.get("default_fix_effort", "Low"),
                frame_numbers=frame_nums[:5]
            ))

        # ── 1. Protocol / STARTTLS / Cleartext Rules ──────────────────────────
        if starttls_state == "STRIPPING_SUSPECTED":
            add_finding("RULE-STARTTLS-001", "STARTTLS capability advertised in server greeting but dropped/omitted before mail application transmission.")
            add_finding("RULE-COMP-002", "STARTTLS negotiation bypassed in violation of RFC 8314.")

        if plaintext_creds:
            add_finding("RULE-AUTH-001", "User authentication credentials (AUTH/LOGIN/PASS) detected in cleartext on unencrypted TCP stream.")
            if protocol in ["IMAP", "POP3"]:
                add_finding("RULE-AUTH-002", f"Cleartext {protocol} login sequence observed on standard port.")

        if not tls_summary or not tls_summary.negotiated_version:
            if starttls_state != "STRIPPING_SUSPECTED" and not plaintext_creds:
                add_finding("RULE-STARTTLS-002", f"Email session ({protocol}) operated completely in cleartext without TLS encryption.")
            return findings

        # ── 2. TLS Protocol Version Rules ─────────────────────────────────────
        version = tls_summary.negotiated_version or ""
        if version == "SSL 2.0":
            add_finding("RULE-TLS-001", "Negotiated SSL 2.0 in ServerHello.")
            add_finding("RULE-COMP-001", "SSL 2.0 is strictly prohibited by NIST SP 800-52r2.")
        elif version == "SSL 3.0":
            add_finding("RULE-TLS-002", "Negotiated SSL 3.0 in ServerHello (vulnerable to POODLE).")
            add_finding("RULE-COMP-001", "SSL 3.0 violates NIST SP 800-52r2 Section 3.1.")
        elif version == "TLS 1.0":
            add_finding("RULE-TLS-003", "Negotiated TLS 1.0 in ServerHello (RFC 8996 deprecated).")
            add_finding("RULE-COMP-001", "TLS 1.0 violates NIST SP 800-52r2 Section 3.1 baseline.")
        elif version == "TLS 1.1":
            add_finding("RULE-TLS-004", "Negotiated TLS 1.1 in ServerHello (RFC 8996 deprecated).")
            add_finding("RULE-COMP-001", "TLS 1.1 violates NIST SP 800-52r2 Section 3.1 baseline.")

        # Check client offered versions for legacy support
        client_vers = set(tls_summary.client_offered_versions)
        if ("TLS 1.0" in client_vers or "TLS 1.1" in client_vers) and version not in ["TLS 1.0", "TLS 1.1", "SSL 3.0", "SSL 2.0"]:
            add_finding("RULE-TLS-005", f"ClientHello advertised support for legacy versions: {', '.join(client_vers & {'TLS 1.0', 'TLS 1.1'})}")

        # ── 3. Cipher Suite & Key Exchange Rules ──────────────────────────────
        cipher = tls_summary.negotiated_cipher or ""
        cipher_upper = cipher.upper()

        if "NULL" in cipher_upper:
            add_finding("RULE-CIPHER-001", f"Negotiated NULL cipher suite: {cipher}")
        if "EXPORT" in cipher_upper or "DES40" in cipher_upper:
            add_finding("RULE-CIPHER-002", f"Negotiated export-grade cipher: {cipher}")
        if "RC4" in cipher_upper:
            add_finding("RULE-CIPHER-003", f"Negotiated RC4 cipher suite: {cipher}")
        if "3DES" in cipher_upper or "DES_CBC" in cipher_upper:
            add_finding("RULE-CIPHER-004", f"Negotiated 64-bit block cipher susceptible to Sweet32: {cipher}")
        if "TLS_RSA_WITH_" in cipher_upper and not any(k in cipher_upper for k in ["ECDHE", "DHE"]):
            add_finding("RULE-CIPHER-005", f"Static RSA key exchange negotiated: {cipher} (No Forward Secrecy)")
        if "CBC" in cipher_upper and not tls_summary.is_tls13:
            add_finding("RULE-CIPHER-006", f"CBC mode cipher negotiated: {cipher}")
        if any(w in cipher_upper for w in ["SEED", "IDEA", "CAMELLIA"]):
            add_finding("RULE-CIPHER-007", f"Non-standard legacy symmetric cipher negotiated: {cipher}")
        if "DHE" in cipher_upper and not "ECDHE" in cipher_upper:
            add_finding("RULE-CIPHER-008", "Legacy DHE key exchange without confirmed >=2048 bit safe primes.")
        if "MD5" in cipher_upper:
            add_finding("RULE-CIPHER-009", f"MD5 integrity hash in cipher: {cipher}")
        elif "SHA" in cipher_upper and not any(s in cipher_upper for s in ["SHA256", "SHA384", "SHA512", "GCM", "POLY1305"]):
            add_finding("RULE-CIPHER-010", f"SHA-1 HMAC used in cipher: {cipher}")

        # ── 4. Extension Rules ────────────────────────────────────────────────
        if version == "TLS 1.2" and not tls_summary.has_extended_master_secret:
            add_finding("RULE-CONF-002", "Extended Master Secret (EMS) extension absent in TLS 1.2 handshake.")
        if not tls_summary.sni:
            add_finding("RULE-CONF-004", "SNI (Server Name Indication) extension was omitted in ClientHello.")
        if not tls_summary.alpn and not tls_summary.is_tls13:
            add_finding("RULE-CONF-005", "ALPN (Application-Layer Protocol Negotiation) extension not negotiated.")

        # ── 5. Certificate Rules ──────────────────────────────────────────────
        if cert and cert.observable:
            if cert.is_expired:
                add_finding("RULE-CERT-001", f"Certificate expired. NotAfter: {cert.not_after}")
            if cert.is_not_yet_valid:
                add_finding("RULE-CERT-002", f"Certificate is not yet valid. NotBefore: {cert.not_before}")
            if cert.is_self_signed:
                add_finding("RULE-CERT-003", f"Certificate is self-signed (Issuer = Subject = {cert.subject})")
            if cert.key_algo == "RSA" and cert.key_bits < 2048:
                add_finding("RULE-CERT-004", f"Weak RSA public key size: {cert.key_bits} bits (< 2048 required)")
                add_finding("RULE-COMP-001", f"RSA key length {cert.key_bits}-bit violates NIST SP 800-52r2 baseline.")
            if "md5" in cert.sig_algo.lower():
                add_finding("RULE-CERT-005", f"Broken MD5 certificate signature: {cert.sig_algo}")
            elif "sha1" in cert.sig_algo.lower():
                add_finding("RULE-CERT-006", f"Deprecated SHA-1 certificate signature: {cert.sig_algo}")
            if not cert.san_list:
                add_finding("RULE-CERT-007", "Certificate is missing Subject Alternative Name (SAN) extension.")
            if not cert.is_expired and 0 <= cert.days_until_expiry <= 14:
                add_finding("RULE-CERT-009", f"Certificate expires in {cert.days_until_expiry} days.")

        return findings
