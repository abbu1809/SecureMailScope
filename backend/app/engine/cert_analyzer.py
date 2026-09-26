"""
X.509 Certificate Analyzer and Cryptographic Strength Assessor.
Leverages pyca/cryptography to inspect public keys, validity, and trust chains.
"""
import hashlib
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

from app.core.schemas import CertificateModel

class CertAnalyzer:
    """
    Analyzes raw DER X.509 certificate data and assesses cryptographic properties.
    """

    @classmethod
    def analyze_der(cls, der_bytes: bytes) -> Optional[CertificateModel]:
        if not HAS_CRYPTO or not der_bytes:
            return None

        try:
            cert = x509.load_der_x509_certificate(der_bytes, default_backend())
            now = datetime.now(timezone.utc)

            # Subject and Issuer strings
            subject_str = cert.subject.rfc4514_string()
            issuer_str = cert.issuer.rfc4514_string()
            is_self_signed = (subject_str == issuer_str)

            # Validity Dates
            try:
                not_before = cert.not_valid_before_utc
                not_after = cert.not_valid_after_utc
            except AttributeError:
                # Older cryptography version compatibility
                not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
                not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

            is_expired = (now > not_after)
            is_not_yet_valid = (now < not_before)
            days_until_expiry = (not_after - now).days

            # Public Key Algorithm and Size
            pub_key = cert.public_key()
            key_algo = "Unknown"
            key_bits = 2048

            if isinstance(pub_key, rsa.RSAPublicKey):
                key_algo = "RSA"
                key_bits = pub_key.key_size
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                key_algo = f"ECDSA ({pub_key.curve.name})"
                key_bits = pub_key.key_size
            elif isinstance(pub_key, ed25519.Ed25519PublicKey):
                key_algo = "Ed25519"
                key_bits = 256
            elif isinstance(pub_key, dsa.DSAPublicKey):
                key_algo = "DSA"
                key_bits = pub_key.key_size

            # Signature Algorithm
            sig_algo = cert.signature_algorithm_oid._name or "Unknown"

            # SAN list
            san_list = []
            try:
                san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                for name in san_ext.value:
                    san_list.append(name.value)
            except Exception:
                pass

            sha256_fp = hashlib.sha256(der_bytes).hexdigest()

            return CertificateModel(
                subject=subject_str,
                issuer=issuer_str,
                not_before=not_before.isoformat(),
                not_after=not_after.isoformat(),
                is_expired=is_expired,
                is_not_yet_valid=is_not_yet_valid,
                is_self_signed=is_self_signed,
                key_algo=key_algo,
                key_bits=key_bits,
                sig_algo=sig_algo,
                san_list=san_list,
                days_until_expiry=days_until_expiry,
                observable=True,
                fingerprint_sha256=sha256_fp
            )
        except Exception:
            return None

    @classmethod
    def create_tls13_unobservable(cls) -> CertificateModel:
        """
        Creates an explicit unobservable certificate representation for TLS 1.3 encrypted handshakes.
        """
        return CertificateModel(
            subject="Encrypted in TLS 1.3 Handshake",
            issuer="Encrypted in TLS 1.3 Handshake",
            not_before=None,
            not_after=None,
            is_expired=False,
            is_not_yet_valid=False,
            is_self_signed=False,
            key_algo="ECDHE / X25519 (Encrypted)",
            key_bits=256,
            sig_algo="TLS 1.3 Authenticated AEAD",
            san_list=[],
            days_until_expiry=365,
            observable=False
        )
