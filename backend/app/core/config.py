"""
Configuration and constants for SecureMailScope.
"""
from typing import Dict, Any

APP_NAME = "SecureMailScope"
APP_VERSION = "1.1.0"
APP_DESCRIPTION = "AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications (SIH PS 26159)"

# SCoRE Severity weights (w_i)
SEVERITY_WEIGHTS = {
    "CRITICAL": 35.0,
    "HIGH": 20.0,
    "MEDIUM": 10.0,
    "LOW": 5.0,
    "INFO": 0.0
}

# Fix effort default tiers (1=Low, 2=Medium, 3=High)
FIX_EFFORT_MAP = {
    "CRITICAL": 1.5,
    "HIGH": 2.0,
    "MEDIUM": 2.5,
    "LOW": 3.0,
    "INFO": 4.0
}

# Standard Port mappings
PORT_PROTOCOL_MAP = {
    25: "SMTP",
    587: "SMTP (Submission)",
    465: "SMTPS (Implicit TLS)",
    110: "POP3",
    995: "POP3S (Implicit TLS)",
    143: "IMAP",
    993: "IMAPS (Implicit TLS)",
}

# Compliance Standards References
COMPLIANCE_STANDARDS = {
    "NIST_SP_800_52R2": "NIST SP 800-52 Rev 2: Guidelines for the Selection, Configuration, and Use of TLS",
    "RFC_8996": "RFC 8996: Deprecating TLS 1.0 and TLS 1.1",
    "RFC_8314": "RFC 8314: Cleartext Considered Obsolete: Use of TLS for Email Submission and Access",
    "RFC_7465": "RFC 7465: Prohibiting RC4 Cipher Suites",
    "RFC_7568": "RFC 7568: Deprecating Secure Sockets Layer Version 3.0",
    "PCI_DSS_V4": "PCI-DSS v4.0 Requirement 4: Protect Cardholder Data with Strong Cryptography",
    "HIPAA_SECURITY": "HIPAA 45 CFR § 164.312(e)(1): Transmission Security",
}
