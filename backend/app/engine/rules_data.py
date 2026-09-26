"""
Deterministic Cryptographic Vulnerability Rules for SecureMailScope (>=30 Rules).
Strictly compliant with NIST SP 800-52r2, RFC 8996, RFC 8314, PCI-DSS v4.0.
"""

RULES_DATABASE = [
    # ─── PROTOCOL VERSION RULES (RFC 8996, NIST SP 800-52r2) ────────────────────────
    {
        "rule_id": "RULE-TLS-001",
        "title": "Obsolete SSLv2 Protocol Negotiated",
        "severity": "CRITICAL",
        "category": "Protocol Version",
        "weight": 35.0,
        "default_fix_effort": "Low",
        "description": "The session negotiated SSL 2.0, a cryptographically broken protocol vulnerable to DROWN and plaintext extraction.",
        "compliance_refs": ["RFC 6176", "NIST SP 800-52r2 Section 3.1", "PCI-DSS v4.0 Req 4.1"],
        "remediation": "Disable SSLv2 immediately across all mail services.\n\nPostfix (main.cf):\nsmtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1, >=TLSv1.2\n\nDovecot (10-ssl.conf):\nssl_min_protocol = TLSv1.2"
    },
    {
        "rule_id": "RULE-TLS-002",
        "title": "Obsolete SSLv3 Protocol Negotiated",
        "severity": "CRITICAL",
        "category": "Protocol Version",
        "weight": 35.0,
        "default_fix_effort": "Low",
        "description": "The session negotiated SSL 3.0, which suffers from fundamental CBC padding flaws (POODLE attack CVE-2014-3566).",
        "compliance_refs": ["RFC 7568", "NIST SP 800-52r2 Section 3.1", "PCI-DSS v4.0 Req 4.1"],
        "remediation": "Disable SSLv3 across all mail endpoints.\n\nPostfix (main.cf):\nsmtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1, >=TLSv1.2\n\nDovecot (10-ssl.conf):\nssl_min_protocol = TLSv1.2"
    },
    {
        "rule_id": "RULE-TLS-003",
        "title": "Deprecated TLS 1.0 Protocol Negotiated",
        "severity": "HIGH",
        "category": "Protocol Version",
        "weight": 20.0,
        "default_fix_effort": "Low",
        "description": "TLS 1.0 lacks modern authenticated encryption (AEAD) and is vulnerable to BEAST and padding oracle attacks. Deprecated by IETF RFC 8996.",
        "compliance_refs": ["RFC 8996 Section 2", "NIST SP 800-52r2 Section 3.1", "RFC 8314 Section 3"],
        "remediation": "Enforce minimum TLS 1.2 or TLS 1.3 on all submission and MTA ports.\n\nPostfix (main.cf):\nsmtpd_tls_mandatory_protocols = >=TLSv1.2\nsmtp_tls_mandatory_protocols = >=TLSv1.2"
    },
    {
        "rule_id": "RULE-TLS-004",
        "title": "Deprecated TLS 1.1 Protocol Negotiated",
        "severity": "HIGH",
        "category": "Protocol Version",
        "weight": 20.0,
        "default_fix_effort": "Low",
        "description": "TLS 1.1 has been formally deprecated by RFC 8996 due to lack of support for current cipher suites and weak SHA-1 signatures.",
        "compliance_refs": ["RFC 8996", "NIST SP 800-52r2 Section 3.1"],
        "remediation": "Upgrade mail transfer and client access to TLS 1.2 or TLS 1.3.\n\nDovecot (10-ssl.conf):\nssl_min_protocol = TLSv1.2"
    },
    {
        "rule_id": "RULE-TLS-005",
        "title": "Client Advertises Deprecated TLS Versions (TLS 1.0/1.1)",
        "severity": "LOW",
        "category": "Protocol Version",
        "weight": 5.0,
        "default_fix_effort": "Medium",
        "description": "The client ClientHello advertised support for deprecated TLS 1.0 or 1.1 versions in its version range list.",
        "compliance_refs": ["RFC 8996 Section 4", "NIST SP 800-52r2 Section 3.1"],
        "remediation": "Update client mail user agents (MUAs) and MTA connectors to send TLS 1.2+ exclusively in ClientHello."
    },

    # ─── CIPHER SUITE & KEY EXCHANGE RULES ─────────────────────────────────────────
    {
        "rule_id": "RULE-CIPHER-001",
        "title": "NULL Cipher Suite Negotiated (Unencrypted Payload)",
        "severity": "CRITICAL",
        "category": "Cipher Suite",
        "weight": 35.0,
        "default_fix_effort": "Low",
        "description": "A NULL cipher (e.g., TLS_RSA_WITH_NULL_SHA) was negotiated. Handshake authenticated without symmetric data encryption.",
        "compliance_refs": ["NIST SP 800-52r2 Section 3.3.1", "PCI-DSS v4.0 Req 4.1", "RFC 8314"],
        "remediation": "Disallow all eNULL and aNULL cipher suites.\n\nPostfix (main.cf):\nsmtpd_tls_exclude_ciphers = aNULL, eNULL, EXPORT, RC4, DES, 3DES, MD5"
    },
    {
        "rule_id": "RULE-CIPHER-002",
        "title": "Export-Grade / Insecure 40/56-bit Cipher Negotiated",
        "severity": "CRITICAL",
        "category": "Cipher Suite",
        "weight": 35.0,
        "default_fix_effort": "Low",
        "description": "Negotiated export-grade legacy cipher suite susceptible to FREAK (CVE-2015-0204) and Logjam (CVE-2015-4000) attacks.",
        "compliance_refs": ["NIST SP 800-52r2 Section 3.3.1", "RFC 8996"],
        "remediation": "Remove all EXPORT ciphers and disable export DH parameters from mail server configs."
    },
    {
        "rule_id": "RULE-CIPHER-003",
        "title": "RC4 Stream Cipher Negotiated",
        "severity": "CRITICAL",
        "category": "Cipher Suite",
        "weight": 35.0,
        "default_fix_effort": "Low",
        "description": "RC4 has known statistical keystream biases enabling plaintext recovery (Bar Mitzvah, RC4 NOMORE). Prohibited by RFC 7465.",
        "compliance_refs": ["RFC 7465 Section 2", "NIST SP 800-52r2 Section 3.3.1", "PCI-DSS v4.0 Req 4.1"],
        "remediation": "Remove RC4 ciphers from cipher strings.\n\nDovecot (10-ssl.conf):\nssl_cipher_list = ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
    },
    {
        "rule_id": "RULE-CIPHER-004",
        "title": "DES / 3DES (Triple-DES) Cipher Suite Negotiated",
        "severity": "HIGH",
        "category": "Cipher Suite",
        "weight": 20.0,
        "default_fix_effort": "Low",
        "description": "3DES uses a 64-bit block size vulnerable to birthday collision attacks (SWEET32, CVE-2016-2183) allowing session recovery.",
        "compliance_refs": ["NIST SP 800-52r2 Section 3.3.1", "RFC 8996 Section 2.1"],
        "remediation": "Exclude 3DES / DES ciphers from Postfix/Dovecot cipherlists.\n\nPostfix (main.cf):\ntls_medium_cipherlist = ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
    },
    {
        "rule_id": "RULE-CIPHER-005",
        "title": "Static RSA Key Exchange Without Forward Secrecy (PFS)",
        "severity": "HIGH",
        "category": "Key Exchange",
        "weight": 20.0,
        "default_fix_effort": "Medium",
        "description": "Session uses static RSA key exchange (TLS_RSA_WITH_*). If the server private key is ever compromised, all past intercepted traffic can be decrypted retroactively.",
        "compliance_refs": ["NIST SP 800-52r2 Section 3.2", "RFC 8314 Section 3"],
        "remediation": "Enforce Ephemeral Diffie-Hellman (ECDHE / DHE) key exchange.\n\nPostfix (main.cf):\nsmtpd_tls_eecdh_grade = strong\nsmtpd_tls_mandatory_ciphers = high"
    },
    {
        "rule_id": "RULE-CIPHER-006",
        "title": "CBC Mode Cipher Negotiated Without Encrypt-then-MAC",
        "severity": "MEDIUM",
        "category": "Cipher Suite",
        "weight": 10.0,
        "default_fix_effort": "Low",
        "description": "AES-CBC ciphers without Encrypt-then-MAC (RFC 7366) are vulnerable to timing side-channels and padding oracle attacks (Lucky Thirteen).",
        "compliance_refs": ["NIST SP 800-52r2 Section 3.3.1.1", "RFC 7366"],
        "remediation": "Prioritize AEAD ciphers (AES-GCM, CHACHA20-POLY1305) over CBC mode ciphers."
    },
    {
        "rule_id": "RULE-CIPHER-007",
        "title": "Obsolete SEED / IDEA / ARCFOUR / Camellia Legacy Cipher",
        "severity": "MEDIUM",
        "category": "Cipher Suite",
        "weight": 10.0,
        "default_fix_effort": "Low",
        "description": "Legacy non-standard symmetric cipher negotiated which is not recommended for production email encryption.",
        "compliance_refs": ["NIST SP 800-52r2 Section 3.3"],
        "remediation": "Restrict cipher suites strictly to AES-GCM and ChaCha20-Poly1305."
    },
    {
        "rule_id": "RULE-CIPHER-008",
        "title": "Weak Diffie-Hellman Parameter Size (< 2048-bit DH)",
        "severity": "HIGH",
        "category": "Key Exchange",
        "weight": 20.0,
        "default_fix_effort": "Low",
        "description": "Server negotiated finite field DHE with parameters shorter than 2048 bits, vulnerable to precomputation attacks (Logjam).",
        "compliance_refs": ["NIST SP 800-52r2 Section 3.2", "RFC 7919"],
        "remediation": "Generate custom 2048-bit or 4096-bit DH parameters or migrate to ECDHE (curves X25519 / secp256r1).\n\nPostfix (main.cf):\nsmtpd_tls_dh1024_param_file = /etc/postfix/dh2048.pem"
    },
    {
        "rule_id": "RULE-CIPHER-009",
        "title": "Cipher Suite Uses Deprecated MD5 Integrity Hash (MAC)",
        "severity": "CRITICAL",
        "category": "Integrity / MAC",
        "weight": 35.0,
        "default_fix_effort": "Low",
        "description": "Cipher suite relies on MD5 for record integrity, which is completely broken by collision attacks.",
        "compliance_refs": ["RFC 6151", "NIST SP 800-52r2 Section 3.3.2"],
        "remediation": "Exclude MD5 from cipher strings and upgrade to AEAD or SHA-256 MACs."
    },
    {
        "rule_id": "RULE-CIPHER-010",
        "title": "Cipher Suite Uses SHA-1 Integrity Hash (MAC)",
        "severity": "MEDIUM",
        "category": "Integrity / MAC",
        "weight": 10.0,
        "default_fix_effort": "Low",
        "description": "Cipher suite relies on SHA-1 HMAC (e.g. ECDHE-RSA-AES128-SHA). NIST SP 800-52r2 disallows SHA-1 for government and high-assurance systems.",
        "compliance_refs": ["NIST SP 800-52r2 Section 3.3.2", "RFC 8996"],
        "remediation": "Configure TLS to prioritize SHA-256 or SHA-384 based cipher suites."
    },

    # ─── CERTIFICATE & PUBLIC KEY RULES (X.509, NIST, RFC 8314) ────────────────────
    {
        "rule_id": "RULE-CERT-001",
        "title": "X.509 Certificate Has Expired",
        "severity": "CRITICAL",
        "category": "Certificate",
        "weight": 35.0,
        "default_fix_effort": "Low",
        "description": "The presented server certificate has passed its NotAfter expiration date, causing validation failures and MitM vulnerability.",
        "compliance_refs": ["RFC 5280 Section 4.1.2.5", "RFC 8314 Section 3", "NIST SP 800-52r2 Section 4.1"],
        "remediation": "Renew the TLS certificate immediately using ACME/Certbot or internal PKI.\n\nCertbot:\ncertbot certonly --standalone -d mail.domain.com"
    },
    {
        "rule_id": "RULE-CERT-002",
        "title": "X.509 Certificate Not Yet Valid",
        "severity": "HIGH",
        "category": "Certificate",
        "weight": 20.0,
        "default_fix_effort": "Low",
        "description": "The certificate NotBefore timestamp is in the future, indicating system clock skew or premature deployment.",
        "compliance_refs": ["RFC 5280 Section 4.1.2.5"],
        "remediation": "Check NTP time synchronization on the mail server and verify certificate generation validity timestamps."
    },
    {
        "rule_id": "RULE-CERT-003",
        "title": "Untrusted Self-Signed Certificate Detected",
        "severity": "HIGH",
        "category": "Certificate",
        "weight": 20.0,
        "default_fix_effort": "Low",
        "description": "The server certificate is self-signed (Issuer matches Subject) without a trusted CA chain or DANE TLSA record, allowing transparent active MitM interception.",
        "compliance_refs": ["RFC 8314 Section 3", "NIST SP 800-52r2 Section 4.1"],
        "remediation": "Obtain a publicly trusted certificate from Let's Encrypt or deploy DANE TLSA DNSSEC records (RFC 7672)."
    },
    {
        "rule_id": "RULE-CERT-004",
        "title": "Weak Asymmetric RSA Key Size (< 2048 bits)",
        "severity": "CRITICAL",
        "category": "Certificate",
        "weight": 35.0,
        "default_fix_effort": "Low",
        "description": "The RSA public key length is 512 or 1024 bits. Factoring attacks make keys under 2048 bits breakable by modest compute resources.",
        "compliance_refs": ["NIST SP 800-57 Part 1 Rev 5", "NIST SP 800-52r2 Section 4.1", "PCI-DSS v4.0 Req 4.1"],
        "remediation": "Re-issue certificate with at least 2048-bit RSA (or preferably ECDSA with P-256 / P-384).\n\nOpenSSL:\nopenssl req -newkey rsa:2048 -nodes -keyout /etc/ssl/mail.key"
    },
    {
        "rule_id": "RULE-CERT-005",
        "title": "Certificate Signed with Cryptographically Broken MD5 Algorithm",
        "severity": "CRITICAL",
        "category": "Certificate",
        "weight": 35.0,
        "default_fix_effort": "Low",
        "description": "The certificate signature algorithm is md5WithRSAEncryption. Practical collision attacks allow attackers to forge rogue CA certificates.",
        "compliance_refs": ["RFC 6151", "NIST SP 800-52r2 Section 4.1"],
        "remediation": "Re-issue certificate signed with SHA-256 or SHA-384."
    },
    {
        "rule_id": "RULE-CERT-006",
        "title": "Certificate Signed with Deprecated SHA-1 Algorithm",
        "severity": "HIGH",
        "category": "Certificate",
        "weight": 20.0,
        "default_fix_effort": "Low",
        "description": "The certificate signature algorithm is sha1WithRSAEncryption. SHA-1 has collision attacks (SHAttered) and is rejected by modern TLS clients.",
        "compliance_refs": ["NIST SP 800-52r2 Section 4.1", "CA/Browser Forum Baseline Requirements"],
        "remediation": "Re-generate certificate with SHA-256 (sha256WithRSAEncryption or ecdsa-with-SHA256)."
    },
    {
        "rule_id": "RULE-CERT-007",
        "title": "Certificate Missing Subject Alternative Name (SAN) Extension",
        "severity": "MEDIUM",
        "category": "Certificate",
        "weight": 10.0,
        "default_fix_effort": "Low",
        "description": "Certificate relies solely on legacy Subject CN without SAN extensions (RFC 5280 / RFC 6125), causing validation rejections in modern MUAs.",
        "compliance_refs": ["RFC 6125 Section 6.4.4", "RFC 5280 Section 4.2.1.6"],
        "remediation": "Re-issue certificate including DNS subjectAltName matching all server MX hostnames."
    },
    {
        "rule_id": "RULE-CERT-008",
        "title": "Excessive Certificate Validity Period (> 398 Days)",
        "severity": "LOW",
        "category": "Certificate",
        "weight": 5.0,
        "default_fix_effort": "Low",
        "description": "Certificate validity exceeds the industry standard 398 days limit, increasing the window of exposure for compromised keys.",
        "compliance_refs": ["CA/B Forum Ballot SC22", "Apple / Mozilla Certificate Policies"],
        "remediation": "Configure automated renewal for certificates with validity periods <= 90 to 365 days."
    },
    {
        "rule_id": "RULE-CERT-009",
        "title": "Certificate Nearing Expiration (< 14 Days)",
        "severity": "MEDIUM",
        "category": "Certificate",
        "weight": 10.0,
        "default_fix_effort": "Low",
        "description": "The certificate is valid but expires in less than 14 days, risking an impending service outage and delivery failures.",
        "compliance_refs": ["NIST SP 800-52r2 Section 4.1"],
        "remediation": "Trigger automated certificate renewal immediately."
    },

    # ─── STARTTLS & CLEAR-TEXT EMAIL ATTACK RULES (RFC 8314, RFC 7672) ─────────────
    {
        "rule_id": "RULE-STARTTLS-001",
        "title": "Active STARTTLS Stripping Attack Suspected",
        "severity": "CRITICAL",
        "category": "STARTTLS Protocol",
        "weight": 35.0,
        "default_fix_effort": "Medium",
        "description": "Server advertised STARTTLS capability (250-STARTTLS), but STARTTLS was omitted or dropped in the conversation and plaintext application commands (AUTH/MAIL) followed. Indicates an active adversary in the middle stripping TLS.",
        "compliance_refs": ["RFC 8314 Section 3", "RFC 7672 (DANE)", "RFC 8461 (MTA-STS)"],
        "remediation": "Enforce mandatory TLS on client submission ports (587/465) and deploy MTA-STS / DANE DNSSEC policies for MTA-to-MTA delivery.\n\nPostfix (main.cf):\nsmtpd_tls_security_level = encrypt\nsmtp_tls_security_level = dane\nsmtp_dns_support_level = dnssec"
    },
    {
        "rule_id": "RULE-STARTTLS-002",
        "title": "Cleartext Email Submission Without Encryption",
        "severity": "HIGH",
        "category": "Protocol Security",
        "weight": 20.0,
        "default_fix_effort": "Low",
        "description": "Email submission occurred over plaintext port 25/587 without negotiating TLS encryption. Cleartext submission is considered obsolete per RFC 8314.",
        "compliance_refs": ["RFC 8314 Section 1", "PCI-DSS v4.0 Req 4.1", "HIPAA § 164.312(e)(1)"],
        "remediation": "Require STARTTLS or implicit TLS for all submission clients.\n\nPostfix (master.cf):\nsubmission inet n - y - - smtpd -o smtpd_tls_security_level=encrypt"
    },
    {
        "rule_id": "RULE-AUTH-001",
        "title": "Plaintext Credentials Transmitted Over Unencrypted Channel",
        "severity": "CRITICAL",
        "category": "Authentication",
        "weight": 35.0,
        "default_fix_effort": "Low",
        "description": "User authentication credentials (AUTH PLAIN, AUTH LOGIN base64) were sent in cleartext over an unencrypted TCP stream.",
        "compliance_refs": ["RFC 8314 Section 3", "PCI-DSS v4.0 Req 4.1", "NIST SP 800-52r2"],
        "remediation": "Disable plaintext authentication mechanisms when TLS is not active.\n\nPostfix (main.cf):\nsmtpd_tls_auth_only = yes\n\nDovecot (10-auth.conf):\ndisable_plaintext_auth = yes"
    },
    {
        "rule_id": "RULE-AUTH-002",
        "title": "Cleartext IMAP/POP3 Login Detected",
        "severity": "CRITICAL",
        "category": "Authentication",
        "weight": 35.0,
        "default_fix_effort": "Low",
        "description": "Cleartext IMAP LOGIN or POP3 USER/PASS command executed without TLS wrapping on port 143/110.",
        "compliance_refs": ["RFC 8314 Section 4", "RFC 8314 Section 5"],
        "remediation": "Block non-TLS client access for POP3 and IMAP.\n\nDovecot (10-ssl.conf):\nssl = required\ndisable_plaintext_auth = yes"
    },

    # ─── EXTENSIONS, COMPRESSION & ADVANCED CONFIGURATION ──────────────────────────
    {
        "rule_id": "RULE-CONF-001",
        "title": "Insecure TLS Compression Enabled (CRIME Attack Risk)",
        "severity": "HIGH",
        "category": "Configuration",
        "weight": 20.0,
        "default_fix_effort": "Low",
        "description": "TLS record layer compression is enabled. Attackers observing encrypted traffic length can extract secret session cookies and tokens (CRIME attack).",
        "compliance_refs": ["RFC 7525 Section 3.3", "NIST SP 800-52r2 Section 3.4.1"],
        "remediation": "Disable TLS compression in OpenSSL / Postfix configurations.\n\nOpenSSL/Postfix:\nsmtpd_tls_compression = no"
    },
    {
        "rule_id": "RULE-CONF-002",
        "title": "Missing Extended Master Secret (EMS) Extension",
        "severity": "LOW",
        "category": "Configuration",
        "weight": 5.0,
        "default_fix_effort": "Medium",
        "description": "TLS 1.2 handshake did not include Extended Master Secret (RFC 7627), making it susceptible to Triple Handshake vulnerabilities.",
        "compliance_refs": ["RFC 7627", "NIST SP 800-52r2 Section 3.4.2"],
        "remediation": "Ensure OpenSSL version is >= 1.1.1 and EMS extension negotiation is permitted."
    },
    {
        "rule_id": "RULE-CONF-003",
        "title": "Session Tickets Enabled Without Frequent Key Rotation",
        "severity": "LOW",
        "category": "Configuration",
        "weight": 5.0,
        "default_fix_effort": "Low",
        "description": "TLS Session Tickets (RFC 5077) without STEK rotation can weaken Forward Secrecy across reconnections.",
        "compliance_refs": ["RFC 5077", "RFC 8446"],
        "remediation": "Configure automated session ticket encryption key (STEK) rotation."
    },
    {
        "rule_id": "RULE-CONF-004",
        "title": "Missing Server Name Indication (SNI) in Client Handshake",
        "severity": "INFO",
        "category": "Configuration",
        "weight": 0.0,
        "default_fix_effort": "Low",
        "description": "Client did not provide SNI extension, which can lead to multi-tenant hostname mismatch or default certificate serving.",
        "compliance_refs": ["RFC 6066 Section 3"],
        "remediation": "Enable SNI support in client mail user agent configuration."
    },
    {
        "rule_id": "RULE-CONF-005",
        "title": "Missing ALPN (Application-Layer Protocol Negotiation)",
        "severity": "INFO",
        "category": "Configuration",
        "weight": 0.0,
        "default_fix_effort": "Low",
        "description": "Handshake does not negotiate ALPN tokens (e.g., 'smtp', 'imap', 'pop3').",
        "compliance_refs": ["RFC 7301"],
        "remediation": "Configure modern TLS libraries to advertise standard email ALPN tokens."
    },
    {
        "rule_id": "RULE-COMP-001",
        "title": "Non-Compliance with NIST SP 800-52 Rev 2 Cryptographic Baseline",
        "severity": "HIGH",
        "category": "Compliance Baseline",
        "weight": 20.0,
        "default_fix_effort": "Medium",
        "description": "The TLS configuration violates NIST SP 800-52r2 Section 3 baseline requirements (TLS 1.2+ mandatory, approved AEAD cipher suites, >= 2048-bit RSA/DH).",
        "compliance_refs": ["NIST SP 800-52r2 Section 3", "Federal FISMA Guidelines"],
        "remediation": "Apply hardened NIST SP 800-52r2 configuration profile to mail transfer agents."
    },
    {
        "rule_id": "RULE-COMP-002",
        "title": "Non-Compliance with RFC 8314 Email Encryption Mandate",
        "severity": "HIGH",
        "category": "Compliance Baseline",
        "weight": 20.0,
        "default_fix_effort": "Medium",
        "description": "Cleartext transmission of email submissions or client mailbox access detected, in direct violation of RFC 8314.",
        "compliance_refs": ["RFC 8314 Section 3"],
        "remediation": "Migrate all mail endpoints to implicit TLS (ports 465, 993, 995) or mandatory STARTTLS (port 587)."
    }
]

RULES_BY_ID = {rule["rule_id"]: rule for rule in RULES_DATABASE}
