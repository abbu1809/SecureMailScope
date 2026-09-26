"""
Synthetic PCAP Generator for SecureMailScope.
Generates genuine byte-level PCAP captures containing realistic SMTP/IMAP/POP3
traffic, TLS Handshakes, X.509 DER certificates, and deliberate security vulnerabilities.
"""
import io
import time
import struct
import socket
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Tuple

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

def create_synthetic_cert(
    common_name: str,
    key_size: int = 2048,
    is_expired: bool = False,
    days_valid: int = 90,
    sig_hash: str = "sha256"
) -> bytes:
    """Generates an in-memory DER X.509 certificate for realistic test frames."""
    if not HAS_CRYPTO:
        return b"\x30\x82\x01\x00" + b"\x00" * 200

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Karnataka"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Bengaluru"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MailCorp Security Lab"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now = datetime.now(timezone.utc)
    if is_expired:
        not_before = now - timedelta(days=400)
        not_after = now - timedelta(days=35)
    else:
        not_before = now - timedelta(days=1)
        not_after = now + timedelta(days=days_valid)

    hash_algo = hashes.SHA256()

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name), x509.DNSName(f"mail.{common_name}")]),
            critical=False,
        )
        .sign(private_key, hash_algo, default_backend())
    )
    return cert.public_bytes(serialization.Encoding.DER)


class PCAPWriter:
    """Helper to write standard libpcap binary files (magic 0xa1b2c3d4)."""
    def __init__(self):
        self.buf = io.BytesIO()
        # Global header: magic, v_maj(2), v_min(4), thiszone(0), sigfigs(0), snaplen(65535), linktype(1=Ethernet)
        self.buf.write(struct.pack("!IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))

    def write_packet(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, payload: bytes, ts: float = None):
        ts = ts or time.time()
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1000000)

        # Ethernet Header (14 bytes)
        eth_dst = b"\x00\x0c\x29\x11\x22\x33"
        eth_src = b"\x00\x0c\x29\xaa\xbb\xcc"
        eth_type = 0x0800  # IPv4
        eth_hdr = eth_dst + eth_src + struct.pack("!H", eth_type)

        # IP Header (20 bytes)
        ip_v_ihl = (4 << 4) | 5
        ip_tos = 0
        ip_len = 20 + 20 + len(payload)
        ip_id = 0x1234
        ip_flags_fo = 0x4000  # Don't fragment
        ip_ttl = 64
        ip_proto = 6  # TCP
        ip_csum = 0
        src_ip_bytes = socket.inet_aton(src_ip)
        dst_ip_bytes = socket.inet_aton(dst_ip)
        ip_hdr = struct.pack("!BBHHHBBH4s4s", ip_v_ihl, ip_tos, ip_len, ip_id, ip_flags_fo, ip_ttl, ip_proto, ip_csum, src_ip_bytes, dst_ip_bytes)

        # TCP Header (20 bytes)
        tcp_seq = 1000
        tcp_ack = 2000
        tcp_offset_flags = (5 << 12) | 0x018  # Data offset 5 (20B), PSH+ACK
        tcp_win = 64240
        tcp_csum = 0
        tcp_urg = 0
        tcp_hdr = struct.pack("!HHIIHHHH", src_port, dst_port, tcp_seq, tcp_ack, tcp_offset_flags, tcp_win, tcp_csum, tcp_urg)

        packet_bytes = eth_hdr + ip_hdr + tcp_hdr + payload
        pkt_len = len(packet_bytes)

        # Packet Header (16 bytes): ts_sec, ts_usec, incl_len, orig_len
        pkt_hdr = struct.pack("!IIII", ts_sec, ts_usec, pkt_len, pkt_len)
        self.buf.write(pkt_hdr)
        self.buf.write(packet_bytes)

    def getvalue(self) -> bytes:
        return self.buf.getvalue()


def build_tls_client_hello(ciphers: List[int], sni: str = "mail.corp.internal", legacy_ver: int = 0x0303, extensions: List[int] = None) -> bytes:
    """Builds a real TLS ClientHello record byte stream."""
    extensions = extensions or [0x0000, 0x000a, 0x000b, 0x0017]
    body = io.BytesIO()
    # Client Version
    body.write(struct.pack("!H", legacy_ver))
    # Random (32 bytes)
    body.write(b"\xaa" * 32)
    # Session ID length 0
    body.write(b"\x00")
    # Cipher suites
    body.write(struct.pack("!H", len(ciphers) * 2))
    for c in ciphers:
        body.write(struct.pack("!H", c))
    # Compression (0 = None)
    body.write(b"\x01\x00")

    # Extensions
    ext_buf = io.BytesIO()
    for ext in extensions:
        if ext == 0x0000:  # SNI
            sni_b = sni.encode('utf-8')
            sni_data = struct.pack("!HB", len(sni_b) + 3, 0) + struct.pack("!H", len(sni_b)) + sni_b
            ext_buf.write(struct.pack("!HH", 0x0000, len(sni_data)))
            ext_buf.write(sni_data)
        elif ext == 0x000a:  # Elliptic Curves
            curves_data = struct.pack("!HHHH", 6, 0x001d, 0x0017, 0x0018)  # X25519, secp256r1, secp384r1
            ext_buf.write(struct.pack("!HH", 0x000a, len(curves_data)))
            ext_buf.write(curves_data)
        elif ext == 0x000b:  # EC point formats
            ec_data = b"\x01\x00"  # uncompressed
            ext_buf.write(struct.pack("!HH", 0x000b, len(ec_data)))
            ext_buf.write(ec_data)
        elif ext == 0x0017:  # Extended Master Secret
            ext_buf.write(struct.pack("!HH", 0x0017, 0))

    ext_bytes = ext_buf.getvalue()
    body.write(struct.pack("!H", len(ext_bytes)))
    body.write(ext_bytes)

    ch_body = body.getvalue()
    # Handshake type 0x01 (ClientHello) + 3-byte length
    hs_hdr = bytes([0x01, (len(ch_body) >> 16) & 0xFF, (len(ch_body) >> 8) & 0xFF, len(ch_body) & 0xFF]) + ch_body

    # TLS Record Header (ContentType 0x16 = Handshake, Version, Length)
    rec_hdr = struct.pack("!BBBH", 0x16, (legacy_ver >> 8) & 0xFF, legacy_ver & 0xFF, len(hs_hdr))
    return rec_hdr + hs_hdr


def build_tls_server_hello(cipher: int, version: int = 0x0303, cert_der: bytes = None) -> bytes:
    """Builds a real TLS ServerHello and Certificate record byte stream."""
    body = io.BytesIO()
    # Server Version
    body.write(struct.pack("!H", version))
    # Random (32 bytes)
    body.write(b"\xbb" * 32)
    # Session ID length 0
    body.write(b"\x00")
    # Cipher suite
    body.write(struct.pack("!H", cipher))
    # Compression (0)
    body.write(b"\x00")

    # Extensions (e.g. if TLS 1.3 negotiated)
    ext_buf = io.BytesIO()
    if version == 0x0304:
        ext_buf.write(struct.pack("!HHH", 0x002b, 2, 0x0304))
    ext_b = ext_buf.getvalue()
    if ext_b:
        body.write(struct.pack("!H", len(ext_b)))
        body.write(ext_b)

    sh_body = body.getvalue()
    hs_hdr = bytes([0x02, (len(sh_body) >> 16) & 0xFF, (len(sh_body) >> 8) & 0xFF, len(sh_body) & 0xFF]) + sh_body
    rec_hello = struct.pack("!BBBH", 0x16, (version >> 8) & 0xFF, version & 0xFF, len(hs_hdr)) + hs_hdr

    if cert_der and version != 0x0304:
        # Build Certificate Handshake message (0x0b)
        cert_len = len(cert_der)
        total_len = cert_len + 3
        cert_msg_body = bytes([
            (total_len >> 16) & 0xFF, (total_len >> 8) & 0xFF, total_len & 0xFF,
            (cert_len >> 16) & 0xFF, (cert_len >> 8) & 0xFF, cert_len & 0xFF
        ]) + cert_der
        cert_hs = bytes([0x0b, (len(cert_msg_body) >> 16) & 0xFF, (len(cert_msg_body) >> 8) & 0xFF, len(cert_msg_body) & 0xFF]) + cert_msg_body
        rec_cert = struct.pack("!BBBH", 0x16, (version >> 8) & 0xFF, version & 0xFF, len(cert_hs)) + cert_hs
        return rec_hello + rec_cert

    return rec_hello


def generate_all_synthetic_pcaps() -> Dict[str, Tuple[bytes, str]]:
    """
    Builds the complete suite of 8 realistic synthetic PCAPs for testing & demonstration.
    Returns dict: { filename: (pcap_bytes, description) }
    """
    now_ts = time.time()
    results = {}

    # ──────────────────────────────────────────────────────────────────────────
    # 1. STARTTLS Stripping Attack
    # ──────────────────────────────────────────────────────────────────────────
    pw1 = PCAPWriter()
    pw1.write_packet("192.168.10.15", 25, "10.0.0.5", 54321, b"220 mail.defense-hub.gov ESMTP Postfix\r\n", now_ts)
    pw1.write_packet("10.0.0.5", 54321, "192.168.10.15", 25, b"EHLO analyst-workstation.lan\r\n", now_ts + 0.05)
    # Server advertises STARTTLS capability
    pw1.write_packet("192.168.10.15", 25, "10.0.0.5", 54321, b"250-mail.defense-hub.gov\r\n250-PIPELINING\r\n250-SIZE 10485760\r\n250-STARTTLS\r\n250-AUTH LOGIN PLAIN\r\n250 8BITMIME\r\n", now_ts + 0.1)
    # Attacker intercepted/stripped STARTTLS: client sends cleartext AUTH and MAIL FROM directly
    pw1.write_packet("10.0.0.5", 54321, "192.168.10.15", 25, b"AUTH LOGIN\r\n", now_ts + 0.2)
    pw1.write_packet("192.168.10.15", 25, "10.0.0.5", 54321, b"334 VXNlcm5hbWU6\r\n", now_ts + 0.25)
    pw1.write_packet("10.0.0.5", 54321, "192.168.10.15", 25, b"YWRtaW5AZGVmZW5zZS1odWIuZ292\r\n", now_ts + 0.3)
    pw1.write_packet("192.168.10.15", 25, "10.0.0.5", 54321, b"334 UGFzc3dvcmQ6\r\n", now_ts + 0.35)
    pw1.write_packet("10.0.0.5", 54321, "192.168.10.15", 25, b"U3VwZXJTZWNyZXRQYXNzMjAyNiE=\r\n", now_ts + 0.4)
    pw1.write_packet("192.168.10.15", 25, "10.0.0.5", 54321, b"235 2.7.0 Authentication successful\r\n", now_ts + 0.45)
    pw1.write_packet("10.0.0.5", 54321, "192.168.10.15", 25, b"MAIL FROM: <commander@defense-hub.gov>\r\n", now_ts + 0.5)
    pw1.write_packet("192.168.10.15", 25, "10.0.0.5", 54321, b"250 2.1.0 Ok\r\n", now_ts + 0.55)
    results["starttls_stripping_attack.pcap"] = (
        pw1.getvalue(),
        "Active MitM adversary stripped STARTTLS capability from SMTP session, capturing cleartext credentials."
    )

    # ──────────────────────────────────────────────────────────────────────────
    # 2. Legacy SSLv3 with RC4 Stream Cipher
    # ──────────────────────────────────────────────────────────────────────────
    pw2 = PCAPWriter()
    cert2 = create_synthetic_cert("legacy-mail.org", key_size=1024, is_expired=False)
    pw2.write_packet("172.16.5.1", 465, "10.1.1.20", 51200, b"220 legacy-mail.org ESMTP\r\n", now_ts)
    ch2 = build_tls_client_hello([0x0004, 0x0005, 0x000a], sni="legacy-mail.org", legacy_ver=0x0300)
    pw2.write_packet("10.1.1.20", 51200, "172.16.5.1", 465, ch2, now_ts + 0.1)
    sh2 = build_tls_server_hello(0x0004, version=0x0300, cert_der=cert2)  # SSL 3.0 + TLS_RSA_WITH_RC4_128_MD5
    pw2.write_packet("172.16.5.1", 465, "10.1.1.20", 51200, sh2, now_ts + 0.2)
    results["legacy_sslv3_rc4_mail.pcap"] = (
        pw2.getvalue(),
        "Deprecated SSL 3.0 session negotiating broken RC4-MD5 cipher suite with 1024-bit RSA key."
    )

    # ──────────────────────────────────────────────────────────────────────────
    # 3. Expired & Weak RSA 1024-bit SHA-1 Certificate (IMAP)
    # ──────────────────────────────────────────────────────────────────────────
    pw3 = PCAPWriter()
    cert3 = create_synthetic_cert("imap.insecure-corp.com", key_size=1024, is_expired=True, sig_hash="sha1")
    pw3.write_packet("192.168.2.50", 993, "10.2.2.14", 48100, b"* OK [CAPABILITY IMAP4rev1 SASL-IR] Dovecot ready.\r\n", now_ts)
    ch3 = build_tls_client_hello([0x002f, 0x0035], sni="imap.insecure-corp.com", legacy_ver=0x0303)
    pw3.write_packet("10.2.2.14", 48100, "192.168.2.50", 993, ch3, now_ts + 0.1)
    sh3 = build_tls_server_hello(0x002f, version=0x0303, cert_der=cert3)  # TLS 1.2 + TLS_RSA_WITH_AES_128_CBC_SHA
    pw3.write_packet("192.168.2.50", 993, "10.2.2.14", 48100, sh3, now_ts + 0.2)
    results["expired_weak_rsa1024_cert.pcap"] = (
        pw3.getvalue(),
        "IMAPS session using expired X.509 certificate signed with SHA-1 and weak 1024-bit RSA key."
    )

    # ──────────────────────────────────────────────────────────────────────────
    # 4. Plaintext SMTP Credentials Leak (Port 25)
    # ──────────────────────────────────────────────────────────────────────────
    pw4 = PCAPWriter()
    pw4.write_packet("10.20.30.40", 25, "192.168.1.100", 55210, b"220 relay.legacy-relay.net ESMTP\r\n", now_ts)
    pw4.write_packet("192.168.1.100", 55210, "10.20.30.40", 25, b"EHLO office-pc.local\r\n", now_ts + 0.05)
    pw4.write_packet("10.20.30.40", 25, "192.168.1.100", 55210, b"250-relay.legacy-relay.net\r\n250-AUTH LOGIN\r\n250 HELP\r\n", now_ts + 0.1)
    pw4.write_packet("192.168.1.100", 55210, "10.20.30.40", 25, b"AUTH PLAIN dXNlcjFAZXhhbXBsZS5jb20AdXNlcjEAcGFzc3dvcmQxMjM=\r\n", now_ts + 0.2)
    pw4.write_packet("10.20.30.40", 25, "192.168.1.100", 55210, b"235 2.7.0 Authentication successful\r\n", now_ts + 0.25)
    results["plaintext_smtp_credentials_leak.pcap"] = (
        pw4.getvalue(),
        "Cleartext SMTP submission on port 25 without TLS; AUTH PLAIN credentials leaked in cleartext."
    )

    # ──────────────────────────────────────────────────────────────────────────
    # 5. Modern Hardened TLS 1.3 Mail Session
    # ──────────────────────────────────────────────────────────────────────────
    pw5 = PCAPWriter()
    pw5.write_packet("10.50.0.1", 465, "172.20.10.5", 58800, b"220 mail.cyber-command.gov ESMTP Postfix\r\n", now_ts)
    ch5 = build_tls_client_hello([0x1301, 0x1302, 0x1303, 0xc02f, 0xc030], sni="mail.cyber-command.gov", legacy_ver=0x0303)
    pw5.write_packet("172.20.10.5", 58800, "10.50.0.1", 465, ch5, now_ts + 0.05)
    sh5 = build_tls_server_hello(0x1301, version=0x0304)  # TLS 1.3 + TLS_AES_128_GCM_SHA256 (Observable: False cert)
    pw5.write_packet("10.50.0.1", 465, "172.20.10.5", 58800, sh5, now_ts + 0.1)
    results["modern_hardened_tls13_mail.pcap"] = (
        pw5.getvalue(),
        "Fully hardened TLS 1.3 submission with AES-128-GCM and encrypted handshake cert metadata."
    )

    # ──────────────────────────────────────────────────────────────────────────
    # 6. Anomalous JA3 Malicious / Rare Mailer
    # ──────────────────────────────────────────────────────────────────────────
    pw6 = PCAPWriter()
    cert6 = create_synthetic_cert("suspicious-mta.net", key_size=2048, is_expired=False)
    # Uncommon cipher order and rare extension hash to trigger Isolation Forest
    ch6 = build_tls_client_hello([0xc014, 0x009c, 0x0035], sni="suspicious-mta.net", extensions=[0x0000, 0x0017, 0x000a, 0x0023, 0x0015])
    pw6.write_packet("198.51.100.22", 587, "203.0.113.88", 62100, b"220 suspicious-mta.net ESMTP\r\n", now_ts)
    pw6.write_packet("203.0.113.88", 62100, "198.51.100.22", 587, ch6, now_ts + 0.05)
    sh6 = build_tls_server_hello(0xc014, version=0x0303, cert_der=cert6)
    pw6.write_packet("198.51.100.22", 587, "203.0.113.88", 62100, sh6, now_ts + 0.1)
    results["anomalous_ja3_malicious_mailer.pcap"] = (
        pw6.getvalue(),
        "Anomalous JA3 client fingerprint and rare TLS extension permutation detected by Isolation Forest AI."
    )

    # ──────────────────────────────────────────────────────────────────────────
    # 7. TLS 1.0 Sweet32 3DES Session
    # ──────────────────────────────────────────────────────────────────────────
    pw7 = PCAPWriter()
    cert7 = create_synthetic_cert("old-exchange.local", key_size=2048, is_expired=False)
    pw7.write_packet("10.88.1.1", 465, "10.88.2.200", 53300, b"220 old-exchange.local Microsoft ESMTP MAIL Service\r\n", now_ts)
    ch7 = build_tls_client_hello([0x000a, 0x0016, 0xc012], sni="old-exchange.local", legacy_ver=0x0301)
    pw7.write_packet("10.88.2.200", 53300, "10.88.1.1", 465, ch7, now_ts + 0.05)
    sh7 = build_tls_server_hello(0x000a, version=0x0301, cert_der=cert7)  # TLS 1.0 + TLS_RSA_WITH_3DES_EDE_CBC_SHA
    pw7.write_packet("10.88.1.1", 465, "10.88.2.200", 53300, sh7, now_ts + 0.1)
    results["tls10_sweet32_des_session.pcap"] = (
        pw7.getvalue(),
        "TLS 1.0 session negotiating 3DES cipher vulnerable to SWEET32 block collision attack."
    )

    # ──────────────────────────────────────────────────────────────────────────
    # 8. Enterprise Mixed Traffic Capture (Comprehensive SOC Simulation)
    # ──────────────────────────────────────────────────────────────────────────
    pw8 = PCAPWriter()
    # 8.1 Critical Stripping
    pw8.write_packet("10.10.1.5", 25, "10.200.1.1", 41001, b"220 mail1.corp.lan ESMTP\r\n250-STARTTLS\r\n", now_ts)
    pw8.write_packet("10.200.1.1", 41001, "10.10.1.5", 25, b"AUTH LOGIN\r\n", now_ts + 0.02)
    # 8.2 Hardened TLS 1.3
    ch8_1 = build_tls_client_hello([0x1301, 0x1302], sni="smtp-gateway.corp.lan")
    sh8_1 = build_tls_server_hello(0x1301, version=0x0304)
    pw8.write_packet("10.200.1.2", 41002, "10.10.1.6", 465, ch8_1, now_ts + 0.05)
    pw8.write_packet("10.10.1.6", 465, "10.200.1.2", 41002, sh8_1, now_ts + 0.08)
    # 8.3 Expired Cert IMAP
    cert8_exp = create_synthetic_cert("imap-archive.corp.lan", key_size=2048, is_expired=True)
    ch8_2 = build_tls_client_hello([0xc02f, 0xc030], sni="imap-archive.corp.lan")
    sh8_2 = build_tls_server_hello(0xc02f, version=0x0303, cert_der=cert8_exp)
    pw8.write_packet("10.200.1.3", 41003, "10.10.1.7", 993, ch8_2, now_ts + 0.12)
    pw8.write_packet("10.10.1.7", 993, "10.200.1.3", 41003, sh8_2, now_ts + 0.15)
    # 8.4 Deprecated TLS 1.0 with 3DES
    cert8_des = create_synthetic_cert("legacy-mail.corp.lan", key_size=1024, is_expired=False)
    ch8_3 = build_tls_client_hello([0x000a], sni="legacy-mail.corp.lan", legacy_ver=0x0301)
    sh8_3 = build_tls_server_hello(0x000a, version=0x0301, cert_der=cert8_des)
    pw8.write_packet("10.200.1.4", 41004, "10.10.1.8", 587, ch8_3, now_ts + 0.18)
    pw8.write_packet("10.10.1.8", 587, "10.200.1.4", 41004, sh8_3, now_ts + 0.22)
    # 8.5 Clean Modern TLS 1.2 ECDHE-GCM
    cert8_clean = create_synthetic_cert("secure-imap.corp.lan", key_size=2048, is_expired=False, days_valid=120)
    ch8_4 = build_tls_client_hello([0xc02f, 0xc030], sni="secure-imap.corp.lan", legacy_ver=0x0303)
    sh8_4 = build_tls_server_hello(0xc02f, version=0x0303, cert_der=cert8_clean)
    pw8.write_packet("10.200.1.5", 41005, "10.10.1.9", 993, ch8_4, now_ts + 0.25)
    pw8.write_packet("10.10.1.9", 993, "10.200.1.5", 41005, sh8_4, now_ts + 0.28)

    results["enterprise_mixed_traffic_500mb_sim.pcap"] = (
        pw8.getvalue(),
        "Realistic corporate network capture featuring mixed modern TLS 1.3, STARTTLS stripping, expired certs, and legacy 3DES."
    )

    return results
