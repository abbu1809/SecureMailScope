"""
Protocol Classifier and STARTTLS State Machine Tracker.
Identifies SMTP, IMAP, POP3 protocols and tracks STARTTLS negotiation states.
"""
import re
from typing import List, Dict, Tuple, Optional

class ProtocolClassifier:
    """
    Classifies mail application protocols from banners, ports, and commands,
    and tracks STARTTLS state transitions.
    """

    SMTP_PORTS = {25, 587, 465, 2525}
    IMAP_PORTS = {143, 993}
    POP3_PORTS = {110, 995}
    IMPLICIT_TLS_PORTS = {465, 993, 995}

    @classmethod
    def classify(cls, src_port: int, dst_port: int, payloads: List[bytes]) -> Tuple[str, Optional[str]]:
        """
        Classifies protocol based on port + banner content.
        Returns (protocol_name, banner_string).
        """
        banner_str = None
        for p in payloads:
            if not p:
                continue
            text = p.decode('latin1', errors='ignore')
            # Look for common mail banners
            if text.startswith("220") or "ESMTP" in text or "SMTP" in text:
                banner_str = text.splitlines()[0] if text.splitlines() else text[:80]
                return "SMTP", banner_str
            if text.startswith("* OK") or "IMAP" in text:
                banner_str = text.splitlines()[0] if text.splitlines() else text[:80]
                return "IMAP", banner_str
            if text.startswith("+OK") or "POP3" in text:
                banner_str = text.splitlines()[0] if text.splitlines() else text[:80]
                return "POP3", banner_str

        # Fallback to port inspection
        port_pair = {src_port, dst_port}
        if port_pair & cls.SMTP_PORTS:
            return "SMTP", banner_str
        if port_pair & cls.IMAP_PORTS:
            return "IMAP", banner_str
        if port_pair & cls.POP3_PORTS:
            return "POP3", banner_str

        return "Other", banner_str

    @classmethod
    def track_starttls_and_commands(
        cls,
        protocol: str,
        src_port: int,
        dst_port: int,
        client_payloads: List[bytes],
        server_payloads: List[bytes],
        has_tls_handshake: bool
    ) -> Tuple[str, List[str], bool]:
        """
        Tracks STARTTLS state machine and extracts observed commands.
        Returns: (starttls_state, commands_observed, plaintext_credentials_detected)
        
        States:
        - NOT_APPLICABLE (Direct TLS ports like 465, 993, 995)
        - OFFERED (Server announced STARTTLS capability)
        - REQUESTED (Client requested STARTTLS)
        - COMPLETED (STARTTLS accepted and TLS handshake occurred)
        - STRIPPING_SUSPECTED (STARTTLS capability stripped or aborted, plaintext mail/auth follows)
        """
        if src_port in cls.IMPLICIT_TLS_PORTS or dst_port in cls.IMPLICIT_TLS_PORTS:
            return "NOT_APPLICABLE", [], False

        starttls_offered = False
        starttls_requested = False
        plaintext_creds = False
        commands: List[str] = []

        # Analyze Server payloads for STARTTLS advertisement
        for sp in server_payloads:
            text = sp.decode('latin1', errors='ignore')
            if "250-STARTTLS" in text or "250 STARTTLS" in text:
                starttls_offered = True
            if "STARTTLS" in text and ("CAPABILITY" in text or "* OK" in text or "+OK" in text):
                starttls_offered = True

        # Analyze Client payloads for commands
        for cp in client_payloads:
            text = cp.decode('latin1', errors='ignore')
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                cmd_upper = line.upper()
                if cmd_upper.startswith("EHLO") or cmd_upper.startswith("HELO"):
                    commands.append(line[:40])
                elif cmd_upper.startswith("STARTTLS"):
                    starttls_requested = True
                    commands.append("STARTTLS")
                elif cmd_upper.startswith("AUTH"):
                    commands.append("AUTH [PROTECTED]")
                    if not has_tls_handshake:
                        plaintext_creds = True
                elif cmd_upper.startswith("MAIL FROM:"):
                    commands.append("MAIL FROM: <...>")
                elif cmd_upper.startswith("RCPT TO:"):
                    commands.append("RCPT TO: <...>")
                elif cmd_upper.startswith("DATA"):
                    commands.append("DATA")
                elif cmd_upper.startswith("LOGIN ") or " LOGIN " in cmd_upper:
                    commands.append("LOGIN [PROTECTED]")
                    if not has_tls_handshake:
                        plaintext_creds = True
                elif cmd_upper.startswith("USER ") or cmd_upper.startswith("PASS "):
                    commands.append(line.split()[0] + " [PROTECTED]")
                    if not has_tls_handshake:
                        plaintext_creds = True

        # State determination
        if has_tls_handshake:
            if starttls_requested or starttls_offered:
                state = "COMPLETED"
            else:
                state = "COMPLETED"
        elif starttls_offered and not starttls_requested and any(c.startswith("MAIL") or c.startswith("AUTH") for c in commands):
            # STARTTLS offered by server, but client skipped and sent unencrypted MAIL/AUTH -> Stripping suspected
            state = "STRIPPING_SUSPECTED"
        elif starttls_requested and not has_tls_handshake:
            # Client asked for STARTTLS, but handshake never completed and plaintext continued -> Stripping suspected
            state = "STRIPPING_SUSPECTED"
        elif starttls_offered:
            state = "OFFERED"
        elif starttls_requested:
            state = "REQUESTED"
        else:
            state = "OFFERED" if protocol in ["SMTP", "IMAP", "POP3"] else "NOT_APPLICABLE"

        return state, commands, plaintext_creds
