"""
TLS Handshake Parser, Record Extractor, and JA3 / JA3S Fingerprinter.
Fully supports SSL 3.0, TLS 1.0, 1.1, 1.2, and TLS 1.3 (with explicit observable: false).
"""
import struct
import hashlib
from typing import Dict, List, Optional, Tuple, Any

# Map of standard TLS Cipher Suite IDs to names
CIPHER_SUITE_MAP = {
    0x0000: "TLS_NULL_WITH_NULL_NULL",
    0x0001: "TLS_RSA_WITH_NULL_MD5",
    0x0002: "TLS_RSA_WITH_NULL_SHA",
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x0008: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
    0x0009: "TLS_RSA_WITH_DES_CBC_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0013: "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
    0x0015: "TLS_DHE_RSA_WITH_DES_CBC_SHA",
    0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0xC011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    # TLS 1.3 Cipher Suites
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
}

VERSION_MAP = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
    0x0200: "SSL 2.0"
}

# GREASE values to filter out from JA3
GREASE_VALUES = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
}

class TLSParser:
    """
    Byte-level parser for TLS Handshake records and JA3 / JA3S fingerprint generator.
    """

    @classmethod
    def parse_stream(cls, client_data: bytes, server_data: bytes) -> Dict[str, Any]:
        """
        Parses combined client and server bytes for TLS records.
        Returns a comprehensive TLS summary dictionary.
        """
        result = {
            "has_tls": False,
            "negotiated_version": None,
            "client_offered_versions": [],
            "negotiated_cipher": None,
            "client_offered_ciphers": [],
            "key_exchange": None,
            "sni": None,
            "alpn": None,
            "ja3": None,
            "ja3_string": None,
            "ja3s": None,
            "ja3s_string": None,
            "has_extended_master_secret": False,
            "is_tls13": False,
            "handshake_encrypted": False,
            "raw_certificates": []
        }

        # Parse ClientHello from client stream (or server stream if reversed)
        client_hello = cls._find_and_parse_client_hello(client_data) or cls._find_and_parse_client_hello(server_data)
        if client_hello:
            result["has_tls"] = True
            result["client_offered_versions"] = client_hello.get("supported_versions", [])
            result["client_offered_ciphers"] = client_hello.get("ciphers", [])
            result["sni"] = client_hello.get("sni")
            result["ja3"] = client_hello.get("ja3")
            result["ja3_string"] = client_hello.get("ja3_string")
            result["has_extended_master_secret"] = client_hello.get("has_ems", False)

        # Parse ServerHello and Certificate from server stream (or client stream if reversed)
        server_hello = cls._find_and_parse_server_hello(server_data) or cls._find_and_parse_server_hello(client_data)
        if server_hello:
            result["has_tls"] = True
            result["negotiated_version"] = server_hello.get("version")
            result["negotiated_cipher"] = server_hello.get("cipher")
            result["alpn"] = server_hello.get("alpn")
            result["ja3s"] = server_hello.get("ja3s")
            result["ja3s_string"] = server_hello.get("ja3s_string")
            result["is_tls13"] = (server_hello.get("version") == "TLS 1.3")
            if result["is_tls13"]:
                result["handshake_encrypted"] = True

            # Determine key exchange from cipher name
            cipher_name = result["negotiated_cipher"] or ""
            if "ECDHE" in cipher_name or result["is_tls13"]:
                result["key_exchange"] = "ECDHE"
            elif "DHE" in cipher_name:
                result["key_exchange"] = "DHE"
            elif "RSA" in cipher_name:
                result["key_exchange"] = "RSA (Static)"

        # Parse Certificates from server stream (or client stream)
        certs = cls._extract_certificates(server_data) or cls._extract_certificates(client_data)
        result["raw_certificates"] = certs

        return result

    @classmethod
    def _find_and_parse_client_hello(cls, data: bytes) -> Optional[Dict[str, Any]]:
        offset = 0
        while offset + 5 <= len(data):
            content_type, rec_ver_maj, rec_ver_min, rec_len = struct.unpack("!BBBH", data[offset:offset+5])
            if content_type == 0x16:  # Handshake
                rec_payload = data[offset+5 : offset+5+rec_len]
                if len(rec_payload) >= 4:
                    hs_type = rec_payload[0]
                    if hs_type == 0x01:  # ClientHello
                        return cls._parse_client_hello_payload(rec_payload)
                offset += 5 + rec_len
            else:
                offset += 1
        return None

    @classmethod
    def _parse_client_hello_payload(cls, payload: bytes) -> Dict[str, Any]:
        result = {
            "ciphers": [],
            "supported_versions": [],
            "sni": None,
            "ja3": None,
            "ja3_string": None,
            "has_ems": False
        }
        try:
            # Skip Handshake Type (1) + Length (3)
            ptr = 4
            version_raw = struct.unpack("!H", payload[ptr:ptr+2])[0]
            ptr += 2 + 32  # Skip Version + Random (32)
            
            # Session ID
            sess_id_len = payload[ptr]
            ptr += 1 + sess_id_len

            # Cipher Suites
            cs_len = struct.unpack("!H", payload[ptr:ptr+2])[0]
            ptr += 2
            cipher_list = []
            cipher_names = []
            for i in range(0, cs_len, 2):
                cs_val = struct.unpack("!H", payload[ptr+i:ptr+i+2])[0]
                if cs_val not in GREASE_VALUES:
                    cipher_list.append(cs_val)
                    cipher_names.append(CIPHER_SUITE_MAP.get(cs_val, f"UNKNOWN_CIPHER_0x{cs_val:04X}"))
            ptr += cs_len
            result["ciphers"] = cipher_names

            # Compression Methods
            comp_len = payload[ptr]
            ptr += 1 + comp_len

            # Extensions
            extensions = []
            elliptic_curves = []
            ec_point_formats = []
            supported_versions = []

            if ptr + 2 <= len(payload):
                ext_total_len = struct.unpack("!H", payload[ptr:ptr+2])[0]
                ptr += 2
                ext_end = ptr + ext_total_len

                while ptr + 4 <= ext_end and ptr + 4 <= len(payload):
                    ext_type, ext_len = struct.unpack("!HH", payload[ptr:ptr+4])
                    ptr += 4
                    ext_data = payload[ptr:ptr+ext_len]

                    if ext_type not in GREASE_VALUES:
                        extensions.append(ext_type)

                    # SNI (0)
                    if ext_type == 0x0000 and len(ext_data) > 5:
                        try:
                            # server_name_list_length (2), name_type (1), name_length (2)
                            sni_len = struct.unpack("!H", ext_data[3:5])[0]
                            result["sni"] = ext_data[5:5+sni_len].decode('utf-8', errors='ignore')
                        except Exception:
                            pass

                    # Supported Elliptic Curves (10)
                    elif ext_type == 0x000a and len(ext_data) >= 2:
                        curves_len = struct.unpack("!H", ext_data[0:2])[0]
                        for c_i in range(2, min(2 + curves_len, len(ext_data)), 2):
                            curve_val = struct.unpack("!H", ext_data[c_i:c_i+2])[0]
                            if curve_val not in GREASE_VALUES:
                                elliptic_curves.append(curve_val)

                    # EC Point Formats (11)
                    elif ext_type == 0x000b and len(ext_data) >= 1:
                        point_len = ext_data[0]
                        for p_i in range(1, 1 + point_len):
                            if p_i < len(ext_data):
                                ec_point_formats.append(ext_data[p_i])

                    # Extended Master Secret (23)
                    elif ext_type == 0x0017:
                        result["has_ems"] = True

                    # Supported Versions extension (43)
                    elif ext_type == 0x002b and len(ext_data) >= 1:
                        sv_len = ext_data[0]
                        for sv_i in range(1, min(1 + sv_len, len(ext_data)), 2):
                            sv_val = struct.unpack("!H", ext_data[sv_i:sv_i+2])[0]
                            if sv_val not in GREASE_VALUES and sv_val in VERSION_MAP:
                                supported_versions.append(VERSION_MAP[sv_val])

                    ptr += ext_len

            if not supported_versions:
                supported_versions.append(VERSION_MAP.get(version_raw, f"0x{version_raw:04X}"))
            result["supported_versions"] = supported_versions

            # Compute standard JA3 string
            ja3_str = f"{version_raw}," + \
                      f"{'-'.join(str(x) for x in cipher_list)}," + \
                      f"{'-'.join(str(x) for x in extensions)}," + \
                      f"{'-'.join(str(x) for x in elliptic_curves)}," + \
                      f"{'-'.join(str(x) for x in ec_point_formats)}"
            
            result["ja3_string"] = ja3_str
            result["ja3"] = hashlib.md5(ja3_str.encode('utf-8')).hexdigest()

        except Exception as e:
            pass

        return result

    @classmethod
    def _find_and_parse_server_hello(cls, data: bytes) -> Optional[Dict[str, Any]]:
        offset = 0
        while offset + 5 <= len(data):
            content_type, rec_ver_maj, rec_ver_min, rec_len = struct.unpack("!BBBH", data[offset:offset+5])
            if content_type == 0x16:  # Handshake
                rec_payload = data[offset+5 : offset+5+rec_len]
                if len(rec_payload) >= 4:
                    hs_type = rec_payload[0]
                    if hs_type == 0x02:  # ServerHello
                        return cls._parse_server_hello_payload(rec_payload)
                offset += 5 + rec_len
            else:
                offset += 1
        return None

    @classmethod
    def _parse_server_hello_payload(cls, payload: bytes) -> Dict[str, Any]:
        result = {
            "version": "TLS 1.2",
            "cipher": None,
            "alpn": None,
            "ja3s": None,
            "ja3s_string": None
        }
        try:
            ptr = 4
            version_raw = struct.unpack("!H", payload[ptr:ptr+2])[0]
            result["version"] = VERSION_MAP.get(version_raw, "TLS 1.2")
            ptr += 2 + 32  # Skip Version + Random (32)

            # Session ID
            sess_id_len = payload[ptr]
            ptr += 1 + sess_id_len

            # Negotiated Cipher Suite
            cs_val = struct.unpack("!H", payload[ptr:ptr+2])[0]
            ptr += 2
            result["cipher"] = CIPHER_SUITE_MAP.get(cs_val, f"UNKNOWN_CIPHER_0x{cs_val:04X}")

            # Compression
            ptr += 1

            # Extensions
            extensions = []
            if ptr + 2 <= len(payload):
                ext_total_len = struct.unpack("!H", payload[ptr:ptr+2])[0]
                ptr += 2
                ext_end = ptr + ext_total_len
                while ptr + 4 <= ext_end and ptr + 4 <= len(payload):
                    ext_type, ext_len = struct.unpack("!HH", payload[ptr:ptr+4])
                    ptr += 4
                    ext_data = payload[ptr:ptr+ext_len]
                    if ext_type not in GREASE_VALUES:
                        extensions.append(ext_type)

                    # Supported Versions extension for TLS 1.3
                    if ext_type == 0x002b and len(ext_data) >= 2:
                        sel_ver = struct.unpack("!H", ext_data[0:2])[0]
                        if sel_ver == 0x0304:
                            result["version"] = "TLS 1.3"

                    # ALPN
                    elif ext_type == 0x0010 and len(ext_data) >= 3:
                        try:
                            # alpn_list_len (2), str_len (1)
                            alpn_str_len = ext_data[2]
                            result["alpn"] = ext_data[3:3+alpn_str_len].decode('latin1', errors='ignore')
                        except Exception:
                            pass

                    ptr += ext_len

            # JA3S Calculation
            ja3s_str = f"{version_raw},{cs_val},{'-'.join(str(x) for x in extensions)}"
            result["ja3s_string"] = ja3s_str
            result["ja3s"] = hashlib.md5(ja3s_str.encode('utf-8')).hexdigest()

        except Exception:
            pass

        return result

    @classmethod
    def _extract_certificates(cls, data: bytes) -> List[bytes]:
        """
        Extracts raw DER encoded X.509 certificate byte blobs from Server Handshake.
        """
        certs = []
        offset = 0
        while offset + 5 <= len(data):
            content_type, maj, min_, rec_len = struct.unpack("!BBBH", data[offset:offset+5])
            if content_type == 0x16:  # Handshake
                rec_payload = data[offset+5 : offset+5+rec_len]
                if len(rec_payload) >= 4 and rec_payload[0] == 0x0b:  # Certificate type
                    try:
                        # Skip type (1) + len (3) + total certs len (3)
                        ptr = 7
                        while ptr + 3 < len(rec_payload):
                            # 3-byte cert length
                            c_len = (rec_payload[ptr] << 16) | (rec_payload[ptr+1] << 8) | rec_payload[ptr+2]
                            ptr += 3
                            if ptr + c_len <= len(rec_payload):
                                cert_der = rec_payload[ptr:ptr+c_len]
                                certs.append(cert_der)
                                ptr += c_len
                            else:
                                break
                    except Exception:
                        pass
                offset += 5 + rec_len
            else:
                offset += 1
        return certs
