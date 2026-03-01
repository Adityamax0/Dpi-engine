"""
========================================================
  sni_extractor.py — TLS SNI & HTTP Host Extractor
  Author   : Aditya Pandey
  Project  : DPI Engine (Deep Packet Inspection)
========================================================

What is SNI?
    SNI (Server Name Indication) is a TLS extension.
    When your browser connects to https://youtube.com,
    the FIRST packet it sends (Client Hello) contains
    the domain name in PLAINTEXT — before encryption starts.

    This is the key insight that makes DPI possible:
    even encrypted HTTPS traffic reveals WHAT you're
    connecting to, just not the content.

    Client Hello Structure (simplified):
    ┌─────────────────────────────────────────────┐
    │ TLS Record Header (5 bytes)                 │
    │ ┌───────────────────────────────────────┐   │
    │ │ Handshake Header (4 bytes)            │   │
    │ │ ┌───────────────────────────────────┐ │   │
    │ │ │ ClientHello Body                  │ │   │
    │ │ │  - Version (2 bytes)              │ │   │
    │ │ │  - Random (32 bytes)              │ │   │
    │ │ │  - Session ID (variable)          │ │   │
    │ │ │  - Cipher Suites (variable)       │ │   │
    │ │ │  - Compression Methods (variable) │ │   │
    │ │ │  - Extensions (variable)          │ │   │
    │ │ │      └─ SNI Extension (Type 0x00) │ │   │
    │ │ │             └─ "youtube.com" ← !! │ │   │
    │ │ └───────────────────────────────────┘ │   │
    │ └───────────────────────────────────────┘   │
    └─────────────────────────────────────────────┘

Aditya's note:
    I find SNI extraction one of the most elegant parts of
    network security — it's the point where protocol knowledge
    meets practical impact. Understanding TLS structure from
    scratch (not just using a library) is what separates a
    systems thinker from a script runner.
"""

import struct
import logging
from typing import Optional

logger = logging.getLogger("SNIExtractor")

# ─────────────────────────────────────────────
# TLS Constants
# ─────────────────────────────────────────────
TLS_CONTENT_HANDSHAKE    = 0x16
TLS_HANDSHAKE_CLIENT_HELLO = 0x01
TLS_EXT_SNI              = 0x0000
TLS_SNI_TYPE_HOSTNAME    = 0x00


class SNIExtractor:
    """
    Extracts the SNI hostname from TLS Client Hello payloads.
    Also extracts Host header from HTTP/1.x requests.

    Two extraction methods:
        1. TLS SNI  → for HTTPS traffic (port 443)
        2. HTTP Host → for plain HTTP traffic (port 80)
    """

    def extract(self, payload: bytes) -> Optional[str]:
        """
        Try both TLS SNI and HTTP Host extraction.
        Returns the domain string, or None if not found.
        """
        if not payload:
            return None

        # Try TLS first (more common in modern traffic)
        sni = self._extract_tls_sni(payload)
        if sni:
            return sni

        # Fall back to HTTP Host header
        return self._extract_http_host(payload)

    def _extract_tls_sni(self, payload: bytes) -> Optional[str]:
        """
        Navigate the TLS Client Hello byte structure to find SNI.

        Offset map:
          [0]     - Content Type (must be 0x16 = Handshake)
          [1:3]   - TLS Version
          [3:5]   - Record Length
          [5]     - Handshake Type (must be 0x01 = ClientHello)
          [6:9]   - Handshake Length (3 bytes)
          [9:11]  - Client Version
          [11:43] - Client Random (32 bytes)
          [43]    - Session ID Length
          [44+]   - Session ID
          ...continuing through Cipher Suites, Compression...
          ...until Extensions section...
          ...where we scan for Extension Type 0x0000 (SNI)...
        """
        try:
            if len(payload) < 5:
                return None

            # Check TLS record type
            if payload[0] != TLS_CONTENT_HANDSHAKE:
                return None

            # Check handshake message type
            if payload[5] != TLS_HANDSHAKE_CLIENT_HELLO:
                return None

            # Offset 9: start of ClientHello body
            offset = 9

            # Skip Client Version (2 bytes)
            offset += 2

            # Skip Client Random (32 bytes)
            offset += 32

            if offset >= len(payload):
                return None

            # Skip Session ID
            session_id_len = payload[offset]
            offset += 1 + session_id_len

            if offset + 2 > len(payload):
                return None

            # Skip Cipher Suites
            cipher_suites_len = struct.unpack("!H", payload[offset:offset + 2])[0]
            offset += 2 + cipher_suites_len

            if offset >= len(payload):
                return None

            # Skip Compression Methods
            comp_methods_len = payload[offset]
            offset += 1 + comp_methods_len

            if offset + 2 > len(payload):
                return None

            # Extensions total length
            extensions_len = struct.unpack("!H", payload[offset:offset + 2])[0]
            offset += 2
            extensions_end = offset + extensions_len

            # ── Scan Extensions for SNI (Type 0x0000) ──
            while offset + 4 <= extensions_end and offset + 4 <= len(payload):
                ext_type   = struct.unpack("!H", payload[offset:offset + 2])[0]
                ext_len    = struct.unpack("!H", payload[offset + 2:offset + 4])[0]
                ext_data   = payload[offset + 4: offset + 4 + ext_len]

                if ext_type == TLS_EXT_SNI:
                    return self._parse_sni_extension(ext_data)

                offset += 4 + ext_len

        except (struct.error, IndexError, UnicodeDecodeError):
            pass  # Malformed packet — silently skip

        return None

    def _parse_sni_extension(self, ext_data: bytes) -> Optional[str]:
        """
        Parse the SNI extension data to extract the hostname.

        SNI Extension Layout:
          [0:2]  - Server Name List Length
          [2]    - Name Type (0x00 = hostname)
          [3:5]  - Name Length
          [5+]   - Hostname bytes (ASCII)
        """
        try:
            if len(ext_data) < 5:
                return None

            name_list_len = struct.unpack("!H", ext_data[0:2])[0]
            name_type     = ext_data[2]

            if name_type != TLS_SNI_TYPE_HOSTNAME:
                return None

            name_len  = struct.unpack("!H", ext_data[3:5])[0]
            hostname  = ext_data[5: 5 + name_len].decode("ascii").strip()

            if hostname:
                logger.debug(f"SNI extracted: {hostname}")
                return hostname

        except (struct.error, UnicodeDecodeError, IndexError):
            pass

        return None

    def _extract_http_host(self, payload: bytes) -> Optional[str]:
        """
        Extract Host header from plaintext HTTP/1.x requests.
        Example: GET / HTTP/1.1\\r\\nHost: www.example.com\\r\\n
        """
        try:
            text = payload.decode("ascii", errors="ignore")
            if not text.startswith(("GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "CONNECT ")):
                return None

            for line in text.split("\r\n"):
                if line.lower().startswith("host:"):
                    host = line.split(":", 1)[1].strip()
                    # Strip port if present
                    if ":" in host:
                        host = host.split(":")[0]
                    if host:
                        logger.debug(f"HTTP Host extracted: {host}")
                        return host
        except Exception:
            pass

        return None
