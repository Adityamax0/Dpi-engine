"""
========================================================
  packet_parser.py — Ethernet/IP/TCP/UDP Byte Parser
  Author   : Aditya Pandey
  Project  : DPI Engine (Deep Packet Inspection)
========================================================

Aditya's note:
    This module is where raw bytes become structured data.
    I find byte-level parsing fascinating — everything on
    the internet is ultimately just bytes following a spec.
    Once you understand the spec, parsing is just careful
    arithmetic and struct unpacking.

Packet Structure (the "Russian nesting doll"):
    ┌─────────────────────────────────┐
    │ Ethernet Header  (14 bytes)     │
    │ ┌─────────────────────────────┐ │
    │ │ IP Header  (20+ bytes)      │ │
    │ │ ┌─────────────────────────┐ │ │
    │ │ │ TCP/UDP Header          │ │ │
    │ │ │ ┌─────────────────────┐ │ │ │
    │ │ │ │ Payload (App Data)  │ │ │ │
    │ │ │ └─────────────────────┘ │ │ │
    │ │ └─────────────────────────┘ │ │
    │ └─────────────────────────────┘ │
    └─────────────────────────────────┘
"""

import struct
import socket
import logging
from typing import Optional

from .types import ParsedPacket, EtherType, Protocol

logger = logging.getLogger("PacketParser")

# ─────────────────────────────────────────────
# Header Size Constants (bytes)
# ─────────────────────────────────────────────
ETHERNET_HEADER_LEN = 14   # Fixed size — always 14 bytes
MIN_IP_HEADER_LEN   = 20   # Variable, but minimum is 20
MIN_TCP_HEADER_LEN  = 20
UDP_HEADER_LEN      = 8    # Fixed size — always 8 bytes


class PacketParser:
    """
    Parses raw Ethernet frame bytes into a structured ParsedPacket.

    Architecture:
        parse() calls: _parse_ethernet() → _parse_ip() → _parse_tcp() / _parse_udp()

    Each sub-parser reads its own header and advances an offset pointer.
    This clean separation means each layer is independently testable.
    """

    def parse(self, raw: bytes, ts_sec: int = 0, ts_usec: int = 0) -> Optional[ParsedPacket]:
        """
        Main entry point. Parse a raw frame into a ParsedPacket.
        Returns None if the frame is too short or malformed.
        """
        if len(raw) < ETHERNET_HEADER_LEN:
            return None

        pkt = ParsedPacket(
            raw_data      = raw,
            timestamp_sec = ts_sec,
            timestamp_usec= ts_usec
        )

        # ── Layer 2: Ethernet ──
        offset = self._parse_ethernet(raw, pkt)
        if offset < 0:
            return pkt  # Non-IP frame, return with just Ethernet info

        # ── Layer 3: IP ──
        if pkt.ether_type == EtherType.IPv4:
            offset = self._parse_ipv4(raw, pkt, offset)
        else:
            return pkt  # IPv6/ARP — return with Ethernet only

        if not pkt.has_ip or offset < 0:
            return pkt

        # ── Layer 4: TCP or UDP ──
        if pkt.protocol == Protocol.TCP:
            self._parse_tcp(raw, pkt, offset)
        elif pkt.protocol == Protocol.UDP:
            self._parse_udp(raw, pkt, offset)

        return pkt

    def _parse_ethernet(self, raw: bytes, pkt: ParsedPacket) -> int:
        """
        Parse 14-byte Ethernet header.

        Layout:
          [0:6]  - Destination MAC
          [6:12] - Source MAC
          [12:14] - EtherType
        """
        dst_mac = raw[0:6]
        src_mac = raw[6:12]
        ether_type = struct.unpack("!H", raw[12:14])[0]

        pkt.dst_mac    = ":".join(f"{b:02x}" for b in dst_mac)
        pkt.src_mac    = ":".join(f"{b:02x}" for b in src_mac)
        pkt.ether_type = ether_type

        if ether_type in (EtherType.IPv4, EtherType.IPv6, EtherType.ARP):
            return ETHERNET_HEADER_LEN
        return -1  # Unknown EtherType

    def _parse_ipv4(self, raw: bytes, pkt: ParsedPacket, offset: int) -> int:
        """
        Parse IPv4 header (variable length, minimum 20 bytes).

        Layout (first 20 bytes):
          [0]     - Version (4 bits) + IHL (4 bits)
          [1]     - DSCP + ECN
          [2:4]   - Total Length
          [4:6]   - Identification
          [6:8]   - Flags + Fragment Offset
          [8]     - TTL
          [9]     - Protocol
          [10:12] - Header Checksum
          [12:16] - Source IP
          [16:20] - Destination IP
        """
        if len(raw) < offset + MIN_IP_HEADER_LEN:
            return -1

        version_ihl = raw[offset]
        version     = (version_ihl >> 4) & 0xF
        ihl         = (version_ihl & 0xF) * 4   # IHL is in 32-bit words

        if version != 4 or ihl < MIN_IP_HEADER_LEN:
            return -1

        ttl      = raw[offset + 8]
        protocol = raw[offset + 9]
        src_ip   = socket.inet_ntoa(raw[offset + 12: offset + 16])
        dst_ip   = socket.inet_ntoa(raw[offset + 16: offset + 20])

        pkt.has_ip        = True
        pkt.ip_version    = version
        pkt.ip_header_len = ihl
        pkt.ttl           = ttl
        pkt.protocol      = protocol
        pkt.src_ip        = src_ip
        pkt.dst_ip        = dst_ip

        return offset + ihl   # Advance past IP header

    def _parse_tcp(self, raw: bytes, pkt: ParsedPacket, offset: int):
        """
        Parse TCP header.

        Layout:
          [0:2]  - Source Port
          [2:4]  - Destination Port
          [4:8]  - Sequence Number
          [8:12] - Acknowledgment Number
          [12]   - Data Offset (4 bits) + Reserved (4 bits)
          [13]   - Flags (FIN SYN RST PSH ACK URG)
          [14:16] - Window Size
        """
        if len(raw) < offset + MIN_TCP_HEADER_LEN:
            return

        src_port   = struct.unpack("!H", raw[offset:offset + 2])[0]
        dst_port   = struct.unpack("!H", raw[offset + 2:offset + 4])[0]
        seq        = struct.unpack("!I", raw[offset + 4:offset + 8])[0]
        ack        = struct.unpack("!I", raw[offset + 8:offset + 12])[0]
        data_off   = ((raw[offset + 12] >> 4) & 0xF) * 4
        flags      = raw[offset + 13]

        pkt.has_tcp        = True
        pkt.src_port       = src_port
        pkt.dst_port       = dst_port
        pkt.seq_number     = seq
        pkt.ack_number     = ack
        pkt.tcp_header_len = data_off
        pkt.tcp_flags      = flags

        payload_start = offset + data_off
        pkt.payload   = raw[payload_start:] if payload_start < len(raw) else b""

    def _parse_udp(self, raw: bytes, pkt: ParsedPacket, offset: int):
        """
        Parse UDP header (always 8 bytes).

        Layout:
          [0:2] - Source Port
          [2:4] - Destination Port
          [4:6] - Length
          [6:8] - Checksum
        """
        if len(raw) < offset + UDP_HEADER_LEN:
            return

        src_port = struct.unpack("!H", raw[offset:offset + 2])[0]
        dst_port = struct.unpack("!H", raw[offset + 2:offset + 4])[0]

        pkt.has_udp  = True
        pkt.src_port = src_port
        pkt.dst_port = dst_port
        pkt.payload  = raw[offset + UDP_HEADER_LEN:]
