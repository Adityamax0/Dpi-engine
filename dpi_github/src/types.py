"""
========================================================
  types.py — Core Data Structures
  Author   : Aditya Pandey
  Project  : DPI Engine (Deep Packet Inspection)
========================================================
Aditya's design note:
    Define your data structures first. When you know exactly
    what shape your data takes, writing the logic becomes
    straightforward. OOP principle: Encapsulation starts here.
"""

import socket
from dataclasses import dataclass
from typing import Optional
from enum import IntEnum, Enum


class EtherType(IntEnum):
    IPv4 = 0x0800
    IPv6 = 0x86DD
    ARP  = 0x0806

class Protocol(IntEnum):
    ICMP = 1
    TCP  = 6
    UDP  = 17

class DPIDecision(Enum):
    """
    Final verdict for each inspected packet.
    ALLOW=forward, BLOCK=drop, PENDING=awaiting more info.
    """
    ALLOW   = "ALLOW"
    BLOCK   = "BLOCK"
    PENDING = "PENDING"


@dataclass(frozen=True)
class FlowKey:
    """
    5-tuple uniquely identifying a network connection.
    frozen=True → hashable → usable as dict/set key.
    Bidirectional: A→B and B→A produce the same key.
    """
    src_ip   : str
    dst_ip   : str
    src_port : int
    dst_port : int
    protocol : int

    @classmethod
    def from_packet(cls, src_ip, dst_ip, src_port, dst_port, protocol):
        ep1 = (src_ip, src_port)
        ep2 = (dst_ip, dst_port)
        if ep1 > ep2:
            ep1, ep2 = ep2, ep1
        return cls(src_ip=ep1[0], dst_ip=ep2[0],
                   src_port=ep1[1], dst_port=ep2[1],
                   protocol=protocol)

    def __str__(self):
        proto = {6: "TCP", 17: "UDP"}.get(self.protocol, str(self.protocol))
        return f"{self.src_ip}:{self.src_port} <-> {self.dst_ip}:{self.dst_port} [{proto}]"


@dataclass
class ParsedPacket:
    """Fully parsed network packet — Ethernet / IP / TCP/UDP / Payload."""
    raw_data       : bytes = b""
    timestamp_sec  : int   = 0
    timestamp_usec : int   = 0
    src_mac        : str   = ""
    dst_mac        : str   = ""
    ether_type     : int   = 0
    has_ip         : bool  = False
    ip_version     : int   = 0
    src_ip         : str   = ""
    dst_ip         : str   = ""
    protocol       : int   = 0
    ttl            : int   = 0
    ip_header_len  : int   = 0
    has_tcp        : bool  = False
    src_port       : int   = 0
    dst_port       : int   = 0
    seq_number     : int   = 0
    ack_number     : int   = 0
    tcp_flags      : int   = 0
    tcp_header_len : int   = 0
    has_udp        : bool  = False
    payload        : bytes = b""

    def flow_key(self) -> FlowKey:
        return FlowKey.from_packet(self.src_ip, self.dst_ip,
                                   self.src_port, self.dst_port, self.protocol)

    def tcp_flags_str(self) -> str:
        names = [(0x02,"SYN"),(0x10,"ACK"),(0x01,"FIN"),(0x04,"RST"),(0x08,"PSH"),(0x20,"URG")]
        return " ".join(n for bit, n in names if self.tcp_flags & bit) or "NONE"

    def summary(self) -> str:
        if self.has_tcp:
            return f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} [TCP {self.tcp_flags_str()}] {len(self.payload)}B"
        elif self.has_udp:
            return f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} [UDP] {len(self.payload)}B"
        return f"Non-IP (EtherType=0x{self.ether_type:04X})"
