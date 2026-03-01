"""
========================================================
  pcap_reader.py — PCAP File Parser
  Author   : Aditya Pandey
  Project  : DPI Engine (Deep Packet Inspection)
========================================================

What is a PCAP?
    PCAP (Packet Capture) is a binary file format used to
    store raw network packets. Tools like Wireshark, tcpdump,
    and our DPI engine use this format.

File Structure:
    [Global Header 24 bytes]
    [Packet Record 1]
      └─ [Packet Header 16 bytes]
      └─ [Raw Packet Data N bytes]
    [Packet Record 2]
    ...

Aditya's note:
    I chose to implement the PCAP parser manually (using struct)
    rather than using a library. This gives full control over
    byte-level parsing and makes the system dependency-free.
    Understanding the binary format is non-negotiable for
    anyone serious about systems programming.
"""

import struct
import logging
from typing import Iterator, Tuple
from pathlib import Path

logger = logging.getLogger("PCAPReader")

# ─────────────────────────────────────────────
# PCAP Format Constants
# ─────────────────────────────────────────────
PCAP_MAGIC_LE     = 0xA1B2C3D4   # Little-endian, microseconds
PCAP_MAGIC_BE     = 0xD4C3B2A1   # Big-endian, microseconds
PCAP_MAGIC_LE_NS  = 0xA1B23C4D   # Little-endian, nanoseconds
GLOBAL_HEADER_LEN = 24
PACKET_HEADER_LEN = 16


class PCAPReader:
    """
    Reads raw packets from a PCAP file.

    Design (Aditya Pandey):
        - Implements Python's iterator protocol (__iter__, __next__)
        - Caller can simply: `for raw, ts_sec, ts_usec in reader`
        - No data loaded into memory at once — streams packet by packet
        - Handles both little-endian and big-endian PCAP files

    Usage:
        reader = PCAPReader("capture.pcap")
        for raw_bytes, ts_sec, ts_usec in reader:
            packet = parser.parse(raw_bytes, ts_sec, ts_usec)
    """

    def __init__(self, filepath: str):
        self.filepath   = Path(filepath)
        self._file      = None
        self._endian    = "<"        # default little-endian
        self._link_type = 1          # 1 = Ethernet (most common)
        self._count     = 0
        self._valid     = False

    def open(self):
        """Open and validate the PCAP file by reading the global header."""
        if not self.filepath.exists():
            raise FileNotFoundError(f"PCAP file not found: {self.filepath}")

        self._file = open(self.filepath, "rb")
        self._read_global_header()
        self._valid = True
        logger.info(f"Opened PCAP: {self.filepath.name} | LinkType={self._link_type}")
        return self

    def _read_global_header(self):
        """
        Parse the 24-byte PCAP global header.
        Determines byte order and validates file format.

        Global Header Layout:
          magic_number  (4B) - identifies PCAP format & byte order
          version_major (2B)
          version_minor (2B)
          thiszone      (4B) - GMT offset (almost always 0)
          sigfigs       (4B) - timestamp precision (almost always 0)
          snaplen       (4B) - max bytes per packet saved
          network       (4B) - link layer type (1=Ethernet)
        """
        header = self._file.read(GLOBAL_HEADER_LEN)
        if len(header) < GLOBAL_HEADER_LEN:
            raise ValueError("File too small to be a valid PCAP")

        magic = struct.unpack("<I", header[:4])[0]

        if magic == PCAP_MAGIC_LE or magic == PCAP_MAGIC_LE_NS:
            self._endian = "<"
        elif magic == PCAP_MAGIC_BE:
            self._endian = ">"
        else:
            raise ValueError(f"Invalid PCAP magic number: 0x{magic:08X}")

        fmt = f"{self._endian}IHHiIII"
        (magic, v_maj, v_min, tz, sig, snaplen, self._link_type) = struct.unpack(fmt, header)
        logger.debug(f"PCAP v{v_maj}.{v_min} | Endian={'LE' if self._endian == '<' else 'BE'} | SnapLen={snaplen}")

    def __iter__(self) -> Iterator[Tuple[bytes, int, int]]:
        """Iterate over all packets in the file."""
        if not self._valid:
            self.open()
        return self

    def __next__(self) -> Tuple[bytes, int, int]:
        """
        Read and return the next packet.
        Returns: (raw_bytes, timestamp_sec, timestamp_usec)
        """
        header = self._file.read(PACKET_HEADER_LEN)
        if not header or len(header) < PACKET_HEADER_LEN:
            self.close()
            raise StopIteration

        fmt = f"{self._endian}IIII"
        ts_sec, ts_usec, cap_len, orig_len = struct.unpack(fmt, header)

        raw_data = self._file.read(cap_len)
        if len(raw_data) < cap_len:
            self.close()
            raise StopIteration

        self._count += 1
        return raw_data, ts_sec, ts_usec

    def close(self):
        if self._file:
            self._file.close()
            self._file = None

    def packet_count(self) -> int:
        return self._count

    def __enter__(self):
        return self.open()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
