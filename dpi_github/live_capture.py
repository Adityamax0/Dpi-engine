"""
========================================================
  live_capture.py — Real-Time Network Traffic Capture
  Author   : Aditya Pandey
  Project  : DPI Engine v2.0
  Requires : scapy (pip install scapy)
========================================================

Aditya's design note:
    Live capture is where the engine becomes a real tool.
    Instead of reading saved files, it sniffs packets off
    your network interface in real time — exactly what
    enterprise firewalls and IDS systems do.

    Scapy gives us the raw packet bytes. Our engine then
    processes them identically to the PCAP pipeline,
    because the data format is the same.

    Architecture:
        [Scapy Sniffer Thread]
             │  raw bytes
             ▼
        [PacketParser]
             │  ParsedPacket
             ▼
        [DPIEngine.inspect()]
             │  InspectionResult
             ▼
        [Callback / Queue / Dashboard]
"""

import sys
import threading
import logging
import time
from typing import Optional, Callable
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from src.types         import DPIDecision
from src.dpi_engine    import DPIEngine
from src.packet_parser import PacketParser

logger = logging.getLogger("LiveCapture")


def list_interfaces() -> list:
    """
    Return available network interfaces.
    Requires scapy to be installed.
    """
    try:
        from scapy.all import get_if_list
        return get_if_list()
    except ImportError:
        return ["scapy not installed — run: pip install scapy"]


class LiveCapture:
    """
    Real-time packet capture using Scapy.

    Captures live traffic from a network interface,
    parses each packet through our DPI engine,
    and fires a callback with the result.

    Usage:
        capture = LiveCapture(
            interface  = "Wi-Fi",
            block_apps = ["TikTok", "YouTube"],
            on_result  = lambda r: print(r)
        )
        capture.start()
        time.sleep(60)
        capture.stop()
    """

    def __init__(
        self,
        interface : str,
        block_apps: list            = None,
        on_result : Optional[Callable] = None,
        packet_count: int           = 0,    # 0 = infinite
    ):
        self.interface    = interface
        self.on_result    = on_result
        self.packet_count = packet_count
        self.engine       = DPIEngine(rules_config={
            "blocked_apps": block_apps or []
        })
        self.parser       = PacketParser()
        self._stop_event  = threading.Event()
        self._thread      = None
        self._captured    = 0

    def start(self):
        """Start live capture in a background thread."""
        try:
            import scapy.all as scapy
        except ImportError:
            raise RuntimeError(
                "Scapy is required for live capture.\n"
                "Install it with: pip install scapy\n"
                "On Windows, also install: pip install pywin32 npcap"
            )

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()
        logger.info(f"Live capture started on interface: {self.interface}")

    def stop(self):
        """Stop the capture."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3)
        logger.info(f"Live capture stopped. Captured {self._captured} packets.")

    def _capture_loop(self):
        """Internal capture loop — runs in background thread."""
        try:
            import scapy.all as scapy

            def process_packet(scapy_pkt):
                if self._stop_event.is_set():
                    return True  # stops sniff()

                # Convert scapy packet to raw bytes and feed to our parser
                raw = bytes(scapy_pkt)
                ts  = int(time.time())

                packet = self.parser.parse(raw, ts, 0)
                if packet and packet.has_ip:
                    result = self.engine.inspect(packet)
                    self._captured += 1

                    if self.on_result:
                        self.on_result(result, packet)

                    if self.packet_count > 0 and self._captured >= self.packet_count:
                        return True  # stop

            scapy.sniff(
                iface    = self.interface,
                prn      = process_packet,
                store    = False,
                stop_filter = lambda _: self._stop_event.is_set()
            )

        except PermissionError:
            logger.error(
                "Permission denied. On Windows: run as Administrator.\n"
                "On Linux/Mac: use sudo."
            )
        except Exception as e:
            logger.error(f"Capture error: {e}")

    def get_stats(self) -> dict:
        return {**self.engine.get_stats(), "captured": self._captured}


def run_live_demo(interface: str, duration: int = 30, block_apps: list = None):
    """
    Convenience function: run live capture for N seconds and print results.

    Usage:
        python live_capture.py --iface "Wi-Fi" --duration 30 --block YouTube TikTok
    """
    block_apps = block_apps or []

    print(f"\n{'='*55}")
    print(f"  DPI Engine — Live Capture Mode")
    print(f"  Author   : Aditya Pandey")
    print(f"  Interface: {interface}")
    print(f"  Duration : {duration}s")
    print(f"  Blocking : {block_apps or 'nothing'}")
    print(f"{'='*55}")
    print(f"\n  Sniffing... (press Ctrl+C to stop early)\n")

    def on_result(result, packet):
        marker = "🚫 BLOCK" if result.decision == DPIDecision.BLOCK else "✅ ALLOW"
        app    = result.app_detected or "Unknown"
        sni    = result.sni or ""
        if result.sni or result.app_detected:   # Only print interesting packets
            print(f"  {marker} | {app:<18} | {sni:<35} | {packet.src_ip} → {packet.dst_ip}")

    capture = LiveCapture(
        interface  = interface,
        block_apps = block_apps,
        on_result  = on_result
    )

    try:
        capture.start()
        time.sleep(duration)
    except KeyboardInterrupt:
        print("\n\n  Stopped by user.")
    finally:
        capture.stop()

    stats = capture.get_stats()
    print(f"\n{'='*55}")
    print(f"  RESULTS")
    print(f"  Packets Captured : {stats['captured']}")
    print(f"  Total Inspected  : {stats['total_inspected']}")
    print(f"  Allowed          : {stats['allowed']}")
    print(f"  Blocked          : {stats['blocked']}")
    print(f"  Block Rate       : {stats['block_rate_pct']}%")
    print(f"{'='*55}\n")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="DPI Engine — Live Capture Mode | Aditya Pandey"
    )
    parser.add_argument("--iface",    default="Wi-Fi",  help="Network interface name")
    parser.add_argument("--duration", type=int, default=30, help="Capture duration in seconds")
    parser.add_argument("--block",    nargs="*", default=[], metavar="APP",
                        help="Apps to block (e.g. YouTube TikTok)")
    parser.add_argument("--list-ifaces", action="store_true", help="List available interfaces")
    args = parser.parse_args()

    if args.list_ifaces:
        print("\nAvailable interfaces:")
        for iface in list_interfaces():
            print(f"  • {iface}")
        print()
    else:
        run_live_demo(
            interface  = args.iface,
            duration   = args.duration,
            block_apps = args.block
        )
