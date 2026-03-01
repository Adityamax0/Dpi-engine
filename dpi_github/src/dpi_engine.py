"""
========================================================
  dpi_engine.py — Core Deep Packet Inspection Engine
  Author   : Aditya Pandey
  Built With: Python 3.x + Claude (Anthropic AI)
  Domain   : Network Security / Packet Analysis
========================================================

Design Philosophy (Aditya Pandey):
    - Understand the problem before touching code
    - Modular, readable structure over clever one-liners
    - System-level thinking: each class owns one responsibility
    - Practical ML/CS alignment: real networking meets Python engineering

Architecture:
    Raw Packet
        |
    [PacketParser]     --> Ethernet / IP / TCP / UDP
        |
    [SNIExtractor]     --> TLS Client Hello domain extraction
        |
    [AppClassifier]    --> YouTube / Facebook / WhatsApp / etc.
        |
    [RuleManager]      --> Block / Allow policy evaluation
        |
    [ConnectionTracker]--> Flow lifecycle & fast-path caching
        |
    InspectionResult   --> ALLOW / BLOCK / PENDING
"""

import logging
from dataclasses import dataclass
from typing import Optional

from .types import ParsedPacket, FlowKey, DPIDecision
from .sni_extractor import SNIExtractor
from .app_classifier import AppClassifier
from .rule_manager import RuleManager
from .connection_tracker import ConnectionTracker

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("DPIEngine")


@dataclass
class InspectionResult:
    """Structured verdict returned after DPI inspection of one packet."""
    decision     : DPIDecision
    flow_key     : Optional[FlowKey] = None
    sni          : Optional[str]     = None
    app_detected : Optional[str]     = None
    reason       : Optional[str]     = None
    packet_num   : int               = 0

    def __str__(self):
        return (
            f"[Pkt #{self.packet_num}] "
            f"{self.decision.value} | "
            f"App={self.app_detected or 'Unknown'} | "
            f"SNI={self.sni or 'N/A'} | "
            f"Reason={self.reason or 'N/A'}"
        )


class DPIEngine:
    """
    Core DPI Engine — orchestrates all inspection components.

    Usage:
        engine = DPIEngine(rules_config={
            "blocked_apps": ["TikTok", "YouTube"],
            "blocked_ports": [6881]
        })
        result = engine.inspect(parsed_packet)
    """

    def __init__(self, rules_config: Optional[dict] = None):
        self.sni_extractor      = SNIExtractor()
        self.app_classifier     = AppClassifier()
        self.rule_manager       = RuleManager(rules_config or {})
        self.connection_tracker = ConnectionTracker()
        self._packet_count      = 0
        self._blocked_count     = 0
        self._allowed_count     = 0
        logger.info("DPI Engine initialized | Author: Aditya Pandey | Built with Claude")
        logger.info(f"Active rules: {self.rule_manager.rule_count()}")

    def inspect(self, packet: ParsedPacket) -> InspectionResult:
        """
        Inspect one parsed packet and return a verdict.
        FIX: Guard against None/invalid packet to avoid AttributeError crash.
        """
        if packet is None or not packet.has_ip:
            return InspectionResult(
                decision   = DPIDecision.ALLOW,
                reason     = "non_ip_packet",
                packet_num = self._packet_count
            )
        self._packet_count += 1
        flow_key      = packet.flow_key()
        existing_flow = self.connection_tracker.get_flow(flow_key)

        # Fast path: already decided this flow
        if existing_flow and existing_flow.decision != DPIDecision.PENDING:
            self._update_counters(existing_flow.decision)
            return InspectionResult(
                decision     = existing_flow.decision,
                flow_key     = flow_key,
                sni          = existing_flow.sni,
                app_detected = existing_flow.app,
                reason       = "cached_flow",
                packet_num   = self._packet_count
            )

        # SNI extraction
        sni = None
        if packet.has_tcp and packet.payload:
            sni = self.sni_extractor.extract(packet.payload)

        # App classification
        app = self.app_classifier.classify(sni) if sni else None

        # Rule evaluation
        decision, reason = self.rule_manager.evaluate(
            sni=sni, app=app,
            src_ip=packet.src_ip, dst_ip=packet.dst_ip,
            dst_port=packet.dst_port
        )

        # Track flow
        self.connection_tracker.update(
            flow_key=flow_key, sni=sni, app=app, decision=decision
        )

        self._update_counters(decision)
        result = InspectionResult(
            decision=decision, flow_key=flow_key,
            sni=sni, app_detected=app,
            reason=reason, packet_num=self._packet_count
        )
        logger.debug(str(result))
        return result

    def _update_counters(self, decision: DPIDecision):
        if decision == DPIDecision.ALLOW:
            self._allowed_count += 1
        elif decision == DPIDecision.BLOCK:
            self._blocked_count += 1

    def get_stats(self) -> dict:
        return {
            "total_inspected" : self._packet_count,
            "allowed"         : self._allowed_count,
            "blocked"         : self._blocked_count,
            "active_flows"    : self.connection_tracker.active_flow_count(),
            "block_rate_pct"  : round(
                (self._blocked_count / max(self._packet_count, 1)) * 100, 2
            )
        }

    def reset(self):
        self.connection_tracker.reset()
        self._packet_count  = 0
        self._blocked_count = 0
        self._allowed_count = 0
