"""
========================================================
  rule_manager.py — Block/Allow Rule Engine
  Author   : Aditya Pandey
  Project  : DPI Engine (Deep Packet Inspection)
========================================================

Aditya's design note:
    The rule engine is where policy meets packets.
    Rules are evaluated in priority order:
      1. Blocked IPs (network-level, fastest)
      2. Blocked apps (app-level)
      3. Blocked domains (SNI-level)
      4. Blocked ports (transport-level)
      5. Default: ALLOW

    This ordering is intentional — fail fast on the most
    specific rules first. ISPs and enterprise firewalls
    use similar tiered evaluation logic.
"""

import logging
from typing import Optional, Set, Dict, Tuple

from .types import DPIDecision  # circular? no — we import the enum only

logger = logging.getLogger("RuleManager")


class RuleManager:
    """
    Evaluates network traffic against configured rules.
    Returns (DPIDecision, reason_string) for each packet.

    Configuration dict format:
    {
        "blocked_apps":    ["YouTube", "TikTok", "Facebook"],
        "blocked_domains": ["ads.example.com"],
        "blocked_ips":     ["1.2.3.4"],
        "blocked_ports":   [6881, 6882],   # e.g. BitTorrent
        "default":         "allow"          # or "block"
    }
    """

    def __init__(self, config: dict):
        self._blocked_apps:    Set[str] = set(config.get("blocked_apps",    []))
        self._blocked_domains: Set[str] = set(config.get("blocked_domains", []))
        self._blocked_ips:     Set[str] = set(config.get("blocked_ips",     []))
        self._blocked_ports:   Set[int] = set(config.get("blocked_ports",   []))
        self._default_action           = config.get("default", "allow").lower()

        self._eval_count  = 0
        self._block_count = 0

        logger.info(
            f"RuleManager initialized | "
            f"blocked_apps={len(self._blocked_apps)} | "
            f"blocked_domains={len(self._blocked_domains)} | "
            f"blocked_ips={len(self._blocked_ips)} | "
            f"default={self._default_action}"
        )

    def evaluate(
        self,
        sni:      Optional[str],
        app:      Optional[str],
        src_ip:   str,
        dst_ip:   str,
        dst_port: int
    ) -> Tuple[DPIDecision, str]:
        """
        Evaluate all rules and return a (decision, reason) tuple.

        Evaluation order (highest priority first):
          1. Blocked source/dest IP
          2. Blocked app name
          3. Blocked domain/SNI
          4. Blocked destination port
          5. Default policy
        """
        self._eval_count += 1

        # ── Rule 1: IP-level block ──
        if src_ip in self._blocked_ips:
            return self._block(f"blocked_src_ip:{src_ip}")
        if dst_ip in self._blocked_ips:
            return self._block(f"blocked_dst_ip:{dst_ip}")

        # ── Rule 2: App-level block ──
        if app and app in self._blocked_apps:
            return self._block(f"blocked_app:{app}")

        # ── Rule 3: Domain/SNI block ──
        if sni:
            for blocked in self._blocked_domains:
                if sni == blocked or sni.endswith("." + blocked):
                    return self._block(f"blocked_domain:{sni}")

        # ── Rule 4: Port-level block ──
        if dst_port in self._blocked_ports:
            return self._block(f"blocked_port:{dst_port}")

        # ── Rule 5: Default policy ──
        if self._default_action == "block":
            return self._block("default_block_policy")

        return DPIDecision.ALLOW, "default_allow"

    def _block(self, reason: str) -> Tuple[DPIDecision, str]:
        self._block_count += 1
        return DPIDecision.BLOCK, reason

    def add_blocked_app(self, app: str):
        """Dynamically add a blocked app (hot update)."""
        self._blocked_apps.add(app)
        logger.info(f"Rule added: block app '{app}'")

    def add_blocked_domain(self, domain: str):
        """Dynamically add a blocked domain (hot update)."""
        self._blocked_domains.add(domain)
        logger.info(f"Rule added: block domain '{domain}'")

    def rule_count(self) -> int:
        return (
            len(self._blocked_apps) +
            len(self._blocked_domains) +
            len(self._blocked_ips) +
            len(self._blocked_ports)
        )

    def stats(self) -> dict:
        return {
            "evaluations"     : self._eval_count,
            "blocks_triggered": self._block_count,
            "blocked_apps"    : list(self._blocked_apps),
            "blocked_domains" : list(self._blocked_domains),
            "blocked_ports"   : list(self._blocked_ports),
        }
