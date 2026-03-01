"""
========================================================
  connection_tracker.py — TCP/UDP Flow State Manager
  Author   : Aditya Pandey
  Project  : DPI Engine (Deep Packet Inspection)
========================================================

Aditya's design note:
    A "flow" is a full conversation between two endpoints.
    Tracking flows lets us avoid re-inspecting every packet
    from the same connection — once we know a flow belongs to
    YouTube, every subsequent packet gets the same decision.

    This is the "fast path" optimization: the first packet
    of a flow is expensive (full DPI), all subsequent packets
    are cheap (dict lookup).

    Data structure choice:
        dict[FlowKey → FlowState]
        - O(1) lookup by FlowKey hash
        - Memory bounded by active_flow_count
        - FlowKey is frozen dataclass → hashable
"""

import time
import logging
from typing import Optional, Dict
from dataclasses import dataclass, field

from .types import FlowKey
from .types import DPIDecision

logger = logging.getLogger("ConnectionTracker")

# Flows idle for longer than this are cleaned up
FLOW_TIMEOUT_SECONDS = 120


@dataclass
class FlowState:
    """
    Tracks the state and metadata of a single network flow.

    Aditya's note:
        Each flow accumulates metadata over its lifetime:
        SNI (discovered from first packet), app classification,
        decision, packet count, byte count, and timing.
        This is what generates the per-flow report at the end.
    """
    flow_key    : FlowKey
    sni         : Optional[str]       = None
    app         : Optional[str]       = None
    decision    : DPIDecision         = DPIDecision.PENDING
    packet_count: int                 = 0
    byte_count  : int                 = 0
    first_seen  : float               = field(default_factory=time.time)
    last_seen   : float               = field(default_factory=time.time)

    def update_seen(self, nbytes: int = 0):
        self.packet_count += 1
        self.byte_count   += nbytes
        self.last_seen     = time.time()

    def duration_seconds(self) -> float:
        return self.last_seen - self.first_seen

    def __str__(self):
        return (
            f"Flow[{self.flow_key}] | "
            f"App={self.app or 'Unknown'} | "
            f"SNI={self.sni or 'N/A'} | "
            f"Decision={self.decision.value} | "
            f"Pkts={self.packet_count} | "
            f"Bytes={self.byte_count}"
        )


class ConnectionTracker:
    """
    Manages the lifecycle of all tracked network flows.

    Core operations:
        get_flow(key)           → retrieve existing flow state
        update(key, ...)        → create or update a flow
        active_flow_count()     → how many flows are active
        cleanup_stale_flows()   → remove timed-out flows
        get_all_flows()         → list all flows (for reporting)
        reset()                 → clear all state
    """

    def __init__(self):
        self._flows: Dict[FlowKey, FlowState] = {}
        self._total_created = 0

    def get_flow(self, key: FlowKey) -> Optional[FlowState]:
        """Return existing flow state or None if not tracked yet."""
        return self._flows.get(key)

    def update(
        self,
        flow_key : FlowKey,
        sni      : Optional[str]  = None,
        app      : Optional[str]  = None,
        decision : DPIDecision    = DPIDecision.PENDING,
        nbytes   : int            = 0
    ):
        """
        Create or update a flow entry.
        If the flow already exists, update with new info.
        If it's new, create it.
        """
        if flow_key in self._flows:
            flow = self._flows[flow_key]
            flow.update_seen(nbytes)
            # Only update SNI/app/decision if we now have better info
            if sni and not flow.sni:
                flow.sni = sni
            if app and not flow.app:
                flow.app = app
            if decision != DPIDecision.PENDING:
                flow.decision = decision
        else:
            flow = FlowState(
                flow_key = flow_key,
                sni      = sni,
                app      = app,
                decision = decision
            )
            flow.update_seen(nbytes)
            self._flows[flow_key] = flow
            self._total_created  += 1
            logger.debug(f"New flow tracked: {flow_key}")

    def cleanup_stale_flows(self):
        """Remove flows that haven't seen traffic in FLOW_TIMEOUT_SECONDS."""
        now     = time.time()
        stale   = [k for k, v in self._flows.items()
                   if now - v.last_seen > FLOW_TIMEOUT_SECONDS]
        for k in stale:
            del self._flows[k]
        if stale:
            logger.info(f"Cleaned up {len(stale)} stale flows")

    def get_all_flows(self):
        """Return all tracked flows as a list."""
        return list(self._flows.values())

    def active_flow_count(self) -> int:
        return len(self._flows)

    def total_flows_created(self) -> int:
        return self._total_created

    def reset(self):
        """Clear all flow state."""
        self._flows.clear()
        self._total_created = 0
        logger.info("ConnectionTracker reset.")
