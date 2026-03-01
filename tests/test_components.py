"""
========================================================
  test_components.py — Unit Tests for DPI Engine
  Author   : Aditya Pandey
  Project  : DPI Engine (Deep Packet Inspection)
========================================================

Aditya's note:
    Testing is not optional. Each module is tested
    independently before integration. This catches
    bugs at the unit level where they're cheapest to fix.
"""

import sys
import os
import struct

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.types          import FlowKey, ParsedPacket, DPIDecision, EtherType, Protocol
from src.sni_extractor  import SNIExtractor
from src.app_classifier import AppClassifier
from src.rule_manager   import RuleManager
from src.connection_tracker import ConnectionTracker
from src.packet_parser  import PacketParser


# ─────────────────────────────────────────────
# Test: FlowKey bidirectionality
# ─────────────────────────────────────────────

def test_flow_key_bidirectional():
    """A→B and B→A must produce the same FlowKey."""
    key1 = FlowKey.from_packet("192.168.1.1", "8.8.8.8", 54321, 443, 6)
    key2 = FlowKey.from_packet("8.8.8.8", "192.168.1.1", 443, 54321, 6)
    assert key1 == key2, "Bidirectional FlowKey mismatch!"
    print("  [PASS] FlowKey bidirectional equality")


def test_flow_key_hashable():
    """FlowKey must be usable as a dict key."""
    key = FlowKey.from_packet("10.0.0.1", "10.0.0.2", 1234, 80, 6)
    d = {key: "test_value"}
    assert d[key] == "test_value"
    print("  [PASS] FlowKey hashable (dict key)")


# ─────────────────────────────────────────────
# Test: AppClassifier
# ─────────────────────────────────────────────

def test_app_classifier_exact():
    clf = AppClassifier()
    assert clf.classify("youtube.com")    == "YouTube"
    assert clf.classify("github.com")     == "GitHub"
    assert clf.classify("discord.com")    == "Discord"
    assert clf.classify("whatsapp.com")   == "WhatsApp"
    print("  [PASS] AppClassifier exact domain match")


def test_app_classifier_subdomain():
    clf = AppClassifier()
    assert clf.classify("api.github.com")      == "GitHub"
    assert clf.classify("web.whatsapp.com")    == "WhatsApp"
    assert clf.classify("cdn.discordapp.com")  == "Discord"
    assert clf.classify("www.youtube.com")     == "YouTube"
    print("  [PASS] AppClassifier subdomain match")


def test_app_classifier_unknown():
    clf = AppClassifier()
    result = clf.classify("completely.unknown.xyz")
    assert result is None
    print("  [PASS] AppClassifier returns None for unknown domains")


# ─────────────────────────────────────────────
# Test: RuleManager
# ─────────────────────────────────────────────

def test_rule_manager_block_app():
    mgr = RuleManager({"blocked_apps": ["YouTube", "TikTok"]})
    dec, reason = mgr.evaluate(sni="youtube.com", app="YouTube",
                                src_ip="1.1.1.1", dst_ip="2.2.2.2", dst_port=443)
    assert dec == DPIDecision.BLOCK
    assert "YouTube" in reason
    print("  [PASS] RuleManager blocks by app name")


def test_rule_manager_block_domain():
    mgr = RuleManager({"blocked_domains": ["ads.example.com"]})
    dec, reason = mgr.evaluate(sni="ads.example.com", app=None,
                                src_ip="1.1.1.1", dst_ip="2.2.2.2", dst_port=443)
    assert dec == DPIDecision.BLOCK
    print("  [PASS] RuleManager blocks by domain")


def test_rule_manager_block_port():
    mgr = RuleManager({"blocked_ports": [6881]})
    dec, reason = mgr.evaluate(sni=None, app=None,
                                src_ip="1.1.1.1", dst_ip="2.2.2.2", dst_port=6881)
    assert dec == DPIDecision.BLOCK
    assert "6881" in reason
    print("  [PASS] RuleManager blocks by port")


def test_rule_manager_default_allow():
    mgr = RuleManager({})
    dec, _ = mgr.evaluate(sni="legit.com", app="LegitApp",
                           src_ip="1.1.1.1", dst_ip="2.2.2.2", dst_port=443)
    assert dec == DPIDecision.ALLOW
    print("  [PASS] RuleManager default ALLOW")


# ─────────────────────────────────────────────
# Test: ConnectionTracker
# ─────────────────────────────────────────────

def test_connection_tracker():
    tracker = ConnectionTracker()
    key = FlowKey.from_packet("10.0.0.1", "10.0.0.2", 1234, 443, 6)

    # Initially no flow
    assert tracker.get_flow(key) is None

    # Add flow
    tracker.update(key, sni="youtube.com", app="YouTube", decision=DPIDecision.BLOCK)
    flow = tracker.get_flow(key)
    assert flow is not None
    assert flow.app == "YouTube"
    assert flow.decision == DPIDecision.BLOCK

    # Count
    assert tracker.active_flow_count() == 1
    print("  [PASS] ConnectionTracker create and retrieve flow")


def test_connection_tracker_reset():
    tracker = ConnectionTracker()
    key = FlowKey.from_packet("10.0.0.1", "10.0.0.2", 80, 80, 6)
    tracker.update(key, decision=DPIDecision.ALLOW)
    tracker.reset()
    assert tracker.active_flow_count() == 0
    print("  [PASS] ConnectionTracker reset")


# ─────────────────────────────────────────────
# Test: SNI Extractor (HTTP Host header)
# ─────────────────────────────────────────────

def test_sni_extractor_http():
    extractor = SNIExtractor()
    http_payload = b"GET / HTTP/1.1\r\nHost: www.example.com\r\nConnection: keep-alive\r\n\r\n"
    result = extractor.extract(http_payload)
    assert result == "www.example.com", f"Expected 'www.example.com', got {result}"
    print("  [PASS] SNIExtractor HTTP Host header extraction")


def test_sni_extractor_empty():
    extractor = SNIExtractor()
    assert extractor.extract(b"") is None
    assert extractor.extract(None) is None
    print("  [PASS] SNIExtractor handles empty/None payload")


# ─────────────────────────────────────────────
# Test: ParsedPacket helpers
# ─────────────────────────────────────────────

def test_parsed_packet_flags():
    pkt = ParsedPacket(tcp_flags=0x12)  # SYN + ACK
    flags = pkt.tcp_flags_str()
    assert "SYN" in flags
    assert "ACK" in flags
    print("  [PASS] ParsedPacket TCP flags string")


def test_parsed_packet_summary():
    pkt = ParsedPacket(
        has_ip=True, has_tcp=True,
        src_ip="192.168.1.1", dst_ip="8.8.8.8",
        src_port=54321, dst_port=443,
        tcp_flags=0x02, payload=b"x" * 50
    )
    summary = pkt.summary()
    assert "192.168.1.1" in summary
    assert "8.8.8.8" in summary
    print("  [PASS] ParsedPacket summary()")


# ─────────────────────────────────────────────
# Test Runner
# ─────────────────────────────────────────────

def run_all_tests():
    print("\n" + "=" * 55)
    print("  DPI ENGINE — UNIT TESTS")
    print("  Author: Aditya Pandey")
    print("=" * 55)

    tests = [
        test_flow_key_bidirectional,
        test_flow_key_hashable,
        test_app_classifier_exact,
        test_app_classifier_subdomain,
        test_app_classifier_unknown,
        test_rule_manager_block_app,
        test_rule_manager_block_domain,
        test_rule_manager_block_port,
        test_rule_manager_default_allow,
        test_connection_tracker,
        test_connection_tracker_reset,
        test_sni_extractor_http,
        test_sni_extractor_empty,
        test_parsed_packet_flags,
        test_parsed_packet_summary,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"  [FAIL] {test.__name__}: {e}")
            failed += 1

    print("=" * 55)
    print(f"  Results: {passed} passed, {failed} failed")
    print("=" * 55 + "\n")
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
