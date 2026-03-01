"""
========================================================
  main.py — CLI Entry Point for DPI Engine
  Author   : Aditya Pandey
  Project  : DPI Engine (Deep Packet Inspection)
  Built With: Python 3.x + Claude (Anthropic AI)
  GitHub   : github.com/aditya-pandey  (your handle)
  Date     : 2026
========================================================

Usage:
    python main.py --pcap capture.pcap
    python main.py --pcap capture.pcap --block YouTube TikTok
    python main.py --pcap capture.pcap --report report.txt
    python main.py --pcap capture.pcap --verbose
    python main.py --demo

Description:
    A complete Deep Packet Inspection system built entirely
    in Python. Analyzes PCAP files, detects which applications
    are generating traffic using SNI extraction, and applies
    configurable block/allow rules.

    Built from scratch by Aditya Pandey — a CSE student
    specializing in AI & ML systems — with AI-assisted
    architecture (Claude by Anthropic).
"""

import argparse
import sys
import json
import time
from pathlib import Path
from datetime import datetime

# ── Project imports ──
sys.path.insert(0, str(Path(__file__).parent))
from src.pcap_reader    import PCAPReader
from src.packet_parser  import PacketParser
from src.dpi_engine     import DPIEngine
from src.types          import DPIDecision


# ─────────────────────────────────────────────
# ASCII Banner
# ─────────────────────────────────────────────
BANNER = """
╔══════════════════════════════════════════════════════════════╗
║          DPI Engine — Deep Packet Inspection System          ║
║                                                              ║
║  Author   : Aditya Pandey                                    ║
║  Built With: Python 3.x + Claude (Anthropic AI)             ║
║  Domain   : Network Security / Packet Analysis               ║
║  Version  : 1.0.0                                            ║
╚══════════════════════════════════════════════════════════════╝
"""


def parse_args():
    parser = argparse.ArgumentParser(
        prog="dpi_engine",
        description="DPI Engine by Aditya Pandey — Deep Packet Inspection in Python",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --pcap traffic.pcap
  python main.py --pcap traffic.pcap --block YouTube TikTok Facebook
  python main.py --pcap traffic.pcap --block-ports 6881 6882
  python main.py --pcap traffic.pcap --report output.txt --verbose
  python main.py --demo
        """
    )
    parser.add_argument("--pcap",        type=str,            help="Path to input PCAP file")
    parser.add_argument("--block",       nargs="*", default=[], metavar="APP",
                        help="App names to block (e.g. YouTube TikTok Facebook)")
    parser.add_argument("--block-domains", nargs="*", default=[], metavar="DOMAIN",
                        help="Domain names to block (e.g. ads.example.com)")
    parser.add_argument("--block-ips",   nargs="*", default=[], metavar="IP",
                        help="IP addresses to block")
    parser.add_argument("--block-ports", nargs="*", type=int, default=[], metavar="PORT",
                        help="TCP/UDP ports to block (e.g. 6881 for BitTorrent)")
    parser.add_argument("--report",      type=str,            help="Save report to file")
    parser.add_argument("--verbose",     action="store_true", help="Print every packet result")
    parser.add_argument("--demo",        action="store_true", help="Run offline demo (no PCAP needed)")
    parser.add_argument("--stats-only",  action="store_true", help="Print only final stats")
    return parser.parse_args()


def run_analysis(pcap_path: str, engine: DPIEngine, verbose: bool = False) -> list:
    """
    Main analysis loop.
    Reads each packet from PCAP, parses it, runs DPI inspection.
    Returns list of InspectionResult for reporting.
    """
    reader  = PCAPReader(pcap_path)
    parser  = PacketParser()
    results = []

    print(f"\n[+] Analyzing: {pcap_path}")
    print(f"[+] Rules active: {engine.rule_manager.rule_count()}")
    print("-" * 60)

    start_time = time.time()

    with reader:
        for raw, ts_sec, ts_usec in reader:
            packet = parser.parse(raw, ts_sec, ts_usec)
            if packet is None:
                continue

            result = engine.inspect(packet)
            results.append(result)

            if verbose:
                marker = "🚫 BLOCK" if result.decision == DPIDecision.BLOCK else "✅ ALLOW"
                print(f"  {marker} | {result}")

    elapsed = time.time() - start_time
    print(f"\n[+] Analysis complete in {elapsed:.3f}s")
    return results


def print_report(results: list, engine: DPIEngine, save_to: str = None):
    """Generate and optionally save the final DPI report."""
    stats  = engine.get_stats()
    flows  = engine.connection_tracker.get_all_flows()

    # Build app breakdown
    app_counts = {}
    for flow in flows:
        app = flow.app or "Unknown"
        if app not in app_counts:
            app_counts[app] = {"flows": 0, "blocked": 0, "allowed": 0}
        app_counts[app]["flows"] += 1
        if flow.decision == DPIDecision.BLOCK:
            app_counts[app]["blocked"] += 1
        else:
            app_counts[app]["allowed"] += 1

    lines = []
    lines.append("=" * 60)
    lines.append("  DPI ENGINE — ANALYSIS REPORT")
    lines.append(f"  Author  : Aditya Pandey")
    lines.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 60)
    lines.append("")
    lines.append("  SUMMARY")
    lines.append(f"  Total Packets Inspected : {stats['total_inspected']}")
    lines.append(f"  Allowed                 : {stats['allowed']}")
    lines.append(f"  Blocked                 : {stats['blocked']}")
    lines.append(f"  Block Rate              : {stats['block_rate_pct']}%")
    lines.append(f"  Active Flows Tracked    : {stats['active_flows']}")
    lines.append("")
    lines.append("  APPLICATION BREAKDOWN")
    lines.append(f"  {'Application':<25} {'Flows':>6} {'Blocked':>8} {'Allowed':>8}")
    lines.append("  " + "-" * 50)
    for app, counts in sorted(app_counts.items(), key=lambda x: -x[1]["flows"]):
        lines.append(
            f"  {app:<25} {counts['flows']:>6} {counts['blocked']:>8} {counts['allowed']:>8}"
        )
    lines.append("")
    lines.append("  TOP SNIs DETECTED")
    sni_list = [(f.sni, f.app or "Unknown", f.decision.value) for f in flows if f.sni]
    for sni, app, dec in sni_list[:15]:
        lines.append(f"  {'[' + dec + ']':<10} {app:<20} {sni}")
    lines.append("")
    lines.append("=" * 60)

    report_str = "\n".join(lines)
    print(report_str)

    if save_to:
        with open(save_to, "w") as f:
            f.write(report_str)
        print(f"\n[+] Report saved to: {save_to}")


def run_demo():
    """
    Offline demo that simulates DPI without a real PCAP file.
    Shows the system working end-to-end using crafted test data.
    """
    print("\n[DEMO MODE] Simulating DPI inspection on crafted packets...\n")
    from src.sni_extractor  import SNIExtractor
    from src.app_classifier import AppClassifier
    from src.rule_manager   import RuleManager
    from src.types          import DPIDecision

    classifier = AppClassifier()
    rule_mgr   = RuleManager({
        "blocked_apps": ["TikTok", "YouTube"],
        "blocked_domains": ["ads.doubleclick.net"]
    })

    test_domains = [
        "www.youtube.com",
        "api.github.com",
        "web.whatsapp.com",
        "www.tiktok.com",
        "www.instagram.com",
        "ads.doubleclick.net",
        "teams.microsoft.com",
        "discord.com",
        "www.netflix.com",
        "api.anthropic.com",
    ]

    print(f"  {'Domain':<35} {'App':<20} {'Decision'}")
    print("  " + "-" * 70)

    for domain in test_domains:
        app = classifier.classify(domain)
        decision, reason = rule_mgr.evaluate(
            sni=domain, app=app,
            src_ip="192.168.1.1", dst_ip="1.2.3.4", dst_port=443
        )
        marker = "🚫 BLOCK" if decision == DPIDecision.BLOCK else "✅ ALLOW"
        print(f"  {domain:<35} {(app or 'Unknown'):<20} {marker}")

    print(f"\n[DEMO] DPI Engine is fully operational.")
    print(f"[DEMO] Use --pcap <file.pcap> to analyze real network captures.")


def main():
    print(BANNER)
    args = parse_args()

    if args.demo:
        run_demo()
        return

    if not args.pcap:
        print("[!] Error: --pcap <file> is required. Use --demo for offline testing.")
        print("    Run: python main.py --help")
        sys.exit(1)

    if not Path(args.pcap).exists():
        print(f"[!] Error: PCAP file not found: {args.pcap}")
        sys.exit(1)

    # Build rules config from CLI args
    rules_config = {
        "blocked_apps"   : args.block,
        "blocked_domains": args.block_domains,
        "blocked_ips"    : args.block_ips,
        "blocked_ports"  : args.block_ports,
    }

    engine  = DPIEngine(rules_config)
    results = run_analysis(args.pcap, engine, verbose=args.verbose)

    if not args.stats_only:
        print_report(results, engine, save_to=args.report)
    else:
        print("\n[STATS]", json.dumps(engine.get_stats(), indent=2))


if __name__ == "__main__":
    main()
