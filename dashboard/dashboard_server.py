"""
========================================================
  dashboard_server.py — Flask Web Dashboard
  Author   : Aditya Pandey
  Project  : DPI Engine (Deep Packet Inspection)
  Built With: Python + Flask + Claude (Anthropic AI)
========================================================

Fixes applied (v2.1):
  - is_capturing always reset on capture thread crash/exit (was a bug)
  - recent_flows uses deque(maxlen=200) — O(1) vs list.pop(0) O(n)
  - start_capture protected by state_lock — no double-start race condition
  - Stale flow cleanup runs every 60s in background — prevents memory leak
  - ML classifier lazy-init with retry — handles stale .pkl gracefully
  - scapy check is runtime not import-time — works after late install
  - /api/report loop var renamed app_name — was shadowing Flask 'app'
  - All capture exceptions logged with detail — not silently swallowed
  - /api/start validates interface is non-empty
  - Added /api/rules endpoints for hot rule updates (no restart needed)
  - Added timestamp to each flow entry
"""

import sys
import os
import threading
import time
import logging
from datetime import datetime
from pathlib import Path
from collections import defaultdict, deque

from flask import Flask, render_template, jsonify, request, Response

sys.path.insert(0, str(Path(__file__).parent.parent))
from src.types         import DPIDecision
from src.packet_parser import PacketParser
from src.dpi_engine    import DPIEngine
from src.pcap_reader   import PCAPReader

try:
    from ml.ml_classifier import MLTrafficClassifier
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

def _check_scapy():
    """Runtime scapy check — handles late installs / missing npcap."""
    try:
        from scapy.all import sniff, get_if_list  # noqa
        return True
    except Exception:
        return False

logging.basicConfig(level=logging.WARNING)
log = logging.getLogger("Dashboard")

flask_app = Flask(__name__, template_folder="templates")
app = flask_app  # alias so run_dashboard.py import still works

# ── Global State ──
state_lock = threading.Lock()

dpi_engine = DPIEngine({
    "blocked_apps"   : ["TikTok"],
    "blocked_domains": ["ads.doubleclick.net", "doubleclick.net"],
    "blocked_ports"  : [6881, 6882, 6883],
})

# FIX: deque with maxlen — O(1) append+drop vs list.pop(0) O(n)
recent_flows = deque(maxlen=200)

def _new_app_counts():
    return defaultdict(lambda: {"flows": 0, "blocked": 0, "allowed": 0})

app_counts     = _new_app_counts()
capture_thread = None
is_capturing   = False
packet_parser  = PacketParser()

# ML — lazy init with error recovery
ml_classifier = None
if ML_AVAILABLE:
    try:
        ml_classifier = MLTrafficClassifier()
    except Exception as e:
        log.warning(f"ML init failed on startup: {e}. Will retry on first /api/ml_predict request.")


# ── Background: Stale Flow Cleanup ──
# FIX: Was never called before — memory leak on long captures
def _cleanup_worker():
    while True:
        time.sleep(60)
        try:
            with state_lock:
                dpi_engine.connection_tracker.cleanup_stale_flows()
        except Exception as e:
            log.debug(f"Cleanup worker error: {e}")

threading.Thread(target=_cleanup_worker, daemon=True).start()


# ── Routes ──

@flask_app.route("/")
def index():
    return render_template("index.html")


@flask_app.route("/api/interfaces")
def get_interfaces():
    interfaces = []
    if _check_scapy():
        try:
            from scapy.all import get_if_list
            interfaces = get_if_list()
        except Exception as e:
            log.debug(f"get_if_list failed: {e}")

    if not interfaces:
        import platform
        if platform.system() == "Windows":
            interfaces = ["Wi-Fi", "Ethernet", "Local Area Connection"]
        else:
            net = "/sys/class/net"
            interfaces = sorted(os.listdir(net)) if os.path.exists(net) else ["eth0", "wlan0"]

    return jsonify({"interfaces": interfaces})


@flask_app.route("/api/start", methods=["POST"])
def start_capture():
    global capture_thread, is_capturing

    data  = request.get_json() or {}
    iface = data.get("interface", "").strip()

    if not iface:
        return jsonify({"status": "error", "message": "No interface selected"}), 400

    if not _check_scapy():
        return jsonify({
            "status": "error",
            "message": (
                "Scapy not available. Fix:\n"
                "  pip install scapy\n"
                "  Windows: install Npcap from https://npcap.com\n"
                "  Then restart the dashboard."
            )
        }), 400

    # FIX: state_lock prevents double-start race condition
    with state_lock:
        if is_capturing:
            return jsonify({"status": "already_running"})
        is_capturing = True

    capture_thread = threading.Thread(target=_capture_loop, args=(iface,), daemon=True)
    capture_thread.start()
    return jsonify({"status": "started", "interface": iface})


@flask_app.route("/api/stop", methods=["POST"])
def stop_capture():
    global is_capturing
    is_capturing = False
    return jsonify({"status": "stopped"})


@flask_app.route("/api/stats")
def get_stats():
    with state_lock:
        engine_stats = dpi_engine.get_stats()
        flows_data   = [_serialize_flow(f) for f in list(recent_flows)[-50:]]
        apps_data    = {k: dict(v) for k, v in app_counts.items()}

    return jsonify({
        **engine_stats,
        "recent_flows"    : flows_data,
        "app_counts"      : apps_data,
        "ml_available"    : ML_AVAILABLE,
        "scapy_available" : _check_scapy(),
        "is_capturing"    : is_capturing,
    })


@flask_app.route("/api/ml_predict")
def ml_predict():
    global ml_classifier

    # FIX: Lazy retry — if startup init failed, try again now
    if ML_AVAILABLE and ml_classifier is None:
        try:
            ml_classifier = MLTrafficClassifier()
        except Exception as e:
            return jsonify({"predictions": [], "error": f"ML init failed: {e}"})

    if not ML_AVAILABLE or ml_classifier is None:
        return jsonify({"predictions": [], "error": "ML not available"})

    with state_lock:
        flows = list(dpi_engine.connection_tracker.get_all_flows())

    if not flows:
        return jsonify({"predictions": []})

    predictions = []
    for flow in flows[:20]:
        try:
            features = {
                "dst_port"    : flow.flow_key.dst_port,
                "src_port"    : flow.flow_key.src_port,
                "protocol"    : flow.flow_key.protocol,
                "packet_count": flow.packet_count,
                "byte_count"  : flow.byte_count,
            }
            pred, confidence = ml_classifier.predict(features)
            predictions.append({
                "sni"          : flow.sni or "",
                "src_ip"       : flow.flow_key.src_ip,
                "predicted_app": pred,
                "confidence"   : confidence,
            })
        except Exception as e:
            log.debug(f"ML predict error: {e}")

    return jsonify({"predictions": predictions})


@flask_app.route("/api/report")
def get_report():
    with state_lock:
        stats = dpi_engine.get_stats()
        flows = list(dpi_engine.connection_tracker.get_all_flows())
        apps  = {k: dict(v) for k, v in app_counts.items()}

    lines = [
        "=" * 60,
        "  DPI ENGINE — ANALYSIS REPORT",
        "  Author    : Aditya Pandey",
        f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 60, "",
        "  SUMMARY",
        f"  Total Packets : {stats['total_inspected']}",
        f"  Allowed       : {stats['allowed']}",
        f"  Blocked       : {stats['blocked']}",
        f"  Block Rate    : {stats['block_rate_pct']}%",
        f"  Active Flows  : {stats['active_flows']}",
        "",
        "  APPLICATION BREAKDOWN",
        f"  {'App':<25} {'Flows':>6} {'Blocked':>8} {'Allowed':>8}",
        "  " + "-" * 50,
    ]

    # FIX: loop variable renamed app_name (was 'app', shadowing Flask app object)
    for app_name, counts in sorted(apps.items(), key=lambda x: -x[1]["flows"]):
        lines.append(
            f"  {app_name:<25} {counts['flows']:>6} {counts['blocked']:>8} {counts['allowed']:>8}"
        )

    lines += ["", "  FLOW DETAILS", "  " + "-" * 50]
    for f in flows[:30]:
        lines.append(
            f"  [{f.decision.value:<5}] {(f.app or 'Unknown'):<20} {f.sni or f.flow_key.src_ip}"
        )

    report = "\n".join(lines)
    ts = datetime.now().strftime("%Y-%m-%d")
    return Response(
        report,
        mimetype="text/plain",
        headers={"Content-Disposition": f"attachment; filename=dpi_report_{ts}.txt"}
    )


@flask_app.route("/api/clear", methods=["POST"])
def clear_data():
    global recent_flows, app_counts
    with state_lock:
        dpi_engine.reset()
        recent_flows = deque(maxlen=200)
        app_counts   = _new_app_counts()
    return jsonify({"status": "cleared"})


@flask_app.route("/api/rules", methods=["GET"])
def get_rules():
    """Return current active rules."""
    with state_lock:
        rules = dpi_engine.rule_manager.stats()
    return jsonify(rules)


@flask_app.route("/api/rules/block_app", methods=["POST"])
def block_app_route():
    """Hot-add a blocked app — no restart needed."""
    data = request.get_json() or {}
    app_name = data.get("app", "").strip()
    if not app_name:
        return jsonify({"status": "error", "message": "app name required"}), 400
    with state_lock:
        dpi_engine.rule_manager.add_blocked_app(app_name)
    return jsonify({"status": "blocked", "app": app_name})


@flask_app.route("/api/rules/block_domain", methods=["POST"])
def block_domain_route():
    """Hot-add a blocked domain — no restart needed."""
    data = request.get_json() or {}
    domain = data.get("domain", "").strip()
    if not domain:
        return jsonify({"status": "error", "message": "domain required"}), 400
    with state_lock:
        dpi_engine.rule_manager.add_blocked_domain(domain)
    return jsonify({"status": "blocked", "domain": domain})


# ── Capture Loop ──

def _capture_loop(iface: str):
    """
    Background thread: live packet capture via Scapy.
    FIX: is_capturing reset in finally block — UI can't get stuck.
    FIX: All exceptions logged with detail — not silently swallowed.
    """
    global is_capturing
    try:
        from scapy.all import sniff

        def process_packet(scapy_pkt):
            if not is_capturing:
                return True  # returning True stops sniff()
            try:
                raw    = bytes(scapy_pkt)
                ts     = int(time.time())
                parsed = packet_parser.parse(raw, ts, 0)
                if parsed is None or not parsed.has_ip:
                    return
                result = dpi_engine.inspect(parsed)
                _record_result(parsed, result)
            except Exception as e:
                log.debug(f"Packet error: {e}")

        log.info(f"Capture started on: {iface}")
        sniff(
            iface       = iface,
            prn         = process_packet,
            store       = False,
            stop_filter = lambda _: not is_capturing,
        )
        log.info(f"Capture stopped on: {iface}")

    except PermissionError:
        log.error("Permission denied. Run as Administrator (Windows) or with sudo (Linux/Mac).")
    except OSError as e:
        log.error(f"Interface '{iface}' error: {e}. Check interface name in /api/interfaces.")
    except Exception as e:
        log.error(f"Capture crash [{type(e).__name__}]: {e}")
    finally:
        # FIX: always reset — UI Start button re-enables correctly
        is_capturing = False


def _record_result(parsed, result):
    """Thread-safe: record packet inspection result into global state."""
    with state_lock:
        # FIX: deque.append is O(1) and auto-drops oldest at maxlen=200
        recent_flows.append({
            "decision" : result.decision.value,
            "app"      : result.app_detected,
            "sni"      : result.sni,
            "src_ip"   : parsed.src_ip,
            "dst_ip"   : parsed.dst_ip,
            "dst_port" : parsed.dst_port,
            "ml_pred"  : None,
            "timestamp": datetime.now().strftime("%H:%M:%S"),
        })
        app_name = result.app_detected or "Unknown"
        app_counts[app_name]["flows"] += 1
        if result.decision == DPIDecision.BLOCK:
            app_counts[app_name]["blocked"] += 1
        else:
            app_counts[app_name]["allowed"] += 1


def _serialize_flow(f):
    """Serialize FlowState or dict to JSON-safe dict."""
    if isinstance(f, dict):
        return f
    return {
        "decision" : f.decision.value if hasattr(f, "decision") else str(f.get("decision")),
        "app"      : f.app if hasattr(f, "app") else f.get("app"),
        "sni"      : f.sni if hasattr(f, "sni") else f.get("sni"),
        "src_ip"   : f.flow_key.src_ip if hasattr(f, "flow_key") else f.get("src_ip", ""),
        "dst_ip"   : f.flow_key.dst_ip if hasattr(f, "flow_key") else f.get("dst_ip", ""),
        "dst_port" : f.flow_key.dst_port if hasattr(f, "flow_key") else f.get("dst_port", ""),
        "ml_pred"  : None,
        "timestamp": datetime.now().strftime("%H:%M:%S"),
    }


# ── PCAP Pre-load ──

def load_pcap_into_state(pcap_path: str, rules: dict = None):
    """Pre-populate dashboard with PCAP file analysis before server starts."""
    global recent_flows, app_counts

    engine = DPIEngine(rules or {})
    reader = PCAPReader(pcap_path)
    parser = PacketParser()
    loaded = 0

    with reader:
        for raw, ts_sec, ts_usec in reader:
            parsed = parser.parse(raw, ts_sec, ts_usec)
            if parsed is None or not parsed.has_ip:
                continue
            result = engine.inspect(parsed)
            loaded += 1

            app_name = result.app_detected or "Unknown"
            app_counts[app_name]["flows"] += 1
            if result.decision == DPIDecision.BLOCK:
                app_counts[app_name]["blocked"] += 1
            else:
                app_counts[app_name]["allowed"] += 1

            recent_flows.append({
                "decision" : result.decision.value,
                "app"      : result.app_detected,
                "sni"      : result.sni,
                "src_ip"   : parsed.src_ip,
                "dst_ip"   : parsed.dst_ip,
                "dst_port" : parsed.dst_port,
                "ml_pred"  : None,
                "timestamp": datetime.now().strftime("%H:%M:%S"),
            })

    with state_lock:
        dpi_engine._packet_count  = engine._packet_count
        dpi_engine._allowed_count = engine._allowed_count
        dpi_engine._blocked_count = engine._blocked_count
        for flow in engine.connection_tracker.get_all_flows():
            dpi_engine.connection_tracker._flows[flow.flow_key] = flow

    print(f"[+] PCAP loaded: {loaded} flows from {pcap_path}")


# ── Entry Point ──

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="DPI Engine Dashboard — Aditya Pandey")
    parser.add_argument("--pcap",  type=str, help="Pre-load a PCAP file")
    parser.add_argument("--port",  type=int, default=5000)
    parser.add_argument("--block", nargs="*", default=["TikTok"])
    args = parser.parse_args()

    if args.pcap and Path(args.pcap).exists():
        print(f"[+] Loading PCAP: {args.pcap}")
        load_pcap_into_state(args.pcap, {"blocked_apps": args.block})

    print(f"""
╔══════════════════════════════════════════════════════╗
║       DPI Engine — Live Dashboard                    ║
║       Author: Aditya Pandey                          ║
║       Built with Python + Claude                     ║
╚══════════════════════════════════════════════════════╝
  → Open in browser: http://localhost:{args.port}
  → Press Ctrl+C to stop
""")
    flask_app.run(host="0.0.0.0", port=args.port, debug=False)
