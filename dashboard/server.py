"""
========================================================
  dashboard/server.py — Real-Time DPI Web Dashboard
  Author   : Aditya Pandey
  Project  : DPI Engine v2.0
  Built With: Flask + SSE (Server-Sent Events)
========================================================

Architecture:
    Flask serves the dashboard HTML.
    A background thread runs the DPI engine continuously.
    SSE (Server-Sent Events) pushes live updates to the browser
    without needing WebSockets — clean, simple, no JS framework.

    Browser ←── SSE stream ──── Flask ←── DPI Engine thread
"""

import sys
import os
import json
import time
import threading
import queue
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

from flask import Flask, render_template, Response, jsonify, request
from src.types           import DPIDecision
from src.dpi_engine      import DPIEngine
from src.packet_parser   import PacketParser
from src.pcap_reader     import PCAPReader
from src.app_classifier  import AppClassifier, AppCategory

app = Flask(__name__)

# ─────────────────────────────────────────────
# Global State (shared between threads)
# ─────────────────────────────────────────────

engine       = DPIEngine()
event_queue  = queue.Queue(maxsize=500)
session_log  = []          # last 100 packet events
is_running   = False
run_lock     = threading.Lock()

# Live counters
stats = {
    "total"      : 0,
    "allowed"    : 0,
    "blocked"    : 0,
    "flows"      : 0,
    "app_counts" : {},
    "recent"     : [],
    "timeline"   : [],     # [{time, blocked, allowed}] per second
    "started_at" : None,
}


def push_event(data: dict):
    """Push a JSON event to the SSE queue."""
    try:
        event_queue.put_nowait(json.dumps(data))
    except queue.Full:
        pass


def analyze_pcap_thread(pcap_path: str, block_apps: list):
    """Background thread: runs DPI engine on PCAP and streams results."""
    global is_running, engine, stats

    with run_lock:
        is_running = True

    engine = DPIEngine(rules_config={"blocked_apps": block_apps})
    parser = PacketParser()

    stats["total"]      = 0
    stats["allowed"]    = 0
    stats["blocked"]    = 0
    stats["flows"]      = 0
    stats["app_counts"] = {}
    stats["recent"]     = []
    stats["timeline"]   = []
    stats["started_at"] = datetime.now().strftime("%H:%M:%S")

    push_event({"type": "status", "msg": f"Analysis started: {Path(pcap_path).name}"})

    try:
        reader = PCAPReader(pcap_path)
        second_bucket = {"ts": int(time.time()), "blocked": 0, "allowed": 0}

        with reader:
            for raw, ts_sec, ts_usec in reader:
                packet = parser.parse(raw, ts_sec, ts_usec)
                if not packet or not packet.has_ip:
                    continue

                result = engine.inspect(packet)
                stats["total"]  += 1
                stats["flows"]   = engine.connection_tracker.active_flow_count()

                # App counter
                app_name = result.app_detected or "Unknown"
                if app_name not in stats["app_counts"]:
                    stats["app_counts"][app_name] = {"allowed": 0, "blocked": 0}

                if result.decision == DPIDecision.ALLOW:
                    stats["allowed"] += 1
                    stats["app_counts"][app_name]["allowed"] += 1
                    second_bucket["allowed"] += 1
                else:
                    stats["blocked"] += 1
                    stats["app_counts"][app_name]["blocked"] += 1
                    second_bucket["blocked"] += 1

                # Recent log (last 50)
                entry = {
                    "num"     : stats["total"],
                    "src"     : f"{packet.src_ip}:{packet.src_port}",
                    "dst"     : f"{packet.dst_ip}:{packet.dst_port}",
                    "app"     : app_name,
                    "sni"     : result.sni or "—",
                    "decision": result.decision.value,
                }
                stats["recent"].insert(0, entry)
                if len(stats["recent"]) > 50:
                    stats["recent"].pop()

                # Timeline bucket
                now_sec = int(time.time())
                if now_sec != second_bucket["ts"]:
                    stats["timeline"].append({
                        "t"      : second_bucket["ts"],
                        "blocked": second_bucket["blocked"],
                        "allowed": second_bucket["allowed"],
                    })
                    if len(stats["timeline"]) > 30:
                        stats["timeline"].pop(0)
                    second_bucket = {"ts": now_sec, "blocked": 0, "allowed": 0}

                # Push live update every 10 packets
                if stats["total"] % 10 == 0:
                    push_event({"type": "tick", "stats": _safe_stats()})

                time.sleep(0.005)   # slight delay so UI can animate

        push_event({"type": "tick",   "stats": _safe_stats()})
        push_event({"type": "status", "msg":  "Analysis complete ✓"})
        push_event({"type": "done"})

    except Exception as e:
        push_event({"type": "error", "msg": str(e)})

    with run_lock:
        is_running = False


def run_demo_thread(block_apps: list):
    """Background thread: runs demo simulation for when no PCAP is available."""
    global is_running, engine, stats

    with run_lock:
        is_running = True

    engine = DPIEngine(rules_config={"blocked_apps": block_apps})
    classifier = AppClassifier()

    stats["total"]      = 0
    stats["allowed"]    = 0
    stats["blocked"]    = 0
    stats["flows"]      = 0
    stats["app_counts"] = {}
    stats["recent"]     = []
    stats["timeline"]   = []
    stats["started_at"] = datetime.now().strftime("%H:%M:%S")

    # Simulated traffic
    import random
    domains = [
        ("www.youtube.com",      "192.168.1.10", "172.217.14.206"),
        ("api.github.com",       "192.168.1.11", "140.82.121.4"),
        ("web.whatsapp.com",     "192.168.1.12", "157.240.20.35"),
        ("www.tiktok.com",       "192.168.1.13", "23.22.31.39"),
        ("www.instagram.com",    "192.168.1.14", "157.240.20.174"),
        ("discord.com",          "192.168.1.15", "162.159.135.232"),
        ("www.netflix.com",      "192.168.1.16", "54.74.116.131"),
        ("teams.microsoft.com",  "192.168.1.17", "52.113.194.132"),
        ("www.reddit.com",       "192.168.1.18", "151.101.129.140"),
        ("api.anthropic.com",    "192.168.1.19", "160.79.104.50"),
        ("ads.doubleclick.net",  "192.168.1.20", "74.125.200.157"),
        ("www.spotify.com",      "192.168.1.21", "35.186.224.53"),
        ("www.linkedin.com",     "192.168.1.22", "108.174.10.10"),
        ("www.twitch.tv",        "192.168.1.23", "151.101.2.167"),
        ("pypi.org",             "192.168.1.24", "151.101.0.63"),
    ]

    push_event({"type": "status", "msg": "Demo simulation running..."})

    for i in range(200):
        domain, src_ip, dst_ip = random.choice(domains)
        app_name   = classifier.classify(domain) or "Unknown"
        block_apps_set = set(block_apps)
        decision   = "BLOCK" if app_name in block_apps_set or domain == "ads.doubleclick.net" else "ALLOW"

        stats["total"] += 1
        stats["flows"]  = min(stats["total"] // 3, 25)

        if app_name not in stats["app_counts"]:
            stats["app_counts"][app_name] = {"allowed": 0, "blocked": 0}

        if decision == "ALLOW":
            stats["allowed"] += 1
            stats["app_counts"][app_name]["allowed"] += 1
        else:
            stats["blocked"] += 1
            stats["app_counts"][app_name]["blocked"] += 1

        entry = {
            "num"     : stats["total"],
            "src"     : f"{src_ip}:{random.randint(49152,65535)}",
            "dst"     : f"{dst_ip}:443",
            "app"     : app_name,
            "sni"     : domain,
            "decision": decision,
        }
        stats["recent"].insert(0, entry)
        if len(stats["recent"]) > 50:
            stats["recent"].pop()

        if stats["total"] % 5 == 0:
            push_event({"type": "tick", "stats": _safe_stats()})

        time.sleep(0.08)

    push_event({"type": "tick",   "stats": _safe_stats()})
    push_event({"type": "status", "msg": "Demo complete ✓ — upload a real PCAP to analyze live traffic"})
    push_event({"type": "done"})

    with run_lock:
        is_running = False


def _safe_stats():
    """Return a JSON-serializable copy of current stats."""
    top_apps = sorted(
        [{"app": k, **v, "total": v["allowed"] + v["blocked"]}
         for k, v in stats["app_counts"].items()],
        key=lambda x: -x["total"]
    )[:10]
    return {
        "total"      : stats["total"],
        "allowed"    : stats["allowed"],
        "blocked"    : stats["blocked"],
        "flows"      : stats["flows"],
        "block_rate" : round((stats["blocked"] / max(stats["total"], 1)) * 100, 1),
        "top_apps"   : top_apps,
        "recent"     : stats["recent"][:15],
        "timeline"   : stats["timeline"][-20:],
        "started_at" : stats["started_at"],
    }


# ─────────────────────────────────────────────
# Flask Routes
# ─────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/stats")
def api_stats():
    return jsonify(_safe_stats())


@app.route("/api/start_demo", methods=["POST"])
def start_demo():
    global is_running
    if is_running:
        return jsonify({"error": "Already running"}), 400
    data       = request.get_json() or {}
    block_apps = data.get("block_apps", ["TikTok", "YouTube"])
    t = threading.Thread(target=run_demo_thread, args=(block_apps,), daemon=True)
    t.start()
    return jsonify({"status": "started"})


@app.route("/api/start_pcap", methods=["POST"])
def start_pcap():
    global is_running
    if is_running:
        return jsonify({"error": "Already running"}), 400
    data       = request.get_json() or {}
    pcap_path  = data.get("pcap_path", "")
    block_apps = data.get("block_apps", [])
    if not pcap_path or not Path(pcap_path).exists():
        return jsonify({"error": f"PCAP not found: {pcap_path}"}), 400
    t = threading.Thread(target=analyze_pcap_thread, args=(pcap_path, block_apps), daemon=True)
    t.start()
    return jsonify({"status": "started"})


@app.route("/stream")
def stream():
    """SSE endpoint — browser subscribes here for live updates."""
    def event_generator():
        yield "data: {\"type\": \"connected\"}\n\n"
        while True:
            try:
                msg = event_queue.get(timeout=30)
                yield f"data: {msg}\n\n"
            except queue.Empty:
                yield "data: {\"type\": \"ping\"}\n\n"
    return Response(event_generator(),
                    mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no"})


if __name__ == "__main__":
    print("\n" + "="*55)
    print("  DPI Engine Dashboard — Aditya Pandey")
    print("  Open: http://localhost:5000")
    print("="*55 + "\n")
    app.run(debug=False, threaded=True, port=5000)
