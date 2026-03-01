"""
========================================================
  run_dashboard.py — One-click dashboard launcher
  Author: Aditya Pandey
========================================================

Usage:
    python run_dashboard.py                        # just dashboard
    python run_dashboard.py --pcap capture.pcap   # pre-load PCAP
    python run_dashboard.py --port 8080            # custom port
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from dashboard.dashboard_server import app, load_pcap_into_state
import argparse

parser = argparse.ArgumentParser(description="DPI Engine Dashboard — Aditya Pandey")
parser.add_argument("--pcap",  type=str,  help="Pre-load a PCAP file into dashboard")
parser.add_argument("--port",  type=int,  default=5000)
parser.add_argument("--block", nargs="*", default=["TikTok"])
args = parser.parse_args()

if args.pcap:
    print(f"[+] Pre-loading PCAP: {args.pcap}")
    load_pcap_into_state(args.pcap, {"blocked_apps": args.block})

print(f"""
╔══════════════════════════════════════════════════════╗
║       DPI Engine — Live Dashboard                    ║
║       Author: Aditya Pandey                          ║
║       Built with Python + Claude                     ║
╚══════════════════════════════════════════════════════╝

  Dashboard → http://localhost:{args.port}
  Press Ctrl+C to stop
""")
app.run(host="0.0.0.0", port=args.port, debug=False)
