#!/usr/bin/env python3
"""Convenience launcher for the TrapNest honeypot project.

This provides a single entry point so the user does not have to run each script
manually in separate commands. You can either use the interactive menu or invoke
subcommands directly.
"""

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

from config import ProjectConfig

try:
    import tkinter as tk
    from tkinter import ttk
except ImportError:  # pragma: no cover
    tk = None
    ttk = None

ROOT = Path(__file__).resolve().parent


def run_process(script_name, *extra_args):
    return subprocess.run(
        [sys.executable, str(ROOT / script_name), *extra_args],
        cwd=str(ROOT),
        check=False,
    )


def start_honeypot(host="127.0.0.1", telnet_port=2323, http_port=8080):
    proc = subprocess.Popen(
        [
            sys.executable,
            str(ROOT / "honeypot.py"),
            "--host",
            host,
            "--telnet-port",
            str(telnet_port),
            "--http-port",
            str(http_port),
        ],
        cwd=str(ROOT),
    )
    time.sleep(1.2)
    return proc


def run_demo(host="127.0.0.1", telnet_port=2323, http_port=8080, delay=2.0):
    print("[+] Starting honeypot...")
    proc = start_honeypot(host=host, telnet_port=telnet_port, http_port=http_port)
    time.sleep(delay)
    print("[+] Generating demo attacks...")
    run_process(
        "simulate_attacks.py",
        "--host",
        host,
        "--telnet-port",
        str(telnet_port),
        "--http-port",
        str(http_port),
    )
    print("[+] Building threat report...")
    run_process(
        "analyze.py",
        "--log",
        "logs/events.jsonl",
        "--report",
        "report.html",
        "--blocklist",
        "blocklist.txt",
    )
    print("[+] Demo complete. Report saved to report.html")
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        proc.kill()
    return 0


def build_parser():
    parser = argparse.ArgumentParser(description="TrapNest launcher")
    subparsers = parser.add_subparsers(dest="command")

    start = subparsers.add_parser("start", help="start the honeypot")
    start.add_argument("--host", default="127.0.0.1")
    start.add_argument("--telnet-port", type=int, default=2323)
    start.add_argument("--http-port", type=int, default=8080)

    simulate = subparsers.add_parser("simulate", help="generate demo attacks")
    simulate.add_argument("--host", default="127.0.0.1")
    simulate.add_argument("--telnet-port", type=int, default=2323)
    simulate.add_argument("--http-port", type=int, default=8080)

    analyze = subparsers.add_parser("analyze", help="generate report and blocklist")
    analyze.add_argument("--log", default="logs/events.jsonl")
    analyze.add_argument("--report", default="report.html")
    analyze.add_argument("--blocklist", default="blocklist.txt")

    demo = subparsers.add_parser("demo", help="run the full workflow automatically")
    demo.add_argument("--host", default="127.0.0.1")
    demo.add_argument("--telnet-port", type=int, default=2323)
    demo.add_argument("--http-port", type=int, default=8080)
    demo.add_argument("--delay", type=float, default=2.0)

    gui = subparsers.add_parser("gui", help="open the Tkinter control panel")
    gui.add_argument("--host", default="127.0.0.1")
    gui.add_argument("--telnet-port", type=int, default=2323)
    gui.add_argument("--http-port", type=int, default=8080)

    return parser


def prompt_menu():
    print("\nTrapNest Control Panel")
    print("1) Start honeypot")
    print("2) Simulate attacks")
    print("3) Generate report")
    print("4) Run full demo")
    print("5) Open report in browser")
    print("6) Exit")
    choice = input("Select an option: ").strip()

    config = ProjectConfig()
    if choice == "1":
        start_honeypot(config.host, config.telnet_port, config.http_port)
        print("[+] Honeypot running in background. Press Ctrl+C in that terminal to stop it.")
    elif choice == "2":
        run_process("simulate_attacks.py", "--host", config.host, "--telnet-port", str(config.telnet_port), "--http-port", str(config.http_port))
    elif choice == "3":
        run_process("analyze.py", "--log", config.log_file, "--report", config.report_file, "--blocklist", config.blocklist_file)
    elif choice == "4":
        run_demo(config.host, config.telnet_port, config.http_port, config.demo_delay)
    elif choice == "5":
        report_path = (ROOT / config.report_file).resolve()
        print(f"[+] Open this file in a browser: {report_path}")
        try:
            if sys.platform.startswith("darwin"):
                subprocess.run(["open", str(report_path)], check=False)
            elif os.name == "nt":
                os.startfile(str(report_path))
            else:
                subprocess.run(["xdg-open", str(report_path)], check=False)
        except Exception:
            pass
    elif choice == "6":
        return 0
    else:
        print("[!] Invalid option")
    return 0


def launch_gui():
    if tk is None:
        print("[!] Tkinter is not available in this environment.")
        return 1

    cfg = ProjectConfig()
    root = tk.Tk()
    root.title("TrapNest Control Panel")
    root.geometry("420x260")
    root.resizable(False, False)

    def start_action():
        start_honeypot(cfg.host, cfg.telnet_port, cfg.http_port)

    def simulate_action():
        run_process("simulate_attacks.py", "--host", cfg.host, "--telnet-port", str(cfg.telnet_port), "--http-port", str(cfg.http_port))

    def analyze_action():
        run_process("analyze.py", "--log", cfg.log_file, "--report", cfg.report_file, "--blocklist", cfg.blocklist_file)

    def demo_action():
        run_demo(cfg.host, cfg.telnet_port, cfg.http_port, cfg.demo_delay)

    def open_report_action():
        report_path = (ROOT / cfg.report_file).resolve()
        try:
            if sys.platform.startswith("darwin"):
                subprocess.run(["open", str(report_path)], check=False)
            elif os.name == "nt":
                os.startfile(str(report_path))
            else:
                subprocess.run(["xdg-open", str(report_path)], check=False)
        except Exception:
            pass

    frame = ttk.Frame(root, padding=16)
    frame.pack(fill="both", expand=True)

    ttk.Label(frame, text="TrapNest", font=("Segoe UI", 18, "bold")).pack(pady=(0, 12))
    ttk.Button(frame, text="Start Honeypot", command=start_action, width=28).pack(pady=4)
    ttk.Button(frame, text="Simulate Attacks", command=simulate_action, width=28).pack(pady=4)
    ttk.Button(frame, text="Generate Report", command=analyze_action, width=28).pack(pady=4)
    ttk.Button(frame, text="Run Full Demo", command=demo_action, width=28).pack(pady=4)
    ttk.Button(frame, text="Open Report", command=open_report_action, width=28).pack(pady=4)

    root.mainloop()
    return 0


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "start":
        start_honeypot(args.host, args.telnet_port, args.http_port)
        print("[+] Honeypot running. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[+] Stopped")
        return 0

    if args.command == "simulate":
        return run_process("simulate_attacks.py", "--host", args.host, "--telnet-port", str(args.telnet_port), "--http-port", str(args.http_port))

    if args.command == "analyze":
        return run_process("analyze.py", "--log", args.log, "--report", args.report, "--blocklist", args.blocklist)

    if args.command == "demo":
        return run_demo(args.host, args.telnet_port, args.http_port, args.delay)

    if args.command == "gui":
        return launch_gui()

    if not args.command:
        while True:
            rc = prompt_menu()
            if rc != 0:
                return rc
            again = input("\nRun another action? [y/N]: ").strip().lower()
            if again not in {"y", "yes"}:
                return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
