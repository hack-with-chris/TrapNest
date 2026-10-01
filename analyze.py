#!/usr/bin/env python3
"""Turn logs/events.jsonl into a threat-intel report (report.html) + iptables-ready blocklist."""
import argparse
import html
import json
import sqlite3
import sys
from collections import Counter
from pathlib import Path


def parse_args():
    parser = argparse.ArgumentParser(description="Generate a TrapNest report")
    parser.add_argument("--log", default="logs/events.jsonl")
    parser.add_argument("--db", default="logs/trapnest.db")
    parser.add_argument("--report", default="report.html")
    parser.add_argument("--blocklist", default="blocklist.txt")
    return parser.parse_args()


def load(log_path, db_path):
    if log_path.exists():
        out = []
        for line in log_path.read_text(encoding="utf-8").splitlines():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out

    if db_path.exists():
        conn = sqlite3.connect(db_path)
        try:
            rows = conn.execute("SELECT payload FROM events").fetchall()
            return [json.loads(row[0]) for row in rows]
        finally:
            conn.close()

    sys.exit("No log file or database yet - run honeypot.py first.")


def table(title, counter, n=10):
    rows = "".join(f"<tr><td>{html.escape(str(k))}</td><td>{v}</td></tr>" for k, v in counter.most_common(n)) or "<tr><td colspan=2>none</td></tr>"
    return f"<div class=card><h3>{title}</h3><table>{rows}</table></div>"


def main():
    args = parse_args()
    LOG = Path(args.log)
    DB = Path(args.db)
    REPORT = Path(args.report)
    BLOCK = Path(args.blocklist)

    ev = load(LOG, DB)
    ips = Counter(e["ip"] for e in ev)
    users = Counter(e.get("username") for e in ev if e["event"] == "login_attempt")
    pws = Counter(e.get("password") for e in ev if e["event"] == "login_attempt")
    combos = Counter(f'{e.get("username")} / {e.get("password")}' for e in ev if e["event"] == "login_attempt")
    cmds = Counter(e.get("command") for e in ev if e["event"] == "command")
    tags = Counter(t for e in ev for t in e.get("tags", []))
    svc = Counter(e["service"] for e in ev)
    hours = Counter(e["ts"][:13] for e in ev)
    paths = Counter(e.get("path") for e in ev if e["service"] == "http")
    agents = Counter(e.get("user_agent") for e in ev if e.get("user_agent"))
    urls = [e["command"] for e in ev if "malware_download" in e.get("tags", [])]
    peak = max(hours.values()) if hours else 1
    timeline = "".join(f"<div class=bar><span>{html.escape(h)}</span><i style='width:{int(300*c/peak)}px'></i>{c}</div>" for h, c in sorted(hours.items()))
    dl = "".join(f"<li><code>{html.escape(u)}</code></li>" for u in urls[:20]) or "<li>none</li>"
    page = f"""<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>TrapNest Report</title><style>
:root{{--bg:#07111f;--bg-soft:#101d33;--panel:#13243d;--panel-2:#1a304f;--accent:#5eead4;--accent-2:#7dd3fc;--text:#e2e8f0;--muted:#9fb3c8;--danger:#f87171;--warning:#fbbf24;--ok:#4ade80;}}
body{{font-family:system-ui;background:linear-gradient(135deg,#07111f,#101d33 40%,#0d1322);color:var(--text);margin:0;padding:28px;}}
h1{{margin:0 0 8px;font-size:2rem;}}
.subtitle{{color:var(--muted);margin-bottom:20px;}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px;margin-top:20px;}}
.card{{background:rgba(19,36,61,0.95);border:1px solid rgba(125,211,252,0.15);border-radius:16px;padding:16px;box-shadow:0 10px 30px rgba(0,0,0,0.2);}}
.card h3{{margin-top:0;color:var(--accent);font-size:1.1rem;}}
.summary{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;margin:18px 0;}}
.summary .card{{padding:14px 12px;}}
.big{{font-size:2rem;font-weight:700;color:var(--accent-2);margin-bottom:6px;}}
table{{width:100%;border-collapse:collapse;}}
td{{padding:6px 0;border-bottom:1px solid rgba(255,255,255,0.08);word-break:break-all;}}
td:last-child{{text-align:right;width:65px;color:var(--accent);font-weight:600;}}
.bar{{font-size:12px;margin:3px 0;color:var(--muted);}}
.bar span{{display:inline-block;width:120px;}}
.bar i{{display:inline-block;height:10px;background:linear-gradient(90deg,var(--accent),var(--accent-2));margin-right:8px;border-radius:999px;}}
code{{color:var(--warning);background:rgba(251,191,36,0.08);padding:2px 6px;border-radius:6px;}}
ul{{padding-left:20px;margin:0;}}
li{{margin:4px 0;}}
</style>
<h1>🍯 TrapNest Threat Report</h1>
<p class=subtitle>{len(ev)} events from {len(ips)} unique attacker IPs</p>
<div class=summary>
<div class=card><div class=big>{len(ev)}</div>total events</div>
<div class=card><div class=big>{len(ips)}</div>unique IPs</div>
<div class=card><div class=big>{sum(tags.values())}</div>tagged attacks</div>
<div class=card><div class=big>{len(svc)}</div>services</div>
</div>
<div class=grid>
{table("Top attacker IPs", ips)}{table("Services targeted", svc)}{table("Attack types", tags)}
{table("Usernames tried", users)}{table("Passwords tried", pws)}{table("Credential pairs", combos)}
{table("Commands run", cmds)}{table("Web paths probed", paths)}{table("User agents", agents, 5)}
<div class=card><h3>Malware download attempts</h3><ul>{dl}</ul></div>
<div class=card style="grid-column:1/-1"><h3>Activity timeline (per hour, UTC)</h3>{timeline}</div></div>"""
    REPORT.write_text(page, encoding="utf-8")
    BLOCK.write_text("\n".join(ip for ip, c in ips.items() if c >= 5) + "\n", encoding="utf-8")
    print(f"[+] {len(ev)} events, {len(ips)} IPs -> {REPORT}, {BLOCK}")
    print("[+] Top IPs:", ips.most_common(3))
    print("[+] Attack types:", dict(tags))


if __name__ == "__main__":
    main()
