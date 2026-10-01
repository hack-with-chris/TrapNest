# 🍯 TrapNest – Python Honeypot & Threat-Intelligence Reporter

TrapNest is a **low-interaction honeypot** that imitates a vulnerable IoT router. It lures attackers, records what they
do, and turns the raw logs into a **threat-intelligence report**. Written in pure Python (standard library only).

## What it simulates
| Service | Default port | What it captures |
|---|---|---|
| Fake Telnet router (BusyBox-style login + shell) | 2323 | usernames, passwords, shell commands, malware download attempts |
| Fake admin web panel (spoofed Apache banner) | 8080 | login credentials, probed paths, user agents, SQLi / XSS / traversal payloads |

> **Safety:** nothing an attacker types is ever executed – the shell is fully emulated with canned replies.
> Still, run it only in a VM/lab, on unprivileged ports, never on a machine holding real data.

## Quick start
The project now includes a single launcher and a simple GUI for easier use.

```bash
python main.py
```

This opens a simple control panel with these options:
- Start honeypot
- Simulate attacks
- Generate report
- Run full demo
- Open the report

You can also launch a small Tkinter window directly:

```bash
python main.py gui
```

You can also run the full workflow directly:

```bash
python main.py demo
```

Manual mode still works if you prefer the original scripts:

```bash
python3 honeypot.py                 # terminal 1 - start the traps (Ctrl+C to stop)
python3 simulate_attacks.py         # terminal 2 - optional: generate demo attacks against your own honeypot
python3 analyze.py                  # build report.html + blocklist.txt
```

Open `report.html` in a browser for the dashboard: top attacker IPs, credential pairs, commands, attack types
(`sqli`, `xss`, `path_traversal`, `cmd_injection`, `malware_download`), malware URLs and an hourly timeline.
`blocklist.txt` lists IPs with 5+ events, ready for a firewall (`iptables -A INPUT -s <ip> -j DROP`).

## Test it with Kali tools
```bash
nmap -sV -p 2323,8080 <honeypot-ip>      # see the fake services get detected & logged
nc <honeypot-ip> 2323                     # log in with anything, try: whoami, uname -a, wget http://x/y.sh
curl "http://<honeypot-ip>:8080/index.php?id=1' OR '1'='1"
```
Capture the traffic in **Wireshark** (`tcp.port == 2323 || tcp.port == 8080`) and compare it with the JSON logs.

## Design highlights
- Thread-per-connection servers with timeouts, 256-byte line limits and 2 KB body limits (DoS-resistant logging)
- Regex signature engine tags hostile input in real time
- Structured JSON-lines logs (`logs/events.jsonl`) → easy SIEM/Splunk ingestion
- Report output is HTML-escaped, so attacker-supplied strings can't attack the analyst (log-injection/XSS safe)

## Ideas for extension
GeoIP enrichment · SSH emulation with `paramiko` · e-mail/Telegram alerts · Splunk forwarder · Docker container

## Author
Chris Sunil Macwan – Cyber Security Internship Project
