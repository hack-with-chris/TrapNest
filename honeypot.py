#!/usr/bin/env python3
"""TrapNest - a low-interaction honeypot (fake Telnet router + fake admin web panel).
Logs every connection, credential and command as JSON lines for later analysis.
Run ONLY inside an isolated lab / VM. Uses no real shell: nothing an attacker types is ever executed."""
import argparse, json, os, re, socketserver, threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote_plus

from db import save_event

LOG_FILE = "logs/events.jsonl"
DB_FILE = "logs/trapnest.db"
MAX_FIELD = 500                      # truncate logged strings (prevents log flooding)
_lock = threading.Lock()

# Signature tagging of hostile input
SIGS = {
    "sqli": re.compile(r"(\bunion\b.+\bselect\b|'\s*or\s*'?1'?\s*=\s*'?1|--\s|sleep\(|information_schema)", re.I),
    "xss": re.compile(r"(<script|onerror\s*=|javascript:|alert\s*\()", re.I),
    "path_traversal": re.compile(r"(\.\./|%2e%2e|/\.\./)", re.I),
    "cmd_injection": re.compile(r"(;\s*(cat|ls|id|wget|curl|nc|bash|sh)|\|\||&&|`|\$\()\s*(cat|ls|id|wget|curl|nc|bash|sh)\b", re.I),
    "malware_download": re.compile(r"\b(wget|curl|tftp|ftpget)\b.*(http|ftp|\d+\.\d+\.\d+\.\d+)", re.I),
    "bruteforce": re.compile(r"(?:admin\s+admin|root\s+root|user\s+user|guest\s+guest|(?:admin|root|guest|user)\s+(?:admin|root|guest|user|1234|password|pass|admin123))", re.I),
    "reverse_shell": re.compile(r"(?:/dev/tcp|nc\s+-e|bash\s+-i|sh\s+-i|python\s+-c\s+.*socket|perl\s+-e\s+.*socket)", re.I),
    "scanner": re.compile(r"(?:nmap|masscan|zmap|sqlmap|nikto)\b", re.I),
    "enumeration": re.compile(r"(?:whoami|uname\s+-a|id\s*$|cat\s+/etc/passwd|ls\s+/)", re.I),
}
def tag(text): return [name for name, rx in SIGS.items() if rx.search(text)]

def log(service, ip, event, **data):
    rec = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "service": service, "ip": ip, "event": event}
    rec.update({k: (v[:MAX_FIELD] if isinstance(v, str) else v) for k, v in data.items()})
    line = json.dumps(rec)
    with _lock:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f: f.write(line + "\n")
        try:
            save_event(rec, DB_FILE)
        except Exception:
            pass
    print(line, flush=True)

# ---------------------------------------------------------------- fake Telnet router
FAKE_PASSWD = "root:x:0:0:root:/root:/bin/sh\nadmin:x:1000:1000::/home/admin:/bin/sh\n"
CANNED = {
    "whoami": "root", "id": "uid=0(root) gid=0(root)", "pwd": "/root",
    "uname -a": "Linux router 3.10.14 #1 SMP PREEMPT mips GNU/Linux", "uname": "Linux",
    "ls": "bin  dev  etc  lib  proc  tmp  var", "cat /etc/passwd": FAKE_PASSWD.strip(),
    "ifconfig": "eth0  Link encap:Ethernet  inet addr:192.168.1.1  Mask:255.255.255.0",
}
class TelnetHandler(socketserver.StreamRequestHandler):
    def readline(self):
        raw = self.rfile.readline(256)
        return raw.decode("utf-8", "replace").strip() if raw else None
    def send(self, text): self.wfile.write(text.encode())
    def handle(self):
        ip = self.client_address[0]
        self.request.settimeout(45)
        log("telnet", ip, "connect")
        try:
            for attempt in range(1, 4):
                self.send("router login: "); user = self.readline()
                if user is None: return
                self.send("Password: "); pw = self.readline()
                if pw is None: return
                log("telnet", ip, "login_attempt", username=user, password=pw)
            self.send("\r\nBusyBox v1.19.4 built-in shell (ash)\r\n# ")   # let them "in" so we can watch commands
            for _ in range(50):
                cmd = self.readline()
                if cmd is None or cmd in ("exit", "logout", "quit"): break
                tags = tag(cmd)
                log("telnet", ip, "command", command=cmd, tags=tags)
                if "malware_download" in tags: out = "wget: can't connect to remote host"
                else: out = CANNED.get(cmd, f"sh: {cmd.split(' ')[0]}: not found" if cmd else "")
                self.send(out + ("\r\n" if out else "") + "# ")
        except OSError:
            pass
        finally:
            log("telnet", ip, "disconnect")

class ThreadedTCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True; daemon_threads = True

# ---------------------------------------------------------------- fake admin web panel
LOGIN_PAGE = b"""<html><head><title>Admin Panel</title></head><body style="font-family:sans-serif">
<h2>Router Administration</h2><form method="POST" action="/login">
User: <input name="username"><br>Pass: <input name="password" type="password"><br><button>Login</button></form></body></html>"""

class WebHandler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.29"; sys_version = "(Ubuntu)"      # spoofed banner
    def log_message(self, *a): pass
    def _respond(self, code, body):
        self.send_response(code); self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        ip = self.client_address[0]
        log("http", ip, "request", method="GET", path=self.path, user_agent=self.headers.get("User-Agent", ""),
            tags=tag(unquote_plus(self.path)))
        self._respond(200, LOGIN_PAGE)
    def do_POST(self):
        ip = self.client_address[0]
        length = min(int(self.headers.get("Content-Length") or 0), 2048)
        body = self.rfile.read(length).decode("utf-8", "replace")
        form = {k: v[0] for k, v in parse_qs(body).items()}
        log("http", ip, "login_attempt", method="POST", path=self.path, username=unquote_plus(form.get("username", "")),
            password=unquote_plus(form.get("password", "")), user_agent=self.headers.get("User-Agent", ""),
            tags=tag(unquote_plus(body)))
        self._respond(200, b"<html><body>Invalid credentials</body></html>")

def main():
    ap = argparse.ArgumentParser(description="TrapNest honeypot")
    ap.add_argument("--host", default="0.0.0.0"); ap.add_argument("--telnet-port", type=int, default=2323)
    ap.add_argument("--http-port", type=int, default=8080)
    a = ap.parse_args()
    tel = ThreadedTCP((a.host, a.telnet_port), TelnetHandler)
    web = ThreadingHTTPServer((a.host, a.http_port), WebHandler); web.daemon_threads = True
    print(f"[+] Telnet trap on {a.telnet_port}, web trap on {a.http_port}. Logging to {LOG_FILE}. Ctrl+C to stop.")
    threading.Thread(target=tel.serve_forever, daemon=True).start()
    try: web.serve_forever()
    except KeyboardInterrupt: print("\n[+] Stopped")

if __name__ == "__main__":
    main()
