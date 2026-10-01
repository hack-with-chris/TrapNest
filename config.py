from dataclasses import dataclass


@dataclass
class ProjectConfig:
    host: str = "127.0.0.1"
    telnet_port: int = 2323
    http_port: int = 8080
    log_file: str = "logs/events.jsonl"
    db_file: str = "logs/trapnest.db"
    report_file: str = "report.html"
    blocklist_file: str = "blocklist.txt"
    simulator_host: str = "127.0.0.1"
    demo_delay: float = 2.0

    @classmethod
    def from_args(cls, **kwargs):
        return cls(**kwargs)
