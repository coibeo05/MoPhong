# detection_module.py
from dataclasses import dataclass
from typing import List, Set
from network_traffic import Connection

@dataclass
class SnortAlert:
    conn_id:     int
    src_ip:      str
    rule_id:     str
    severity:    int
    description: str
    timestamp:   float

class SnortDetector:
    """
    Mô phỏng Snort IDS trong Honeyanole
    Phân tích lưu lượng được mirror từ production server
    Phát hiện và đưa IP vào blacklist
    """
    RULES = [
        {
            "id":       "SID-2001",
            "severity": 1,
            "keywords": ["phpMyAdmin", "wp-login", "setup.php",
                         "DROP TABLE", "SHELLCODE",
                         "etc/passwd", "etc/shadow"],
            "desc":     "Web attack / exploit detected",
        },
        {
            "id":       "SID-2002",
            "severity": 1,
            "keywords": ["USER root", "PASS toor", "nc -e /bin/sh"],
            "desc":     "Brute force / reverse shell attempt",
        },
        {
            "id":       "SID-2003",
            "severity": 2,
            "keywords": ["nmap", "TRACE", "OPTIONS",
                         "nonexistent_page", "CONNECT"],
            "desc":     "Port scan / honeypot fingerprint probe",
        },
        {
            "id":       "SID-2004",
            "severity": 2,
            "keywords": ["/../../../", "buffer_overflow",
                         "\x90\x90\x90"],
            "desc":     "Path traversal / buffer overflow attempt",
        },
    ]

    def __init__(self):
        self.alerts:          List[SnortAlert] = []
        self.suspicious_ips:  Set[str]         = set()
        self.alert_counter    = 0

    def inspect(self, conn: Connection) -> List[SnortAlert]:
        new_alerts = []
        for rule in self.RULES:
            matched = any(
                kw.lower() in conn.payload.lower()
                for kw in rule["keywords"]
            )
            if matched:
                self.alert_counter += 1
                alert = SnortAlert(
                    conn_id     = conn.conn_id,
                    src_ip      = conn.src_ip,
                    rule_id     = rule["id"],
                    severity    = rule["severity"],
                    description = rule["desc"],
                    timestamp   = conn.timestamp,
                )
                self.alerts.append(alert)
                new_alerts.append(alert)
                # Severity 1 → đưa vào danh sách nghi ngờ
                if rule["severity"] == 1:
                    self.suspicious_ips.add(conn.src_ip)
                break
        return new_alerts

    def analyze_all(self,
                    connections: List[Connection]) -> List[SnortAlert]:
        for conn in connections:
            self.inspect(conn)
        sev1 = sum(1 for a in self.alerts if a.severity == 1)
        sev2 = sum(1 for a in self.alerts if a.severity == 2)
        print(f"[Snort]  Alerts={len(self.alerts)} | "
              f"High={sev1} | Medium={sev2} | "
              f"Suspicious IPs={len(self.suspicious_ips)}")
        return self.alerts