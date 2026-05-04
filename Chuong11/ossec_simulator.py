# ossec_simulator.py
import random
from dataclasses import dataclass
from typing import List
from honeyd_simulator import NetworkPacket

@dataclass
class OSSECAlert:
    timestamp:    float
    alert_id:     str
    level:        int       # 0-15 (OSSEC scale)
    rule_id:      str
    description:  str
    src_ip:       str
    affected_file: str
    action:       str       # email / block / log
    attack_class: str

class OSSECSimulator:
    """
    Mô phỏng OSSEC - Host IDS
    Giám sát:
      - File integrity (checksum)
      - Log analysis (predecoding → decoding → rule matching)
      - Brute force detection
    """

    LOG_FILES = [
        "/var/log/auth.log",
        "/var/log/syslog",
        "/var/log/apache2/access.log",
        "/var/log/mysql/error.log",
        "C:\\Windows\\System32\\winevt\\Security.evtx",
    ]

    OSSEC_RULES = [
        {
            "rule_id": "OSSEC-5503",
            "level":   10,
            "desc":    "User authentication failure (brute force)",
            "triggers":["SSH-2.0", "POST /login", "net user"],
            "file":    "/var/log/auth.log",
            "class":   "internal",
        },
        {
            "rule_id": "OSSEC-5501",
            "level":   12,
            "desc":    "File integrity violation detected",
            "triggers":["chmod 777", "reg add", "/etc/shadow"],
            "file":    "/etc/passwd",
            "class":   "internal",
        },
        {
            "rule_id": "OSSEC-31103",
            "level":   9,
            "desc":    "Web attack - SQL injection",
            "triggers":["SELECT", "DROP TABLE", "1=1"],
            "file":    "/var/log/apache2/access.log",
            "class":   "external",
        },
        {
            "rule_id": "OSSEC-1002",
            "level":   7,
            "desc":    "Unknown problem somewhere in the system",
            "triggers":["EXPLOIT", "OVERFLOW"],
            "file":    "/var/log/syslog",
            "class":   "external",
        },
        {
            "rule_id": "OSSEC-5304",
            "level":   8,
            "desc":    "Data exfiltration attempt via network",
            "triggers":["nc attacker", "4444", "/etc/passwd"],
            "file":    "/var/log/syslog",
            "class":   "internal",
        },
    ]

    def __init__(self):
        self.alerts: List[OSSECAlert] = []
        self.counter = 0

    def _process_log(self, pkt: NetworkPacket):
        """
        Quy trình OSSEC:
        Pre-decoding → Decoding → Rule matching → Alert
        """
        for rule in self.OSSEC_RULES:
            for trigger in rule["triggers"]:
                if trigger.lower() in pkt.payload.lower():
                    self.counter += 1
                    level = rule["level"]
                    action = ("email+block" if level >= 12
                              else "email" if level >= 9
                              else "log")
                    alert = OSSECAlert(
                        timestamp    = pkt.timestamp,
                        alert_id     = f"OSSEC-{self.counter:05d}",
                        level        = level,
                        rule_id      = rule["rule_id"],
                        description  = rule["desc"],
                        src_ip       = pkt.src_ip,
                        affected_file= rule["file"],
                        action       = action,
                        attack_class = rule["class"],
                    )
                    self.alerts.append(alert)
                    break

    def analyze_all(self, packets: List[NetworkPacket]) -> List[OSSECAlert]:
        for pkt in packets:
            self._process_log(pkt)
        high   = sum(1 for a in self.alerts if a.level >= 10)
        medium = sum(1 for a in self.alerts if 7 <= a.level < 10)
        low    = sum(1 for a in self.alerts if a.level < 7)
        print(f"[OSSEC] Generated {len(self.alerts)} alerts | "
              f"High(≥10)={high} | Medium(7-9)={medium} | Low(<7)={low}")
        return self.alerts