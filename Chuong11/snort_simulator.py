# snort_simulator.py
from dataclasses import dataclass
from typing import List, Dict
from honeyd_simulator import NetworkPacket

@dataclass
class SnortAlert:
    timestamp:   float
    alert_id:    str
    severity:    int        # 1=High, 2=Medium, 3=Low
    rule_name:   str
    src_ip:      str
    dst_ip:      str
    dst_port:    int
    protocol:    str
    description: str
    packet_ref:  NetworkPacket

class SnortSimulator:
    """
    Mô phỏng SNORT - Network IDS
    Phân tích gói tin bằng Deep Packet Inspection
    So khớp payload với signature rules
    """

    RULES = [
        {
            "id":       "SID-1001",
            "name":     "SQL_INJECTION_ATTEMPT",
            "severity": 1,
            "keywords": ["SELECT", "DROP TABLE", "1=1", "UNION"],
            "desc":     "SQL Injection attempt detected",
        },
        {
            "id":       "SID-1002",
            "name":     "BRUTE_FORCE_SSH",
            "severity": 1,
            "keywords": ["SSH-2.0", "SSH-1."],
            "desc":     "SSH brute force attempt",
            "port":     22,
        },
        {
            "id":       "SID-1003",
            "name":     "WEB_SCAN_PHPMYADMIN",
            "severity": 2,
            "keywords": ["phpMyAdmin", "wp-admin", "admin-ajax"],
            "desc":     "Web vulnerability scan detected",
        },
        {
            "id":       "SID-1004",
            "name":     "PRIVILEGE_ESCALATION",
            "severity": 1,
            "keywords": ["sudo su", "chmod 777", "net user administrator"],
            "desc":     "Privilege escalation attempt",
        },
        {
            "id":       "SID-1005",
            "name":     "DATA_EXFILTRATION",
            "severity": 1,
            "keywords": ["nc attacker", "/etc/passwd", "4444"],
            "desc":     "Possible data exfiltration",
        },
        {
            "id":       "SID-1006",
            "name":     "BUFFER_OVERFLOW",
            "severity": 1,
            "keywords": ["EXPLOIT", "OVERFLOW", "\x00\x50\x56"],
            "desc":     "Buffer overflow exploit attempt",
        },
        {
            "id":       "SID-1007",
            "name":     "FTP_ANONYMOUS_LOGIN",
            "severity": 3,
            "keywords": ["USER anonymous", "PASS guest"],
            "desc":     "FTP anonymous login attempt",
            "port":     21,
        },
        {
            "id":       "SID-1008",
            "name":     "REGISTRY_MODIFICATION",
            "severity": 2,
            "keywords": ["reg add", "HKLM", "SAM"],
            "desc":     "Windows registry modification attempt",
        },
    ]

    def __init__(self):
        self.alerts: List[SnortAlert] = []
        self.alert_counter = 0

    def _match_rules(self, pkt: NetworkPacket) -> List[Dict]:
        matched = []
        for rule in self.RULES:
            for kw in rule["keywords"]:
                if kw.lower() in pkt.payload.lower():
                    matched.append(rule)
                    break
        return matched

    def inspect_packet(self, pkt: NetworkPacket) -> List[SnortAlert]:
        new_alerts = []
        matched_rules = self._match_rules(pkt)
        for rule in matched_rules:
            self.alert_counter += 1
            alert = SnortAlert(
                timestamp   = pkt.timestamp,
                alert_id    = f"SNORT-{self.alert_counter:05d}",
                severity    = rule["severity"],
                rule_name   = rule["name"],
                src_ip      = pkt.src_ip,
                dst_ip      = pkt.dst_ip,
                dst_port    = pkt.dst_port,
                protocol    = pkt.protocol,
                description = rule["desc"],
                packet_ref  = pkt,
            )
            self.alerts.append(alert)
            new_alerts.append(alert)
        return new_alerts

    def analyze_all(self, packets: List[NetworkPacket]) -> List[SnortAlert]:
        for pkt in packets:
            self.inspect_packet(pkt)
        sev1 = sum(1 for a in self.alerts if a.severity == 1)
        sev2 = sum(1 for a in self.alerts if a.severity == 2)
        sev3 = sum(1 for a in self.alerts if a.severity == 3)
        print(f"[SNORT] Generated {len(self.alerts)} alerts | "
              f"High={sev1} | Medium={sev2} | Low={sev3}")
        return self.alerts