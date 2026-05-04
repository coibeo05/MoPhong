# blacklist_manager.py
import time
from dataclasses import dataclass, field
from typing import List, Dict, Set
from detection_module import SnortAlert

@dataclass
class BlacklistEntry:
    ip:           str
    score:        int       # điểm nguy hiểm tích lũy
    first_seen:   float
    last_seen:    float
    attack_types: List[str] = field(default_factory=list)
    blocked:      bool      = False

class BlacklistManager:
    """
    Quản lý danh sách đen theo Chương 13:
    Thu thập → Phân tích → Quyết định → Phân phối
    Tích hợp thông tin từ:
      1. Snort alerts
      2. Unauthorized access logs
      3. Probe records
      4. Exchanged defense info
    """
    SCORE_THRESHOLD = 3   # Ngưỡng để block

    def __init__(self):
        self.entries:    Dict[str, BlacklistEntry] = {}
        self.blacklist:  Set[str]                  = set()

    def _get_or_create(self, ip: str) -> BlacklistEntry:
        if ip not in self.entries:
            self.entries[ip] = BlacklistEntry(
                ip         = ip,
                score      = 0,
                first_seen = time.time(),
                last_seen  = time.time(),
                attack_types = [],
            )
        return self.entries[ip]

    def add_from_snort(self, alerts: List[SnortAlert]):
        """Nguồn 1: Snort IDS alerts"""
        for alert in alerts:
            entry = self._get_or_create(alert.src_ip)
            entry.score     += (3 if alert.severity == 1 else 1)
            entry.last_seen  = alert.timestamp
            entry.attack_types.append(alert.description[:30])

    def add_from_probe_log(self, probe_ips: List[str]):
        """Nguồn 3: Ghi nhận thăm dò"""
        for ip in probe_ips:
            entry = self._get_or_create(ip)
            entry.score     += 1
            entry.attack_types.append("probe/fingerprint")

    def add_from_exchange(self, external_ips: List[str]):
        """Nguồn 4: Thông tin phòng thủ trao đổi"""
        for ip in external_ips:
            entry = self._get_or_create(ip)
            entry.score     += 2
            entry.attack_types.append("external_threat_intel")

    def build_blacklist(self) -> Set[str]:
        """Xây dựng danh sách đen từ các entry vượt ngưỡng"""
        self.blacklist.clear()
        for ip, entry in self.entries.items():
            if entry.score >= self.SCORE_THRESHOLD:
                entry.blocked = True
                self.blacklist.add(ip)

        blocked   = sum(1 for e in self.entries.values() if e.blocked)
        monitored = len(self.entries) - blocked
        print(f"[Blacklist] Total IPs tracked={len(self.entries)} | "
              f"Blocked={blocked} | Monitored={monitored}")
        return self.blacklist

    def is_blacklisted(self, ip: str) -> bool:
        return ip in self.blacklist

    def get_top_threats(self, n: int = 5) -> List[BlacklistEntry]:
        blocked = [e for e in self.entries.values() if e.blocked]
        return sorted(blocked,
                      key=lambda e: e.score,
                      reverse=True)[:n]