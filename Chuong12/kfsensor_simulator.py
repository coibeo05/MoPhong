# kfsensor_simulator.py
import random
from dataclasses import dataclass
from typing import List

@dataclass
class NetworkObservation:
    """Quan sát lưu lượng mạng tại một thời điểm"""
    obs_id:       int
    rtipa:        float   # Trusted IP rate (pkt/s)
    uarpp:        float   # Unusual ARP packets (pkt/s)
    rarpp:        float   # ARP packet rate (pkt/s)
    attack_type:  str     # 'ip_spoofing'/'arp_spoofing'/'normal'
    description:  str

class KFSensorSimulator:
    """
    Mô phỏng KFSensor honeypot + Nmap Idle Scan attack
    Tái hiện thí nghiệm Chương 12:
    - Kẻ tấn công 192.168.0.50 dùng Nmap idle scan
    - Ngụy trang bằng IP nạn nhân 192.168.0.160
    - Tấn công honeypot 192.168.0.175
    """

    def _normal_observation(self, obs_id: int) -> NetworkObservation:
        return NetworkObservation(
            obs_id      = obs_id,
            rtipa       = random.uniform(80,  180),
            uarpp       = random.uniform(10,  20),
            rarpp       = random.uniform(50,  120),
            attack_type = "normal",
            description = "Normal network traffic"
        )

    def _ip_spoofing_attack(self, obs_id: int) -> NetworkObservation:
        """
        IP Spoofing: gửi ồ ạt gói tin từ IP tin cậy giả mạo
        → RTIPA tăng cao (DOS-like)
        """
        return NetworkObservation(
            obs_id      = obs_id,
            rtipa       = random.uniform(350, 500),
            uarpp       = random.uniform(10,  25),
            rarpp       = random.uniform(50,  150),
            attack_type = "ip_spoofing",
            description = "Nmap idle scan - IP spoofing via "
                          "192.168.0.160 → targeting 192.168.0.175"
        )

    def _arp_spoofing_attack(self, obs_id: int) -> NetworkObservation:
        """
        ARP Spoofing: gửi ARP reply giả mạo → chiếm MAC table
        → UARPP và RARPP tăng cao
        """
        return NetworkObservation(
            obs_id      = obs_id,
            rtipa       = random.uniform(80,  200),
            uarpp       = random.uniform(40,  60),
            rarpp       = random.uniform(200, 300),
            attack_type = "arp_spoofing",
            description = "ARP spoofing - MITM attempt on LAN"
        )

    def _combined_attack(self, obs_id: int) -> NetworkObservation:
        """Kết hợp cả IP và ARP spoofing"""
        return NetworkObservation(
            obs_id      = obs_id,
            rtipa       = random.uniform(300, 500),
            uarpp       = random.uniform(40,  60),
            rarpp       = random.uniform(200, 300),
            attack_type = "combined_spoofing",
            description = "Combined IP+ARP spoofing attack"
        )

    def generate_observations(self, n: int = 30) -> List[NetworkObservation]:
        observations = []
        for i in range(1, n + 1):
            r = random.random()
            if r < 0.30:
                obs = self._normal_observation(i)
            elif r < 0.55:
                obs = self._ip_spoofing_attack(i)
            elif r < 0.80:
                obs = self._arp_spoofing_attack(i)
            else:
                obs = self._combined_attack(i)
            observations.append(obs)

        # ── 6 case cố định từ Bảng I Chương 12 ──────────────────
        # Obs.100: RTIPA=452 (High), UARPP=22 (Low), RARPP=113 (Low)
        #          → SAP MEDIUM (~50%)
        # Obs.101: RTIPA=198 (Low),  UARPP=37 (Medium), RARPP=187 (Medium)
        #          → SAP MEDIUM (~50%)
        # Obs.102: RTIPA=321 (Medium), UARPP=53 (High), RARPP=255 (High)
        #          → SAP HIGH (~80%)  ← đã sửa RARPP từ 20 → 255
        # Obs.103: RTIPA=87  (Low),  UARPP=13 (Low), RARPP=78 (Low)
        #          → SAP LOW (~20%)
        # Obs.104: RTIPA=277 (Medium), UARPP=40 (Medium), RARPP=122 (Low-Med)
        #          → SAP MEDIUM (~50%)
        # Obs.105: RTIPA=386 (High), UARPP=51 (High), RARPP=254 (High)
        #          → SAP HIGH (~80%)
        fixed_cases = [
            NetworkObservation(
                100, 452, 22, 113,
                "ip_spoofing",
                "Table I - Obs.1 | RTIPA=High, UARPP=Low, RARPP=Low"
            ),
            NetworkObservation(
                101, 198, 37, 187,
                "arp_spoofing",
                "Table I - Obs.2 | RTIPA=Low, UARPP=Medium, RARPP=Medium"
            ),
            NetworkObservation(
                102, 321, 53, 255,          # ← RARPP sửa 20 → 255
                "combined_spoofing",
                "Table I - Obs.3 | RTIPA=Medium, UARPP=High, RARPP=High"
            ),
            NetworkObservation(
                103, 87, 13, 78,
                "normal",
                "Table I - Obs.4 | RTIPA=Low, UARPP=Low, RARPP=Low"
            ),
            NetworkObservation(
                104, 277, 40, 122,
                "arp_spoofing",
                "Table I - Obs.5 | RTIPA=Medium, UARPP=Medium, RARPP=Low"
            ),
            NetworkObservation(
                105, 386, 51, 254,
                "combined_spoofing",
                "Table I - Obs.6 | RTIPA=High, UARPP=High, RARPP=High"
            ),
        ]
        observations.extend(fixed_cases)
        return observations