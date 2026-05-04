# traffic_generator.py
import random
import time
from dataclasses import dataclass
from typing import List

@dataclass
class Packet:
    src_ip: str
    dst_ip: str
    dst_port: int
    payload: bytes
    timestamp: float
    flags: str        # SYN, SYN-ACK, RST, ACK
    seq_num: int
    ttl: int
    malware_type: str # 'mirai', 'hajime', 'generic', 'web_scan'

def ip_to_int(ip: str) -> int:
    parts = ip.split('.')
    return (int(parts[0]) << 24 | int(parts[1]) << 16 |
            int(parts[2]) << 8  | int(parts[3]))

def generate_mirai_packet(dst_ip: str) -> Packet:
    """
    Mirai đặc trưng: seq_num = dst_ip (dạng integer)
    Quét cổng 23 (Telnet) và 2323
    """
    src_ip = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
    dst_port = random.choice([23, 2323])
    seq_num = ip_to_int(dst_ip)   # đặc trưng nhận dạng Mirai

    payload = b"\x00\x50\x56" + random.randbytes(8)  # Telnet banner probe
    return Packet(
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        payload=payload,
        timestamp=time.time(),
        flags="SYN",
        seq_num=seq_num,
        ttl=64,
        malware_type="mirai"
    )

def generate_web_scan_packet(dst_ip: str) -> Packet:
    """Quét lỗ hổng web qua cổng 80"""
    src_ip = f"10.0.{random.randint(1,254)}.{random.randint(1,254)}"
    payloads = [
        b"GET /phpMyAdmin-2.11.1-all-languages/scripts/setup.php HTTP/1.0\r\n",
        b"GET /phpMyAdmin-3.0.0.0-all-languages/scripts/setup.php HTTP/1.1\r\n",
        b"HEAD / HTTP/1.0\r\n",
        b"HEAD / HTTP/1.1\r\n",
        b"GET /admin/config.php HTTP/1.1\r\nUser-Agent: ZmEu\r\n",
    ]
    return Packet(
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=80,
        payload=random.choice(payloads),
        timestamp=time.time(),
        flags="SYN",
        seq_num=random.randint(1000, 99999),
        ttl=128,
        malware_type="web_scan"
    )

def generate_hajime_packet(dst_ip: str) -> Packet:
    """
    Hajime đặc trưng: 16 bit trên HOẶC dưới của seq_num = 0
    Quét cổng 23
    """
    src_ip = f"172.16.{random.randint(1,254)}.{random.randint(1,254)}"
    base_seq = random.randint(1, 65535)
    seq_num = base_seq << 16   # 16 bit dưới = 0 → đặc trưng Hajime

    return Packet(
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=23,
        payload=b"\xff\xfd\x18\xff\xfd\x20",  # Telnet negotiation
        timestamp=time.time(),
        flags="SYN",
        seq_num=seq_num,
        ttl=64,
        malware_type="hajime"
    )

def generate_traffic(dst_ip: str, n_packets: int = 200) -> List[Packet]:
    """Sinh hỗn hợp các loại gói tin tấn công"""
    packets = []
    generators = [
        (generate_mirai_packet,   0.35),  # 35% Mirai
        (generate_web_scan_packet,0.40),  # 40% web scan
        (generate_hajime_packet,  0.25),  # 25% Hajime
    ]
    for _ in range(n_packets):
        r = random.random()
        cumulative = 0
        for gen_fn, prob in generators:
            cumulative += prob
            if r < cumulative:
                packets.append(gen_fn(dst_ip))
                break
    return packets