# honeypot.py
from traffic_generator import Packet
from typing import List, Dict
import time

class LowInteractionHoneypot:
    """
    Mô phỏng Lurker:
    - Chỉ phản hồi TCP SYN và ICMP Echo
    - Thu thập payload đầu tiên sau handshake
    - Gán Stream ID cho mỗi luồng
    """
    def __init__(self, node_id: str, location: str):
        self.node_id = node_id
        self.location = location          # 'near_darknet' hoặc 'far_darknet'
        self.captured_streams: List[Dict] = []
        self.stream_counter = 0

    def _is_mirai_signature(self, pkt: Packet) -> bool:
        """Kiểm tra đặc trưng Mirai: seq = dst_ip"""
        from traffic_generator import ip_to_int
        return pkt.seq_num == ip_to_int(pkt.dst_ip)

    def _is_hajime_signature(self, pkt: Packet) -> bool:
        """Kiểm tra đặc trưng Hajime: 16 bit dưới của seq = 0"""
        return (pkt.seq_num & 0xFFFF) == 0

    def _detect_malware_type(self, pkt: Packet) -> str:
        if self._is_mirai_signature(pkt):
            return "mirai"
        elif self._is_hajime_signature(pkt):
            return "hajime"
        return "unknown"

    def process_packet(self, pkt: Packet) -> Dict:
        """
        Xử lý gói SYN đến:
        1. Gửi SYN-ACK (mô phỏng)
        2. Thu thập payload
        3. Gán stream ID
        """
        if pkt.flags != "SYN":
            return None

        self.stream_counter += 1
        detected_type = self._detect_malware_type(pkt)

        stream = {
            "stream_id":    f"{self.node_id}_stream_{self.stream_counter:04d}",
            "src_ip":       pkt.src_ip,
            "dst_ip":       pkt.dst_ip,
            "dst_port":     pkt.dst_port,
            "payload":      pkt.payload,
            "timestamp":    pkt.timestamp,
            "seq_num":      pkt.seq_num,
            "ttl":          pkt.ttl,
            "detected_type":detected_type,
            "honeypot_node":self.node_id,
            "location":     self.location,
        }
        self.captured_streams.append(stream)
        return stream

    def capture_all(self, packets: List[Packet]) -> List[Dict]:
        results = []
        for pkt in packets:
            s = self.process_packet(pkt)
            if s:
                results.append(s)
        print(f"[{self.node_id}] Captured {len(results)} streams "
              f"({self.location})")
        return results