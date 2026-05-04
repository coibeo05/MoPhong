# darknet_sensor.py
from traffic_generator import Packet, ip_to_int
from typing import List, Dict

class DarknetSensor:
    """
    Giám sát không gian /24 (256 địa chỉ IP không sử dụng).
    Ghi nhận mọi gói tin đến — chủ yếu là TCP SYN.
    """
    def __init__(self, network_prefix: str = "10.0.99"):
        self.network_prefix = network_prefix
        self.observed_packets: List[Dict] = []

    def _is_darknet_target(self, dst_ip: str) -> bool:
        return dst_ip.startswith(self.network_prefix)

    def observe(self, packets: List[Packet]) -> List[Dict]:
        for pkt in packets:
            if self._is_darknet_target(pkt.dst_ip):
                record = {
                    "src_ip":    pkt.src_ip,
                    "dst_ip":    pkt.dst_ip,
                    "dst_port":  pkt.dst_port,
                    "timestamp": pkt.timestamp,
                    "seq_num":   pkt.seq_num,
                    "ttl":       pkt.ttl,
                    "flags":     pkt.flags,
                    "malware_type": pkt.malware_type,
                }
                self.observed_packets.append(record)

        print(f"[Darknet] Observed {len(self.observed_packets)} packets "
              f"on {self.network_prefix}.0/24")
        return self.observed_packets