# attack_estimator.py
from typing import List, Dict

class AttackScaleEstimator:

    def _is_mirai(self, seq: int, dst_ip: str) -> bool:
        from traffic_generator import ip_to_int
        return seq == ip_to_int(dst_ip)

    def _is_hajime(self, seq: int) -> bool:
        return (seq & 0xFFFF) == 0

    def correlate(self,
                  streams: List[Dict],
                  darknet_packets: List[Dict],
                  time_window: float = 3600.0) -> List[Dict]:

        results = []
        for stream in streams:
            t0   = stream["timestamp"]
            t1   = t0 + time_window
            port = stream["dst_port"]
            seq  = stream["seq_num"]
            src  = stream["src_ip"]

            if self._is_mirai(seq, stream["dst_ip"]):
                match_type = "mirai_signature"
                # Khớp theo cổng + thời gian + đặc trưng Mirai
                matched = [
                    p for p in darknet_packets
                    if p["dst_port"] == port
                    and t0 <= p["timestamp"] <= t1
                    and (self._is_mirai(p["seq_num"], p["dst_ip"])
                         or p["malware_type"] == "mirai")
                ]

            elif self._is_hajime(seq):
                match_type = "hajime_signature"
                matched = [
                    p for p in darknet_packets
                    if p["dst_port"] == port
                    and t0 <= p["timestamp"] <= t1
                    and (self._is_hajime(p["seq_num"])
                         or p["malware_type"] == "hajime")
                ]

            else:
                match_type = "source_ip"
                # Khớp theo cổng + thời gian + loại web_scan
                matched = [
                    p for p in darknet_packets
                    if p["dst_port"] == port
                    and t0 <= p["timestamp"] <= t1
                    and p["malware_type"] == "web_scan"
                ]

            results.append({
                "stream_id":     stream["stream_id"],
                "src_ip":        src,
                "dst_port":      port,
                "match_type":    match_type,
                "darknet_hits":  len(matched),
                "timestamp":     t0,
                "detected_type": stream["detected_type"],
            })

        return results