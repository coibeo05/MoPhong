# central_database.py
import pandas as pd
from typing import List
from honeyd_simulator import NetworkPacket
from snort_simulator  import SnortAlert
from ossec_simulator  import OSSECAlert

class CentralDatabase:
    """
    Cơ sở dữ liệu tập trung - lưu trữ dạng tcpdump log
    Tổng hợp dữ liệu từ Honeyd + SNORT + OSSEC
    """

    def __init__(self):
        self.packet_log:  List[dict] = []
        self.snort_log:   List[dict] = []
        self.ossec_log:   List[dict] = []

    def store_packets(self, packets: List[NetworkPacket]):
        for pkt in packets:
            self.packet_log.append({
                "timestamp":    pkt.timestamp,
                "src_ip":       pkt.src_ip,
                "dst_ip":       pkt.dst_ip,
                "src_port":     pkt.src_port,
                "dst_port":     pkt.dst_port,
                "protocol":     pkt.protocol,
                "flags":        pkt.flags,
                "ttl":          pkt.ttl,
                "packet_size":  pkt.packet_size,
                "payload_len":  len(pkt.payload),
                "attack_class": pkt.attack_class,
                # Đặc trưng cho Bayes
                "is_internal_ip": pkt.src_ip.startswith("192.168.1."),
                "high_port":      pkt.dst_port in [22, 445, 3306],
                "large_packet":   pkt.packet_size > 500,
                "has_syn":        "SYN" in pkt.flags,
            })
        print(f"[DB] Stored {len(packets)} packets")

    def store_snort_alerts(self, alerts: List[SnortAlert]):
        for a in alerts:
            self.snort_log.append({
                "timestamp":   a.timestamp,
                "alert_id":    a.alert_id,
                "severity":    a.severity,
                "rule_name":   a.rule_name,
                "src_ip":      a.src_ip,
                "dst_port":    a.dst_port,
                "description": a.description,
            })
        print(f"[DB] Stored {len(alerts)} SNORT alerts")

    def store_ossec_alerts(self, alerts: List[OSSECAlert]):
        for a in alerts:
            self.ossec_log.append({
                "timestamp":    a.timestamp,
                "alert_id":     a.alert_id,
                "level":        a.level,
                "rule_id":      a.rule_id,
                "description":  a.description,
                "src_ip":       a.src_ip,
                "affected_file":a.affected_file,
                "action":       a.action,
                "attack_class": a.attack_class,
            })
        print(f"[DB] Stored {len(alerts)} OSSEC alerts")

    def get_feature_dataframe(self) -> pd.DataFrame:
        return pd.DataFrame(self.packet_log)

    def summary(self):
        df = pd.DataFrame(self.packet_log)
        print(f"\n{'='*40}")
        print(f"  DATABASE SUMMARY")
        print(f"{'='*40}")
        print(f"  Total packets : {len(self.packet_log)}")
        print(f"  SNORT alerts  : {len(self.snort_log)}")
        print(f"  OSSEC alerts  : {len(self.ossec_log)}")
        print(f"  Attack dist   : {df['attack_class'].value_counts().to_dict()}")