# honeyanole.py
from typing import List
from network_traffic  import TrafficGenerator, Connection
from detection_module import SnortDetector
from blacklist_manager import BlacklistManager
from redirector        import HoneyanoleRedirector
from deception_server  import DeceptionServer

class Honeyanole:
    """
    Hệ thống Honeyanole hoàn chỉnh - Chương 13
    3 giai đoạn:
      Phase 1: Collection  - Thu thập & xây dựng blacklist
      Phase 2: Redirection - Chuyển hướng L2/L3
      Phase 3: Deception   - Đánh lừa & ghi nhận tấn công
    """

    def __init__(self):
        self.snort      = SnortDetector()
        self.blacklist  = BlacklistManager()
        self.deception  = DeceptionServer()
        self.connections: List[Connection] = []

    def phase1_collection(self,
                          connections: List[Connection]):
        """
        Phase 1: Thu thập thông tin tấn công
        Snort mirror → Alerts → Blacklist
        """
        print("\n── PHASE 1: COLLECTION ──────────────────────")

        # Snort phân tích traffic được mirror
        alerts = self.snort.analyze_all(connections)

        # Xây dựng blacklist từ nhiều nguồn
        self.blacklist.add_from_snort(alerts)

        # Nguồn 3: IPs từ probe connections
        probe_ips = [c.src_ip for c in connections
                     if c.conn_type == "probe"]
        self.blacklist.add_from_probe_log(probe_ips)

        # Nguồn 4: Threat intelligence bên ngoài
        external_threats = [
            "45.33.32.156",    # known scanner
            "198.20.69.74",    # shodan crawler
            "216.244.66.229",  # masscan user
        ]
        self.blacklist.add_from_exchange(external_threats)

        # Build final blacklist
        bl = self.blacklist.build_blacklist()

        print(f"\n  Top threats:")
        for entry in self.blacklist.get_top_threats(5):
            print(f"  [{entry.ip}] score={entry.score} | "
                  f"types={set(entry.attack_types[:2])}")
        return bl

    def phase2_redirection(self,
                           connections: List[Connection]):
        """
        Phase 2: Chuyển hướng L2/L3
        """
        print("\n── PHASE 2: REDIRECTION ────────────────────")
        redirector = HoneyanoleRedirector(self.blacklist)
        results    = redirector.process(connections)

        # Thống kê latency
        l2_lat = [r.latency_ms for r in results
                  if r.redirect_type == "L2_production"]
        l3_lat = [r.latency_ms for r in results
                  if r.redirect_type.startswith("L3")]

        if l2_lat:
            print(f"  L2 avg latency: {sum(l2_lat)/len(l2_lat):.3f} ms")
        if l3_lat:
            print(f"  L3 avg latency: {sum(l3_lat)/len(l3_lat):.3f} ms")
        return results, redirector

    def phase3_deception(self,
                         redirect_results,
                         connections):
        """
        Phase 3: Máy chủ đánh lừa ghi nhận tấn công
        """
        print("\n── PHASE 3: DECEPTION ──────────────────────")
        records = self.deception.receive(
            redirect_results, connections
        )
        return records

    def run(self, connections: List[Connection]):
        self.connections = connections
        bl      = self.phase1_collection(connections)
        results, redirector = self.phase2_redirection(connections)
        records = self.phase3_deception(results, connections)
        return results, records, redirector