# redirector.py
from dataclasses import dataclass
from typing import List
from network_traffic import Connection

@dataclass
class RedirectResult:
    conn_id:      int
    src_ip:       str
    original_dst: str
    final_dst:    str
    redirect_type: str    # 'L2_production'/'L3_deception'
    ttl_original:  int
    ttl_modified:  int
    latency_ms:    float
    description:   str

class HoneyanoleRedirector:
    """
    Mô phỏng Iptables - Mô-đun chuyển hướng Honeyanole

    Layer 2 Redirect (bình thường / thăm dò):
    - Chuyển thẳng đến production server
    - Không thay đổi nội dung gói tin
    - Độ trễ cực thấp → không gây nghi ngờ

    Layer 3 Redirect (tấn công / blacklist):
    - Ngụy trang đích (destination masquerading)
    - Điều chỉnh TTL để che giấu hop thêm
    - Chuyển đến deception server
    """
    PRODUCTION_IP = "192.168.1.10"
    DECEPTION_IPS = {
        "honeyd":    "192.168.1.100",
        "honeytrap": "192.168.1.101",
        "sebek":     "192.168.1.102",
    }

    def __init__(self, blacklist):
        self.blacklist    = blacklist
        self.results:     List[RedirectResult] = []
        self.l2_count     = 0
        self.l3_count     = 0

    def _select_deception_server(self, conn: Connection) -> str:
        """
        Chọn máy chủ đánh lừa phù hợp:
        - Port 22/23    → Honeytrap (SSH/Telnet attacks)
        - Web attacks   → Honeyd
        - Complex attacks → Sebek (high-interaction)
        """
        if conn.dst_port in [22, 23, 21]:
            return "honeytrap", self.DECEPTION_IPS["honeytrap"]
        elif "SHELLCODE" in conn.payload or "buffer" in conn.payload.lower():
            return "sebek", self.DECEPTION_IPS["sebek"]
        else:
            return "honeyd", self.DECEPTION_IPS["honeyd"]

    def _layer2_redirect(self, conn: Connection) -> RedirectResult:
        """
        Chuyển hướng Layer 2:
        - Thay đổi địa chỉ MAC (mô phỏng)
        - Không thay đổi IP header
        - Độ trễ ≈ kết nối trực tiếp
        """
        import random
        latency = random.uniform(0.2, 0.5)   # ms - gần với direct
        self.l2_count += 1
        return RedirectResult(
            conn_id       = conn.conn_id,
            src_ip        = conn.src_ip,
            original_dst  = conn.dst_ip,
            final_dst     = self.PRODUCTION_IP,
            redirect_type = "L2_production",
            ttl_original  = conn.ttl,
            ttl_modified  = conn.ttl,    # TTL không đổi
            latency_ms    = latency,
            description   = "Normal/probe → Production (Apache)",
        )

    def _layer3_redirect(self, conn: Connection) -> RedirectResult:
        """
        Chuyển hướng Layer 3:
        - Destination masquerading: đổi IP đích
        - TTL masquerading: điều chỉnh TTL
          để che giấu thêm 1 hop
        """
        import random
        server_name, deception_ip = self._select_deception_server(conn)
        # TTL giảm đi 1 để che hop chuyển hướng
        ttl_modified = max(conn.ttl - 1, 1)
        latency = random.uniform(0.3, 0.7)   # ms - vẫn thấp
        self.l3_count += 1
        return RedirectResult(
            conn_id       = conn.conn_id,
            src_ip        = conn.src_ip,
            original_dst  = conn.dst_ip,
            final_dst     = deception_ip,
            redirect_type = f"L3_{server_name}",
            ttl_original  = conn.ttl,
            ttl_modified  = ttl_modified,
            latency_ms    = latency,
            description   = f"Attack → {server_name.capitalize()} "
                            f"({deception_ip})",
        )

    def process(self,
                connections: List[Connection]) -> List[RedirectResult]:
        for conn in connections:
            if (self.blacklist.is_blacklisted(conn.src_ip)
                    or conn.conn_type == "attack"):
                result = self._layer3_redirect(conn)
            else:
                result = self._layer2_redirect(conn)
            self.results.append(result)

        print(f"[Redirector] L2(Production)={self.l2_count} | "
              f"L3(Deception)={self.l3_count}")
        return self.results