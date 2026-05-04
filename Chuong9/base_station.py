# base_station.py
import time
from dataclasses import dataclass, field
from typing import List, Dict, Tuple
from tinymt_prng     import TinyMT
from secure_channel  import SecureChannel, CoordinationMessage
from decoy_node      import TransmittedPacket

@dataclass
class WindowAnalysis:
    """Kết quả phân tích một cửa sổ thời gian"""
    window_id:       int
    node_id:         str
    total_packets:   int
    received:        int
    lost:            int
    tampered:        int
    avg_delay_ms:    float
    loss_rate:       float
    attack_detected: bool
    attack_type:     str
    alert_reason:    str

@dataclass
class AttackAlert:
    """Cảnh báo tấn công"""
    alert_id:    int
    timestamp:   float
    node_id:     str
    attack_type: str
    severity:    str    # 'HIGH'/'MEDIUM'/'LOW'
    evidence:    str

class BaseStation:
    """
    Trạm gốc (Base Station) trong BAN Honeypot

    Nhiệm vụ:
    1. Gửi tin điều phối cho nút mồi
    2. Nhận và xác minh dữ liệu honeypot
    3. So sánh với dữ liệu đã biết trước (ground truth)
    4. Duy trì cửa sổ thời gian n=10, ngưỡng k=4
    5. Phát cảnh báo khi phát hiện tấn công
    """

    WINDOW_SIZE = 10    # n = 10
    THRESHOLD_K = 4     # k = 4 (ngưỡng mất gói)
    DELAY_THRESHOLD_MS = 50.0   # ngưỡng trễ bất thường

    def __init__(self, bs_id: str = "BS_001"):
        self.bs_id   = bs_id
        self.channel = SecureChannel()
        self.alerts: List[AttackAlert] = []
        self.window_results: List[WindowAnalysis] = []
        self.alert_counter = 0
        # Ground truth PRNGs (biết trước seed)
        self.node_prngs: Dict[str, TinyMT] = {}

    def register_node(self,
                      node_id: str,
                      seed: int):
        """Đăng ký nút mồi và tạo PRNG xác minh"""
        self.node_prngs[node_id] = TinyMT(seed)
        print(f"  [BS] Registered node {node_id} "
              f"with seed={seed}")

    def send_coordination(self,
                          node_id: str,
                          activity: str = "walking") -> object:
        """Gửi tin điều phối qua kênh bảo mật cao"""
        import random
        coord = CoordinationMessage(
            data_type    = "accelerometer",
            frequency_hz = 10.0,
            seed         = random.randint(1000, 9999),
            window_size  = self.WINDOW_SIZE,
            threshold_k  = self.THRESHOLD_K,
        )
        msg = self.channel.encrypt_coordination(
            coord, self.bs_id, node_id
        )
        print(f"  [BS → {node_id}] Coordination sent | "
              f"seed={coord.seed} | "
              f"freq={coord.frequency_hz}Hz")
        return msg

    def _verify_data_integrity(self,
                               pkt: TransmittedPacket,
                               node_id: str) -> bool:
        """
        Xác minh tính toàn vẹn dữ liệu
        So sánh noise sequence với PRNG đã biết
        """
        if node_id not in self.node_prngs:
            return False

        prng     = self.node_prngs[node_id]
        expected = prng.generate_noise(3, scale=0.015)

        # So sánh noise (tolerance ±0.001)
        for recv, exp in zip(pkt.noise_applied, expected):
            if abs(recv - exp) > 0.001:
                return False   # Dữ liệu bị giả mạo!
        return True

    def analyze_window(self,
                       window_id: int,
                       node_id: str,
                       packets: List[TransmittedPacket]
                       ) -> WindowAnalysis:
        """
        Phân tích cửa sổ n=10 gói tin
        Áp dụng ngưỡng k=4
        """
        n_total    = len(packets)
        n_lost     = sum(1 for p in packets if p.is_lost)
        n_received = n_total - n_lost
        n_tampered = sum(1 for p in packets if p.is_tampered)

        delays     = [p.delay_ms for p in packets
                      if not p.is_lost]
        avg_delay  = (sum(delays)/len(delays)
                      if delays else 0.0)
        loss_rate  = n_lost / n_total

        # ── Phát hiện tấn công ───────────────────────────────────
        attack_detected = False
        attack_type     = "None"
        alert_reason    = ""

        # Tiêu chí 1: Mất gói vượt ngưỡng k=4
        if n_lost >= self.THRESHOLD_K:
            attack_detected = True
            attack_type     = "Packet Loss Attack"
            alert_reason    = (f"Lost {n_lost}/{n_total} packets "
                               f"≥ threshold k={self.THRESHOLD_K}")

        # Tiêu chí 2: Độ trễ bất thường
        if avg_delay > self.DELAY_THRESHOLD_MS:
            attack_detected = True
            attack_type     = "Delay-based Attack (MITM)"
            alert_reason    += (f" | Avg delay {avg_delay:.1f}ms "
                                f"> {self.DELAY_THRESHOLD_MS}ms")

        # Tiêu chí 3: Phát hiện giả mạo dữ liệu
        if n_tampered > 0:
            attack_detected = True
            attack_type     = "Data Tampering"
            alert_reason   += (f" | {n_tampered} packets "
                               f"tampered (PRNG mismatch)")

        result = WindowAnalysis(
            window_id       = window_id,
            node_id         = node_id,
            total_packets   = n_total,
            received        = n_received,
            lost            = n_lost,
            tampered        = n_tampered,
            avg_delay_ms    = round(avg_delay, 2),
            loss_rate       = round(loss_rate, 3),
            attack_detected = attack_detected,
            attack_type     = attack_type,
            alert_reason    = alert_reason,
        )

        if attack_detected:
            self._issue_alert(node_id, result)

        self.window_results.append(result)
        return result

    def _issue_alert(self,
                     node_id: str,
                     analysis: WindowAnalysis):
        """Phát cảnh báo tấn công"""
        self.alert_counter += 1

        # Xác định mức độ nghiêm trọng
        if analysis.loss_rate >= 0.7:
            severity = "HIGH"
        elif analysis.loss_rate >= 0.4:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        alert = AttackAlert(
            alert_id    = self.alert_counter,
            timestamp   = time.time(),
            node_id     = node_id,
            attack_type = analysis.attack_type,
            severity    = severity,
            evidence    = analysis.alert_reason,
        )
        self.alerts.append(alert)
        emoji = ("🔴" if severity == "HIGH"
                 else "🟠" if severity == "MEDIUM"
                 else "🟡")
        print(f"  {emoji} [ALERT #{self.alert_counter}] "
              f"Node={node_id} | {analysis.attack_type} | "
              f"{severity}")

    def get_detection_summary(self) -> Dict:
        """Tổng hợp kết quả phát hiện"""
        total_windows    = len(self.window_results)
        attacked_windows = sum(
            1 for w in self.window_results
            if w.attack_detected
        )
        attack_types = {}
        for w in self.window_results:
            if w.attack_detected:
                t = w.attack_type
                attack_types[t] = attack_types.get(t, 0) + 1

        return {
            "total_windows":    total_windows,
            "attacked_windows": attacked_windows,
            "clean_windows":    total_windows - attacked_windows,
            "detection_rate":   (attacked_windows/total_windows*100
                                 if total_windows > 0 else 0),
            "total_alerts":     len(self.alerts),
            "attack_types":     attack_types,
            "high_alerts":      sum(1 for a in self.alerts
                                    if a.severity == "HIGH"),
            "medium_alerts":    sum(1 for a in self.alerts
                                    if a.severity == "MEDIUM"),
            "low_alerts":       sum(1 for a in self.alerts
                                    if a.severity == "LOW"),
        }