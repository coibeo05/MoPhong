# attack_simulator.py
import random
from dataclasses import dataclass
from typing import List
from decoy_node  import DecoyNode, TransmittedPacket

@dataclass
class AttackScenario:
    """Kịch bản tấn công"""
    name:        str
    attack_type: str
    description: str
    n_windows:   int
    expected_loss_rate: float

class AttackSimulator:
    """
    Mô phỏng 3 loại tấn công trên BAN:

    1. MITM (Man-in-the-Middle):
       - Chặn và sửa gói tin giữa nút và trạm gốc
       - Gây trễ cao + giả mạo dữ liệu
       - Phát hiện: delay tăng + PRNG mismatch

    2. Node Spoofing (Giả mạo nút):
       - Kẻ tấn công giả làm nút mồi hợp lệ
       - Gửi dữ liệu không có noise TinyMT đúng
       - Phát hiện: PRNG mismatch + loss pattern

    3. BS Spoofing (Giả mạo trạm gốc):
       - Kẻ tấn công giả làm trạm gốc
       - Gửi seed sai → nút dùng PRNG sai
       - Phát hiện: MAC verification fail
    """

    SCENARIOS = [
        AttackScenario(
            name        = "Normal Operation",
            attack_type = None,
            description = "Hoạt động bình thường, không tấn công",
            n_windows   = 5,
            expected_loss_rate = 0.05,
        ),
        AttackScenario(
            name        = "MITM Attack",
            attack_type = "mitm",
            description = "Man-in-the-Middle: chặn và sửa gói tin",
            n_windows   = 5,
            expected_loss_rate = 0.35,
        ),
        AttackScenario(
            name        = "Node Spoofing",
            attack_type = "node_spoof",
            description = "Giả mạo nút mồi hợp lệ",
            n_windows   = 5,
            expected_loss_rate = 0.20,
        ),
        AttackScenario(
            name        = "BS Spoofing",
            attack_type = "bs_spoof",
            description = "Giả mạo trạm gốc",
            n_windows   = 5,
            expected_loss_rate = 0.15,
        ),
    ]

    def run_scenario(self,
                     scenario: AttackScenario,
                     node: DecoyNode) -> List[List[TransmittedPacket]]:
        """Chạy một kịch bản tấn công"""
        all_windows = []
        for w in range(scenario.n_windows):
            window_start = w * node.config.window_size
            packets = node.transmit_window(
                window_start,
                attack_mode=scenario.attack_type
            )
            all_windows.append(packets)
        return all_windows

    def run_all_scenarios(self,
                          nodes: List[DecoyNode]
                          ) -> List[dict]:
        """Chạy tất cả kịch bản trên các nút"""
        results = []
        for scenario in self.SCENARIOS:
            node     = random.choice(nodes)
            windows  = self.run_scenario(scenario, node)
            results.append({
                "scenario": scenario,
                "node_id":  node.node_id,
                "windows":  windows,
            })
        return results