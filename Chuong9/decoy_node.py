# decoy_node.py
import time
import random
from dataclasses import dataclass, field
from typing import List, Optional
from accelerometer_data import UCIAccelerometerData, AccelSample
from tinymt_prng        import TinyMT
from secure_channel     import SecureChannel, CoordinationMessage

@dataclass
class TransmittedPacket:
    """Gói tin được truyền từ nút mồi"""
    packet_id:     int
    node_id:       str
    timestamp:     float
    sequence_num:  int
    accel_data:    AccelSample
    noise_applied: List[float]
    is_lost:       bool    = False
    delay_ms:      float   = 0.0
    is_tampered:   bool    = False

@dataclass
class DecoyNodeConfig:
    """Cấu hình nút mồi nhận từ trạm gốc"""
    data_type:    str    = "accelerometer"
    frequency_hz: float  = 10.0
    seed:         int    = 42
    window_size:  int    = 10
    threshold_k:  int    = 4
    activity:     str    = "walking"

class DecoyNode:
    """
    Nút mồi (Decoy Node) trong mạng BAN Honeypot

    Nhiệm vụ:
    1. Nhận cấu hình từ trạm gốc qua kênh bảo mật cao
    2. Tải dữ liệu gia tốc kế UCI
    3. Thêm nhiễu TinyMT để tránh nhận dạng
    4. Gửi dữ liệu qua kênh bảo mật thích ứng
    5. Duy trì cửa sổ thời gian n=10
    """

    def __init__(self,
                 node_id: str,
                 config: DecoyNodeConfig = None):
        self.node_id    = node_id
        self.config     = config or DecoyNodeConfig()
        self.channel    = SecureChannel()
        self.accel_db   = UCIAccelerometerData()
        self.prng       = TinyMT(self.config.seed)
        self.packet_counter = 0
        self.transmitted: List[TransmittedPacket] = []

        # Tải dữ liệu honeypot
        self.honeypot_data = self.accel_db.generate_honeypot_data(
            activity   = self.config.activity,
            n_samples  = 500,
            seed       = self.config.seed,
            noise_seed = self.config.seed + 1000,
        )
        print(f"  [Node {self.node_id}] Initialized | "
              f"activity={self.config.activity} | "
              f"seed={self.config.seed} | "
              f"data={len(self.honeypot_data)} samples")

    def receive_coordination(self,
                             coord_msg) -> bool:
        """Nhận và xử lý tin điều phối từ trạm gốc"""
        is_valid, payload = self.channel.verify_and_decrypt(
            coord_msg
        )
        if is_valid:
            parts = payload.decode().split('|')
            self.config.data_type    = parts[0]
            self.config.frequency_hz = float(parts[1])
            self.config.seed         = int(parts[2])
            self.config.window_size  = int(parts[3])
            self.config.threshold_k  = int(parts[4])
            # Cập nhật PRNG với seed mới
            self.prng = TinyMT(self.config.seed)
            return True
        return False

    def transmit_packet(self,
                        seq_num: int,
                        attack_mode: str = None) -> TransmittedPacket:
        """
        Truyền một gói tin honeypot

        attack_mode: None/'mitm'/'node_spoof'/'bs_spoof'
        """
        self.packet_counter += 1
        # Lấy sample từ buffer xoay vòng
        sample_idx = seq_num % len(self.honeypot_data)
        sample     = self.honeypot_data[sample_idx]

        # Tạo nhiễu từ TinyMT
        noise = self.prng.generate_noise(3, scale=0.015)

        # Áp dụng nhiễu vào dữ liệu
        from accelerometer_data import AccelSample as AS
        noisy_sample = AS(
            timestamp = sample.timestamp,
            x         = sample.x + noise[0],
            y         = sample.y + noise[1],
            z         = sample.z + noise[2],
            activity  = sample.activity,
        )

        # Mô phỏng mất gói và trễ mạng
        loss_prob  = 0.05    # 5% mất gói bình thường
        delay_base = random.uniform(1, 10)   # ms

        if attack_mode == "mitm":
            loss_prob  = 0.35   # MITM gây mất gói nhiều hơn
            delay_base = random.uniform(20, 80)  # trễ cao hơn
        elif attack_mode == "node_spoof":
            loss_prob  = 0.20
            delay_base = random.uniform(5, 30)
        elif attack_mode == "bs_spoof":
            loss_prob  = 0.15
            delay_base = random.uniform(10, 50)

        is_lost = random.random() < loss_prob

        pkt = TransmittedPacket(
            packet_id    = self.packet_counter,
            node_id      = self.node_id,
            timestamp    = time.time(),
            sequence_num = seq_num,
            accel_data   = noisy_sample,
            noise_applied= noise,
            is_lost      = is_lost,
            delay_ms     = delay_base if not is_lost else 0,
            is_tampered  = (attack_mode is not None
                            and not is_lost
                            and random.random() < 0.3),
        )
        self.transmitted.append(pkt)
        return pkt

    def transmit_window(self,
                        window_start: int,
                        attack_mode: str = None) -> List[TransmittedPacket]:
        """Truyền một cửa sổ n=10 gói tin"""
        packets = []
        for i in range(self.config.window_size):
            pkt = self.transmit_packet(
                window_start + i, attack_mode
            )
            packets.append(pkt)
        return packets