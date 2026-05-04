# tinymt_prng.py
from dataclasses import dataclass
from typing import List

@dataclass
class TinyMTState:
    """Trạng thái nội tại của TinyMT"""
    status: List[int]   # 4 words × 32-bit
    mat1:   int
    mat2:   int
    tmat:   int

class TinyMT:
    """
    TinyMT - Tiny Mersenne Twister PRNG
    Được thiết kế cho thiết bị nhúng (IoT, wearable)
    Kích thước state nhỏ: 127 bit (phù hợp thiết bị nhỏ)

    Trong hệ thống Honeypot BAN:
    - Trạm gốc và nút mồi dùng cùng seed
    - Tạo chuỗi số giống nhau → xác minh tính toàn vẹn
    - Nếu kẻ tấn công không biết seed → không thể giả mạo
    """

    # Tham số TinyMT32 mặc định
    MAT1 = 0x8f7011ee
    MAT2 = 0xfc78ff1f
    TMAT = 0x3793fdff

    MEXP    = 127
    SH0     = 1
    SH1     = 10
    SH8     = 8
    MASK    = 0x7fffffff
    MIN_LOOP = 8
    PRE_LOOP = 8

    def __init__(self, seed: int = 42):
        self.state = TinyMTState(
            status = [0, 0, 0, 0],
            mat1   = self.MAT1,
            mat2   = self.MAT2,
            tmat   = self.TMAT,
        )
        self._init(seed)

    def _init(self, seed: int):
        """Khởi tạo state từ seed"""
        self.state.status[0] = seed
        self.state.status[1] = self.MAT1
        self.state.status[2] = self.MAT2
        self.state.status[3] = self.TMAT

        for i in range(1, self.MIN_LOOP + self.PRE_LOOP + 1):
            prev = self.state.status[(i-1) & 3]
            curr_idx = i & 3
            val = (1812433253
                   * (prev ^ (prev >> 30))
                   + i) & 0xFFFFFFFF
            self.state.status[curr_idx] ^= val

        # Đảm bảo state không bị zero
        if (self.state.status[0] & self.MASK == 0
                and self.state.status[1] == 0
                and self.state.status[2] == 0
                and self.state.status[3] == 0):
            self.state.status[0] = ord('T')
            self.state.status[1] = ord('I')
            self.state.status[2] = ord('N')
            self.state.status[3] = ord('Y')

    def _next_state(self):
        """Chuyển trạng thái"""
        y = self.state.status[3]
        x = ((self.state.status[0] & self.MASK)
             ^ self.state.status[1]
             ^ self.state.status[2])
        x ^= (x << self.SH0) & 0xFFFFFFFF
        y ^= (y >> self.SH0) ^ x

        self.state.status[0] = self.state.status[1]
        self.state.status[1] = self.state.status[2]
        self.state.status[2] = (x ^ ((y << self.SH1)
                                     & 0xFFFFFFFF))
        self.state.status[3] = y

        if y & 1:
            self.state.status[1] ^= self.state.mat1
            self.state.status[2] ^= self.state.mat2

    def _temper(self) -> int:
        """Tempering output"""
        t0 = self.state.status[3]
        t1 = (self.state.status[0]
              + (self.state.status[2] >> self.SH8))
        t0 ^= t1
        if t1 & 1:
            t0 ^= self.state.tmat
        return t0 & 0xFFFFFFFF

    def generate_uint32(self) -> int:
        """Sinh số nguyên 32-bit"""
        self._next_state()
        return self._temper()

    def generate_float(self) -> float:
        """Sinh số thực [0, 1)"""
        return self.generate_uint32() / 4294967296.0

    def generate_sequence(self, n: int) -> List[float]:
        """Sinh dãy n số trong [0, 1)"""
        return [self.generate_float() for _ in range(n)]

    def generate_noise(self,
                       n: int,
                       scale: float = 0.02) -> List[float]:
        """Sinh nhiễu ngẫu nhiên cho honeypot data"""
        return [(self.generate_float() * 2 - 1) * scale
                for _ in range(n)]

    def verify_sequence(self,
                        received: List[float],
                        seed: int,
                        tolerance: float = 0.001) -> bool:
        """
        Xác minh chuỗi số nhận được có khớp với seed không
        Dùng để phát hiện giả mạo dữ liệu
        """
        verifier = TinyMT(seed)
        expected = verifier.generate_sequence(len(received))
        mismatches = sum(
            1 for r, e in zip(received, expected)
            if abs(r - e) > tolerance
        )
        return mismatches == 0