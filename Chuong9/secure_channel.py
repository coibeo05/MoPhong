# secure_channel.py
import hashlib
import random
import struct
from dataclasses import dataclass
from typing import Tuple, Optional

@dataclass
class SecureMessage:
    """Tin nhắn được mã hóa AES-128 (mô phỏng)"""
    msg_id:      int
    sender_id:   str
    receiver_id: str
    msg_type:    str     # 'coordination'/'data'/'alert'
    payload:     bytes
    encrypted:   bytes
    mac:         str     # Message Authentication Code
    timestamp:   float
    is_valid:    bool    = True

@dataclass
class CoordinationMessage:
    """Tin nhắn điều phối qua kênh bảo mật cao"""
    data_type:    str    # loại dữ liệu ('accelerometer')
    frequency_hz: float  # tần suất gửi
    seed:         int    # hạt giống TinyMT
    window_size:  int    # n = 10
    threshold_k:  int    # k = 4

class SecureChannel:
    """
    Mô phỏng kênh bảo mật AES-128

    2 loại kênh trong BAN Honeypot:
    1. Kênh bảo mật CAO: gửi tin điều phối (seed, freq, type)
       → Mã hóa + xác thực mạnh
    2. Kênh bảo mật THÍCH ỨNG: gửi dữ liệu honeypot
       → Mã hóa nhẹ hơn, phù hợp thiết bị wearable
    """

    def __init__(self, key_hex: str = None):
        # AES-128 key (16 bytes = 128 bits)
        if key_hex:
            self.key = bytes.fromhex(key_hex)
        else:
            # Key mặc định cho demo
            self.key = bytes([
                0x2b, 0x7e, 0x15, 0x16,
                0x28, 0xae, 0xd2, 0xa6,
                0xab, 0xf7, 0x15, 0x88,
                0x09, 0xcf, 0x4f, 0x3c
            ])
        self.msg_counter = 0

    def _simulate_aes128_encrypt(self,
                                  plaintext: bytes,
                                  key: bytes) -> bytes:
        """
        Mô phỏng AES-128 encryption
        (Thực tế dùng thư viện pycryptodome)
        """
        # XOR với key và thêm biến đổi đơn giản
        encrypted = bytearray()
        for i, byte in enumerate(plaintext):
            encrypted.append(byte ^ key[i % len(key)]
                              ^ (i & 0xFF))
        return bytes(encrypted)

    def _compute_mac(self,
                     data: bytes,
                     key: bytes) -> str:
        """Tính HMAC-SHA256 (rút gọn 8 bytes)"""
        mac = hashlib.hmac if hasattr(hashlib, 'hmac') else None
        combined = key + data + key
        return hashlib.sha256(combined).hexdigest()[:16]

    def encrypt_coordination(self,
                              msg: CoordinationMessage,
                              sender: str,
                              receiver: str) -> SecureMessage:
        """
        Mã hóa tin điều phối qua kênh bảo mật cao
        """
        import time
        self.msg_counter += 1

        # Serialize coordination message
        payload = (f"{msg.data_type}|{msg.frequency_hz}|"
                   f"{msg.seed}|{msg.window_size}|"
                   f"{msg.threshold_k}").encode()

        encrypted = self._simulate_aes128_encrypt(
            payload, self.key
        )
        mac = self._compute_mac(encrypted, self.key)

        return SecureMessage(
            msg_id      = self.msg_counter,
            sender_id   = sender,
            receiver_id = receiver,
            msg_type    = "coordination",
            payload     = payload,
            encrypted   = encrypted,
            mac         = mac,
            timestamp   = time.time(),
            is_valid    = True,
        )

    def encrypt_data(self,
                     data: bytes,
                     sender: str,
                     receiver: str,
                     adaptive: bool = True) -> SecureMessage:
        """
        Mã hóa dữ liệu honeypot
        adaptive=True: kênh bảo mật thích ứng (nhẹ hơn)
        """
        import time
        self.msg_counter += 1

        if adaptive:
            # Kênh thích ứng: chỉ mã hóa một phần
            encrypted = self._simulate_aes128_encrypt(
                data, self.key[:8]   # 64-bit key
            )
        else:
            # Kênh bảo mật cao: AES-128 đầy đủ
            encrypted = self._simulate_aes128_encrypt(
                data, self.key
            )

        mac = self._compute_mac(encrypted, self.key)

        return SecureMessage(
            msg_id      = self.msg_counter,
            sender_id   = sender,
            receiver_id = receiver,
            msg_type    = "data",
            payload     = data,
            encrypted   = encrypted,
            mac         = mac,
            timestamp   = time.time(),
            is_valid    = True,
        )

    def verify_and_decrypt(self,
                           msg: SecureMessage) -> Tuple[bool, bytes]:
        """
        Xác minh MAC và giải mã
        Phát hiện giả mạo nếu MAC không khớp
        """
        # Kiểm tra MAC
        expected_mac = self._compute_mac(
            msg.encrypted, self.key
        )
        if msg.mac != expected_mac:
            return False, b""   # Phát hiện giả mạo!

        # Giải mã
        if len(msg.payload) > 0:
            return True, msg.payload
        return True, b""

    def tamper_message(self,
                       msg: SecureMessage) -> SecureMessage:
        """
        Mô phỏng kẻ tấn công giả mạo tin nhắn
        MAC sẽ không hợp lệ → bị phát hiện
        """
        import copy
        tampered = copy.deepcopy(msg)
        # Kẻ tấn công sửa payload nhưng không biết key
        tampered.payload = b"FAKE_DATA_FROM_ATTACKER"
        tampered.encrypted = b"TAMPERED_" + tampered.encrypted
        # MAC cũ không còn hợp lệ
        return tampered