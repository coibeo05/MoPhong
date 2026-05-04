# accelerometer_data.py
import numpy as np
from dataclasses import dataclass
from typing import List, Tuple

@dataclass
class AccelSample:
    """Mẫu gia tốc kế 3 trục"""
    timestamp: float
    x:         float   # m/s²
    y:         float
    z:         float
    activity:  str     # 'walking'/'running'/'sitting'/'lying'

class UCIAccelerometerData:
    """
    Dữ liệu gia tốc kế 3 trục từ UCI Machine Learning Repository
    Dataset: Human Activity Recognition Using Smartphones
    Tần số: 50Hz, 6 hoạt động cơ bản

    Dữ liệu được hardcode để mô phỏng
    (không cần tải file thực từ UCI)
    """

    # Đặc trưng của từng hoạt động (mean ± std) m/s²
    ACTIVITY_PROFILES = {
        "walking": {
            "x": (0.2,  0.8),
            "y": (0.1,  0.5),
            "z": (9.5,  0.6),
            "freq_hz": 2.0,
        },
        "running": {
            "x": (0.5,  2.5),
            "y": (0.3,  1.8),
            "z": (9.8,  2.0),
            "freq_hz": 3.5,
        },
        "sitting": {
            "x": (0.02, 0.1),
            "y": (0.01, 0.08),
            "z": (9.81, 0.05),
            "freq_hz": 0.1,
        },
        "lying": {
            "x": (0.01, 0.05),
            "y": (9.80, 0.04),
            "z": (0.02, 0.06),
            "freq_hz": 0.05,
        },
        "stairs_up": {
            "x": (0.3,  1.2),
            "y": (0.2,  0.9),
            "z": (9.6,  1.1),
            "freq_hz": 1.5,
        },
        "stairs_down": {
            "x": (0.4,  1.4),
            "y": (0.2,  1.0),
            "z": (9.4,  1.3),
            "freq_hz": 1.5,
        },
    }

    def generate_samples(self,
                         activity: str,
                         n_samples: int = 100,
                         seed: int = 42) -> List[AccelSample]:
        """
        Tạo dữ liệu gia tốc kế mô phỏng UCI
        Dùng seed để reproducible (quan trọng cho honeypot)
        """
        np.random.seed(seed)
        profile  = self.ACTIVITY_PROFILES.get(
            activity, self.ACTIVITY_PROFILES["walking"]
        )
        samples  = []
        dt       = 1.0 / 50.0   # 50Hz sampling

        for i in range(n_samples):
            t = i * dt
            # Thêm thành phần tuần hoàn + noise Gaussian
            freq = profile["freq_hz"]
            x = (profile["x"][0] * np.sin(2*np.pi*freq*t)
                 + np.random.normal(0, profile["x"][1]))
            y = (profile["y"][0] * np.cos(2*np.pi*freq*t)
                 + np.random.normal(0, profile["y"][1]))
            z = (profile["z"][0]
                 + 0.2*np.sin(2*np.pi*freq*t*0.5)
                 + np.random.normal(0, profile["z"][1]))

            samples.append(AccelSample(
                timestamp=t,
                x=round(x, 4),
                y=round(y, 4),
                z=round(z, 4),
                activity=activity
            ))
        return samples

    def generate_honeypot_data(self,
                               activity: str,
                               n_samples: int,
                               seed: int,
                               noise_seed: int) -> List[AccelSample]:
        """
        Tạo dữ liệu honeypot = dữ liệu thật + nhiễu TinyMT
        Kẻ tấn công không thể phân biệt với dữ liệu thật
        """
        real_data = self.generate_samples(
            activity, n_samples, seed
        )
        # Thêm nhiễu ngẫu nhiên từ TinyMT PRNG
        np.random.seed(noise_seed)
        noisy = []
        for s in real_data:
            noise_scale = 0.02   # nhiễu nhỏ, khó phát hiện
            noisy.append(AccelSample(
                timestamp = s.timestamp,
                x = s.x + np.random.uniform(
                    -noise_scale, noise_scale
                ),
                y = s.y + np.random.uniform(
                    -noise_scale, noise_scale
                ),
                z = s.z + np.random.uniform(
                    -noise_scale, noise_scale
                ),
                activity  = s.activity,
            ))
        return noisy

    def get_all_activities(self) -> List[str]:
        return list(self.ACTIVITY_PROFILES.keys())