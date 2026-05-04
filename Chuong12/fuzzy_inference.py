# fuzzy_inference.py
import numpy as np
from fuzzy_sets  import (create_RTIPA, create_UARPP,
                          create_RARPP, create_SAP)
from fuzzy_rules import FUZZY_RULES

class MamdaniFIS:
    """
    Hệ thống suy luận mờ Mamdani (Chương 12)
    Input  : RTIPA, UARPP, RARPP (crisp values)
    Output : SAP - Spoofing Attack Probability (0-100%)

    Quy trình:
    1. Fuzzification  - chuyển giá trị rõ → độ thuộc
    2. Rule Inference - áp dụng 27 quy tắc (AND = min)
    3. Aggregation    - gộp kết quả (OR = max)
    4. Defuzzification- centroid → giá trị rõ SAP
    """

    def __init__(self):
        self.RTIPA = create_RTIPA()
        self.UARPP = create_UARPP()
        self.RARPP = create_RARPP()
        self.SAP   = create_SAP()
        self.resolution = 200   # điểm lấy mẫu cho defuzz

    def _fuzzify(self, rtipa: float,
                 uarpp: float, rarpp: float) -> tuple:
        return (
            self.RTIPA.fuzzify(rtipa),
            self.UARPP.fuzzify(uarpp),
            self.RARPP.fuzzify(rarpp),
        )

    def _infer(self, f_rtipa: dict,
               f_uarpp: dict, f_rarpp: dict) -> dict:
        """
        Áp dụng từng quy tắc:
        firing_strength = min(μ_RTIPA, μ_UARPP, μ_RARPP)
        Gộp các quy tắc cùng đầu ra: max (aggregation)
        """
        aggregated = {label: 0.0 for label in self.SAP.sets}

        for (r_rtipa, r_uarpp, r_rarpp, r_sap) in FUZZY_RULES:
            strength = min(
                f_rtipa.get(r_rtipa, 0),
                f_uarpp.get(r_uarpp, 0),
                f_rarpp.get(r_rarpp, 0),
            )
            # Aggregation: OR = max
            aggregated[r_sap] = max(aggregated[r_sap], strength)

        return aggregated

    def _defuzzify_centroid(self, aggregated: dict) -> float:
        """
        Defuzzification bằng phương pháp Centroid
        (trọng tâm diện tích vùng mờ kết quả)
        """
        x_points = np.linspace(
            self.SAP.min_val,
            self.SAP.max_val,
            self.resolution
        )
        y_points = np.zeros(self.resolution)

        for i, x in enumerate(x_points):
            membership = 0.0
            for label, strength in aggregated.items():
                a, b, c = self.SAP.sets[label]
                # Clipping: cắt hàm thành viên tại firing strength
                mu = min(strength,
                         __import__('fuzzy_sets').trimf(x, a, b, c))
                membership = max(membership, mu)
            y_points[i] = membership

        # Tránh chia cho 0
        denom = np.sum(y_points)
        if denom < 1e-10:
            return 0.0
        return float(np.sum(x_points * y_points) / denom)

    def compute(self, rtipa: float,
                uarpp: float, rarpp: float) -> dict:
        """
        Tính SAP từ 3 giá trị đầu vào
        Trả về dict chi tiết
        """
        # Clamp về phạm vi cho phép
        rtipa = np.clip(rtipa, self.RTIPA.min_val, self.RTIPA.max_val)
        uarpp = np.clip(uarpp, self.UARPP.min_val, self.UARPP.max_val)
        rarpp = np.clip(rarpp, self.RARPP.min_val, self.RARPP.max_val)

        # Bước 1: Fuzzification
        f_rtipa, f_uarpp, f_rarpp = self._fuzzify(rtipa, uarpp, rarpp)

        # Bước 2-3: Inference + Aggregation
        aggregated = self._infer(f_rtipa, f_uarpp, f_rarpp)

        # Bước 4: Defuzzification
        sap = self._defuzzify_centroid(aggregated)

        # Phân loại mức độ
        if sap >= 60:
            level = "HIGH"
            action = "🔴 BLOCK + ALERT"
        elif sap >= 30:
            level = "MEDIUM"
            action = "🟠 ALERT security team"
        else:
            level = "LOW"
            action = "🟢 LOG only"

        return {
            "RTIPA":      rtipa,
            "UARPP":      uarpp,
            "RARPP":      rarpp,
            "SAP":        round(sap, 2),
            "level":      level,
            "action":     action,
            "f_RTIPA":    f_rtipa,
            "f_UARPP":    f_uarpp,
            "f_RARPP":    f_rarpp,
            "aggregated": aggregated,
        }