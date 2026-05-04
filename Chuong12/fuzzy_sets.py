# fuzzy_sets.py
import numpy as np

def trimf(x: float, a: float, b: float, c: float) -> float:
    """
    Hàm thành viên tam giác (Triangular Membership Function)
    theo đúng thiết kế Matlab trong Chương 12
         1    /\
             /  \
            /    \
    0 ----a/------\c----
               b
    """
    if x <= a or x >= c:
        return 0.0
    elif a < x <= b:
        return (x - a) / (b - a)
    else:
        return (c - x) / (c - b)

class FuzzyVariable:
    """
    Biến mờ với các tập mờ Low / Medium / High
    """
    def __init__(self, name: str, min_val: float, max_val: float):
        self.name    = name
        self.min_val = min_val
        self.max_val = max_val
        self.sets: dict = {}

    def add_set(self, label: str, a: float, b: float, c: float):
        self.sets[label] = (a, b, c)

    def fuzzify(self, crisp_value: float) -> dict:
        """Chuyển giá trị rõ → độ thuộc các tập mờ"""
        return {
            label: trimf(crisp_value, a, b, c)
            for label, (a, b, c) in self.sets.items()
        }

# ── Định nghĩa 3 biến đầu vào theo Chương 12 ──────────────

def create_RTIPA() -> FuzzyVariable:
    """
    RTIPA: Tỷ lệ IP đáng tin cậy (80-500 gói/giây)
    Low    = 80-240
    Medium = 210-370
    High   = 340-500
    """
    v = FuzzyVariable("RTIPA", 80, 500)
    v.add_set("Low",    80,  160, 240)
    v.add_set("Medium", 210, 290, 370)
    v.add_set("High",   340, 420, 500)
    return v

def create_UARPP() -> FuzzyVariable:
    """
    UARPP: Gói ARP bất thường (10-60 gói/giây)
    Low    = 10-30
    Medium = 25-45
    High   = 40-60
    """
    v = FuzzyVariable("UARPP", 10, 60)
    v.add_set("Low",    10, 20, 30)
    v.add_set("Medium", 25, 35, 45)
    v.add_set("High",   40, 50, 60)
    return v

def create_RARPP() -> FuzzyVariable:
    """
    RARPP: Tỷ lệ ARP tổng thể (50-300 gói/giây)
    Low    = 50-150
    Medium = 125-225
    High   = 200-300
    """
    v = FuzzyVariable("RARPP", 50, 300)
    v.add_set("Low",    50,  100, 150)
    v.add_set("Medium", 125, 175, 225)
    v.add_set("High",   200, 250, 300)
    return v

def create_SAP() -> FuzzyVariable:
    """
    SAP: Spoofing Attack Probability (0-100%)
    Low    = 0-40%
    Medium = 30-70%
    High   = 60-100%
    """
    v = FuzzyVariable("SAP", 0, 100)
    v.add_set("Low",    0,  20, 40)
    v.add_set("Medium", 30, 50, 70)
    v.add_set("High",   60, 80, 100)
    return v