# fuzzy_rules.py
from typing import List, Tuple

# Quy tắc mờ Mamdani: (RTIPA, UARPP, RARPP) → SAP
# Dựa trên Rule Editor trong Hình 11 - Chương 12
FUZZY_RULES: List[Tuple[str, str, str, str]] = [
    # RTIPA     UARPP     RARPP     SAP
    ("Low",    "Low",    "Low",    "Low"),
    ("Low",    "Low",    "Medium", "Medium"),
    ("Low",    "Low",    "High",   "Medium"),
    ("Low",    "Medium", "Low",    "Medium"),
    ("Low",    "Medium", "Medium", "Medium"),
    ("Low",    "Medium", "High",   "High"),
    ("Low",    "High",   "Low",    "Medium"),
    ("Low",    "High",   "Medium", "High"),
    ("Low",    "High",   "High",   "High"),
    ("Medium", "Low",    "Low",    "Low"),
    ("Medium", "Low",    "Medium", "Medium"),
    ("Medium", "Low",    "High",   "Medium"),
    ("Medium", "Medium", "Low",    "Medium"),
    ("Medium", "Medium", "Medium", "Medium"),
    ("Medium", "Medium", "High",   "High"),
    ("Medium", "High",   "Low",    "Medium"),
    ("Medium", "High",   "Medium", "High"),
    ("Medium", "High",   "High",   "High"),
    ("High",   "Low",    "Low",    "Medium"),
    ("High",   "Low",    "Medium", "High"),
    ("High",   "Low",    "High",   "High"),
    ("High",   "Medium", "Low",    "Medium"),
    ("High",   "Medium", "Medium", "High"),
    ("High",   "Medium", "High",   "High"),
    ("High",   "High",   "Low",    "High"),
    ("High",   "High",   "Medium", "High"),
    ("High",   "High",   "High",   "High"),
]