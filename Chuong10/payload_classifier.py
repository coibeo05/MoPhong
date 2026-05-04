# payload_classifier.py
import numpy as np
from typing import List, Dict, Tuple

class PayloadClassifier:
    """
    Phân loại payload theo thuật toán chương 10:
      Phase 1: Nhóm theo cổng đích
      Phase 2: Gộp độ dài payload gần nhau (|l1-l2| <= 1)
      Phase 3: Tính khoảng cách Manhattan, phân cụm nếu md <= mt
    """

    def _compute_1gram_profile(self, payload: bytes) -> np.ndarray:
        """Tạo vector tần suất 256 chiều (byte 0-255)"""
        profile = np.zeros(256, dtype=float)
        if len(payload) == 0:
            return profile
        for byte in payload:
            profile[byte] += 1
        profile /= len(payload)   # chuẩn hóa
        return profile

    def _manhattan_distance(self, p1: np.ndarray, p2: np.ndarray) -> float:
        return float(np.sum(np.abs(p1 - p2)))

    def classify(self, streams: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Trả về dict: cluster_id → danh sách stream thuộc cụm đó
        """
        # Phase 1: Nhóm theo cổng đích
        by_port: Dict[int, List[Dict]] = {}
        for s in streams:
            port = s["dst_port"]
            by_port.setdefault(port, []).append(s)

        clusters: Dict[str, List[Dict]] = {}
        cluster_counter = 0

        for port, port_streams in by_port.items():
            # Tính profile cho từng stream
            profiles = []
            for s in port_streams:
                profile = self._compute_1gram_profile(s["payload"])
                profiles.append({
                    "stream": s,
                    "length": len(s["payload"]),
                    "profile": profile,
                    "cluster": None
                })

            # Phase 2: Gộp profile có độ dài chênh lệch <= 1
            merged = []
            used = [False] * len(profiles)
            for i in range(len(profiles)):
                if used[i]:
                    continue
                group = [profiles[i]]
                used[i] = True
                for j in range(i+1, len(profiles)):
                    if not used[j]:
                        li = profiles[i]["length"]
                        lj = profiles[j]["length"]
                        if abs(li - lj) <= 1:
                            group.append(profiles[j])
                            used[j] = True
                # Tính profile trung bình của nhóm
                avg_profile = np.mean(
                    [g["profile"] for g in group], axis=0
                )
                avg_length = np.mean([g["length"] for g in group])
                merged.append({
                    "streams":     [g["stream"] for g in group],
                    "avg_profile": avg_profile,
                    "avg_length":  avg_length,
                    "cluster_id":  None
                })

            # Phase 3: Phân cụm theo khoảng cách Manhattan
            for i in range(len(merged)):
                if merged[i]["cluster_id"] is not None:
                    continue
                cluster_id = f"cluster_{cluster_counter:03d}_port{port}"
                cluster_counter += 1
                merged[i]["cluster_id"] = cluster_id

                for j in range(i+1, len(merged)):
                    if merged[j]["cluster_id"] is not None:
                        continue
                    md = self._manhattan_distance(
                        merged[i]["avg_profile"],
                        merged[j]["avg_profile"]
                    )
                    # Ngưỡng mt = avg_length * 0.2
                    mt = merged[i]["avg_length"] * 0.2
                    if md <= mt:
                        merged[j]["cluster_id"] = cluster_id

            # Thu thập kết quả
            for m in merged:
                cid = m["cluster_id"]
                clusters.setdefault(cid, [])
                clusters[cid].extend(m["streams"])

        return clusters

    def detect_new_attacks(self,
                           clusters: Dict[str, List[Dict]],
                           known_clusters: set) -> List[str]:
        """Phát hiện cụm mới chưa từng thấy"""
        new_clusters = []
        for cid in clusters:
            if cid not in known_clusters:
                new_clusters.append(cid)
                print(f"[ALERT] New scanning activity detected: {cid} "
                      f"({len(clusters[cid])} streams)")
        return new_clusters