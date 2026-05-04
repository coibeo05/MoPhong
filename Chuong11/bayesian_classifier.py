# bayesian_classifier.py
import numpy as np
import pandas as pd
from typing import Dict, Tuple

class BayesianThreatClassifier:
    """
    Phân loại Bayes theo công thức Chương 11:
    P(Class|Compromise) = P(Compromise|Class) * P(Class) / P(Compromise)

    Classes: 'external', 'internal', 'normal'
    Features: is_internal_ip, high_port, large_packet, has_syn,
              dst_port, ttl, packet_size
    """

    def __init__(self):
        self.class_priors:     Dict[str, float] = {}
        self.feature_probs:    Dict = {}
        self.classes:          list = []
        self.is_trained:       bool = False

    def train(self, df: pd.DataFrame):
        """
        Huấn luyện: tính P(Class) và P(Feature|Class)
        """
        self.classes = df["attack_class"].unique().tolist()
        total = len(df)

        # P(Class) - xác suất tiên nghiệm
        for cls in self.classes:
            self.class_priors[cls] = len(df[df["attack_class"] == cls]) / total

        # P(Feature|Class) - likelihood cho các đặc trưng nhị phân
        bool_features = ["is_internal_ip", "high_port", "large_packet", "has_syn"]
        self.feature_probs = {cls: {} for cls in self.classes}

        for cls in self.classes:
            subset = df[df["attack_class"] == cls]
            for feat in bool_features:
                # Laplace smoothing tránh xác suất = 0
                prob = (subset[feat].sum() + 1) / (len(subset) + 2)
                self.feature_probs[cls][feat] = prob

            # Đặc trưng liên tục: TTL và packet_size (dùng Gaussian)
            self.feature_probs[cls]["ttl_mean"] = subset["ttl"].mean()
            self.feature_probs[cls]["ttl_std"]  = subset["ttl"].std() + 1e-6
            self.feature_probs[cls]["size_mean"]= subset["packet_size"].mean()
            self.feature_probs[cls]["size_std"] = subset["packet_size"].std() + 1e-6

        self.is_trained = True
        print(f"\n[Bayes] Model trained on {total} samples")
        print(f"  Priors: { {k: f'{v:.3f}' for k,v in self.class_priors.items()} }")

    def _gaussian_prob(self, x, mean, std) -> float:
        exponent = np.exp(-((x - mean) ** 2) / (2 * std ** 2))
        return float((1 / (np.sqrt(2 * np.pi) * std)) * exponent + 1e-9)

    def predict_proba(self, sample: Dict) -> Dict[str, float]:
        """
        Tính P(Class|Features) cho một mẫu
        Trả về xác suất hậu nghiệm cho mỗi lớp
        """
        if not self.is_trained:
            raise RuntimeError("Model not trained yet!")

        posteriors = {}
        bool_features = ["is_internal_ip", "high_port", "large_packet", "has_syn"]

        for cls in self.classes:
            # Bắt đầu với log của prior
            log_prob = np.log(self.class_priors[cls])

            # Nhân likelihood các đặc trưng nhị phân
            for feat in bool_features:
                p = self.feature_probs[cls][feat]
                val = sample.get(feat, False)
                log_prob += np.log(p if val else (1 - p))

            # Nhân likelihood đặc trưng liên tục (Gaussian)
            log_prob += np.log(self._gaussian_prob(
                sample.get("ttl", 64),
                self.feature_probs[cls]["ttl_mean"],
                self.feature_probs[cls]["ttl_std"]
            ))
            log_prob += np.log(self._gaussian_prob(
                sample.get("packet_size", 256),
                self.feature_probs[cls]["size_mean"],
                self.feature_probs[cls]["size_std"]
            ))

            posteriors[cls] = np.exp(log_prob)

        # Chuẩn hóa → tổng = 1 (P(Compromise) ở mẫu số)
        total = sum(posteriors.values()) + 1e-12
        return {cls: v / total for cls, v in posteriors.items()}

    def predict(self, sample: Dict) -> Tuple[str, float]:
        proba = self.predict_proba(sample)
        best_class = max(proba, key=proba.get)
        return best_class, proba[best_class]

    def evaluate(self, df: pd.DataFrame) -> Dict:
        correct = 0
        results = {"external":{"tp":0,"fp":0,"fn":0},
                   "internal":{"tp":0,"fp":0,"fn":0},
                   "normal":  {"tp":0,"fp":0,"fn":0}}

        for _, row in df.iterrows():
            sample = row.to_dict()
            pred, _ = self.predict(sample)
            true = row["attack_class"]
            if pred == true:
                correct += 1
                results[true]["tp"] += 1
            else:
                results[pred]["fp"] += 1
                results[true]["fn"] += 1

        accuracy = correct / len(df)
        print(f"\n[Bayes] Evaluation on {len(df)} samples:")
        print(f"  Overall Accuracy: {accuracy:.1%}")
        for cls, m in results.items():
            tp, fp, fn = m["tp"], m["fp"], m["fn"]
            precision = tp/(tp+fp) if (tp+fp) > 0 else 0
            recall    = tp/(tp+fn) if (tp+fn) > 0 else 0
            f1 = 2*precision*recall/(precision+recall) if (precision+recall) > 0 else 0
            print(f"  [{cls:8s}] Precision={precision:.2f} | "
                  f"Recall={recall:.2f} | F1={f1:.2f}")
        return {"accuracy": accuracy, "details": results}