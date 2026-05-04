# main_c11.py
import random
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib
matplotlib.rcParams['font.family'] = 'DejaVu Sans'
from sklearn.model_selection import train_test_split

from honeyd_simulator    import HoneydSimulator
from snort_simulator     import SnortSimulator
from ossec_simulator     import OSSECSimulator
from central_database    import CentralDatabase
from bayesian_classifier import BayesianThreatClassifier


def run_c11():
    print("=" * 60)
    print("  KHUNG DỰ ĐOÁN MỐI ĐE DỌA - CHƯƠNG 11")
    print("  Honeyd + SNORT + OSSEC + Bayesian ML")
    print("=" * 60)

    # ── 1. Honeyd sinh traffic ──────────────────────────────────
    print("\n[1] Honeyd generating network traffic...")
    honeyd  = HoneydSimulator()
    packets = honeyd.generate_traffic(n=600)

    # ── 2. SNORT phân tích ──────────────────────────────────────
    print("\n[2] SNORT deep packet inspection...")
    snort        = SnortSimulator()
    snort_alerts = snort.analyze_all(packets)

    # ── 3. OSSEC giám sát ───────────────────────────────────────
    print("\n[3] OSSEC host intrusion detection...")
    ossec        = OSSECSimulator()
    ossec_alerts = ossec.analyze_all(packets)

    # ── 4. Lưu vào CSDL tập trung ──────────────────────────────
    print("\n[4] Storing to centralized database...")
    db = CentralDatabase()
    db.store_packets(packets)
    db.store_snort_alerts(snort_alerts)
    db.store_ossec_alerts(ossec_alerts)
    db.summary()

    # ── 5. Huấn luyện Bayes ─────────────────────────────────────
    print("\n[5] Training Bayesian classifier...")
    df = db.get_feature_dataframe()
    train_df, test_df = train_test_split(
        df, test_size=0.3, random_state=42,
        stratify=df["attack_class"]
    )
    print(f"  Train: {len(train_df)} | Test: {len(test_df)}")

    clf = BayesianThreatClassifier()
    clf.train(train_df)

    # ── 6. Đánh giá ─────────────────────────────────────────────
    print("\n[6] Evaluating model...")
    eval_result = clf.evaluate(test_df)

    # ── 7. Demo dự đoán thực tế ─────────────────────────────────
    print("\n[7] Real-time prediction demo:")
    demo_cases = [
        {
            "name":           "External hacker (phpMyAdmin scan)",
            "is_internal_ip": False,
            "high_port":      False,
            "large_packet":   False,
            "has_syn":        True,
            "ttl":            58,
            "packet_size":    256,
        },
        {
            "name":           "Internal privilege escalation",
            "is_internal_ip": True,
            "high_port":      True,
            "large_packet":   False,
            "has_syn":        False,
            "ttl":            127,
            "packet_size":    320,
        },
        {
            "name":           "Normal web browsing",
            "is_internal_ip": True,
            "high_port":      False,
            "large_packet":   False,
            "has_syn":        True,
            "ttl":            64,
            "packet_size":    128,
        },
    ]
    demo_results = []
    for case in demo_cases:
        pred, conf = clf.predict(case)
        proba      = clf.predict_proba(case)
        emoji = "🔴" if pred == "external" else \
                "🟠" if pred == "internal" else "🟢"
        print(f"\n  {emoji} [{case['name']}]")
        print(f"     Prediction : {pred.upper()} ({conf:.1%} confident)")
        print(f"     Probabilities: " +
              " | ".join(f"{k}={v:.1%}" for k, v in proba.items()))
        demo_results.append({
            "case": case["name"], "pred": pred,
            "conf": conf, **proba
        })

    # ── 8. Vẽ biểu đồ ───────────────────────────────────────────
    _plot_results(df, snort_alerts, ossec_alerts,
                  eval_result, demo_results)
    print("\n[DONE] Chapter 11 simulation complete!")


def _plot_results(df, snort_alerts, ossec_alerts,
                  eval_result, demo_results):
    fig, axes = plt.subplots(2, 3, figsize=(18, 10))
    fig.suptitle("Chương 11 – Khung Dự đoán Mối đe dọa\n"
                 "Honeyd + SNORT + OSSEC + Bayesian ML",
                 fontsize=13, fontweight='bold')

    colors = {"external": "#e74c3c",
              "internal": "#e67e22",
              "normal":   "#2ecc71"}

    # --- Biểu đồ 1: Phân phối lưu lượng ---
    ax = axes[0, 0]
    dist = df["attack_class"].value_counts()
    bars = ax.bar(dist.index,
                  dist.values,
                  color=[colors[c] for c in dist.index],
                  edgecolor="black")
    ax.set_title("Phân phối lưu lượng\n(Honeyd capture)")
    ax.set_ylabel("Số packets")
    for bar in bars:
        ax.text(bar.get_x() + bar.get_width()/2,
                bar.get_height() + 2,
                str(int(bar.get_height())),
                ha='center', fontsize=10, fontweight='bold')

    # --- Biểu đồ 2: SNORT alerts theo severity ---
    ax = axes[0, 1]
    sev_labels = {1: "High", 2: "Medium", 3: "Low"}
    sev_colors = {1: "#e74c3c", 2: "#f39c12", 3: "#3498db"}
    sev_counts = {}
    for a in snort_alerts:
        sev_counts[a.severity] = sev_counts.get(a.severity, 0) + 1
    if sev_counts:
        ax.bar([sev_labels[s] for s in sorted(sev_counts)],
               [sev_counts[s] for s in sorted(sev_counts)],
               color=[sev_colors[s] for s in sorted(sev_counts)],
               edgecolor="black")
    ax.set_title("SNORT Alerts\ntheo mức độ nghiêm trọng")
    ax.set_ylabel("Số cảnh báo")

    # --- Biểu đồ 3: OSSEC alerts theo level ---
    ax = axes[0, 2]
    ossec_levels = [a.level for a in ossec_alerts]
    if ossec_levels:
        ax.hist(ossec_levels, bins=range(5, 16),
                color="#9b59b6", edgecolor="black", alpha=0.8)
    ax.set_title("OSSEC Alert Levels\n(0-15 scale)")
    ax.set_xlabel("Alert Level")
    ax.set_ylabel("Số cảnh báo")
    ax.axvline(x=10, color='red', linestyle='--',
               label='Ngưỡng High (≥10)')
    ax.legend(fontsize=8)

    # --- Biểu đồ 4: Prior probability (P(Class)) ---
    ax = axes[1, 0]
    class_counts = df["attack_class"].value_counts()
    total = len(df)
    priors = class_counts / total
    wedge_colors = [colors[c] for c in priors.index]
    ax.pie(priors.values,
           labels=[f"{c}\n({v:.1%})" for c, v in priors.items()],
           colors=wedge_colors,
           autopct='%1.1f%%',
           startangle=90)
    ax.set_title("P(Class) - Xác suất tiên nghiệm\n(Prior Probability)")

    # --- Biểu đồ 5: Accuracy và F1 theo lớp ---
    ax = axes[1, 1]
    class_names = list(eval_result["details"].keys())
    f1_scores = []
    for cls in class_names:
        m  = eval_result["details"][cls]
        tp, fp, fn = m["tp"], m["fp"], m["fn"]
        pr = tp/(tp+fp) if (tp+fp) > 0 else 0
        re = tp/(tp+fn) if (tp+fn) > 0 else 0
        f1 = 2*pr*re/(pr+re) if (pr+re) > 0 else 0
        f1_scores.append(f1)
    bar_colors = [colors[c] for c in class_names]
    bars = ax.bar(class_names, f1_scores,
                  color=bar_colors, edgecolor="black")
    ax.axhline(y=eval_result["accuracy"],
               color='navy', linestyle='--',
               label=f'Accuracy={eval_result["accuracy"]:.1%}')
    ax.set_title("Hiệu suất Bayesian Classifier\n(F1-Score theo lớp)")
    ax.set_ylabel("F1-Score")
    ax.set_ylim(0, 1.1)
    ax.legend(fontsize=9)
    for bar, f1 in zip(bars, f1_scores):
        ax.text(bar.get_x() + bar.get_width()/2,
                bar.get_height() + 0.02,
                f'{f1:.2f}', ha='center', fontsize=10)

    # --- Biểu đồ 6: Demo dự đoán xác suất ---
    ax = axes[1, 2]
    case_labels = [f"Case {i+1}" for i in range(len(demo_results))]
    x = range(len(demo_results))
    w = 0.25
    for i, cls in enumerate(["external", "internal", "normal"]):
        vals = [r.get(cls, 0) for r in demo_results]
        ax.bar([xi + i*w for xi in x], vals,
               width=w, label=cls,
               color=colors[cls], edgecolor="black", alpha=0.85)
    ax.set_title("Demo Dự đoán Xác suất\n(Posterior Probability)")
    ax.set_xticks([xi + w for xi in x])
    ax.set_xticklabels(case_labels)
    ax.set_ylabel("P(Class|Compromise)")
    ax.set_ylim(0, 1.1)
    ax.legend(fontsize=8)
    # Ghi nhãn case
    for i, r in enumerate(demo_results):
        ax.text(i + w, -0.08,
                r["pred"].upper(),
                ha='center', fontsize=8,
                color=colors[r["pred"]],
                fontweight='bold',
                transform=ax.get_xaxis_transform())

    plt.tight_layout()
    plt.savefig("chapter11_threat_prediction.png",
                dpi=150, bbox_inches='tight')
    plt.show()


if __name__ == "__main__":
    run_c11()