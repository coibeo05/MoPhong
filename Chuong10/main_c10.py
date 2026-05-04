# main_simulation.py
import random
import time
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib
matplotlib.rcParams['font.family'] = 'DejaVu Sans'

from traffic_generator  import generate_traffic
from honeypot           import LowInteractionHoneypot
from darknet_sensor     import DarknetSensor
from payload_classifier import PayloadClassifier
from attack_estimator   import AttackScaleEstimator


def run_simulation():
    print("=" * 60)
    print("  HỆ THỐNG TƯƠNG QUAN HONEYPOT + DARKNET (Chương 10)")
    print("=" * 60)

    DARKNET_IP  = "10.0.99.15"
    HONEYPOT_IP = "192.168.1.10"

    # ── 1. Sinh lưu lượng ──────────────────────────────────────
    print("\n[1] Generating attack traffic...")
    base_time = time.time()

    darknet_traffic  = generate_traffic(DARKNET_IP,  n_packets=300)
    honeypot_traffic = generate_traffic(HONEYPOT_IP, n_packets=200)

    # Đồng bộ timestamp về cùng khoảng thời gian
    for p in darknet_traffic:
        p.timestamp = base_time + random.uniform(0, 1800)
    for p in honeypot_traffic:
        p.timestamp = base_time + random.uniform(0, 1800)

    # ── 2. Honeypot thu thập ────────────────────────────────────
    print("\n[2] Honeypot nodes capturing streams...")
    hp1 = LowInteractionHoneypot("HP_Node1", "near_darknet")
    hp2 = LowInteractionHoneypot("HP_Node2", "far_darknet")

    streams1 = hp1.capture_all(honeypot_traffic[:100])
    streams2 = hp2.capture_all(honeypot_traffic[100:])
    all_streams = streams1 + streams2

    # ── 3. Darknet giám sát ─────────────────────────────────────
    print("\n[3] Darknet sensor monitoring /24 space...")
    sensor = DarknetSensor("10.0.99")
    darknet_obs = sensor.observe(darknet_traffic)

    # ── 4. Phân loại payload ────────────────────────────────────
    print("\n[4] Classifying payloads (1-gram + Manhattan clustering)...")
    classifier     = PayloadClassifier()
    clusters       = classifier.classify(all_streams)
    known_clusters = set()
    new_attacks    = classifier.detect_new_attacks(clusters, known_clusters)

    print(f"\n  Total clusters found : {len(clusters)}")
    print(f"  New attack clusters  : {len(new_attacks)}")
    for cid, members in clusters.items():
        types = set(m["detected_type"] for m in members)
        ports = set(m["dst_port"]      for m in members)
        print(f"  [{cid}] → {len(members)} streams | "
              f"ports={ports} | types={types}")

    # ── 5. Ước tính quy mô ──────────────────────────────────────
    print("\n[5] Estimating attack scale via correlation...")
    estimator     = AttackScaleEstimator()
    scale_results = estimator.correlate(all_streams, darknet_obs)

    df = pd.DataFrame(scale_results)
    print(f"\n  Correlation summary (top 10 by darknet hits):")
    print(df.sort_values("darknet_hits", ascending=False)
            [["stream_id", "detected_type", "dst_port",
              "match_type", "darknet_hits"]].head(10).to_string(index=False))

    # ── 6. Vẽ báo cáo ───────────────────────────────────────────
    _plot_results(df, clusters, darknet_obs)
    print("\n[DONE] Simulation complete. See chart output.")


def _plot_results(df, clusters, darknet_obs):
    fig, axes = plt.subplots(1, 3, figsize=(17, 5))
    fig.suptitle("Chương 10 – Tương quan Honeypot & Darknet",
                 fontsize=13, fontweight='bold')

    # --- Biểu đồ 1: Phân loại tấn công theo cổng ---
    ax1 = axes[0]
    port_type = df.groupby(
        ["dst_port", "detected_type"]
    ).size().unstack(fill_value=0)
    port_type.plot(kind="bar", ax=ax1, colormap="Set2", edgecolor="black")
    ax1.set_title("Phân loại tấn công theo cổng")
    ax1.set_xlabel("Cổng đích")
    ax1.set_ylabel("Số streams")
    ax1.tick_params(axis='x', rotation=0)
    ax1.legend(title="Loại", fontsize=8)

    # --- Biểu đồ 2: Quy mô ước tính ---
    ax2 = axes[1]
    scale_by_type = df.groupby("detected_type")["darknet_hits"].sum()
    colors = ["#e74c3c", "#3498db", "#2ecc71"]
    scale_by_type.plot(kind="bar", ax=ax2,
                       color=colors[:len(scale_by_type)],
                       edgecolor="black")
    ax2.set_title("Ước tính quy mô tấn công\n(Darknet packet hits)")
    ax2.set_xlabel("Loại phần mềm độc hại")
    ax2.set_ylabel("Tổng darknet hits")
    ax2.tick_params(axis='x', rotation=15)
    for bar in ax2.patches:
        h = bar.get_height()
        if h > 0:
            ax2.text(bar.get_x() + bar.get_width() / 2,
                     h + 0.5, str(int(h)),
                     ha='center', va='bottom', fontsize=9)

    # --- Biểu đồ 3: Kích thước cụm ---
    ax3 = axes[2]
    cluster_sizes = {cid: len(members)
                     for cid, members in clusters.items()}
    short_labels  = [f"C{i}" for i in range(len(cluster_sizes))]
    sizes         = list(cluster_sizes.values())
    bars = ax3.bar(short_labels, sizes,
                   color="#9b59b6", edgecolor="black", alpha=0.8)
    ax3.set_title(f"Kích thước cụm payload\n({len(cluster_sizes)} cụm)")
    ax3.set_xlabel("Cluster ID")
    ax3.set_ylabel("Số streams")
    for bar, size in zip(bars, sizes):
        ax3.text(bar.get_x() + bar.get_width() / 2,
                 bar.get_height() + 0.2,
                 str(size), ha='center', va='bottom', fontsize=8)

    plt.tight_layout()
    plt.savefig("honeypot_darknet_report.png",
                dpi=150, bbox_inches='tight')
    plt.show()


if __name__ == "__main__":
    run_simulation()