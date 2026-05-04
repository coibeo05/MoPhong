# main_wearable.py
import matplotlib.pyplot as plt
import matplotlib
import numpy as np
matplotlib.rcParams['font.family'] = 'DejaVu Sans'

from accelerometer_data import UCIAccelerometerData
from tinymt_prng        import TinyMT
from decoy_node         import DecoyNode, DecoyNodeConfig
from base_station       import BaseStation
from attack_simulator   import AttackSimulator


def run_wearable():
    print("=" * 60)
    print("  WEARABLE HONEYPOT - BAN (Body Area Network)")
    print("  Decoy Nodes + AES-128 + TinyMT + Window Detection")
    print("=" * 60)

    # ── 1. Khởi tạo trạm gốc ────────────────────────────────────
    print("\n[1] Initializing Base Station...")
    bs = BaseStation("BS_001")

    # ── 2. Khởi tạo nút mồi ─────────────────────────────────────
    print("\n[2] Initializing Decoy Nodes...")
    activities = ["walking", "running", "sitting",
                  "lying", "stairs_up"]
    nodes = []
    seeds = [1234, 5678, 9012, 3456, 7890]

    for i, (activity, seed) in enumerate(
            zip(activities, seeds), 1):
        config = DecoyNodeConfig(
            activity      = activity,
            seed          = seed,
            window_size   = 10,
            threshold_k   = 4,
            frequency_hz  = 10.0,
        )
        node = DecoyNode(f"DN_{i:02d}", config)
        nodes.append(node)
        bs.register_node(node.node_id, seed)

    # ── 3. Gửi tin điều phối ────────────────────────────────────
    print("\n[3] Sending coordination messages (High Security Channel)...")
    for node in nodes:
        coord_msg = bs.send_coordination(node.node_id)
        node.receive_coordination(coord_msg)

    # ── 4. Chạy kịch bản tấn công ───────────────────────────────
    print("\n[4] Running attack scenarios...")
    simulator = AttackSimulator()
    scenario_results = simulator.run_all_scenarios(nodes)

    print(f"\n  {'Scenario':25s} {'Node':8s} "
          f"{'Windows':8s} {'Attacks':8s}")
    print(f"  {'─'*55}")

    window_counter = 0
    for res in scenario_results:
        scen    = res["scenario"]
        node_id = res["node_id"]
        windows = res["windows"]

        n_attacked = 0
        for w_idx, packets in enumerate(windows):
            window_counter += 1
            analysis = bs.analyze_window(
                window_counter, node_id, packets
            )
            if analysis.attack_detected:
                n_attacked += 1

        print(f"  {scen.name:25s} {node_id:8s} "
              f"{len(windows):8d} {n_attacked:8d}")

    # ── 5. Tổng hợp kết quả ─────────────────────────────────────
    print("\n[5] Detection Summary:")
    summary = bs.get_detection_summary()
    print(f"  Total windows analyzed : {summary['total_windows']}")
    print(f"  Attacked windows       : {summary['attacked_windows']}")
    print(f"  Clean windows          : {summary['clean_windows']}")
    print(f"  Detection rate         : "
          f"{summary['detection_rate']:.1f}%")
    print(f"  Total alerts           : {summary['total_alerts']}")
    print(f"    🔴 HIGH               : {summary['high_alerts']}")
    print(f"    🟠 MEDIUM             : {summary['medium_alerts']}")
    print(f"    🟡 LOW                : {summary['low_alerts']}")

    print(f"\n  Attack types detected:")
    for atype, count in summary['attack_types'].items():
        print(f"    {atype:35s}: {count}")

    # ── 6. TinyMT PRNG Verification Demo ────────────────────────
    print("\n[6] TinyMT PRNG Verification Demo:")
    _demo_prng_verification()

    # ── 7. Vẽ biểu đồ ───────────────────────────────────────────
    _plot_results(nodes, bs, scenario_results, summary)
    print("\n[DONE] Wearable Honeypot simulation complete!")


def _demo_prng_verification():
    """Demo xác minh TinyMT"""
    seed = 42
    prng_node = TinyMT(seed)
    prng_bs   = TinyMT(seed)

    seq_node = prng_node.generate_sequence(5)
    seq_bs   = prng_bs.generate_sequence(5)

    print(f"  Seed = {seed}")
    print(f"  Node sequence : {[f'{x:.4f}' for x in seq_node]}")
    print(f"  BS   sequence : {[f'{x:.4f}' for x in seq_bs]}")
    match = all(abs(a-b) < 1e-10
                for a, b in zip(seq_node, seq_bs))
    print(f"  Sequences match: {'✅ YES' if match else '❌ NO'}")

    # Kẻ tấn công dùng seed sai
    prng_attacker = TinyMT(seed + 1)
    seq_attacker  = prng_attacker.generate_sequence(5)
    print(f"\n  Attacker (wrong seed={seed+1}):")
    print(f"  Attacker seq  : "
          f"{[f'{x:.4f}' for x in seq_attacker]}")
    detected = not all(
        abs(a-b) < 0.001
        for a, b in zip(seq_attacker, seq_bs)
    )
    print(f"  Attack detected: {'✅ YES' if detected else '❌ NO'}")


def _plot_results(nodes, bs, scenario_results, summary):
    fig, axes = plt.subplots(2, 3, figsize=(18, 11))
    fig.suptitle(
        "Wearable Honeypot – Body Area Network (BAN)\n"
        "TinyMT PRNG + AES-128 + Window-based Detection",
        fontsize=13, fontweight='bold'
    )

    # ── Biểu đồ 1: Dữ liệu gia tốc kế theo hoạt động ───────────
    ax = axes[0, 0]
    accel_db = UCIAccelerometerData()
    colors_act = {
        "walking":    "#2ecc71",
        "running":    "#e74c3c",
        "sitting":    "#3498db",
        "lying":      "#9b59b6",
        "stairs_up":  "#f39c12",
    }
    for node in nodes[:3]:   # Chỉ vẽ 3 node đầu
        samples = accel_db.generate_samples(
            node.config.activity, n_samples=50,
            seed=node.config.seed
        )
        ts = [s.timestamp for s in samples]
        zs = [s.z for s in samples]
        ax.plot(ts, zs,
                label=node.config.activity,
                color=colors_act.get(
                    node.config.activity, "#95a5a6"
                ), linewidth=1.5)
    ax.set_title("Dữ liệu Gia tốc kế UCI\n(Trục Z - 3 hoạt động)")
    ax.set_xlabel("Thời gian (s)")
    ax.set_ylabel("Gia tốc Z (m/s²)")
    ax.legend(fontsize=8)
    ax.grid(alpha=0.3)

    # ── Biểu đồ 2: TinyMT noise sequence ────────────────────────
    ax = axes[0, 1]
    prng1 = TinyMT(1234)
    prng2 = TinyMT(1235)   # Seed sai
    seq1  = prng1.generate_sequence(50)
    seq2  = prng2.generate_sequence(50)
    ax.plot(seq1, color="#2ecc71",
            label="Correct seed (1234)", linewidth=1.5)
    ax.plot(seq2, color="#e74c3c",
            label="Wrong seed (1235)", linewidth=1.5,
            linestyle='--')
    ax.set_title("TinyMT PRNG Sequences\n"
                 "(Correct vs Wrong Seed)")
    ax.set_xlabel("Sample index")
    ax.set_ylabel("Random value [0,1)")
    ax.legend(fontsize=9)
    ax.grid(alpha=0.3)

    # ── Biểu đồ 3: Window analysis - loss rate ───────────────────
    ax = axes[0, 2]
    window_ids    = [w.window_id for w in bs.window_results]
    loss_rates    = [w.loss_rate for w in bs.window_results]
    attack_flags  = [w.attack_detected for w in bs.window_results]
    bar_colors    = [
        "#e74c3c" if a else "#2ecc71"
        for a in attack_flags
    ]
    ax.bar(window_ids, loss_rates,
           color=bar_colors, edgecolor="black", alpha=0.8)
    ax.axhline(
        y=bs.THRESHOLD_K/bs.WINDOW_SIZE,
        color='red', linestyle='--', linewidth=2,
        label=f'Threshold k/n = {bs.THRESHOLD_K}/{bs.WINDOW_SIZE}'
    )
    ax.set_title("Packet Loss Rate theo Window\n"
                 "(Đỏ = Phát hiện tấn công)")
    ax.set_xlabel("Window ID")
    ax.set_ylabel("Loss Rate")
    ax.set_ylim(0, 1.1)
    ax.legend(fontsize=9)

    # ── Biểu đồ 4: Delay distribution ───────────────────────────
    ax = axes[1, 0]
    delays_normal = [
        w.avg_delay_ms for w in bs.window_results
        if not w.attack_detected
    ]
    delays_attack = [
        w.avg_delay_ms for w in bs.window_results
        if w.attack_detected
    ]
    if delays_normal:
        ax.hist(delays_normal, bins=10,
                color="#2ecc71", alpha=0.7,
                label="Normal", edgecolor="black")
    if delays_attack:
        ax.hist(delays_attack, bins=10,
                color="#e74c3c", alpha=0.7,
                label="Under Attack", edgecolor="black")
    ax.axvline(
        x=bs.DELAY_THRESHOLD_MS,
        color='navy', linestyle='--',
        label=f'Threshold={bs.DELAY_THRESHOLD_MS}ms'
    )
    ax.set_title("Phân phối Độ trễ (Delay)\n"
                 "(Normal vs Under Attack)")
    ax.set_xlabel("Avg Delay (ms)")
    ax.set_ylabel("Số windows")
    ax.legend(fontsize=9)

    # ── Biểu đồ 5: Alert severity ────────────────────────────────
    ax = axes[1, 1]
    sev_data   = {
        "HIGH":   summary['high_alerts'],
        "MEDIUM": summary['medium_alerts'],
        "LOW":    summary['low_alerts'],
    }
    sev_colors = {
        "HIGH":   "#e74c3c",
        "MEDIUM": "#f39c12",
        "LOW":    "#f1c40f",
    }
    if any(v > 0 for v in sev_data.values()):
        ax.pie(
            [v for v in sev_data.values() if v > 0],
            labels=[f"{k}\n({v})"
                    for k, v in sev_data.items() if v > 0],
            colors=[sev_colors[k]
                    for k, v in sev_data.items() if v > 0],
            autopct='%1.1f%%',
            startangle=90,
        )
    ax.set_title(f"Phân phối Alert Severity\n"
                 f"(Tổng {summary['total_alerts']} alerts)")

    # ── Biểu đồ 6: Detection per attack type ────────────────────
    ax = axes[1, 2]
    scen_names  = [res["scenario"].name
                   for res in scenario_results]
    loss_rates_scen = []
    for res in scenario_results:
        all_pkts  = [p for w in res["windows"] for p in w]
        lost      = sum(1 for p in all_pkts if p.is_lost)
        total     = len(all_pkts)
        loss_rates_scen.append(
            lost/total if total > 0 else 0
        )
    bar_colors_scen = [
        "#2ecc71" if r < bs.THRESHOLD_K/bs.WINDOW_SIZE
        else "#e74c3c"
        for r in loss_rates_scen
    ]
    bars = ax.bar(range(len(scen_names)),
                  loss_rates_scen,
                  color=bar_colors_scen,
                  edgecolor="black", alpha=0.85)
    ax.axhline(
        y=bs.THRESHOLD_K/bs.WINDOW_SIZE,
        color='red', linestyle='--',
        label=f'Alert threshold = {bs.THRESHOLD_K}/{bs.WINDOW_SIZE}'
    )
    ax.set_xticks(range(len(scen_names)))
    ax.set_xticklabels(
        [n.replace(" ", "\n") for n in scen_names],
        fontsize=8
    )
    ax.set_title("Loss Rate theo Kịch bản Tấn công\n"
                 "(Đỏ = Vượt ngưỡng phát hiện)")
    ax.set_ylabel("Packet Loss Rate")
    ax.set_ylim(0, 0.6)
    ax.legend(fontsize=9)
    for bar, rate in zip(bars, loss_rates_scen):
        ax.text(
            bar.get_x() + bar.get_width()/2,
            bar.get_height() + 0.01,
            f"{rate:.1%}",
            ha='center', fontsize=9, fontweight='bold'
        )

    plt.tight_layout()
    plt.savefig("wearable_honeypot_results.png",
                dpi=150, bbox_inches='tight')
    plt.show()


if __name__ == "__main__":
    run_wearable()