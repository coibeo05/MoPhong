# main_c12.py
import numpy as np
import matplotlib.pyplot as plt
import matplotlib
matplotlib.rcParams['font.family'] = 'DejaVu Sans'

from fuzzy_sets         import (trimf, create_RTIPA,
                                 create_UARPP, create_RARPP, create_SAP)
from fuzzy_inference    import MamdaniFIS
from kfsensor_simulator import KFSensorSimulator
from network_monitor    import NetworkMonitor


def run_c12():
    print("=" * 60)
    print("  FUZZY LOGIC CHỐNG SPOOFING - CHƯƠNG 12")
    print("  KFSensor + Mamdani FIS")
    print("=" * 60)

    # ── 1. Sinh quan sát ────────────────────────────────────────
    print("\n[1] KFSensor monitoring network...")
    sim  = KFSensorSimulator()
    obs_list = sim.generate_observations(n=30)
    print(f"  Generated {len(obs_list)} observations")

    # ── 2. Chạy Fuzzy Inference ─────────────────────────────────
    print("\n[2] Fuzzy Inference System computing SAP...")
    monitor = NetworkMonitor()
    results = monitor.monitor(obs_list)
    monitor.summary()

    # ── 3. Kiểm tra 6 case từ Bảng I Chương 12 ─────────────────
    print("\n[3] Verifying Table I from Chapter 12:")
    table1_cases = [r for r in results if r["obs_id"] >= 100]
    print(f"\n  {'Obs':>4} | {'RTIPA':>6} {'UARPP':>6} "
          f"{'RARPP':>6} | {'SAP':>6} | Level | KFSensor")
    print(f"  {'─'*65}")
    for r in table1_cases:
        print(f"  {r['obs_id']:>4} | "
              f"{r['RTIPA']:>6.0f} {r['UARPP']:>6.0f} "
              f"{r['RARPP']:>6.0f} | "
              f"{r['SAP']:>5.1f}% | "
              f"{r['level']:>6} | No detection")

    # ── 4. Vẽ biểu đồ ───────────────────────────────────────────
    _plot_results(results, obs_list)
    print("\n[DONE] Chapter 12 simulation complete!")


def _plot_results(results, obs_list):
    fig = plt.figure(figsize=(18, 12))
    fig.suptitle("Chương 12 – Fuzzy Logic phát hiện Spoofing Attack\n"
                 "KFSensor + Mamdani Fuzzy Inference System",
                 fontsize=13, fontweight='bold')

    # ── Hàng 1: Membership functions ────────────────────────────

    # Biểu đồ 1: RTIPA membership
    ax1 = fig.add_subplot(3, 3, 1)
    x = np.linspace(80, 500, 300)
    rtipa = create_RTIPA()
    colors_mf = {"Low": "#3498db", "Medium": "#f39c12", "High": "#e74c3c"}
    for label, (a, b, c) in rtipa.sets.items():
        y = [trimf(xi, a, b, c) for xi in x]
        ax1.plot(x, y, label=label,
                 color=colors_mf[label], linewidth=2)
    ax1.set_title("RTIPA - Biến đầu vào 1\n(Trusted IP Rate)")
    ax1.set_xlabel("gói/giây")
    ax1.set_ylabel("Độ thuộc")
    ax1.legend(fontsize=8)
    ax1.set_ylim(-0.05, 1.15)
    ax1.grid(alpha=0.3)

    # Biểu đồ 2: UARPP membership
    ax2 = fig.add_subplot(3, 3, 2)
    x2 = np.linspace(10, 60, 300)
    uarpp = create_UARPP()
    for label, (a, b, c) in uarpp.sets.items():
        y = [trimf(xi, a, b, c) for xi in x2]
        ax2.plot(x2, y, label=label,
                 color=colors_mf[label], linewidth=2)
    ax2.set_title("UARPP - Biến đầu vào 2\n(Unusual ARP Packets)")
    ax2.set_xlabel("gói/giây")
    ax2.legend(fontsize=8)
    ax2.set_ylim(-0.05, 1.15)
    ax2.grid(alpha=0.3)

    # Biểu đồ 3: RARPP membership
    ax3 = fig.add_subplot(3, 3, 3)
    x3 = np.linspace(50, 300, 300)
    rarpp = create_RARPP()
    for label, (a, b, c) in rarpp.sets.items():
        y = [trimf(xi, a, b, c) for xi in x3]
        ax3.plot(x3, y, label=label,
                 color=colors_mf[label], linewidth=2)
    ax3.set_title("RARPP - Biến đầu vào 3\n(ARP Packet Rate)")
    ax3.set_xlabel("gói/giây")
    ax3.legend(fontsize=8)
    ax3.set_ylim(-0.05, 1.15)
    ax3.grid(alpha=0.3)

    # ── Hàng 2: Kết quả quan sát ─────────────────────────────────

    # Biểu đồ 4: SAP output membership
    ax4 = fig.add_subplot(3, 3, 4)
    x4 = np.linspace(0, 100, 300)
    sap = create_SAP()
    for label, (a, b, c) in sap.sets.items():
        y = [trimf(xi, a, b, c) for xi in x4]
        ax4.plot(x4, y, label=label,
                 color=colors_mf[label], linewidth=2)
    ax4.set_title("SAP - Biến đầu ra\n(Spoofing Attack Probability)")
    ax4.set_xlabel("%")
    ax4.set_ylabel("Độ thuộc")
    ax4.axvline(x=30, color='gray', linestyle='--',
                alpha=0.7, label='Ngưỡng Medium')
    ax4.axvline(x=60, color='red',  linestyle='--',
                alpha=0.7, label='Ngưỡng High')
    ax4.legend(fontsize=7)
    ax4.set_ylim(-0.05, 1.15)
    ax4.grid(alpha=0.3)

    # Biểu đồ 5: SAP theo từng quan sát
    ax5 = fig.add_subplot(3, 3, 5)
    obs_ids = [r["obs_id"] for r in results if r["obs_id"] < 100]
    sap_vals= [r["SAP"]    for r in results if r["obs_id"] < 100]
    bar_colors = []
    for r in results:
        if r["obs_id"] >= 100:
            continue
        if r["level"] == "HIGH":
            bar_colors.append("#e74c3c")
        elif r["level"] == "MEDIUM":
            bar_colors.append("#f39c12")
        else:
            bar_colors.append("#2ecc71")
    ax5.bar(range(len(obs_ids)), sap_vals,
            color=bar_colors, edgecolor="black", alpha=0.85)
    ax5.axhline(y=60, color='red',  linestyle='--',
                label='HIGH threshold (60%)')
    ax5.axhline(y=30, color='orange', linestyle='--',
                label='MEDIUM threshold (30%)')
    ax5.set_title("SAP theo quan sát\n(Random observations)")
    ax5.set_xlabel("Observation index")
    ax5.set_ylabel("SAP (%)")
    ax5.set_ylim(0, 110)
    ax5.legend(fontsize=7)

    # Biểu đồ 6: Phân phối mức cảnh báo
    ax6 = fig.add_subplot(3, 3, 6)
    all_results = results
    level_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in all_results:
        level_counts[r["level"]] += 1
    lv_colors = {"HIGH": "#e74c3c", "MEDIUM": "#f39c12", "LOW": "#2ecc71"}
    bars = ax6.bar(level_counts.keys(),
                   level_counts.values(),
                   color=[lv_colors[l] for l in level_counts],
                   edgecolor="black")
    ax6.set_title("Phân phối mức cảnh báo\n(Tất cả quan sát)")
    ax6.set_ylabel("Số lần")
    for bar in bars:
        h = bar.get_height()
        ax6.text(bar.get_x() + bar.get_width()/2,
                 h + 0.3, str(int(h)),
                 ha='center', fontweight='bold')

    # ── Hàng 3: Bảng I và surface ───────────────────────────────

    # Biểu đồ 7: Bảng I từ Chương 12
    ax7 = fig.add_subplot(3, 3, 7)
    ax7.axis('off')
    table1 = [r for r in results if r["obs_id"] >= 100]
    col_labels = ["Obs", "RTIPA", "UARPP", "RARPP", "SAP", "Level"]
    table_data = [
        [str(r["obs_id"]),
         f"{r['RTIPA']:.0f}",
         f"{r['UARPP']:.0f}",
         f"{r['RARPP']:.0f}",
         f"{r['SAP']:.1f}%",
         r["level"]]
        for r in table1
    ]
    tbl = ax7.table(cellText=table_data,
                    colLabels=col_labels,
                    loc='center', cellLoc='center')
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(9)
    tbl.scale(1.2, 1.8)
    # Tô màu theo level
    level_row_colors = {
        "HIGH":   "#ffcccc",
        "MEDIUM": "#fff3cc",
        "LOW":    "#ccffcc",
    }
    for i, row in enumerate(table_data):
        color = level_row_colors.get(row[5], "white")
        for j in range(len(col_labels)):
            tbl[(i+1, j)].set_facecolor(color)
    ax7.set_title("Bảng I - Kết quả mô phỏng\n(Chương 12, Table I)",
                  fontweight='bold')

    # Biểu đồ 8: Surface RTIPA vs UARPP → SAP
    ax8 = fig.add_subplot(3, 3, 8, projection='3d')
    fis = MamdaniFIS()
    rtipa_vals = np.linspace(80,  500, 20)
    uarpp_vals = np.linspace(10,  60,  20)
    R, U = np.meshgrid(rtipa_vals, uarpp_vals)
    SAP_surface = np.zeros_like(R)
    for i in range(R.shape[0]):
        for j in range(R.shape[1]):
            res = fis.compute(R[i,j], U[i,j], 175)
            SAP_surface[i,j] = res["SAP"]
    surf = ax8.plot_surface(R, U, SAP_surface,
                            cmap='RdYlGn_r', alpha=0.85)
    ax8.set_xlabel("RTIPA", fontsize=8)
    ax8.set_ylabel("UARPP", fontsize=8)
    ax8.set_zlabel("SAP (%)", fontsize=8)
    ax8.set_title("Fuzzy Surface\nRTIPA × UARPP → SAP")
    fig.colorbar(surf, ax=ax8, shrink=0.5)

    # Biểu đồ 9: So sánh KFSensor vs Fuzzy
    ax9 = fig.add_subplot(3, 3, 9)
    table1_sap = [r["SAP"] for r in results if r["obs_id"] >= 100]
    obs_labels  = [f"Obs.{r['obs_id']-99}"
                   for r in results if r["obs_id"] >= 100]
    kfsensor_detect = [0] * len(table1_sap)  # KFSensor không phát hiện
    x_pos = range(len(obs_labels))
    width = 0.35
    ax9.bar([xi - width/2 for xi in x_pos],
            kfsensor_detect, width,
            label="KFSensor (gốc)",
            color="#95a5a6", edgecolor="black")
    ax9.bar([xi + width/2 for xi in x_pos],
            table1_sap, width,
            label="Fuzzy FIS",
            color=[("#e74c3c" if s>=60 else
                    "#f39c12" if s>=30 else "#2ecc71")
                   for s in table1_sap],
            edgecolor="black")
    ax9.axhline(y=60, color='red', linestyle='--', alpha=0.5)
    ax9.axhline(y=30, color='orange', linestyle='--', alpha=0.5)
    ax9.set_title("So sánh KFSensor vs Fuzzy FIS\n(Table I cases)")
    ax9.set_xticks(list(x_pos))
    ax9.set_xticklabels(obs_labels, fontsize=8)
    ax9.set_ylabel("SAP (%) / Detection")
    ax9.set_ylim(0, 110)
    ax9.legend(fontsize=8)

    plt.tight_layout()
    plt.savefig("chapter12_fuzzy_spoofing.png",
                dpi=150, bbox_inches='tight')
    plt.show()


if __name__ == "__main__":
    run_c12()