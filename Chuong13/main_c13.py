# main_c13.py
import matplotlib.pyplot as plt
import matplotlib
import numpy as np
matplotlib.rcParams['font.family'] = 'DejaVu Sans'

from network_traffic  import TrafficGenerator
from honeyanole       import Honeyanole


def run_c13():
    print("=" * 60)
    print("  HỆ THỐNG HONEYANOLE - CHƯƠNG 13")
    print("  Iptables + Snort + Honeyd/Honeytrap/Sebek")
    print("=" * 60)

    # ── 1. Sinh lưu lượng ──────────────────────────────────────
    print("\n[1] Generating network traffic...")
    known_attackers = [
        "203.0.113.10",
        "198.51.100.25",
        "192.0.2.100",
    ]
    gen   = TrafficGenerator()
    conns = gen.generate(n=150,
                         known_attackers=known_attackers)

    # ── 2. Chạy Honeyanole ──────────────────────────────────────
    print("\n[2] Running Honeyanole system...")
    honeyanole = Honeyanole()
    results, records, redirector = honeyanole.run(conns)

    # ── 3. Kiểm tra phát hiện honeypot (Bảng II, III, IV) ──────
    print("\n[3] Service Support Test (Table II - Chapter 13):")
    _service_support_test()

    print("\n[4] Detection Test (Table IV - Chapter 13):")
    _detection_test()

    # ── 5. Vẽ biểu đồ ───────────────────────────────────────────
    _plot_results(conns, results, records, redirector, honeyanole)
    print("\n[DONE] Chapter 13 simulation complete!")


def _service_support_test():
    """Tái hiện Bảng II - Chương 13"""
    headers = ["Loại hỗ trợ", "Direct", "Honeyd",
               "Honeytrap", "Honeyanole"]
    rows = [
        ["HTTP GET",      "+", "-", "-", "+"],
        ["HTTP OPTIONS",  "+", "-", "-", "+"],
        ["HTTP HEAD",     "+", "-", "-", "+"],
        ["HTTP TRACE",    "+", "-", "-", "+"],
        ["Keep-Alive",    "+", "-", "-", "+"],
        ["Pipelining",    "+", "-", "-", "+"],
    ]
    col_w = [16, 8, 8, 10, 12]
    header_str = "".join(
        h.ljust(col_w[i]) for i, h in enumerate(headers)
    )
    print(f"\n  {header_str}")
    print(f"  {'─' * sum(col_w)}")
    for row in rows:
        row_str = "".join(
            v.ljust(col_w[i]) for i, v in enumerate(row)
        )
        print(f"  {row_str}")
    print(f"\n  Kết luận: Honeyd/Honeytrap KHÔNG pass → bị phát hiện")
    print(f"            Honeyanole PASS → tránh bị phát hiện ✅")


def _detection_test():
    """Tái hiện Bảng IV - Chương 13"""
    headers = ["Phương pháp phát hiện", "Honeyd",
               "Honeytrap", "Sebek", "Honeyanole"]
    rows = [
        ["OS Fingerprint (Nmap)",      "❌", "❌", "❌", "✅ Pass"],
        ["RTT Analysis (N-P)",         "❌", "❌", "❌", "✅ Pass"],
        ["TCP/IP Fingerprint (SVM)",   "❌", "❌", "❌", "✅ Pass"],
        ["Filesystem Feature",         "❌", "❌", "⚠️ Det", "✅ Pass*"],
        ["No Line Break",              "❌", "❌", "⚠️ Det", "✅ Pass*"],
        ["Service Support Test",       "⚠️ Det", "⚠️ Det", "✅", "✅ Pass"],
    ]
    col_w = [26, 8, 10, 10, 12]
    header_str = "".join(
        h.ljust(col_w[i]) for i, h in enumerate(headers)
    )
    print(f"\n  {header_str}")
    print(f"  {'─' * sum(col_w)}")
    for row in rows:
        row_str = "".join(
            v.ljust(col_w[i]) for i, v in enumerate(row)
        )
        print(f"  {row_str}")
    print(f"\n  ✅ Pass = Không bị phát hiện | ❌ = Bị phát hiện")
    print(f"  * Sebek (high-interaction) vẫn có thể bị phát hiện")
    print(f"    ở cấp hệ thống → cần honeypot tương tác trung bình")


def _plot_results(conns, results, records,
                  redirector, honeyanole):
    fig, axes = plt.subplots(2, 3, figsize=(18, 11))
    fig.suptitle(
        "Chương 13 – Hệ thống Honeyanole\n"
        "Thu thập | Chuyển hướng L2/L3 | Đánh lừa",
        fontsize=13, fontweight='bold'
    )

    colors = {
        "normal":  "#2ecc71",
        "probe":   "#f39c12",
        "attack":  "#e74c3c",
    }

    # ── Biểu đồ 1: Phân phối lưu lượng ─────────────────────────
    ax = axes[0, 0]
    type_counts = {
        t: sum(1 for c in conns if c.conn_type == t)
        for t in ["normal", "probe", "attack"]
    }
    bars = ax.bar(type_counts.keys(),
                  type_counts.values(),
                  color=[colors[t] for t in type_counts],
                  edgecolor="black")
    ax.set_title("Phân phối lưu lượng\n(TrafficGenerator)")
    ax.set_ylabel("Số kết nối")
    for bar in bars:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2,
                h + 0.5, str(int(h)),
                ha='center', fontweight='bold')

    # ── Biểu đồ 2: Blacklist score distribution ─────────────────
    ax = axes[0, 1]
    scores = [e.score for e in
              honeyanole.blacklist.entries.values()]
    if scores:
        ax.hist(scores, bins=range(1, max(scores)+2),
                color="#9b59b6", edgecolor="black", alpha=0.8)
    ax.axvline(x=honeyanole.blacklist.SCORE_THRESHOLD,
               color='red', linestyle='--',
               label=f'Threshold={honeyanole.blacklist.SCORE_THRESHOLD}')
    ax.set_title("Phân phối Blacklist Score\n(Phase 1: Collection)")
    ax.set_xlabel("Threat Score")
    ax.set_ylabel("Số IP")
    ax.legend(fontsize=9)

    # ── Biểu đồ 3: L2 vs L3 redirection ─────────────────────────
    ax = axes[0, 2]
    l2 = redirector.l2_count
    l3 = redirector.l3_count
    ax.pie([l2, l3],
           labels=[f"L2 - Production\n({l2} conns)",
                   f"L3 - Deception\n({l3} conns)"],
           colors=["#2ecc71", "#e74c3c"],
           autopct='%1.1f%%',
           startangle=90,
           explode=(0, 0.05))
    ax.set_title("Chuyển hướng L2 vs L3\n(Phase 2: Redirection)")

    # ── Biểu đồ 4: Latency so sánh ──────────────────────────────
    ax = axes[1, 0]
    l2_lat = [r.latency_ms for r in results
              if r.redirect_type == "L2_production"]
    l3_lat = [r.latency_ms for r in results
              if r.redirect_type.startswith("L3")]
    bait_lat = [r.latency_ms * 1.8 for r in results
                if r.redirect_type.startswith("L3")]

    data_plot  = []
    label_plot = []
    color_plot = []
    if l2_lat:
        data_plot.append(l2_lat)
        label_plot.append("Direct (L2)")
        color_plot.append("#2ecc71")
    if l3_lat:
        data_plot.append(l3_lat)
        label_plot.append("Honeyanole (L3)")
        color_plot.append("#e74c3c")
    if bait_lat:
        data_plot.append(bait_lat)
        label_plot.append("Bait&Switch")
        color_plot.append("#f39c12")

    bp = ax.boxplot(data_plot, tick_labels=label_plot,
                    patch_artist=True)
    for patch, color in zip(bp['boxes'], color_plot):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)
    ax.set_title("So sánh độ trễ kết nối\n(Bảng II - Chapter 13)")
    ax.set_ylabel("Latency (ms)")

    # ── Biểu đồ 5: Deception server capture ─────────────────────
    ax = axes[1, 1]
    server_counts = {}
    for r in records:
        server_counts[r.server_type] = \
            server_counts.get(r.server_type, 0) + 1
    if server_counts:
        s_colors = {
            "honeyd":    "#3498db",
            "honeytrap": "#e67e22",
            "sebek":     "#8e44ad",
            "unknown":   "#95a5a6",
        }
        bars = ax.bar(
            server_counts.keys(),
            server_counts.values(),
            color=[s_colors.get(k, "#95a5a6")
                   for k in server_counts],
            edgecolor="black"
        )
        for bar in bars:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2,
                    h + 0.2, str(int(h)),
                    ha='center', fontweight='bold')
    ax.set_title("Phân phối tấn công\ntheo Deception Server")
    ax.set_ylabel("Số cuộc tấn công bắt được")

    # ── Biểu đồ 6: Bảng so sánh detection ───────────────────────
    ax = axes[1, 2]
    ax.axis('off')
    methods = ["OS Fingerprint", "RTT Analysis",
               "TCP/IP Fingerprint", "Filesystem",
               "Service Support"]
    honeypots = ["Honeyd", "Honeytrap", "Sebek", "Honeyanole"]
    detect_matrix = [
        [0, 0, 0, 1],
        [0, 0, 0, 1],
        [0, 0, 0, 1],
        [0, 0, 1, 0],
        [1, 1, 0, 1],
    ]
    # 0=không bị phát hiện(xanh), 1=bị phát hiện(đỏ)
    cell_colors = []
    cell_text   = []
    for row in detect_matrix:
        color_row = []
        text_row  = []
        for val in row:
            if val == 0:
                color_row.append("#d5f5e3")
                text_row.append("Pass ✓")
            else:
                color_row.append("#fadbd8")
                text_row.append("Detect ✗")
        cell_colors.append(color_row)
        cell_text.append(text_row)

    tbl = ax.table(
        cellText   = cell_text,
        rowLabels  = methods,
        colLabels  = honeypots,
        cellColours= cell_colors,
        loc='center', cellLoc='center'
    )
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(8)
    tbl.scale(1.3, 1.9)
    ax.set_title("Bảng IV - Kiểm tra phát hiện\n(Chapter 13)",
                 fontweight='bold')

    plt.tight_layout()
    plt.savefig("chapter13_honeyanole.png",
                dpi=150, bbox_inches='tight')
    plt.show()


if __name__ == "__main__":
    run_c13()