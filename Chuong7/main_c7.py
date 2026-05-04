# main_honeyware.py
import matplotlib.pyplot as plt
import matplotlib
import numpy as np
matplotlib.rcParams['font.family'] = 'DejaVu Sans'

from url_database      import URLDatabase
from honeyware_engine  import HoneywareEngine


def run_honeyware():
    print("=" * 60)
    print("  HONEYWARE - CLIENT HONEYPOT TƯƠNG TÁC THẤP")
    print("  94 URLs | 5 AV Engines | IP Bypass Testing")
    print("=" * 60)

    db     = URLDatabase()
    engine = HoneywareEngine()
    urls   = db.get_all_urls()

    malicious_urls = [u for u in urls if u.is_malicious]
    benign_urls    = [u for u in urls if not u.is_malicious]

    print(f"\n[DB] Total URLs: {len(urls)} | "
          f"Malicious: {len(malicious_urls)} | "
          f"Benign: {len(benign_urls)}")

    # ── Phase 1a: Quét ban đầu (chưa update) ───────────────────
    print("\n[1] Phase 1a: Initial scan (before signature update)...")
    results_initial = engine.run_phase1_initial_scan(
        urls, updated=False
    )
    _print_scan_summary(results_initial, "INITIAL SCAN")

    # ── Phase 1b: Quét sau khi update signature ─────────────────
    print("\n[2] Phase 1b: Scan after signature update...")
    results_updated = engine.run_phase1_initial_scan(
        urls, updated=True
    )
    _print_scan_summary(results_updated, "UPDATED SCAN")

    # ── Phase 2: Bypass IP tracking ─────────────────────────────
    print("\n[3] Phase 2: IP tracking bypass test (Mpack)...")
    bypass_results = engine.run_phase2_bypass_test(urls)
    _print_bypass_summary(bypass_results)

    # ── Phase 3: Browser-specific detection ─────────────────────
    print("\n[4] Phase 3: Browser-specific exploit detection...")
    browser_stats = engine.run_phase3_browser_test(malicious_urls)
    _print_browser_summary(browser_stats)

    # ── So sánh với Capture-HPC ─────────────────────────────────
    print("\n[5] Comparison with Capture-HPC:")
    comparison = engine.compare_with_capture_hpc(results_updated)
    _print_comparison(comparison)

    # ── Vẽ biểu đồ ──────────────────────────────────────────────
    _plot_results(results_initial, results_updated,
                  bypass_results, browser_stats, comparison)
    print("\n[DONE] Honeyware simulation complete!")


def _print_scan_summary(results, label):
    malicious_detected = sum(
        1 for r in results
        if r.final_verdict == "MALICIOUS"
    )
    suspicious = sum(
        1 for r in results
        if r.final_verdict == "SUSPICIOUS"
    )
    clean = sum(
        1 for r in results
        if r.final_verdict == "CLEAN"
    )
    total_mal = sum(1 for r in results if r.url_id <= 84)
    detected  = sum(
        1 for r in results
        if r.url_id <= 84
        and r.final_verdict in ["MALICIOUS", "SUSPICIOUS"]
    )

    print(f"\n  [{label}]")
    print(f"  MALICIOUS  : {malicious_detected}")
    print(f"  SUSPICIOUS : {suspicious}")
    print(f"  CLEAN      : {clean}")
    print(f"  Detection  : {detected}/{total_mal} malicious URLs "
          f"({detected/total_mal*100:.1f}%)")

    # AV engine breakdown
    print(f"\n  AV Engine Detection Rates:")
    av_counts = {}
    for r in results:
        if r.url_id > 84:
            continue
        for av in r.detected_by:
            av_counts[av] = av_counts.get(av, 0) + 1
    for av, count in sorted(av_counts.items(),
                             key=lambda x: x[1], reverse=True):
        print(f"    {av:10s}: {count:3d}/{total_mal} "
              f"({count/total_mal*100:.1f}%)")


def _print_bypass_summary(bypass_results):
    success = sum(1 for r in bypass_results if r.bypass_success)
    total   = len(bypass_results)
    print(f"\n  [BYPASS] Results:")
    print(f"  Total Mpack URLs tested : {total}")
    print(f"  Bypass successful       : {success}/{total} "
          f"({success/total*100:.1f}%)")
    print(f"  Malware triggered       : {success}")
    print(f"  Technique: Honeyware IP → initial request")
    print(f"             Wget spider  → trigger malware delivery")


def _print_browser_summary(browser_stats):
    print(f"\n  [BROWSER] Detection by browser type:")
    print(f"  {'Browser':25s} {'Detected':>10} {'Rate':>8}")
    print(f"  {'─'*45}")
    for browser, stats in browser_stats.items():
        print(f"  {browser:25s} "
              f"{stats['detected']:>5}/{stats['total']:<5} "
              f"{stats['detection_rate']:>6.1f}%")


def _print_comparison(comparison):
    print(f"\n  {'System':25s} {'Detected':>10} {'Rate':>8}")
    print(f"  {'─'*45}")
    print(f"  {'Capture-HPC':25s} "
          f"  {comparison['Capture-HPC']:>3}/84    "
          f"{comparison['Capture_HPC_rate']:>5.1f}%")
    print(f"  {'Honeyware (initial)':25s} "
          f"  {comparison['Honeyware_initial']:>3}/84    "
          f"{comparison['Honeyware_init_rate']:>5.1f}%")
    print(f"  {'Honeyware (updated)':25s} "
          f"  {comparison['Honeyware_updated']:>3}/84    "
          f"{comparison['Honeyware_upd_rate']:>5.1f}%")
    print(f"\n  ✅ Honeyware updated vượt trội Capture-HPC: "
          f"{comparison['Honeyware_updated'] - comparison['Capture-HPC']}"
          f" URLs thêm")


def _plot_results(results_init, results_upd,
                  bypass_results, browser_stats, comparison):
    fig, axes = plt.subplots(2, 3, figsize=(18, 11))
    fig.suptitle(
        "Honeyware – Client Honeypot tương tác thấp\n"
        "94 URLs | 5 AV Engines | IP Bypass | Browser Testing",
        fontsize=13, fontweight='bold'
    )

    # ── Biểu đồ 1: Phân phối URL theo loại ──────────────────────
    ax = axes[0, 0]
    categories = {}
    db = URLDatabase()
    for u in db.get_all_urls():
        categories[u.category] = categories.get(u.category, 0) + 1
    cat_colors = {
        "drive-by":        "#e74c3c",
        "exploit_kit":     "#e67e22",
        "phishing":        "#f39c12",
        "direct_download": "#c0392b",
        "normal":          "#2ecc71",
    }
    bars = ax.bar(
        categories.keys(),
        categories.values(),
        color=[cat_colors.get(c, "#95a5a6") for c in categories],
        edgecolor="black"
    )
    ax.set_title("Phân phối 94 URLs\ntheo loại tấn công")
    ax.set_ylabel("Số URLs")
    ax.tick_params(axis='x', rotation=15)
    for bar in bars:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2,
                h + 0.2, str(int(h)),
                ha='center', fontweight='bold')

    # ── Biểu đồ 2: AV detection rate ────────────────────────────
    ax = axes[0, 1]
    av_names   = list(
        URLDatabase().__class__.__mro__[0].__subclasses__()
    )
    av_engines = ["AVG", "F-Prot", "Avast", "ClamAV", "AntiVir"]
    init_rates = []
    upd_rates  = []
    total_mal  = 84

    for av in av_engines:
        init_count = sum(
            1 for r in results_init
            if r.url_id <= 84 and av in r.detected_by
        )
        upd_count = sum(
            1 for r in results_upd
            if r.url_id <= 84 and av in r.detected_by
        )
        init_rates.append(init_count / total_mal * 100)
        upd_rates.append(upd_count / total_mal * 100)

    x   = np.arange(len(av_engines))
    w   = 0.35
    ax.bar(x - w/2, init_rates, w,
           label="Before update",
           color="#f39c12", edgecolor="black", alpha=0.85)
    ax.bar(x + w/2, upd_rates, w,
           label="After update",
           color="#2ecc71", edgecolor="black", alpha=0.85)
    ax.set_title("Tỷ lệ phát hiện của 5 AV Engines\n"
                 "(Trước và Sau cập nhật Signature)")
    ax.set_xticks(x)
    ax.set_xticklabels(av_engines)
    ax.set_ylabel("Detection Rate (%)")
    ax.set_ylim(0, 110)
    ax.legend(fontsize=9)
    ax.axhline(y=100, color='red',
               linestyle='--', alpha=0.5, label='100%')

    # ── Biểu đồ 3: So sánh Honeyware vs Capture-HPC ─────────────
    ax = axes[0, 2]
    systems = ["Capture-HPC", "Honeyware\n(initial)",
               "Honeyware\n(updated)"]
    detected = [
        comparison["Capture-HPC"],
        comparison["Honeyware_initial"],
        comparison["Honeyware_updated"],
    ]
    bar_colors = ["#e74c3c", "#f39c12", "#2ecc71"]
    bars = ax.bar(systems, detected,
                  color=bar_colors, edgecolor="black")
    ax.axhline(y=84, color='navy',
               linestyle='--', label='Total malicious=84')
    ax.set_title("So sánh Honeyware vs Capture-HPC\n"
                 "(84 malicious URLs)")
    ax.set_ylabel("URLs phát hiện được")
    ax.set_ylim(0, 95)
    ax.legend(fontsize=9)
    for bar, val in zip(bars, detected):
        ax.text(bar.get_x() + bar.get_width()/2,
                bar.get_height() + 0.5,
                f"{val}/84\n({val/84*100:.1f}%)",
                ha='center', fontsize=10, fontweight='bold')

    # ── Biểu đồ 4: IP Bypass success rate ───────────────────────
    ax = axes[1, 0]
    success   = sum(1 for r in bypass_results if r.bypass_success)
    fail      = len(bypass_results) - success
    ax.pie(
        [success, fail],
        labels=[f"Bypass thành công\n({success})",
                f"Thất bại\n({fail})"],
        colors=["#2ecc71", "#e74c3c"],
        autopct='%1.1f%%',
        startangle=90,
        explode=(0.05, 0)
    )
    ax.set_title("Kết quả vượt qua IP Tracking\n"
                 "(Mpack exploit kit)")

    # ── Biểu đồ 5: Detection rate theo browser ───────────────────
    ax = axes[1, 1]
    browsers = list(browser_stats.keys())
    rates    = [s["detection_rate"] for s in browser_stats.values()]
    short_names = [b.split()[0] + " " + b.split()[-1]
                   if len(b.split()) > 1 else b
                   for b in browsers]
    bar_colors_br = [
        "#e74c3c" if "Explorer" in b else
        "#3498db" if "Firefox" in b else
        "#2ecc71" if "Chrome" in b else
        "#f39c12"
        for b in browsers
    ]
    bars = ax.bar(range(len(browsers)), rates,
                  color=bar_colors_br, edgecolor="black", alpha=0.85)
    ax.set_xticks(range(len(browsers)))
    ax.set_xticklabels(short_names, rotation=20,
                       ha='right', fontsize=8)
    ax.set_title("Detection Rate theo Browser\n"
                 "(Sau khi cập nhật signature)")
    ax.set_ylabel("Detection Rate (%)")
    ax.set_ylim(0, 110)
    ax.axhline(y=100, color='red',
               linestyle='--', alpha=0.5)
    for bar, rate in zip(bars, rates):
        ax.text(bar.get_x() + bar.get_width()/2,
                bar.get_height() + 1,
                f"{rate:.0f}%",
                ha='center', fontsize=8)

    # ── Biểu đồ 6: Verdict distribution ─────────────────────────
    ax = axes[1, 2]
    verdicts_init = {
        "MALICIOUS":  sum(1 for r in results_init
                          if r.final_verdict == "MALICIOUS"),
        "SUSPICIOUS": sum(1 for r in results_init
                          if r.final_verdict == "SUSPICIOUS"),
        "CLEAN":      sum(1 for r in results_init
                          if r.final_verdict == "CLEAN"),
    }
    verdicts_upd = {
        "MALICIOUS":  sum(1 for r in results_upd
                          if r.final_verdict == "MALICIOUS"),
        "SUSPICIOUS": sum(1 for r in results_upd
                          if r.final_verdict == "SUSPICIOUS"),
        "CLEAN":      sum(1 for r in results_upd
                          if r.final_verdict == "CLEAN"),
    }
    x   = np.arange(3)
    w   = 0.35
    ax.bar(x - w/2,
           [verdicts_init[k]
            for k in ["MALICIOUS","SUSPICIOUS","CLEAN"]],
           w, label="Before update",
           color="#f39c12", edgecolor="black", alpha=0.85)
    ax.bar(x + w/2,
           [verdicts_upd[k]
            for k in ["MALICIOUS","SUSPICIOUS","CLEAN"]],
           w, label="After update",
           color="#2ecc71", edgecolor="black", alpha=0.85)
    ax.set_xticks(x)
    ax.set_xticklabels(["MALICIOUS", "SUSPICIOUS", "CLEAN"])
    ax.set_title("Phân phối kết quả phán quyết\n"
                 "(Trước và Sau cập nhật)")
    ax.set_ylabel("Số URLs")
    ax.legend(fontsize=9)

    plt.tight_layout()
    plt.savefig("honeyware_results.png",
                dpi=150, bbox_inches='tight')
    plt.show()


if __name__ == "__main__":
    run_honeyware()