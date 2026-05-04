# main_webhoneypot.py
import matplotlib.pyplot as plt
import matplotlib
import numpy as np
matplotlib.rcParams['font.family'] = 'DejaVu Sans'

from fake_news_data      import FakeNewsWebsite
from attack_logger       import AttackLogger
from likejacking         import LikeJacking


def run_webhoneypot():
    print("=" * 60)
    print("  ACTIVE WEB HONEYPOT - COUNTERATTACK")
    print("  SQLi + XSS + LikeJacking + Browser Fingerprint")
    print("=" * 60)

    # ── 1. Khởi tạo trang web giả ───────────────────────────────
    print("\n[1] Initializing fake news website...")
    site = FakeNewsWebsite()
    print(f"  Site: {site.SITE_NAME}")
    print(f"  Pages: Beranda | Cari Berita (SQLi) | "
          f"Komentar (XSS)")
    print(f"  Articles: {len(site.ARTICLES)} hardcoded")
    print(f"  Fake DB tables: {site.FAKE_DB.fake_tables}")

    # ── 2. Mô phỏng 36.000 requests ─────────────────────────────
    print("\n[2] Simulating 2 months of attack traffic...")
    logger = AttackLogger()
    events = logger.simulate_2months_traffic(total=36000)
    stats  = logger.get_statistics()

    print(f"\n  📊 Traffic Summary:")
    print(f"  Total requests : {stats['total']:>8,}")
    print(f"  SQL Injection  : {stats['sqli']:>8,} "
          f"({stats['sqli']/stats['total']*100:.1f}%)")
    print(f"  XSS attacks    : {stats['xss']:>8,} "
          f"({stats['xss']/stats['total']*100:.1f}%)")
    print(f"  Normal traffic : {stats['normal']:>8,} "
          f"({stats['normal']/stats['total']*100:.1f}%)")
    print(f"  Unique IPs     : {stats['unique_ips']:>8,}")

    # ── 3. SQLi Analysis ─────────────────────────────────────────
    print("\n[3] SQLi Attack Analysis:")
    print(f"  Stages detected:")
    for stage, count in sorted(
            stats['sqli_stages'].items(),
            key=lambda x: x[1], reverse=True):
        print(f"    {stage:35s}: {count:>5,}")

    sqli_events = [e for e in events if e.attack_type == "SQLi"]
    tools = {}
    for e in sqli_events:
        t = e.sqli_info.tool_detected
        tools[t] = tools.get(t, 0) + 1
    print(f"  Tools detected:")
    for tool, count in sorted(
            tools.items(), key=lambda x: x[1], reverse=True):
        print(f"    {tool:20s}: {count:>5,}")

    # ── 4. XSS Analysis ──────────────────────────────────────────
    print("\n[4] XSS Attack Analysis:")
    print(f"  Attack intents:")
    for intent, count in sorted(
            stats['xss_intents'].items(),
            key=lambda x: x[1], reverse=True):
        print(f"    {intent:30s}: {count:>5,}")

    # ── 5. LikeJacking Results ───────────────────────────────────
    print("\n[5] LikeJacking Results:")
    likejack  = LikeJacking()
    lj_results = likejack.simulate_likejack_capture(n_attacks=200)
    lj_success = sum(1 for r in lj_results if r.success)
    print(f"  Total attackers hit LikeJack trap : 200")
    print(f"  Facebook profiles captured        : {lj_success}")
    print(f"  Success rate                      : "
          f"{lj_success/200*100:.1f}%")
    captured = [r for r in lj_results if r.success][:5]
    print(f"  Sample captured profiles:")
    for r in captured:
        print(f"    [{r.attacker_ip}] → "
              f"fb:{r.facebook_profile}")

    # ── 6. GeoIP Analysis ────────────────────────────────────────
    print("\n[6] Geographic Distribution (Top 5):")
    top_countries = sorted(
        stats['countries'].items(),
        key=lambda x: x[1], reverse=True
    )[:5]
    for country, count in top_countries:
        bar = "█" * (count // 500)
        print(f"  {country:15s}: {count:>6,} {bar}")

    print("\n[7] Top ASNs (Attackers):")
    attack_events = [e for e in events
                     if e.attack_type in ["SQLi", "XSS"]]
    asn_attack = {}
    for e in attack_events:
        a = e.fingerprint.asn
        asn_attack[a] = asn_attack.get(a, 0) + 1
    for asn, count in sorted(
            asn_attack.items(),
            key=lambda x: x[1], reverse=True)[:5]:
        print(f"  {asn:35s}: {count:>5,}")

    # ── 8. Vẽ biểu đồ ───────────────────────────────────────────
    _plot_results(stats, events, lj_results)
    print("\n[DONE] Web Honeypot simulation complete!")


def _plot_results(stats, events, lj_results):
    fig, axes = plt.subplots(2, 3, figsize=(18, 11))
    fig.suptitle(
        "Active Web Honeypot – Counterattack\n"
        "SQLi + XSS + LikeJacking + Browser Fingerprinting",
        fontsize=13, fontweight='bold'
    )

    # ── Biểu đồ 1: Phân phối request ────────────────────────────
    ax = axes[0, 0]
    labels = ["Normal\nTraffic", "SQL\nInjection", "XSS\nAttack"]
    sizes  = [stats['normal'], stats['sqli'], stats['xss']]
    colors = ["#2ecc71", "#e74c3c", "#f39c12"]
    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels, colors=colors,
        autopct='%1.1f%%', startangle=90,
        explode=(0, 0.05, 0.05)
    )
    ax.set_title(f"Phân phối {stats['total']:,} HTTP Requests\n"
                 f"(2 tháng thực tế)")

    # ── Biểu đồ 2: SQLi stages ───────────────────────────────────
    ax = axes[0, 1]
    stages = list(stats['sqli_stages'].keys())
    counts = list(stats['sqli_stages'].values())
    short  = [s.split('/')[0][:20] for s in stages]
    bars   = ax.barh(short, counts,
                     color="#e74c3c", edgecolor="black",
                     alpha=0.85)
    ax.set_title("SQLi Attack Stages\n(Giai đoạn tấn công)")
    ax.set_xlabel("Số lượng")
    for bar in bars:
        w = bar.get_width()
        ax.text(w + 20, bar.get_y() + bar.get_height()/2,
                f"{w:,}", va='center', fontsize=8)

    # ── Biểu đồ 3: XSS intents ───────────────────────────────────
    ax = axes[0, 2]
    intents = list(stats['xss_intents'].keys())
    i_count = list(stats['xss_intents'].values())
    bars    = ax.bar(range(len(intents)), i_count,
                     color="#f39c12", edgecolor="black",
                     alpha=0.85)
    ax.set_xticks(range(len(intents)))
    ax.set_xticklabels(
        [i[:15] for i in intents],
        rotation=20, ha='right', fontsize=8
    )
    ax.set_title("XSS Attack Intents\n(Mục đích tấn công XSS)")
    ax.set_ylabel("Số lượng")
    for bar in bars:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2,
                h + 10, f"{h:,}",
                ha='center', fontsize=8)

    # ── Biểu đồ 4: LikeJacking ───────────────────────────────────
    ax = axes[1, 0]
    lj_success = sum(1 for r in lj_results if r.success)
    lj_fail    = len(lj_results) - lj_success
    ax.pie(
        [lj_success, lj_fail],
        labels=[f"Facebook Captured\n({lj_success})",
                f"Not Captured\n({lj_fail})"],
        colors=["#3498db", "#95a5a6"],
        autopct='%1.1f%%',
        startangle=90,
        explode=(0.05, 0)
    )
    ax.set_title("LikeJacking Results\n"
                 "Facebook Profile Capture")

    # ── Biểu đồ 5: Top countries ─────────────────────────────────
    ax = axes[1, 1]
    top_c = sorted(
        stats['countries'].items(),
        key=lambda x: x[1], reverse=True
    )[:8]
    countries = [c[0] for c in top_c]
    c_counts  = [c[1] for c in top_c]
    c_colors  = ["#e74c3c" if c in
                  ["Indonesia", "China", "Russia"]
                  else "#3498db"
                  for c in countries]
    bars = ax.bar(range(len(countries)), c_counts,
                  color=c_colors, edgecolor="black",
                  alpha=0.85)
    ax.set_xticks(range(len(countries)))
    ax.set_xticklabels(countries, rotation=20,
                       ha='right', fontsize=8)
    ax.set_title("Phân phối Địa lý Kẻ tấn công\n"
                 "(GeoIP MaxMind)")
    ax.set_ylabel("Số requests")

    # ── Biểu đồ 6: Browser fingerprint OS distribution ───────────
    ax = axes[1, 2]
    attack_events = [e for e in events
                     if e.attack_type in ["SQLi", "XSS"]]
    os_count = {}
    for e in attack_events:
        os_name = e.fingerprint.os.split()[0]
        os_count[os_name] = os_count.get(os_name, 0) + 1
    top_os = sorted(
        os_count.items(),
        key=lambda x: x[1], reverse=True
    )[:6]
    os_names   = [o[0] for o in top_os]
    os_counts  = [o[1] for o in top_os]
    os_colors  = ["#9b59b6", "#2ecc71", "#e74c3c",
                  "#f39c12", "#3498db", "#1abc9c"]
    bars = ax.bar(range(len(os_names)), os_counts,
                  color=os_colors[:len(os_names)],
                  edgecolor="black", alpha=0.85)
    ax.set_xticks(range(len(os_names)))
    ax.set_xticklabels(os_names, rotation=15,
                       ha='right', fontsize=9)
    ax.set_title("OS Distribution của Kẻ tấn công\n"
                 "(Browser Fingerprinting)")
    ax.set_ylabel("Số lượng")
    for bar in bars:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2,
                h + 10, f"{h:,}",
                ha='center', fontsize=8)

    plt.tight_layout()
    plt.savefig("webhoneypot_results.png",
                dpi=150, bbox_inches='tight')
    plt.show()


if __name__ == "__main__":
    run_webhoneypot()