# url_database.py
from dataclasses import dataclass, field
from typing import List

@dataclass
class URLEntry:
    url_id:       int
    url:          str
    is_malicious: bool
    category:     str    # 'drive-by'/'exploit'/'phishing'/'normal'
    description:  str
    expected_files: List[str] = field(default_factory=list)

class URLDatabase:
    """
    Bộ sưu tập 94 URL:
    - 84 URL độc hại (từ công cụ tìm kiếm)
    - 10 URL vô hại (kiểm tra false positive)
    """

    def get_all_urls(self) -> List[URLEntry]:
        urls = []

        # ── 84 URL ĐỘC HẠI ──────────────────────────────────────
        # Nhóm 1: Drive-by download (30 URLs)
        drive_by = [
            ("http://malware-site-001.com/exploit.php",
             "Exploit IE vulnerability - downloads trojan.exe"),
            ("http://evil-ads-002.net/banner.php?id=1",
             "Malicious ad redirect - CVE-2006-3003"),
            ("http://badsite-003.ru/load.php",
             "Russian malware dropper - keylogger"),
            ("http://exploit-004.cn/ie.php",
             "Chinese IE exploit pack"),
            ("http://malware-005.com/pdf.php",
             "Malicious PDF exploit - Adobe Reader"),
            ("http://drive-by-006.net/flash.swf",
             "Flash exploit - CVE-2007-0071"),
            ("http://trojan-007.com/update.exe",
             "Fake Windows Update trojan"),
            ("http://spyware-008.net/toolbar.exe",
             "Spyware toolbar installer"),
            ("http://rootkit-009.com/svchost.exe",
             "Rootkit disguised as svchost"),
            ("http://worm-010.ru/spreading.exe",
             "Network worm propagation"),
        ]
        for i, (url, desc) in enumerate(drive_by, 1):
            urls.append(URLEntry(
                url_id=i, url=url,
                is_malicious=True,
                category="drive-by",
                description=desc,
                expected_files=["exploit.html",
                                 "payload.exe", "dropper.dll"]
            ))

        # Nhóm 2: Mpack exploit kit (20 URLs)
        mpack_urls = [
            f"http://mpack-exploit-{i:03d}.com/index.php"
            for i in range(11, 31)
        ]
        mpack_descs = [
            "Mpack IE7 exploit - heap spray",
            "Mpack Firefox exploit - CVE-2006-4253",
            "Mpack Opera exploit",
            "Mpack Safari exploit",
            "Mpack multi-browser exploit",
            "Mpack PDF exploit",
            "Mpack WMF exploit",
            "Mpack ANI exploit - CVE-2007-0038",
            "Mpack MOV exploit",
            "Mpack QuickTime exploit",
            "Mpack Real Player exploit",
            "Mpack WMP exploit",
            "Mpack Java exploit",
            "Mpack ActiveX exploit",
            "Mpack VML exploit",
            "Mpack MDAC exploit",
            "Mpack WebViewFolderIcon exploit",
            "Mpack XML Core exploit",
            "Mpack Snapshot exploit",
            "Mpack CreateObject exploit",
        ]
        for i, (url, desc) in enumerate(
                zip(mpack_urls, mpack_descs), 11):
            urls.append(URLEntry(
                url_id=i, url=url,
                is_malicious=True,
                category="exploit_kit",
                description=desc,
                expected_files=["mpack.php", "shell.exe",
                                 "backdoor.dll"]
            ))

        # Nhóm 3: Phishing (20 URLs)
        phishing_targets = [
            "paypal", "ebay", "bank-of-america",
            "citibank", "chase", "wellsfargo",
            "amazon", "microsoft", "apple", "google",
            "facebook", "twitter", "linkedin",
            "yahoo", "hotmail", "gmail",
            "visa", "mastercard", "western-union", "irs"
        ]
        for i, target in enumerate(phishing_targets, 31):
            urls.append(URLEntry(
                url_id=i,
                url=f"http://secure-{target}-login.com/verify.php",
                is_malicious=True,
                category="phishing",
                description=f"Phishing site impersonating {target}",
                expected_files=["phish.html", "credential_harvester.php"]
            ))

        # Nhóm 4: Malware download trực tiếp (14 URLs)
        malware_types = [
            ("trojan",   "Remote Access Trojan"),
            ("keylogger","Keyboard logger"),
            ("ransomware","File encryption ransomware"),
            ("spyware",  "System monitoring spyware"),
            ("adware",   "Aggressive adware"),
            ("rootkit",  "Kernel-level rootkit"),
            ("botnet",   "Botnet client"),
            ("backdoor", "Remote backdoor"),
            ("downloader","Malware downloader"),
            ("dropper",  "Multi-stage dropper"),
            ("stealer",  "Password stealer"),
            ("worm",     "Self-replicating worm"),
            ("banker",   "Banking trojan"),
            ("rat",      "Remote administration tool"),
        ]
        for i, (mtype, desc) in enumerate(malware_types, 51):
            urls.append(URLEntry(
                url_id=i,
                url=f"http://download-{mtype}-{i:03d}.net/{mtype}.exe",
                is_malicious=True,
                category="direct_download",
                description=desc,
                expected_files=[f"{mtype}.exe", f"{mtype}.dll"]
            ))

        # ── 10 URL VÔ HẠI ───────────────────────────────────────
        benign_sites = [
            ("https://www.google.com",      "Google search engine"),
            ("https://www.wikipedia.org",   "Wikipedia encyclopedia"),
            ("https://www.microsoft.com",   "Microsoft official site"),
            ("https://www.apple.com",       "Apple official site"),
            ("https://www.python.org",      "Python programming"),
            ("https://www.github.com",      "GitHub code repository"),
            ("https://www.stackoverflow.com","Stack Overflow Q&A"),
            ("https://www.mozilla.org",     "Mozilla Firefox"),
            ("https://www.ubuntu.com",      "Ubuntu Linux"),
            ("https://www.w3.org",          "W3C standards"),
        ]
        for i, (url, desc) in enumerate(benign_sites, 85):
            urls.append(URLEntry(
                url_id=i, url=url,
                is_malicious=False,
                category="normal",
                description=desc,
                expected_files=["index.html"]
            ))

        return urls