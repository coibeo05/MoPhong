# browser_fingerprint.py
import random
from dataclasses import dataclass
from typing import Dict, List

@dataclass
class AttackerFingerprint:
    ip_address:    str
    public_ip:     str
    user_agent:    str
    browser:       str
    os:            str
    screen_res:    str
    timezone:      str
    language:      str
    plugins:       List[str]
    asn:           str           # Autonomous System Number
    isp:           str
    country:       str
    city:          str
    latitude:      float
    longitude:     float
    cookie_stolen: str
    referrer:      str
    attack_type:   str

class BrowserFingerprintCollector:
    """
    Thu thập fingerprint kẻ tấn công qua JavaScript obfuscated
    + MaxMind GeoIP2 để định vị địa lý
    """

    # Database GeoIP giả lập
    GEO_DB = {
        "ID": {"country": "Indonesia",
               "cities": ["Jakarta", "Bandung", "Surabaya",
                          "Yogyakarta", "Medan"],
               "asns": ["AS7713 Telkom Indonesia",
                        "AS4761 Indosat",
                        "AS23693 XL Axiata",
                        "AS9341 CBN"]},
        "MY": {"country": "Malaysia",
               "cities": ["Kuala Lumpur", "Penang", "Johor Bahru"],
               "asns": ["AS4788 TM Net",
                        "AS9534 Maxis"]},
        "SG": {"country": "Singapore",
               "cities": ["Singapore"],
               "asns": ["AS4657 StarHub",
                        "AS9506 Singtel"]},
        "US": {"country": "United States",
               "cities": ["New York", "Los Angeles",
                          "Chicago", "Houston"],
               "asns": ["AS7018 AT&T",
                        "AS701 Verizon",
                        "AS3356 Lumen"]},
        "CN": {"country": "China",
               "cities": ["Beijing", "Shanghai", "Guangzhou"],
               "asns": ["AS4134 China Telecom",
                        "AS4837 China Unicom"]},
        "RU": {"country": "Russia",
               "cities": ["Moscow", "Saint Petersburg"],
               "asns": ["AS8359 MTS",
                        "AS3216 VEON Russia"]},
    }

    USER_AGENTS = [
        ("IE 8",
         "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0)",
         "Internet Explorer", "Windows Vista"),
        ("Firefox 52",
         "Mozilla/5.0 (Windows NT 10.0; rv:52.0) "
         "Gecko/20100101 Firefox/52.0",
         "Firefox", "Windows 10"),
        ("Chrome 89",
         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
         "AppleWebKit/537.36 Chrome/89.0.4389.82",
         "Chrome", "Windows 10"),
        ("Kali Linux Firefox",
         "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) "
         "Gecko/20100101 Firefox/78.0",
         "Firefox", "Kali Linux"),
        ("Burp Suite",
         "Mozilla/5.0 (compatible; Burp Suite Professional)",
         "Burp Suite", "Unknown"),
    ]

    ATTACK_TOOLS_UA = [
        "sqlmap/1.7",
        "Nikto/2.1.6",
        "python-requests/2.28.0",
        "curl/7.81.0",
        "Go-http-client/1.1",
        "Wget/1.21.2",
    ]

    def _lookup_geoip(self, ip: str) -> Dict:
        """Tra cứu GeoIP (mô phỏng MaxMind GeoIP2)"""
        # Phân tích octet đầu để đoán quốc gia
        first_octet = int(ip.split('.')[0])
        if first_octet in range(36, 40):
            country_code = "ID"
        elif first_octet in range(115, 120):
            country_code = "CN"
        elif first_octet in range(91, 95):
            country_code = "RU"
        elif first_octet in range(54, 56):
            country_code = "US"
        else:
            country_code = random.choice(list(self.GEO_DB.keys()))

        geo = self.GEO_DB[country_code]
        city = random.choice(geo["cities"])
        asn  = random.choice(geo["asns"])

        # Tọa độ giả lập
        base_coords = {
            "ID": (-6.2, 106.8),
            "MY": (3.1, 101.7),
            "SG": (1.3, 103.8),
            "US": (40.7, -74.0),
            "CN": (39.9, 116.4),
            "RU": (55.7, 37.6),
        }
        lat, lon = base_coords.get(country_code, (0.0, 0.0))

        return {
            "country": geo["country"],
            "city":    city,
            "asn":     asn,
            "lat":     lat + random.uniform(-2, 2),
            "lon":     lon + random.uniform(-2, 2),
        }

    def generate_fingerprint(self,
                             ip: str,
                             attack_type: str) -> AttackerFingerprint:
        """Tạo fingerprint cho kẻ tấn công"""
        geo = self._lookup_geoip(ip)

        # Chọn User-Agent (có thể là tool hoặc browser)
        if random.random() < 0.4:
            # Tool tự động
            ua_str  = random.choice(self.ATTACK_TOOLS_UA)
            browser = ua_str.split('/')[0]
            os_name = "Unknown (Automated Tool)"
        else:
            # Browser thật
            _, ua_str, browser, os_name = random.choice(
                self.USER_AGENTS
            )

        plugins = random.sample([
            "Chrome PDF Plugin",
            "Shockwave Flash",
            "Java Plug-in",
            "Microsoft Office",
            "Silverlight Plug-In",
        ], k=random.randint(0, 3))

        return AttackerFingerprint(
            ip_address    = ip,
            public_ip     = ip,
            user_agent    = ua_str,
            browser       = browser,
            os            = os_name,
            screen_res    = random.choice(
                ["1920x1080", "1366x768",
                 "1280x800", "1024x768"]
            ),
            timezone      = random.choice(
                ["Asia/Jakarta", "Asia/Makassar",
                 "Asia/Jayapura", "UTC", "America/New_York"]
            ),
            language      = random.choice(
                ["id-ID", "en-US", "en-GB", "zh-CN"]
            ),
            plugins       = plugins,
            asn           = geo["asn"],
            isp           = geo["asn"].split(" ", 1)[-1],
            country       = geo["country"],
            city          = geo["city"],
            latitude      = geo["lat"],
            longitude     = geo["lon"],
            cookie_stolen = (
                f"session={random.randint(1000,9999)}abcd;"
                f"PHPSESSID={random.randint(10000,99999)}"
                if random.random() < 0.7 else ""
            ),
            referrer      = random.choice([
                "https://github.com/sqlmapproject/sqlmap",
                "https://www.exploit-db.com",
                "https://hackforums.net",
                "",
                "https://www.google.com",
            ]),
            attack_type   = attack_type,
        )

    def collect_from_xss(self,
                         n: int = 100) -> List[AttackerFingerprint]:
        """Mô phỏng thu thập từ XSS trap"""
        results = []
        for _ in range(n):
            ip  = (f"{random.randint(1,223)}."
                   f"{random.randint(0,255)}."
                   f"{random.randint(0,255)}."
                   f"{random.randint(1,254)}")
            fp  = self.generate_fingerprint(ip, "XSS")
            results.append(fp)
        return results