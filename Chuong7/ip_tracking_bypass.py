# ip_tracking_bypass.py
import random
from dataclasses import dataclass
from typing import List

@dataclass
class BypassResult:
    url:            str
    technique:      str
    honeyware_ip:   str
    spider_ip:      str
    geo_location:   str
    bypass_success: bool
    malware_served: bool
    description:    str

class IPTrackingBypass:
    """
    Mô phỏng kỹ thuật vượt qua theo dõi IP của Honeyware

    Kỹ thuật máy chủ độc hại dùng để tránh bị phát hiện:
    1. IP Tracking  : Chỉ gửi malware cho IP mới, chặn IP đã biết
    2. GeoIP Filter : Chỉ tấn công IP từ quốc gia cụ thể
    3. Visit Limit  : Mỗi IP chỉ được xem 1-2 lần

    Honeyware vượt qua bằng:
    → Gửi yêu cầu ban đầu bằng Honeyware IP
    → Dùng Wget spider mode từ IP khác để "kích hoạt" malware
    → Máy chủ tưởng đây là user thật → gửi malware
    """

    HONEYWARE_IPS = [
        "203.0.113.10",   # IP của Honeyware
        "203.0.113.11",
        "203.0.113.12",
    ]

    SPIDER_IPS = [
        "198.51.100.50",  # IP của Wget spider
        "198.51.100.51",
        "198.51.100.52",
    ]

    GEO_LOCATIONS = {
        "203.0.113.10":  "US - New York",
        "203.0.113.11":  "DE - Berlin",
        "203.0.113.12":  "JP - Tokyo",
        "198.51.100.50": "US - California",
        "198.51.100.51": "GB - London",
        "198.51.100.52": "FR - Paris",
    }

    def _check_ip_tracking(self,
                           url: str,
                           honeyware_ip: str) -> dict:
        """
        Bước 1: Honeyware gửi yêu cầu ban đầu
        Máy chủ độc hại ghi lại IP → chưa gửi malware ngay
        """
        server_response = {
            "ip_recorded":    honeyware_ip,
            "content_served": "decoy_content.html",  # nội dung giả
            "malware_served": False,
            "note": "Server records IP, serves decoy first"
        }
        return server_response

    def _trigger_with_spider(self,
                             url: str,
                             spider_ip: str) -> dict:
        """
        Bước 2: Wget spider mode từ IP khác
        Mô phỏng web crawler → máy chủ tưởng đây là lượt truy cập mới
        → Kích hoạt malware
        """
        # 80% thành công vượt qua IP tracking
        success = random.random() < 0.80
        return {
            "spider_ip":      spider_ip,
            "wget_command":   f"wget --spider {url}",
            "bypass_success": success,
            "malware_served": success,
            "note": ("Spider triggered malware delivery"
                     if success else
                     "Server detected spider - no malware")
        }

    def _check_geoip_filter(self,
                            url: str,
                            ip: str) -> dict:
        """
        Kiểm tra GeoIP filter
        Một số server chỉ tấn công IP từ US/EU
        """
        geo = self.GEO_LOCATIONS.get(ip, "Unknown")
        # US và EU thường được phép
        allowed = any(
            country in geo
            for country in ["US", "DE", "GB", "FR", "JP"]
        )
        return {
            "ip":           ip,
            "geo_location": geo,
            "allowed":      allowed,
            "note": (f"GeoIP: {geo} - ALLOWED"
                     if allowed else
                     f"GeoIP: {geo} - BLOCKED")
        }

    def bypass_ip_tracking(self, url: str) -> BypassResult:
        """
        Quy trình vượt rào đầy đủ theo Honeyware paper
        """
        honeyware_ip = random.choice(self.HONEYWARE_IPS)
        spider_ip    = random.choice(self.SPIDER_IPS)
        geo          = self.GEO_LOCATIONS.get(honeyware_ip, "Unknown")

        # Bước 1: Gửi yêu cầu ban đầu
        initial = self._check_ip_tracking(url, honeyware_ip)

        # Bước 2: Kiểm tra GeoIP
        geo_check = self._check_geoip_filter(url, honeyware_ip)

        # Bước 3: Kích hoạt bằng spider
        spider_result = self._trigger_with_spider(url, spider_ip)

        bypass_success = (geo_check["allowed"] and
                          spider_result["bypass_success"])

        return BypassResult(
            url            = url,
            technique      = "IP_tracking + GeoIP bypass",
            honeyware_ip   = honeyware_ip,
            spider_ip      = spider_ip,
            geo_location   = geo,
            bypass_success = bypass_success,
            malware_served = spider_result["malware_served"],
            description    = (
                f"Step1: {initial['note']} | "
                f"Step2: {geo_check['note']} | "
                f"Step3: {spider_result['note']}"
            ),
        )

    def test_mpack_bypass(self,
                          mpack_urls: List[str]) -> List[BypassResult]:
        """
        Kiểm tra nội bộ với Mpack exploit kit
        theo đúng thí nghiệm trong bài báo
        """
        results = []
        for url in mpack_urls:
            result = self.bypass_ip_tracking(url)
            results.append(result)
        return results