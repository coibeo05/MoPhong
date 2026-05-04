# antivirus_scanner.py
import random
from dataclasses import dataclass
from typing import List, Dict

@dataclass
class ScanResult:
    av_name:      str
    file_name:    str
    detected:     bool
    threat_name:  str
    severity:     str    # 'high'/'medium'/'low'/'clean'
    scan_time_ms: float

@dataclass
class MultiAVResult:
    url_id:       int
    url:          str
    total_files:  int
    detected_by:  List[str]    # AV engines yang mendeteksi
    not_detected: List[str]    # AV engines yang tidak
    all_results:  List[ScanResult]
    final_verdict: str         # 'MALICIOUS'/'CLEAN'/'SUSPICIOUS'
    detection_rate: float      # %

class AntiVirusScanner:
    """
    Mô phỏng 5 phần mềm diệt virus theo Honeyware paper:
    AVG, F-Prot, Avast, ClamAV, AntiVir

    Đặc điểm quan trọng:
    - Mỗi AV có tỷ lệ phát hiện KHÁC nhau
    - Malware mới → có thể thoát khỏi một số AV
    - Sau khi cập nhật signature → tỷ lệ tăng lên
    """

    AV_ENGINES = {
        "AVG": {
            "detection_rate_known":   0.85,
            "detection_rate_new":     0.65,
            "detection_rate_updated": 0.95,
            "scan_speed":             "fast",
            "signatures":             "avg_signatures_v8.0",
        },
        "F-Prot": {
            "detection_rate_known":   0.80,
            "detection_rate_new":     0.60,
            "detection_rate_updated": 0.90,
            "scan_speed":             "medium",
            "signatures":             "fprot_signatures_v6.0",
        },
        "Avast": {
            "detection_rate_known":   0.88,
            "detection_rate_new":     0.70,
            "detection_rate_updated": 0.96,
            "scan_speed":             "fast",
            "signatures":             "avast_vps_v080501",
        },
        "ClamAV": {
            "detection_rate_known":   0.75,
            "detection_rate_new":     0.55,
            "detection_rate_updated": 0.85,
            "scan_speed":             "slow",
            "signatures":             "clamav_daily_8675",
        },
        "AntiVir": {
            "detection_rate_known":   0.90,
            "detection_rate_new":     0.72,
            "detection_rate_updated": 0.97,
            "scan_speed":             "medium",
            "signatures":             "antivir_vdf_v7.6",
        },
    }

    THREAT_NAMES = {
        "drive-by":        ["Trojan.Downloader", "Exploit.HTML",
                            "JS.Exploit", "VBS.Malware"],
        "exploit_kit":     ["Exploit.Mpack", "Trojan.Agent",
                            "Backdoor.Generic", "Rootkit.Generic"],
        "phishing":        ["Phish.HTML", "Fraud.HTML",
                            "HTML.Phishing"],
        "direct_download": ["Trojan.Generic", "Malware.Generic",
                            "Backdoor.Win32", "Worm.Generic"],
        "normal":          [],
    }

    def scan_file(self,
                  av_name: str,
                  file_name: str,
                  category: str,
                  is_malicious: bool,
                  updated: bool = False) -> ScanResult:
        """
        Mô phỏng quét 1 file bởi 1 AV engine
        """
        engine = self.AV_ENGINES[av_name]
        import time
        start = time.time()

        if not is_malicious:
            # File sạch → không bao giờ phát hiện
            detected    = False
            threat_name = ""
            severity    = "clean"
        else:
            # Chọn tỷ lệ phát hiện theo trạng thái signature
            if updated:
                rate = engine["detection_rate_updated"]
            else:
                rate = engine["detection_rate_new"]

            detected = random.random() < rate

            if detected:
                threats     = self.THREAT_NAMES.get(category, [])
                threat_name = (random.choice(threats)
                               if threats else "Malware.Generic")
                severity    = "high"
            else:
                threat_name = ""
                severity    = "clean"

        scan_time = (time.time() - start) * 1000 + random.uniform(10, 500)

        return ScanResult(
            av_name      = av_name,
            file_name    = file_name,
            detected     = detected,
            threat_name  = threat_name,
            severity     = severity,
            scan_time_ms = round(scan_time, 2),
        )

    def scan_url_result(self,
                        entry,
                        response,
                        updated: bool = False) -> MultiAVResult:
        """
        Quét tất cả file tải về từ 1 URL bởi 5 AV engine
        """
        all_results  = []
        detected_by  = []
        not_detected = []

        for av_name in self.AV_ENGINES:
            url_detected = False
            for file_name in response.files_downloaded:
                result = self.scan_file(
                    av_name, file_name,
                    entry.category,
                    entry.is_malicious,
                    updated
                )
                all_results.append(result)
                if result.detected:
                    url_detected = True

            if url_detected:
                detected_by.append(av_name)
            else:
                not_detected.append(av_name)

        # Verdict cuối cùng
        n_detected = len(detected_by)
        if n_detected >= 3:
            verdict = "MALICIOUS"
        elif n_detected >= 1:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"

        detection_rate = (n_detected / len(self.AV_ENGINES)) * 100

        return MultiAVResult(
            url_id         = entry.url_id,
            url            = entry.url,
            total_files    = len(response.files_downloaded),
            detected_by    = detected_by,
            not_detected   = not_detected,
            all_results    = all_results,
            final_verdict  = verdict,
            detection_rate = detection_rate,
        )