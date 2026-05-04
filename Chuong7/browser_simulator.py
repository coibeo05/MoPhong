# browser_simulator.py
import random
from dataclasses import dataclass
from typing import List, Dict

@dataclass
class BrowserProfile:
    name:       str
    user_agent: str
    os:         str
    version:    str
    features:   List[str]   # JavaScript, Flash, Java, etc.

@dataclass
class HTTPResponse:
    url:          str
    status_code:  int
    content_type: str
    content:      bytes
    headers:      Dict[str, str]
    files_downloaded: List[str]
    browser_used: str
    redirect_chain: List[str]

class BrowserSimulator:
    """
    Mô phỏng các trình duyệt khác nhau bằng User-Agent
    Theo đúng thiết kế Honeyware trong bài báo
    """

    BROWSER_PROFILES = [
        BrowserProfile(
            name="Internet Explorer 6",
            user_agent="Mozilla/4.0 (compatible; MSIE 6.0; "
                       "Windows NT 5.1; SV1)",
            os="Windows XP",
            version="6.0",
            features=["JavaScript", "ActiveX", "VBScript",
                      "Flash", "Java"]
        ),
        BrowserProfile(
            name="Internet Explorer 7",
            user_agent="Mozilla/4.0 (compatible; MSIE 7.0; "
                       "Windows NT 6.0)",
            os="Windows Vista",
            version="7.0",
            features=["JavaScript", "ActiveX", "Flash", "Java"]
        ),
        BrowserProfile(
            name="Firefox 2.0",
            user_agent="Mozilla/5.0 (Windows; U; Windows NT 5.1; "
                       "en-US; rv:1.8.1.12) Gecko/20080201 Firefox/2.0",
            os="Windows XP",
            version="2.0",
            features=["JavaScript", "Flash", "Java"]
        ),
        BrowserProfile(
            name="Firefox 3.0",
            user_agent="Mozilla/5.0 (Windows; U; Windows NT 6.0; "
                       "en-US; rv:1.9) Gecko/2008052906 Firefox/3.0",
            os="Windows Vista",
            version="3.0",
            features=["JavaScript", "Flash", "Java", "Canvas"]
        ),
        BrowserProfile(
            name="Chrome 1.0",
            user_agent="Mozilla/5.0 (Windows; U; Windows NT 5.1; "
                       "en-US) AppleWebKit/525.13 "
                       "(KHTML, like Gecko) Chrome/0.2.149.27",
            os="Windows XP",
            version="1.0",
            features=["JavaScript", "Flash", "Canvas"]
        ),
        BrowserProfile(
            name="Opera 9.5",
            user_agent="Opera/9.52 (Windows NT 5.1; U; en)",
            os="Windows XP",
            version="9.5",
            features=["JavaScript", "Flash", "Java"]
        ),
        BrowserProfile(
            name="Safari 3.0",
            user_agent="Mozilla/5.0 (Windows; U; Windows NT 5.1; "
                       "en-US) AppleWebKit/523.15 "
                       "(KHTML, like Gecko) Version/3.0",
            os="Windows XP",
            version="3.0",
            features=["JavaScript", "Flash"]
        ),
    ]

    def _simulate_download(self,
                           url: str,
                           profile: BrowserProfile,
                           entry) -> HTTPResponse:
        """
        Mô phỏng quá trình tải URL và phân tích response
        """
        import random

        # Mô phỏng kết quả dựa trên loại URL
        if entry.is_malicious:
            status = random.choice([200, 200, 200, 301, 302])
            files  = entry.expected_files.copy()

            # Một số exploit chỉ hoạt động với browser cụ thể
            if entry.category == "exploit_kit":
                # Mpack phát hiện browser → gửi exploit tương ứng
                if "MSIE" in profile.user_agent:
                    content = (
                        b"<html><script>"
                        b"var shellcode='\\x90\\x90\\x90';"
                        b"// IE heap spray exploit"
                        b"</script></html>"
                    )
                elif "Firefox" in profile.name:
                    content = (
                        b"<html><script>"
                        b"// Firefox location.hostname exploit"
                        b"document.write('<iframe src=evil.php>');"
                        b"</script></html>"
                    )
                else:
                    content = b"<html>Generic exploit</html>"
            else:
                content = b"<html>Malicious content</html>"

            redirect_chain = []
            if status in [301, 302]:
                redirect_chain = [
                    url,
                    url.replace(".com", ".net"),
                ]

        else:
            status  = 200
            files   = ["index.html"]
            content = b"<html>Normal website content</html>"
            redirect_chain = []

        return HTTPResponse(
            url              = url,
            status_code      = status,
            content_type     = "text/html",
            content          = content,
            headers          = {
                "Server":       "Apache/2.2.14",
                "Content-Type": "text/html; charset=utf-8",
                "User-Agent":   profile.user_agent,
            },
            files_downloaded = files,
            browser_used     = profile.name,
            redirect_chain   = redirect_chain,
        )

    def fetch(self, url: str,
              entry,
              profile: BrowserProfile = None) -> HTTPResponse:
        if profile is None:
            profile = random.choice(self.BROWSER_PROFILES)
        return self._simulate_download(url, profile, entry)

    def fetch_all_browsers(self,
                           url: str,
                           entry) -> List[HTTPResponse]:
        """Thử với tất cả browser profiles"""
        results = []
        for profile in self.BROWSER_PROFILES:
            resp = self.fetch(url, entry, profile)
            results.append(resp)
        return results