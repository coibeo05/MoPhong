# fake_news_data.py
# Dữ liệu hardcoded cho trang tin tức giả tiếng Indonesia
# Không dùng database thật → an toàn

from dataclasses import dataclass
from typing import List, Dict

@dataclass
class NewsArticle:
    id:       int
    title:    str
    content:  str
    author:   str
    date:     str
    category: str

@dataclass
class FakeDBResponse:
    """Phản hồi giả lập khi bị SQLi"""
    query_received: str
    fake_db_name:   str
    fake_tables:    List[str]
    fake_version:   str
    fake_users:     List[Dict]
    fake_columns:   List[str]

class FakeNewsWebsite:
    """
    Trang tin tức giả tiếng Indonesia
    3 trang: Beranda (Home) / SQLi page / XSS page
    """

    SITE_NAME = "BeritaHariIni.co.id"
    SITE_SLOGAN = "Berita Terpercaya Setiap Hari"

    # ── Dữ liệu bài báo hardcoded ────────────────────────────────
    ARTICLES = [
        NewsArticle(
            id=1,
            title="Pemerintah Luncurkan Program Ekonomi Baru",
            content="Jakarta - Pemerintah Indonesia resmi meluncurkan "
                    "program ekonomi baru yang bertujuan meningkatkan "
                    "kesejahteraan masyarakat di seluruh nusantara...",
            author="Ahmad Santoso",
            date="2024-01-15",
            category="Ekonomi"
        ),
        NewsArticle(
            id=2,
            title="Teknologi AI Semakin Berkembang di Indonesia",
            content="Bandung - Perkembangan kecerdasan buatan di Indonesia "
                    "semakin pesat. Berbagai startup lokal mulai mengadopsi "
                    "teknologi AI untuk meningkatkan produktivitas...",
            author="Dewi Rahayu",
            date="2024-01-16",
            category="Teknologi"
        ),
        NewsArticle(
            id=3,
            title="Tim Sepak Bola Nasional Raih Kemenangan",
            content="Surabaya - Tim nasional sepak bola Indonesia berhasil "
                    "meraih kemenangan gemilang dalam pertandingan "
                    "internasional yang digelar kemarin malam...",
            author="Budi Hartono",
            date="2024-01-17",
            category="Olahraga"
        ),
        NewsArticle(
            id=4,
            title="Cuaca Ekstrem Melanda Beberapa Wilayah",
            content="Meteorologi - Badan Meteorologi Klimatologi dan "
                    "Geofisika (BMKG) memperingatkan cuaca ekstrem yang "
                    "akan melanda beberapa wilayah Indonesia...",
            author="Siti Nurhaliza",
            date="2024-01-18",
            category="Cuaca"
        ),
    ]

    # ── Database PALSU untuk SQLi response ──────────────────────
    FAKE_DB = FakeDBResponse(
        query_received = "",
        fake_db_name   = "berita_db",
        fake_tables    = [
            "users", "articles", "comments",
            "admin_panel", "subscribers"
        ],
        fake_version   = "5.7.38-MySQL Community Server",
        fake_users     = [
            {"username": "admin",     "password": "5f4dcc3b5aa765d61d8327deb882cf99"},
            {"username": "editor",    "password": "e10adc3949ba59abbe56e057f20f883e"},
            {"username": "reporter",  "password": "25d55ad283aa400af464c76d713c07ad"},
        ],
        fake_columns   = [
            "id", "username", "password",
            "email", "role", "last_login"
        ]
    )

    def get_home_page(self) -> str:
        """Tạo HTML trang chủ"""
        articles_html = ""
        for art in self.ARTICLES:
            articles_html += f"""
            <div class="article-card">
                <h3><a href="/berita?id={art.id}">{art.title}</a></h3>
                <p class="meta">{art.author} | {art.date} | {art.category}</p>
                <p>{art.content[:100]}...</p>
            </div>"""

        return f"""<!DOCTYPE html>
<html>
<head>
    <title>{self.SITE_NAME} - {self.SITE_SLOGAN}</title>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 0; }}
        .header {{ background: #c0392b; color: white; padding: 20px; }}
        .nav {{ background: #2c3e50; padding: 10px; }}
        .nav a {{ color: white; margin: 0 15px; text-decoration: none; }}
        .container {{ max-width: 1200px; margin: 20px auto; padding: 0 20px; }}
        .article-card {{ border: 1px solid #ddd; padding: 15px;
                         margin: 10px 0; border-radius: 5px; }}
        .meta {{ color: #666; font-size: 0.9em; }}
        .footer {{ background: #2c3e50; color: white;
                   padding: 20px; text-align: center; margin-top: 40px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>📰 {self.SITE_NAME}</h1>
        <p>{self.SITE_SLOGAN}</p>
    </div>
    <div class="nav">
        <a href="/">🏠 Beranda</a>
        <a href="/cari-berita">🔍 Cari Berita</a>
        <a href="/komentar">💬 Komentar</a>
        <a href="/tentang">ℹ️ Tentang Kami</a>
    </div>
    <div class="container">
        <h2>Berita Terkini</h2>
        {articles_html}
    </div>
    <div class="footer">
        <p>© 2024 {self.SITE_NAME} | All Rights Reserved</p>
    </div>
</body>
</html>"""

    def get_article_by_id(self, article_id: int) -> NewsArticle:
        for art in self.ARTICLES:
            if art.id == article_id:
                return art
        return None