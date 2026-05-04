# sqli_handler.py
import re
from dataclasses import dataclass
from typing import List, Tuple
from fake_news_data import FakeNewsWebsite, FakeDBResponse

@dataclass
class SQLiAttackInfo:
    raw_query:      str
    tool_detected:  str    # 'sqlmap'/'manual'/'unknown'
    attack_type:    str    # 'union'/'error'/'blind'/'time'
    payload_stage:  str    # 'detection'/'enumeration'/'extraction'
    fake_response:  str

class SQLiHandler:
    """
    Phát hiện và phản hồi SQL Injection
    Dùng Regex dựa trên pattern của SQLMap

    Chiến lược:
    - Phát hiện pattern → xác định giai đoạn tấn công
    - Trả về data GIẢ nhưng THUYẾT PHỤC
    - Ghi lại payload để phân tích kẻ tấn công
    """

    # ── Regex patterns từ SQLMap ─────────────────────────────────
    SQLMAP_PATTERNS = [
        r"sqlmap",
        r"AND\s+\d+=\d+",
        r"OR\s+\d+=\d+",
        r"UNION\s+SELECT",
        r"UNION\s+ALL\s+SELECT",
        r"information_schema",
        r"@@version",
        r"@@datadir",
        r"SLEEP\(\d+\)",
        r"BENCHMARK\(",
        r"WAITFOR\s+DELAY",
        r"pg_sleep",
        r"--\s*$",
        r";\s*--",
        r"'\s*OR\s*'1'\s*=\s*'1",
        r"admin'--",
        r"1\s*=\s*1",
    ]

    UNION_PATTERNS = [
        r"UNION\s+(ALL\s+)?SELECT",
        r"SELECT\s+.+\s+FROM",
        r"GROUP_CONCAT",
        r"CONCAT\(",
    ]

    BLIND_PATTERNS = [
        r"AND\s+\(SELECT",
        r"AND\s+SUBSTRING",
        r"AND\s+ASCII",
        r"AND\s+ORD\(",
        r"CASE\s+WHEN",
    ]

    TIME_PATTERNS = [
        r"SLEEP\(\d+\)",
        r"BENCHMARK\(\d+",
        r"WAITFOR\s+DELAY\s+'0:0:\d+",
        r"pg_sleep\(\d+\)",
    ]

    def __init__(self):
        self.fake_db = FakeNewsWebsite().FAKE_DB
        self.attack_log: List[SQLiAttackInfo] = []

    def _detect_tool(self, query: str) -> str:
        query_lower = query.lower()
        if "sqlmap" in query_lower:
            return "SQLMap"
        elif any(p in query_lower for p in
                 ["havij", "pangolin"]):
            return "Havij/Pangolin"
        elif re.search(r"'.*or.*'.*=.*'", query_lower, re.I):
            return "Manual"
        return "Unknown"

    def _detect_attack_type(self, query: str) -> str:
        if any(re.search(p, query, re.I)
               for p in self.UNION_PATTERNS):
            return "UNION-based"
        elif any(re.search(p, query, re.I)
                 for p in self.BLIND_PATTERNS):
            return "Blind Boolean"
        elif any(re.search(p, query, re.I)
                 for p in self.TIME_PATTERNS):
            return "Time-based Blind"
        return "Error-based"

    def _detect_stage(self, query: str) -> str:
        query_lower = query.lower()
        if any(kw in query_lower for kw in
               ["version", "database()", "user()"]):
            return "Detection/Fingerprinting"
        elif any(kw in query_lower for kw in
                 ["information_schema", "table_name",
                  "column_name"]):
            return "Schema Enumeration"
        elif any(kw in query_lower for kw in
                 ["username", "password", "email", "admin"]):
            return "Data Extraction"
        return "Initial Probe"

    def _generate_fake_response(self,
                                query: str,
                                attack_type: str,
                                stage: str) -> str:
        """
        Tạo phản hồi GIẢ nhưng THUYẾT PHỤC
        Kẻ tấn công tưởng đã tấn công thành công!
        """
        query_lower = query.lower()

        # Phản hồi version
        if "version" in query_lower or "@@version" in query_lower:
            return f"""
            <div class="result">
                <p>Berita ID: 1</p>
                <p style="display:none">
                    {self.fake_db.fake_version}
                </p>
                <p>Pemerintah Luncurkan Program Ekonomi Baru</p>
            </div>"""

        # Phản hồi database name
        elif ("database()" in query_lower
              or "schema()" in query_lower):
            return f"""
            <div class="result">
                <p>Result: <b>{self.fake_db.fake_db_name}</b></p>
            </div>"""

        # Phản hồi danh sách tables
        elif "information_schema" in query_lower:
            tables_html = "<br>".join(
                f"<b>{t}</b>" for t in self.fake_db.fake_tables
            )
            return f"""
            <div class="result">
                <p>Tables found:</p>
                {tables_html}
            </div>"""

        # Phản hồi dữ liệu users (data extraction stage)
        elif any(kw in query_lower for kw in
                 ["username", "password", "users"]):
            users_html = "".join(
                f"<tr><td>{u['username']}</td>"
                f"<td>{u['password']}</td></tr>"
                for u in self.fake_db.fake_users
            )
            return f"""
            <div class="result">
                <table border="1">
                    <tr><th>Username</th><th>Password (MD5)</th></tr>
                    {users_html}
                </table>
                <p><small>3 rows in set (0.02 sec)</small></p>
            </div>"""

        # Time-based: trả về sau delay giả
        elif any(re.search(p, query, re.I)
                 for p in self.TIME_PATTERNS):
            return """
            <div class="result">
                <p>Query executed (5.002 sec)</p>
                <p>1 row affected</p>
            </div>"""

        # Mặc định
        return f"""
            <div class="result">
                <p>Berita tidak ditemukan untuk ID: {query[:50]}</p>
            </div>"""

    def is_sqli_attempt(self, query: str) -> bool:
        """Kiểm tra có phải SQLi không"""
        return any(
            re.search(p, query, re.I)
            for p in self.SQLMAP_PATTERNS
        )

    def handle(self, query: str) -> SQLiAttackInfo:
        """Xử lý SQLi attack và trả về response giả"""
        tool     = self._detect_tool(query)
        att_type = self._detect_attack_type(query)
        stage    = self._detect_stage(query)
        response = self._generate_fake_response(
            query, att_type, stage
        )

        info = SQLiAttackInfo(
            raw_query     = query,
            tool_detected = tool,
            attack_type   = att_type,
            payload_stage = stage,
            fake_response = response,
        )
        self.attack_log.append(info)
        return info