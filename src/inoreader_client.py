import time
import html
import re
import requests
import urllib3
from typing import List, Dict, Any, Optional


def _timestamp_seconds(value: Any, divisor: int = 1) -> Optional[int]:
    try:
        timestamp = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if timestamp <= 0:
        return None
    try:
        return int(timestamp / divisor)
    except (ValueError, OverflowError):
        return None


class InoreaderClient:
    BASE_URL = "https://www.inoreader.com/reader/api/0"
    LOGIN_URL = "https://www.inoreader.com/accounts/ClientLogin"

    def __init__(self, email: str = "", password: str = "", app_id: str = "", app_key: str = "",
                 token: str = "", stream_id: str = "user/-/state/com.google/reading-list",
                 verify_ssl: bool = False, fetch_full_web: bool = True,
                 use_mock_if_missing: bool = False):
        self.email = email.strip()
        self.password = password.strip()
        self.app_id = app_id.strip()
        self.app_key = app_key.strip()
        self.token = token.strip()
        self.stream_id = stream_id.strip() or "user/-/state/com.google/reading-list"
        self.verify_ssl = verify_ssl
        self.fetch_full_web = fetch_full_web
        self.use_mock_if_missing = use_mock_if_missing
        self.web_fetch_failures = 0
        self.auth_token: Optional[str] = None

        if not self.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def has_credentials(self) -> bool:
        return bool(self.token or (self.app_id and self.app_key and (self.email or self.token)))

    def authenticate(self) -> bool:
        """
        Authenticates via Inoreader ClientLogin using Email, Password, AppId, and AppKey.
        """
        if self.token:
            return True

        if not (self.email and self.password and self.app_id and self.app_key):
            return False

        headers = {
            "AppId": self.app_id,
            "AppKey": self.app_key
        }
        data = {
            "Email": self.email,
            "Passwd": self.password,
            "service": "reader"
        }

        try:
            resp = requests.post(self.LOGIN_URL, headers=headers, data=data, verify=self.verify_ssl, timeout=15)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    if line.startswith("Auth="):
                        self.auth_token = line.split("=", 1)[1].strip()
                        return True
            print(f"[Inoreader Error] ClientLogin failed ({resp.status_code}): {resp.text}")
        except requests.RequestException as e:
            print(f"[Inoreader Exception] Authentication failed: {e}")

        return False

    def fetch_articles(self, count: Optional[int] = None, since_timestamp: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Fetches stream items from Inoreader API, supporting pagination to retrieve
        all available stream items unless an explicit count is requested.
        """
        if not self.auth_token and not self.token:
            if not self.authenticate():
                if self.use_mock_if_missing:
                    print("[Inoreader] Authentication unavailable. Explicit mock mode is enabled.")
                    return self._generate_mock_articles()
                raise RuntimeError(
                    "Inoreader authentication failed. Verify the configured credentials; "
                    "no sample data was substituted."
                )

        headers = {}
        if self.app_id and self.app_key:
            headers["AppId"] = self.app_id
            headers["AppKey"] = self.app_key

        if self.auth_token:
            headers["Authorization"] = f"GoogleLogin auth={self.auth_token}"
        elif self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        url = f"{self.BASE_URL}/stream/contents/{self.stream_id}"
        all_raw_items = []
        continuation = None
        target_count = max(count, 1) if count is not None else None
        page_size = min(target_count, 100) if target_count is not None else 100
        seen_continuations = set()

        try:
            while target_count is None or len(all_raw_items) < target_count:
                params = {"n": page_size}
                if continuation:
                    params["c"] = continuation
                if since_timestamp:
                    params["ot"] = since_timestamp

                for attempt in range(3):
                    try:
                        resp = requests.get(
                            url,
                            headers=headers,
                            params=params,
                            verify=self.verify_ssl,
                            timeout=20,
                        )
                        break
                    except (requests.ConnectionError, requests.Timeout):
                        if attempt == 2:
                            raise
                        retry_delay = 2 ** attempt
                        print(
                            "[Inoreader] Feed connection failed; "
                            f"retrying in {retry_delay}s ({attempt + 1}/3)."
                        )
                        time.sleep(retry_delay)

                if resp.status_code == 200:
                    data = resp.json()
                    items = data.get("items", [])
                    if not items:
                        break
                    all_raw_items.extend(items)
                    continuation = data.get("continuation")
                    if not continuation or (target_count is not None and len(all_raw_items) >= target_count):
                        break
                    if continuation in seen_continuations:
                        raise RuntimeError(
                            "Inoreader repeated a continuation token; refusing to report an incomplete feed."
                        )
                    seen_continuations.add(continuation)
                elif resp.status_code in (401, 403):
                    print(f"[Inoreader Error] Token expired ({resp.status_code}). Refreshing...")
                    if self.auth_token:
                        self.auth_token = None
                    if self.auth_token is None and not self.token and self.authenticate():
                        headers["Authorization"] = f"GoogleLogin auth={self.auth_token}"
                        continue
                    raise RuntimeError(
                        f"Inoreader authorization failed (HTTP {resp.status_code}); "
                        "refreshed credentials were unavailable."
                    )
                else:
                    raise RuntimeError(
                        f"Inoreader feed request failed (HTTP {resp.status_code}): {resp.text[:200]}"
                    )

            return [self._normalize_item(item) for item in all_raw_items]
        except (requests.RequestException, ValueError) as e:
            raise RuntimeError(f"Inoreader feed fetch failed; no sample data was substituted: {e}") from e

    def _clean_html(self, raw_html: str) -> str:
        """Strips HTML markup and unescapes entities to produce clean searchable plaintext."""
        if not raw_html:
            return ""
        text = html.unescape(raw_html)
        text = re.sub(
            r"<(script|style|noscript|template)\b[^>]*>.*?</\1\s*>",
            " ",
            text,
            flags=re.IGNORECASE | re.DOTALL,
        )
        text = re.sub(
            r"(?im)^.*(?:window\.(?:ytcfg|yterr|unhandledErrorMessages|unhandledErrorCount)\b"
            r"|function\s*\(\s*\)\s*\{\s*window\.).*$",
            "",
            text,
        )
        text = re.sub(r'<(?:br|/p|/div|/h\d|/li)\b[^>]*>', '\n', text, flags=re.IGNORECASE)
        text = re.sub(r'<[^>]+>', ' ', text)
        text = re.sub(r'[ \t]+', ' ', text)
        text = re.sub(r'\n\s*\n', '\n', text)
        return text.strip()

    def _fetch_web_article_text(self, url: str) -> str:
        """Fetch and parse the linked advisory page."""
        if not url or not url.startswith("http"):
            return ""
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            }
            resp = requests.get(url, headers=headers, verify=self.verify_ssl, timeout=6)
            if resp.status_code == 200 and resp.text:
                # Extract paragraphs from html
                paragraphs = re.findall(r'<p\b[^>]*>(.*?)</p>', resp.text, re.IGNORECASE | re.DOTALL)
                if paragraphs:
                    full_text = "\n".join([self._clean_html(p) for p in paragraphs])
                    if len(full_text) > 200:
                        return full_text[:15000]  # Cap at 15k chars for performance
                return self._clean_html(resp.text[:15000])
            if resp.status_code != 200:
                self.web_fetch_failures += 1
            else:
                self.web_fetch_failures += 1
        except requests.RequestException:
            self.web_fetch_failures += 1
        return ""

    def enrich_article_content(self, article: Dict[str, Any]) -> Dict[str, Any]:
        """Fetch the full linked advisory page for matched articles."""
        if not self.fetch_full_web or article.get("_full_page_fetched"):
            return article
        content = article.get("content", "")
        link = article.get("link", "")
        if link:
            web_text = self._fetch_web_article_text(link)
            if web_text and web_text not in content:
                if content and content in web_text:
                    content = web_text
                elif content:
                    content = f"{content}\n\n{web_text}"
                else:
                    content = web_text
                article["content"] = content
        article["_full_page_fetched"] = True
        return article

    def _normalize_item(self, item: dict) -> dict:
        canonical = item.get("canonical", [])
        alternate = item.get("alternate", [])
        link = ""
        if canonical and len(canonical) > 0:
            link = canonical[0].get("href", "")
        elif alternate and len(alternate) > 0:
            link = alternate[0].get("href", "")
        elif "href" in item:
            link = item["href"]

        origin = item.get("origin", {})
        source_name = origin.get("title") or item.get("author") or "Inoreader Feed"

        # Extract both summary and content fields
        summary_raw = ""
        if "summary" in item and isinstance(item["summary"], dict):
            summary_raw = item["summary"].get("content", "")
        elif "summary" in item:
            summary_raw = str(item["summary"] or "")

        content_raw = ""
        if "content" in item and isinstance(item["content"], dict):
            content_raw = item["content"].get("content", "")
        elif "content" in item:
            content_raw = str(item["content"] or "")

        clean_summary = self._clean_html(summary_raw)
        clean_content = self._clean_html(content_raw)

        # Merge summary and content, prioritizing the longer text
        if len(clean_content) > len(clean_summary):
            full_text = clean_content
            if clean_summary and clean_summary not in clean_content:
                full_text = f"{clean_summary}\n\n{clean_content}"
        else:
            full_text = clean_summary
            if clean_content and clean_content not in clean_summary:
                full_text = f"{clean_content}\n\n{clean_summary}"

        full_page_fetched = False
        if len(full_text) < 250 and self.fetch_full_web and link:
            web_text = self._fetch_web_article_text(link)
            if web_text and web_text not in full_text:
                full_page_fetched = True
                if full_text and full_text in web_text:
                    full_text = web_text
                elif full_text:
                    full_text = f"{full_text}\n\n{web_text}"
                else:
                    full_text = web_text

        published_ts = _timestamp_seconds(item.get("published")) or int(time.time())
        scan_ts = (
            _timestamp_seconds(item.get("timestampUsec"), 1_000_000)
            or _timestamp_seconds(item.get("crawlTimeMsec"), 1_000)
            or published_ts
        )

        return {
            "id": item.get("id", f"item_{int(time.time()*1000)}"),
            "source_name": source_name,
            "title": self._clean_html(item.get("title", "Untitled Advisory")),
            "link": link,
            "content": full_text,
            "published_timestamp": published_ts,
            "scan_timestamp": scan_ts,
            "_full_page_fetched": full_page_fetched
        }

    def _generate_mock_articles(self) -> List[Dict[str, Any]]:
        now = int(time.time())
        return [
            {
                "id": "cisco-sa-2026-iosxr-bgp-dos",
                "source_name": "Cisco Security Advisories (PSIRT)",
                "title": "Cisco IOS XR Software BGP Memory Exhaustion Denial of Service Vulnerability (CVE-2026-38291)",
                "link": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-bgp-dos",
                "content": "A vulnerability in the Border Gateway Protocol (BGP) implementation of Cisco IOS XR Software could allow an unauthenticated, remote attacker to cause memory exhaustion, leading to a reload of the BGP process on ASR 9000 routers. CVSS Base Score: 8.6 (High).",
                "published_timestamp": now - 3600 * 2
            },
            {
                "id": "oracle-cpu-oct2026-rdbms",
                "source_name": "Oracle Critical Patch Update (CPU)",
                "title": "Oracle Database Server Remote Network Code Execution via TNS Listener (CVE-2026-2810)",
                "link": "https://www.oracle.com/security-alerts/cpujul2026.html",
                "content": "Vulnerability in Oracle Database Core RDBMS / TNS Listener allows unauthenticated attacker via Oracle Net to compromise Oracle Database and Active Data Guard. CVSS Base Score: 8.8 (High).",
                "published_timestamp": now - 3600 * 6
            },
            {
                "id": "paloalto-panos-auth-bypass-2026",
                "source_name": "Palo Alto Networks Unit 42 & Advisories",
                "title": "Critical Authentication Bypass in Palo Alto PAN-OS GlobalProtect Management Interface (CVE-2026-1192)",
                "link": "https://security.paloaltonetworks.com/CVE-2026-1192",
                "content": "An unauthenticated remote code execution and administrative bypass flaw has been identified in PAN-OS when the management interface is exposed. Affects PA-5450. CVSS Base Score: 9.8 (Critical).",
                "published_timestamp": now - 3600 * 10
            }
        ]
