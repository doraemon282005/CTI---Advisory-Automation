import os
import re
import ctypes
import tempfile
from itertools import chain
from pathlib import Path
from typing import List, Dict, Any, Optional
import openpyxl

# Words that should never match as loose standalone search terms
GENERIC_STOPWORDS = {
    "which", "file", "files", "report", "reports", "test", "tests", "tool", "tools",
    "help", "date", "find", "cat", "more", "less", "san", "edge", "core", "app", "apps",
    "base", "data", "view", "info", "link", "list", "web", "service", "services",
    "system", "systems", "user", "users", "time", "teams", "hub", "mail", "portal",
    "agent", "connect", "access", "manager", "client", "desktop", "center", "suite",
    "studio", "assistant", "server", "servers", "cloud", "group", "device", "player",
    "viewer", "builder", "express", "pro", "plus", "standard", "utility", "online",
    "runtime", "software", "network", "host", "security", "protect", "enterprise",
    "professional", "starter", "ultimate", "business", "community", "developer",
    "make", "designer", "json", "administrator", "build", "config", "install", "update", "patch",
    "word", "excel", "office", "reader", "distiller", "backup", "monitor", "console"
}

# Vulnerability & security advisory anchor words
SECURITY_SIGNALS = {
    "vulnerability", "vulnerabilities", "flaw", "flaws", "exploit", "exploited", "exploits",
    "cve", "rce", "zero-day", "0-day", "patch", "patched", "patches", "denial of service",
    "dos", "bypass", "injection", "privilege escalation", "overflow", "security advisory",
    "security update", "security alert", "critical patch", "bulletin", "psirt", "cert"
}

AMBIGUOUS_NAME_TERMS = GENERIC_STOPWORDS | {"learn", "local", "now", "ses"}

class ApplicationInventory:
    def __init__(self, excel_path: str):
        self.excel_path = Path(excel_path)
        self.applications: List[Dict[str, Any]] = []
        self.term_to_app_map: Dict[str, Dict[str, Any]] = {}
        self.compiled_pattern: Optional[re.Pattern] = None
        self._load_inventory()

    @staticmethod
    def _safe_open_workbook(path: Path):
        """
        Attempts to open workbook. If file is locked by Excel (PermissionError),
        uses Win32 shared-read API to copy bytes to a temp file and read safely.
        """
        try:
            return openpyxl.load_workbook(path, read_only=True, data_only=True), None
        except (PermissionError, IOError) as pe:
            try:
                GENERIC_READ = 0x80000000
                FILE_SHARE_READ = 0x00000001
                FILE_SHARE_WRITE = 0x00000002
                FILE_SHARE_DELETE = 0x00000004
                OPEN_EXISTING = 3
                FILE_ATTRIBUTE_NORMAL = 0x80

                handle = ctypes.windll.kernel32.CreateFileW(
                    str(path), GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None
                )

                if handle == -1:
                    raise IOError(f"Could not acquire Win32 handle. Error: {ctypes.windll.kernel32.GetLastError()}")

                temp_fd, temp_path = tempfile.mkstemp(suffix=".xlsx")
                os.close(temp_fd)

                h_dest = ctypes.windll.kernel32.CreateFileW(
                    temp_path, 0x40000000, 0, None, 2, FILE_ATTRIBUTE_NORMAL, None
                )

                buf = ctypes.create_string_buffer(1024 * 1024)
                bytes_read = ctypes.c_ulong(0)
                bytes_written = ctypes.c_ulong(0)

                while ctypes.windll.kernel32.ReadFile(handle, buf, len(buf), ctypes.byref(bytes_read), None) and bytes_read.value > 0:
                    ctypes.windll.kernel32.WriteFile(h_dest, buf, bytes_read.value, ctypes.byref(bytes_written), None)

                ctypes.windll.kernel32.CloseHandle(handle)
                ctypes.windll.kernel32.CloseHandle(h_dest)

                wb = openpyxl.load_workbook(temp_path, read_only=True, data_only=True)
                return wb, temp_path
            except Exception as e:
                print(f"[Inventory Error] Failed to read locked workbook: {e}")
                raise pe

    def _load_inventory(self):
        if not self.excel_path.exists():
            print(f"[Warning] Inventory file not found at: {self.excel_path}")
            return

        wb, temp_to_clean = self._safe_open_workbook(self.excel_path)
        all_terms = set()

        try:
            if "Unique Application Names" in wb.sheetnames:
                ws = wb["Unique Application Names"]
                for row in ws.iter_rows(values_only=True):
                    if not row or not row[0]:
                        continue
                    app_name = str(row[0]).strip()
                    if app_name and app_name.lower() not in ["none", "application name", "row labels"]:
                        self._register_app(app_name, vendor="", domain="Enterprise Application", version="", all_terms=all_terms)

            else:
                ws = wb.active
                rows_iter = ws.iter_rows(values_only=True)
                first_row = next(rows_iter, None)
                if not first_row:
                    return

                raw_headers = [str(cell).strip() if cell is not None else "" for cell in first_row]
                col_map = {"name": 0, "vendor": None, "domain": None, "keywords": None, "version": None}

                for idx, h in enumerate(raw_headers):
                    hl = h.lower()
                    if any(k in hl for k in ["application", "app name", "software", "product", "system"]):
                        col_map["name"] = idx
                    elif "vendor" in hl or "manufacturer" in hl:
                        col_map["vendor"] = idx
                    elif any(k in hl for k in ["domain", "role", "function", "plane", "type"]):
                        col_map["domain"] = idx
                    elif any(k in hl for k in ["keyword", "alias", "search"]):
                        col_map["keywords"] = idx
                    elif "version" in hl or "release" in hl or "deployment" in hl:
                        col_map["version"] = idx

                for row in rows_iter:
                    if not row or not any(row):
                        continue
                    app_name = str(row[col_map["name"]]).strip() if row[col_map["name"]] is not None else ""
                    if not app_name or app_name.lower() in ["none", ""]:
                        continue

                    vendor = str(row[col_map["vendor"]]).strip() if col_map["vendor"] is not None and row[col_map["vendor"]] else ""
                    domain = str(row[col_map["domain"]]).strip() if col_map["domain"] is not None and row[col_map["domain"]] else "Enterprise Application"
                    version = str(row[col_map["version"]]).strip() if col_map["version"] is not None and row[col_map["version"]] else ""
                    keywords = str(row[col_map["keywords"]]).strip() if col_map["keywords"] is not None and row[col_map["keywords"]] else ""

                    self._register_app(app_name, vendor=vendor, domain=domain, version=version, keywords=keywords, all_terms=all_terms)

        finally:
            wb.close()
            if temp_to_clean and os.path.exists(temp_to_clean):
                try:
                    os.remove(temp_to_clean)
                except Exception:
                    pass

        # Build high-speed unified regex pattern
        if all_terms:
            escaped_terms = [re.escape(t) for t in sorted(all_terms, key=len, reverse=True)]
            pattern_str = r'\b(?:' + '|'.join(escaped_terms) + r')\b'
            self.compiled_pattern = re.compile(pattern_str, re.IGNORECASE)

    def _is_usable_term(self, term: str) -> bool:
        t = term.lower().strip()
        if len(t) < 3:
            return False
        # Do not allow standalone generic words without context
        if " " not in t and t in GENERIC_STOPWORDS:
            return False
        return True

    def _register_app(self, app_name: str, vendor: str = "", domain: str = "", version: str = "", keywords: str = "", all_terms: set = None):
        app_entry = {
            "name": app_name,
            "vendor": vendor,
            "domain": domain,
            "version": version
        }
        self.applications.append(app_entry)

        terms = set()
        name_clean = app_name.strip()
        if self._is_usable_term(name_clean):
            terms.add(name_clean.lower())

        # Extract base name without version suffixes: e.g. "Active Data Guard 19c" -> "Active Data Guard"
        base_name = re.sub(r'\s+(?:v?[\d\.]+|[\d]+[a-z]?|\([\d\.\-]+\)|\bDC\b|\bR[\d]+\b)$', '', name_clean, flags=re.IGNORECASE).strip()
        if self._is_usable_term(base_name):
            terms.add(base_name.lower())

        if vendor and base_name.lower().startswith(vendor.lower()):
            sub = base_name[len(vendor):].strip()
            if self._is_usable_term(sub):
                terms.add(sub.lower())

        if keywords:
            for kw in re.split(r'[,;|\n]', keywords):
                kw = kw.strip().lower()
                if self._is_usable_term(kw):
                    terms.add(kw)

        for t in terms:
            if t not in self.term_to_app_map:
                self.term_to_app_map[t] = app_entry
            if all_terms is not None:
                all_terms.add(t)

    def match(self, title: str, content: str) -> List[Dict[str, Any]]:
        """
        High-precision contextual match.
        Requires that matched application is either in the title or appears in substantive
        vulnerability/security context (not just an incidental mention).
        """
        if not self.compiled_pattern:
            return []

        title_text = title or ""
        body_text = content or ""
        full_text = f"{title_text}\n{body_text}".lower()

        # Check for core vulnerability indicators
        has_security_indicator = any(sig in full_text for sig in SECURITY_SIGNALS)
        if not has_security_indicator and not re.search(r'\bcve-\d{4}-\d+\b', full_text, re.IGNORECASE):
            # Not a vulnerability advisory or security update
            return []

        # Exclude browser extension / add-on vulnerabilities (infrastructure policy)
        if re.search(r'\b(?:chrome|browser|edge|firefox)\s+(?:extension|extensions|addon|add-on|add-ons|web store)\b', full_text, re.IGNORECASE):
            return []

        # Find all matching inventory terms
        title_matches = self.compiled_pattern.findall(title_text)
        body_matches = self.compiled_pattern.findall(body_text)

        matched = []
        seen_apps = set()

        # 1. Title matches get highest priority (strongest signal)
        for term in title_matches:
            t_lower = term.lower()
            if t_lower in self.term_to_app_map:
                app = self.term_to_app_map[t_lower]
                app_key = app["name"].lower()
                if app_key not in seen_apps:
                    seen_apps.add(app_key)
                    matched.append({
                        "application_name": app["name"],
                        "vendor": app.get("vendor", ""),
                        "telecom_domain": app.get("domain", "Enterprise Application"),
                        "version_context": app.get("version", ""),
                        "matched_keyword": term,
                        "matched_location": "title"
                    })

        # 2. Body matches: Only accept if the term appears in substantive security context
        for term in body_matches:
            t_lower = term.lower()
            if t_lower in self.term_to_app_map:
                app = self.term_to_app_map[t_lower]
                app_key = app["name"].lower()
                if app_key in seen_apps:
                    continue

                # Product and vulnerability details are often split across adjacent sentences.
                pattern = re.compile(rf'\b{re.escape(term)}\b', re.IGNORECASE)
                substantive = False
                for occurrence in pattern.finditer(body_text):
                    start = max(0, occurrence.start() - 200)
                    end = min(len(body_text), occurrence.end() + 200)
                    context = body_text[start:end].lower()
                    has_security_signal = any(sig in context for sig in SECURITY_SIGNALS) or "cve-" in context
                    has_non_security_news = any(cue in context for cue in [
                        "new feature", "launches", "updated its", "allows it to read", "open tabs",
                        "web pages", "data center", "gpu", "gpus sit idle", "earnings report",
                        "layoffs", "lawsuit", "court case", "startup claims"
                    ])
                    if has_security_signal and not has_non_security_news:
                        substantive = True
                        break

                if substantive:
                    seen_apps.add(app_key)
                    matched.append({
                        "application_name": app["name"],
                        "vendor": app.get("vendor", ""),
                        "telecom_domain": app.get("domain", "Enterprise Application"),
                        "version_context": app.get("version", ""),
                        "matched_keyword": term,
                        "matched_location": "body_contextual"
                    })

        return matched


class NameListMatcher:
    def __init__(self, excel_path: str, header_aliases: List[str]):
        self.excel_path = Path(excel_path)
        if not self.excel_path.exists():
            raise FileNotFoundError(f"Name list workbook not found: {self.excel_path}")

        normalized_aliases = {
            re.sub(r"[^a-z0-9]", "", alias.casefold())
            for alias in header_aliases
        }
        workbook, temp_to_clean = ApplicationInventory._safe_open_workbook(
            self.excel_path
        )
        names = []
        try:
            for worksheet in workbook.worksheets:
                rows = worksheet.iter_rows(values_only=True)
                first_row = next(rows, None)
                if not first_row:
                    continue
                header_index = next(
                    (
                        index
                        for index, value in enumerate(first_row)
                        if isinstance(value, str)
                        and re.sub(r"[^a-z0-9]", "", value.casefold())
                        in normalized_aliases
                    ),
                    None,
                )
                if header_index is None:
                    data_rows = chain((first_row,), rows)
                    name_index = 0
                else:
                    data_rows = rows
                    name_index = header_index

                for row in data_rows:
                    if len(row) <= name_index:
                        continue
                    value = row[name_index]
                    if value is not None and str(value).strip():
                        names.append(str(value).strip())
        finally:
            workbook.close()
            if temp_to_clean and os.path.exists(temp_to_clean):
                os.remove(temp_to_clean)

        self.names = list(dict.fromkeys(names))
        if not self.names:
            raise ValueError(f"No names were found in {self.excel_path.name}.")

        self._canonical_names = {
            name.casefold(): name
            for name in self.names
        }
        alternatives = "|".join(
            re.escape(name)
            for name in sorted(self.names, key=len, reverse=True)
        )
        self._pattern = re.compile(
            rf"(?<!\w)(?:{alternatives})(?!\w)",
            re.IGNORECASE,
        )

    def match(self, text: str) -> List[str]:
        if not text:
            return []
        matches = []
        seen = set()
        for match in self._pattern.finditer(text):
            matched_text = match.group()
            name = self._canonical_names[matched_text.casefold()]
            if len(name.strip()) < 3:
                context = text[max(0, match.start() - 48):match.end() + 48]
                if (
                    name.casefold() != "du"
                    or not re.search(
                        r"\b(?:telecom|operator|carrier|mobile|wireless|network|cellular)\b",
                        context,
                        re.IGNORECASE,
                    )
                ):
                    continue
            if (
                " " not in name
                and name.casefold() in AMBIGUOUS_NAME_TERMS
                and matched_text != name.upper()
            ):
                continue
            key = name.casefold()
            if key not in seen:
                seen.add(key)
                matches.append(name)
        return matches
