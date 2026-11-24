from pathlib import Path
from datetime import date, datetime
from copy import copy
from concurrent.futures import ThreadPoolExecutor
import html
import json
import os
import re
import tempfile
import time
from typing import List, Dict, Any, Optional
import requests
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter
from openpyxl.utils.exceptions import InvalidFileException
from openpyxl.worksheet.datavalidation import DataValidation
from openpyxl.worksheet.hyperlink import Hyperlink
from zipfile import BadZipFile

from relevance_model import AdvisoryRelevanceModel

PAGE_SCRIPT_NOISE = re.compile(
    r"\bwindow\.(?:ytcfg|yterr|unhandledErrorMessages|unhandledErrorCount)\b"
    r"|function\s*\(\s*\)\s*\{\s*window\.",
    re.IGNORECASE,
)

REPORT_IMPACT_CLAIMS = (
    re.compile(
        r"\b(?:remote code execution|\brce\b|arbitrary (?:code|command) execution|"
        r"execute arbitrary code)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\b(?:denial.of.service|\bdos\b)\b", re.IGNORECASE),
    re.compile(r"\bprivilege escalation\b", re.IGNORECASE),
    re.compile(r"\b(?:authentication|authorization) bypass\b", re.IGNORECASE),
    re.compile(r"\b(?:sql|command|code) injection\b", re.IGNORECASE),
    re.compile(r"\binformation disclosure\b", re.IGNORECASE),
)


class AdvisoryExcelExporter:
    RECOMMENDATION_FALLBACK = (
        "No remediation guidance was identified in the advisory or Tenable data. "
        "Consult the linked vendor advisory for remediation instructions."
    )
    EXCEL_CELL_TEXT_LIMIT = 30000
    REVIEW_COLUMNS = ("Review Decision", "Model Suggestion", "Relevance Score")
    STORAGE_COLUMNS = (
        "Article ID",
        "Advisory ID",
        "Detailed Report Path",
        "Member Article IDs",
        "Duplicate Candidate IDs",
        "Summary Conflicts",
        "Delivery Status",
        "Update Summary",
        "Content Hash",
        "Initial Triage",
        "Triage Note",
        "Source References",
        "Recommendation",
        "Affected Products",
        "Affected Versions",
        "Report Summary",
        "Source Content",
        "CVE Metrics JSON",
        "Matched Vendor",
    )

    def __init__(self, nvd_api_key: str = "", tenable_client: Any = None):
        self.nvd_api_key = nvd_api_key.strip()
        self.tenable_client = tenable_client
        self._nvd_cache: Dict[str, Dict[str, Any]] = {}
        self._nvd_cache_checked_at: Dict[str, float] = {}
        self._nvd_failed_cves = set()
        self._source_fetch_failures = 0
        self._nvd_cache_path = Path(__file__).resolve().parent.parent / "data" / "nvd_cve_cache.json"
        self._load_nvd_cache()

    def _load_nvd_cache(self) -> None:
        if not self._nvd_cache_path.exists():
            return
        try:
            data = json.loads(self._nvd_cache_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            print(f"[NVD Warning] Local cache could not be read: {e}")
            return
        if not isinstance(data, dict):
            print("[NVD Warning] Local cache has an unexpected format; ignoring it.")
            return

        now = time.time()
        for cve_id, entry in data.items():
            if not isinstance(entry, dict) or not isinstance(entry.get("metrics"), dict):
                continue
            try:
                checked_at = float(entry.get("checked_at", 0))
            except (TypeError, ValueError):
                continue
            metrics = entry["metrics"]
            has_data = any(
                str(metrics.get(field, "")).strip().upper() not in {"", "NA", "N/A"}
                for field in ("score", "vector")
            )
            ttl = 7 * 24 * 60 * 60 if has_data else 24 * 60 * 60
            if checked_at > 0 and now - checked_at < ttl:
                self._nvd_cache[str(cve_id).upper()] = metrics
                self._nvd_cache_checked_at[str(cve_id).upper()] = checked_at

    def _save_nvd_cache(self) -> None:
        if not self._nvd_cache_checked_at:
            return
        payload = {
            cve_id: {
                "checked_at": checked_at,
                "metrics": self._nvd_cache[cve_id],
            }
            for cve_id, checked_at in self._nvd_cache_checked_at.items()
            if cve_id in self._nvd_cache
        }
        try:
            self._nvd_cache_path.parent.mkdir(parents=True, exist_ok=True)
            temporary_path = self._nvd_cache_path.with_suffix(".tmp")
            temporary_path.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
            temporary_path.replace(self._nvd_cache_path)
        except OSError as e:
            print(f"[NVD Warning] Local cache could not be saved: {e}")

    HEADER_FILL = PatternFill(start_color="1B365D", end_color="1B365D", fill_type="solid")
    HEADER_FONT = Font(name="Calibri", size=11, bold=True, color="FFFFFF")
    DATA_FONT = Font(name="Calibri", size=10)
    BOLD_FONT = Font(name="Calibri", size=10, bold=True)

    SEVERITY_STYLES = {
        "CRITICAL": {"fill": PatternFill(start_color="FFD6D6", end_color="FFD6D6", fill_type="solid"), "font": Font(name="Calibri", size=10, bold=True, color="9C0006")},
        "HIGH": {"fill": PatternFill(start_color="FFE2C6", end_color="FFE2C6", fill_type="solid"), "font": Font(name="Calibri", size=10, bold=True, color="9C4B00")},
        "MEDIUM": {"fill": PatternFill(start_color="FFF0BA", end_color="FFF0BA", fill_type="solid"), "font": Font(name="Calibri", size=10, bold=True, color="8A6D00")},
        "LOW": {"fill": PatternFill(start_color="D1E7DD", end_color="D1E7DD", fill_type="solid"), "font": Font(name="Calibri", size=10, bold=True, color="0F5132")},
        "UNASSESSED": {"fill": PatternFill(start_color="E2E3E5", end_color="E2E3E5", fill_type="solid"), "font": Font(name="Calibri", size=10, bold=True, color="41464B")},
    }

    THIN_BORDER = Border(left=Side(style='thin', color='E0E0E0'), right=Side(style='thin', color='E0E0E0'), top=Side(style='thin', color='E0E0E0'), bottom=Side(style='thin', color='E0E0E0'))

    COLUMNS = [
        ("Source Name", 24, "left"),
        ("Advisory Type", 16, "center"),
        ("Advisory Heading", 42, "left"),
        ("Link of Advisory", 48, "left"),
        ("View Report", 16, "center"),
        ("View Detailed Report", 20, "center"),
        ("Other Sources", 48, "left"),
        ("Duplicate Check", 48, "left"),
        ("Severity", 14, "center"),
        ("CVSS", 10, "center"),
        ("Published Date & Time", 20, "center"),
        ("Security Impact / Summary", 65, "left"),
        ("Matched Application / Component", 32, "left"),
        ("CVE Details", 26, "left"),
        ("CVE Risk Score", 16, "center"),
        ("Attack Vector", 18, "center"),
        ("AV Type", 14, "center"),
        ("IOCs", 48, "left")
    ]

    def _safe_save(
        self,
        wb: openpyxl.Workbook,
        target_path: Path,
        replace_existing: bool = False,
    ) -> str:
        target_path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = None
        try:
            temp_fd, temp_name = tempfile.mkstemp(
                prefix=f".{target_path.stem}_",
                suffix=target_path.suffix,
                dir=str(target_path.parent),
            )
            os.close(temp_fd)
            temp_path = Path(temp_name)
            wb.save(str(temp_path))
            try:
                temp_path.replace(target_path)
                return str(target_path)
            except PermissionError as exc:
                if replace_existing:
                    raise RuntimeError(
                        f"Unable to replace '{target_path.name}' because it is open. "
                        "Close the workbook and retry; the existing file was left unchanged."
                    ) from exc
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                alt_path = target_path.parent / f"{target_path.stem}_{ts}{target_path.suffix}"
                print(
                    f"[Warning] '{target_path.name}' is open in Excel. "
                    f"Saved timestamped copy to: '{alt_path.name}'"
                )
                wb.save(str(alt_path))
                return str(alt_path)
        finally:
            if temp_path and temp_path.exists():
                temp_path.unlink()

    @staticmethod
    def _recorded_on_date(value, target_date: date) -> bool:
        if isinstance(value, datetime):
            return value.date() == target_date
        if isinstance(value, date):
            return value == target_date
        return str(value or "").strip()[:10] == target_date.isoformat()

    def _load_existing_workbook(self, path: Path):
        try:
            return openpyxl.load_workbook(path)
        except (OSError, ValueError, InvalidFileException, BadZipFile) as exc:
            raise RuntimeError(
                f"Unable to read existing workbook '{path}'; it was not modified."
            ) from exc

    def _normalize_text(self, value: Any) -> str:
        return " ".join(str(value or "").split())

    def extract_cves(self, text: str) -> List[str]:
        candidates = re.findall(r'CVE-\d{4}-\d+', (text or '').upper())
        seen = []
        for cve in candidates:
            if cve not in seen:
                seen.append(cve)
        return seen

    def extract_iocs(self, text: str) -> List[str]:
        text = text or ""
        iocs = []
        for pattern in [
            r'https?://[^\s<>\]"\)]+',
            r'(?:(?:\d{1,3}\.){3}\d{1,3})',
            r'(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})',
            r'(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}'
        ]:
            for match in re.findall(pattern, text, re.IGNORECASE):
                value = str(match).strip().rstrip('.,;')
                if value and value not in iocs:
                    iocs.append(value)
        return iocs

    def defang_ioc_text(self, text: Any) -> str:
        value = str(text or "")
        value = re.sub(
            r"\bhttps?://",
            lambda match: "hxxps://" if match.group(0).lower().startswith("https") else "hxxp://",
            value,
            flags=re.IGNORECASE,
        )
        return re.sub(r"(?<!\[)\.(?!\])", "[.]", value)

    def _mask_report_indicators(self, record: Dict[str, Any], text: Any) -> str:
        masked = str(text or "")
        source_text = "\n".join(
            str(record.get(field) or "")
            for field in ("advisory_heading", "source_content", "impact_summary")
        )
        for indicator in sorted(self.extract_iocs(source_text), key=len, reverse=True):
            masked = re.sub(
                re.escape(indicator),
                lambda _match: self.defang_ioc_text(indicator),
                masked,
                flags=re.IGNORECASE,
            )
        return masked

    def _normalize_affected_versions(self, value: Any) -> str:
        versions = str(value or "").strip()
        if versions.casefold() in {
            "",
            "na",
            "n/a",
            "none",
            "null",
            "unknown",
            "not specified",
            "not available",
        }:
            return ""
        if re.fullmatch(
            r"(?:see|check|consult)\s+(?:the\s+)?(?:vendor\s+)?"
            r"(?:advisory|bulletin)(?:\s+for\b.*)?",
            versions,
            re.IGNORECASE,
        ):
            return ""

        valid_parts = []
        for part in re.split(r"\s*;\s*", versions):
            part = part.strip()
            if not part:
                continue
            if re.search(
                r"\b(?:versions?|releases?|builds?|branches?)\b",
                part,
                re.IGNORECASE,
            ):
                valid_parts.append(part)
                continue
            if re.fullmatch(
                r"(?:v?\d+(?:\.\d+){1,4})(?:\s*(?:-|to|through)\s*"
                r"v?\d+(?:\.\d+){1,4})?",
                part,
                re.IGNORECASE,
            ) or re.fullmatch(
                r"from\s+v?\d+(?:\.\d+){1,4}\s+(?:to|through)\s+"
                r"v?\d+(?:\.\d+){1,4}",
                part,
                re.IGNORECASE,
            ) or re.fullmatch(
                r"(?:before|prior to|less than)\s+(?:version\s+)?"
                r"v?\d+(?:\.\d+){1,4}",
                part,
                re.IGNORECASE,
            ) or re.fullmatch(
                r"[\w .:/()_-]{1,80}\s+v?\d+(?:\.\d+){1,4}\s*"
                r"(?:-|to|through)\s*v?\d+(?:\.\d+){1,4}",
                part,
                re.IGNORECASE,
            ):
                valid_parts.append(part)
        return "; ".join(valid_parts)

    def _affected_products_text(self, record: Dict[str, Any]) -> str:
        products = str(record.get("affected_products") or "").strip()
        if PAGE_SCRIPT_NOISE.search(products):
            products = ""
        products = re.sub(
            r"\s*[:;,-]?\s*(?:see|check|consult)\s+(?:the\s+)?"
            r"(?:vendor\s+)?(?:advisory|bulletin)"
            r"(?:\s+for\s+(?:the\s+)?affected\s+(?:versions?|releases?))?[.!]?$",
            "",
            products,
            flags=re.IGNORECASE,
        ).strip()
        applications = str(record.get("matched_app_name") or "").strip()
        versions = self._normalize_affected_versions(record.get("affected_versions"))
        unavailable = {"", "na", "n/a", "none", "null", "unknown"}
        if applications and products.casefold() not in unavailable:
            products = "; ".join(
                part
                for part in (value.strip() for value in products.split(";"))
                if part
                and not (
                    applications.casefold() in part.casefold()
                    and re.search(r"\b\d+\.\d+\b", part)
                    and not self._normalize_affected_versions(part)
                )
            )

        lines = []
        if products.casefold() not in unavailable:
            lines.append(f"Affected products: {products}")
        elif applications and applications.casefold() not in unavailable:
            lines.append(f"Inventory-matched products: {applications}")
        if versions.casefold() not in unavailable and versions.casefold() not in products.casefold():
            lines.append(f"Affected versions: {versions}")
        return "\n".join(lines)

    def extract_recommendation(self, text: str) -> str:
        text = re.sub(r'[ \t]+', ' ', text or '').strip()
        if not text:
            return "NA"

        recommendation_terms = re.compile(
            r'\b(?:recommend\w*|should\s+(?!not\b)(?:apply|install|upgrade|update|patch|disable|'
            r'prioritize|monitor)|must|ensure|upgrade\w*|updat\w*|'
            r'mitigat\w*|workaround\w*|fixed\s+(?:in|release)|fix(?:es|ed)?|'
            r'install\w*|apply|disable\w*|download\w*|solution|resolution|'
            r'remediat\w*|no\s+workaround|back\s+up|monitor|contact\s+(?:the\s+)?'
            r'(?:vendor|support)|released\s+(?:a\s+)?(?:security\s+)?updates?)\b',
            re.IGNORECASE,
        )
        candidates = []
        for sentence in re.split(r'(?<=[.!?])\s+|\n+', text):
            sentence = sentence.strip(" \t\r\n-•")
            if sentence and recommendation_terms.search(sentence) and sentence not in candidates:
                candidates.append(sentence)

        if candidates:
            return "\n".join(candidates)

        patch_attachment = re.search(
            r'\bAttachment\s*:\s*([A-Za-z0-9._-]+\.patch)\b',
            text,
            re.IGNORECASE,
        )
        if patch_attachment:
            return (
                f"Review the vendor-provided patch {patch_attachment.group(1)} linked with this advisory "
                "and apply it after testing."
            )

        fixed_version = re.search(
            r'\b(?:affects?|affecting)\s+([A-Za-z0-9.+#/_ -]{1,60}?)\s+versions?\s+'
            r'(?:before|prior to)\s+(\d+(?:\.\d+){1,3})\b',
            text,
            re.IGNORECASE,
        )
        if fixed_version:
            product = fixed_version.group(1).strip(" .,-")
            version = fixed_version.group(2)
            return (
                f"Upgrade {product} to version {version} or later; "
                f"versions before {version} are affected."
            )

        section_start = re.search(
            r'\b(?:recommendations?|remediation|solution|workarounds?|mitigations?|'
            r'fixed software|patch availability|security updates?|resolution)\b\s*:?\s*',
            text,
            re.IGNORECASE,
        )
        if section_start:
            section = text[section_start.end():]
            section = re.split(
                r'\b(?:description|impact|severity|affected products?|vulnerability details?|'
                r'references?|background)\b\s*:?\s*',
                section,
                maxsplit=1,
                flags=re.IGNORECASE,
            )[0]
            if section.strip():
                return section.strip()
        return "NA"

    def _ensure_recommendation(self, recommendation: Any) -> str:
        value = str(recommendation or "").strip()
        if value.casefold() in {"", "na", "n/a", "none", "null"}:
            return self.RECOMMENDATION_FALLBACK
        return value

    def _display_value(self, value: Any) -> str:
        text = str(value or "").strip()
        if text.casefold() in {"", "na", "n/a", "none", "null"}:
            return "Not available"
        return text

    def _nvd_cve_lookup(self, cve_id: str) -> Dict[str, Any]:
        normalized = cve_id.strip().upper()
        self._nvd_cve_lookup_many([normalized])
        return self._nvd_cache.get(normalized, {})

    def _nvd_cve_lookup_many(self, cve_ids: List[str]) -> None:
        pending = list(dict.fromkeys(
            cve.strip().upper() for cve in cve_ids
            if cve
            and cve.strip().upper() not in self._nvd_cache
            and cve.strip().upper() not in self._nvd_failed_cves
        ))
        if not pending:
            return

        headers = {"apiKey": self.nvd_api_key} if self.nvd_api_key else {}
        endpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        failed_batches = 0
        first_failure = ""
        now = time.time()
        for offset in range(0, len(pending), 100):
            batch = pending[offset:offset + 100]
            try:
                response = requests.get(
                    endpoint,
                    params={"cveIds": ",".join(batch)},
                    headers=headers,
                    timeout=(4, 12),
                )
                if response.status_code != 200:
                    self._nvd_failed_cves.update(batch)
                    failed_batches += 1
                    first_failure = first_failure or f"HTTP {response.status_code}"
                    continue
                data = response.json()
                if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities", []), list):
                    self._nvd_failed_cves.update(batch)
                    failed_batches += 1
                    first_failure = first_failure or "unexpected response"
                    continue
                for item in data.get("vulnerabilities", []):
                    cve = item.get("cve", {})
                    cve_id = str(cve.get("id", "")).upper()
                    if not cve_id:
                        continue
                    metrics = cve.get("metrics", {})
                    result = {}
                    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                        entries = metrics.get(key, [])
                        if entries:
                            metric_data = entries[0].get("cvssData", {})
                            score = metric_data.get("baseScore")
                            vector = metric_data.get("vectorString")
                            result = {
                                "score": str(score) if score is not None else "NA",
                                "vector": str(vector) if vector else "NA",
                                "version": key.removeprefix("cvssMetricV"),
                            }
                            break
                    self._nvd_cache[cve_id] = result
                for cve_id in batch:
                    self._nvd_cache.setdefault(cve_id, {})
                    self._nvd_cache_checked_at[cve_id] = now
            except (requests.RequestException, ValueError, KeyError) as e:
                self._nvd_failed_cves.update(batch)
                failed_batches += 1
                first_failure = first_failure or str(e)
        self._save_nvd_cache()
        if failed_batches:
            print(
                f"[NVD Warning] {failed_batches} batch(es) failed ({first_failure}); "
                "advisory values will be used where available."
            )

    def _extract_cve_context(self, text: str, cve_id: str) -> str:
        occurrences = [match.start() for match in re.finditer(re.escape(cve_id), text, re.IGNORECASE)]
        contexts = []
        for position in occurrences:
            sentence_starts = [
                match.end()
                for match in re.finditer(r'(?<=[.!?])\s+|\n+', text[:position])
            ]
            start = sentence_starts[-1] if sentence_starts else 0
            next_cve = re.search(r'\bCVE-\d{4}-\d+\b', text[position + len(cve_id):], re.IGNORECASE)
            end = position + len(cve_id) + next_cve.start() if next_cve else min(len(text), position + len(cve_id) + 600)
            contexts.append(text[start:end])
        return "\n".join(contexts)

    def _extract_cve_score(self, text: str, cve_id: str) -> str:
        context = self._extract_cve_context(text, cve_id)
        score_pattern = re.compile(
            r'\b(?:CVSS(?:\s*v[34](?:\.[01])?)?(?:\s+base)?(?:\s+score)?|'
            r'rated|base\s+score|score|carries?\s+(?:a\s+)?)\s*(?:is|of|:|=)?\s*((?:10|[0-9])\.[0-9])\b|'
            r'\b((?:10|[0-9])\.[0-9])\s*-rated\b|'
            r'\b((?:10|[0-9])\.[0-9])\s*(?:\/\s*10|out of 10|\bCVSS\b)',
            re.IGNORECASE,
        )
        match = score_pattern.search(context)
        if match:
            return next(group for group in match.groups() if group is not None)
        return "NA"

    def _build_cve_metrics(
        self,
        cve_ids: List[str],
        text: str,
        evaluation: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Dict[str, str]]:
        self._nvd_cve_lookup_many(cve_ids)
        metrics = {}
        for index, cve in enumerate(cve_ids):
            nvd = self._nvd_cve_lookup(cve)
            plugins = self.tenable_client.lookup_cve(cve) if self.tenable_client else []
            tenable_plugin = plugins[0] if plugins else {}
            vector = nvd.get("vector", "NA")
            if vector == "NA":
                vector = str(
                    tenable_plugin.get("cvss_vector")
                    or tenable_plugin.get("cvss3_vector")
                    or tenable_plugin.get("cvss4_vector")
                    or "NA"
                )
            score = nvd.get("score", "NA")
            if score == "NA":
                score = str(
                    tenable_plugin.get("cvss_base_score")
                    or tenable_plugin.get("cvss3_base_score")
                    or tenable_plugin.get("cvss4_base_score")
                    or "NA"
                )
            context = self._extract_cve_context(text, cve)
            if score == "NA":
                score = self._extract_cve_score(text, cve)
            if vector == "NA":
                vector_match = re.search(r'\bCVSS:[34]\.[01]/[A-Z0-9:/]+', context, re.IGNORECASE)
                if vector_match:
                    vector = vector_match.group(0)
            if score == "NA" and index == 0 and evaluation:
                score = str(evaluation.get("cvss_score", "NA"))
            av_type = self.infer_attack_vector(vector)
            if av_type == "NA":
                av_type = self.infer_attack_vector(context)
            if av_type == "NA" and index == 0 and evaluation:
                evaluated_vector = str(evaluation.get("attack_vector", "NA"))
                vector = evaluated_vector
                av_type = self.infer_attack_vector(evaluated_vector)
            nvd_score = nvd.get("score", "NA")
            metrics[cve] = {
                "cvss_score": score,
                "attack_vector": vector,
                "av_type": av_type,
                "risk_score": nvd_score if nvd_score not in {"", "NA", "N/A"} else score,
                "nvd_score": nvd_score,
                "nvd_vector": nvd.get("vector", "NA"),
                "tenable_solution": str(tenable_plugin.get("solution", "")),
            }
        return metrics

    def _tenable_recommendation(self, cve_ids: List[str]) -> str:
        if not self.tenable_client:
            return ""
        solutions = []
        for cve in cve_ids:
            for plugin in self.tenable_client.lookup_cve(cve):
                solution = str(plugin.get("solution") or "").strip()
                if solution and solution.casefold() not in {item.casefold() for item in solutions}:
                    solutions.append(f"{cve}: {solution}")
        return "\n".join(solutions)

    def _fetch_source_content(self, url: str) -> str:
        if not url.startswith(("http://", "https://")):
            return ""
        try:
            response = requests.get(
                url,
                headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityAdvisoryReporter/1.0)"},
                timeout=(4, 10),
            )
            if response.status_code != 200:
                self._source_fetch_failures += 1
                return ""
            paragraphs = re.findall(r'<p\b[^>]*>(.*?)</p>', response.text, re.IGNORECASE | re.DOTALL)
            if paragraphs:
                paragraph_text = "\n".join(
                        re.sub(r'\s+', ' ', html.unescape(re.sub(r'<[^>]+>', ' ', paragraph))).strip()
                    for paragraph in paragraphs
                )
                if paragraph_text.strip():
                    return paragraph_text
            return re.sub(
                r'\s+',
                ' ',
                html.unescape(re.sub(r'<[^>]+>', ' ', response.text[:15000])),
            ).strip()
        except requests.RequestException as e:
            self._source_fetch_failures += 1
            return ""

    def _source_content_matches_record(self, record: Dict[str, Any], content: str) -> bool:
        if not content.strip():
            return False

        expected_cves = set(self.extract_cves(str(record.get("cve_details", ""))))
        content_cves = set(self.extract_cves(content))
        heading = str(record.get("advisory_heading", ""))
        stop_words = {
            "advisory", "allow", "allows", "attack", "attackers", "code", "confirms",
            "critical", "during", "enables", "exposes", "flaw", "flaws", "hackers",
            "historical", "hits", "issue", "lets", "multiple", "new", "patch", "patches",
            "remote", "security",
            "that", "unauthenticated", "update", "vulnerability", "vulnerabilities",
        }
        title_terms = [
            term.casefold()
            for term in re.findall(r"[a-z0-9]+", heading, re.IGNORECASE)
            if (
                len(term) >= 3
                and not term.isdigit()
                and term.casefold() not in stop_words
                and term.casefold() != "cve"
            )
        ]

        content_terms = {
            term.casefold()
            for term in re.findall(r"[a-z0-9]+", content, re.IGNORECASE)
        }
        core_title_terms = set(title_terms[:2])
        overlap = len(set(title_terms).intersection(content_terms))
        title_matches = (
            not title_terms
            or bool(core_title_terms.intersection(content_terms))
            or overlap >= max(1, (len(title_terms) + 1) // 2)
        )

        if expected_cves:
            if expected_cves.intersection(content_cves):
                return not core_title_terms or bool(core_title_terms.intersection(content_terms))
            if content_cves:
                return False
            return title_matches
        return title_matches

    def classify_advisory(self, title: str, content: str) -> str:
        text = f"{title}\n{content}".upper()
        cves = self.extract_cves(text)
        iocs = self.extract_iocs(text)
        if cves:
            return "Patching"
        if iocs:
            return "Actionable"
        return "Information"

    def infer_attack_vector(self, text: str) -> str:
        vector_text = (text or '').upper()
        match = re.search(r'AV:([NALP])', vector_text)
        if match:
            mapping = {'N': 'Network', 'A': 'Adjacent', 'L': 'Local', 'P': 'Physical'}
            return mapping.get(match.group(1), 'Network')
        if re.search(r'\b(?:REMOTE|NETWORK)\b', vector_text):
            return 'Network'
        if re.search(r'\b(?:LOCAL|HOST-LOCAL)\b', vector_text):
            return 'Local'
        if re.search(r'\b(?:PHYSICAL|USER INTERACTION)\b', vector_text):
            return 'Physical'
        return 'NA'

    def build_advisory_record(
        self,
        adv: Dict[str, Any],
        evaluation: Optional[Dict[str, Any]] = None,
        enrich_cves: bool = True,
    ) -> Dict[str, Any]:
        title = adv.get("title", "")
        content = adv.get("content", "")
        text = f"{title}\n{content}"
        cve_list = self.extract_cves(text)
        ioc_list = self.extract_iocs(text)
        classification = self.classify_advisory(title, content)

        cve_details = ", ".join(cve_list) if cve_list else "NA"
        cve_metrics = (
            self._build_cve_metrics(cve_list, text, evaluation)
            if enrich_cves else {}
        )

        first_cve_metrics = cve_metrics.get(cve_list[0], {}) if cve_list else {}
        cve_risk_score = first_cve_metrics.get("risk_score", "NA")
        attack_vector = first_cve_metrics.get("attack_vector", "NA")
        av_type = first_cve_metrics.get("av_type", "NA")
        nvd_score = first_cve_metrics.get("nvd_score", "NA")
        cvss_score = nvd_score if nvd_score not in {"", "NA", "N/A"} else (
            (evaluation or {}).get("cvss_score", cve_risk_score if cve_risk_score != "NA" else "N/A")
        )

        ioc_value = self.defang_ioc_text("; ".join(ioc_list)) if ioc_list else "NA"
        if classification == "Information" and not ioc_list:
            ioc_value = "NA"

        recommendation = self.extract_recommendation(content)
        if recommendation == "NA" and enrich_cves:
            recommendation = self._tenable_recommendation(cve_list)
        recommendation = self._ensure_recommendation(recommendation)

        record = {
            "source_name": adv.get("source_name", "Inoreader Feed"),
            "advisory_heading": evaluation.get("advisory_heading", adv.get("title", "")) if evaluation else adv.get("title", ""),
            "link": adv.get("link", ""),
            "severity": (evaluation or {}).get("severity", "MEDIUM"),
            "cvss_score": cvss_score,
            "published_timestamp": adv.get("published_timestamp", datetime.now().timestamp()),
            "impact_summary": (evaluation or {}).get("impact_summary", "") or (adv.get("content", "")[:700] if adv.get("content") else ""),
            "matched_app_name": adv.get("matched_app_name", ""),
            "matched_vendor": adv.get("matched_vendor", ""),
            "advisory_type": classification,
            "cve_details": cve_details,
            "cve_risk_score": cve_risk_score,
            "cve_metrics": cve_metrics,
            "attack_vector": attack_vector,
            "av_type": av_type,
            "iocs": ioc_value,
            "affected_products": (evaluation or {}).get(
                "affected_products",
                adv.get("affected_products", ""),
            ),
            "affected_versions": (evaluation or {}).get("affected_versions", "NA"),
            "report_summary": (evaluation or {}).get("report_summary", ""),
            "recommendation": recommendation,
            "source_content": content,
        }
        return record

    def _render_headers(self, ws, header_titles: List[str]):
        ws.row_dimensions[1].height = 28
        ws.append(header_titles)
        for col_idx in range(1, len(header_titles) + 1):
            cell = ws.cell(row=1, column=col_idx)
            cell.font = self.HEADER_FONT
            cell.fill = self.HEADER_FILL
            cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)

    def _copy_cell(self, source_cell, target_cell) -> None:
        target_cell.value = source_cell.value
        if source_cell.has_style:
            target_cell._style = copy(source_cell._style)
        target_cell.number_format = source_cell.number_format
        target_cell.protection = copy(source_cell.protection)
        target_cell._hyperlink = copy(source_cell.hyperlink) if source_cell.hyperlink else None
        target_cell.comment = copy(source_cell.comment) if source_cell.comment else None

    def _move_column(self, ws, source_column: int, target_column: int) -> None:
        if source_column == target_column:
            return
        source_cells = [
            copy(ws.cell(row=row_idx, column=source_column))
            for row_idx in range(1, ws.max_row + 1)
        ]
        if source_column > target_column:
            for column in range(source_column, target_column, -1):
                for row_idx in range(1, ws.max_row + 1):
                    self._copy_cell(
                        ws.cell(row=row_idx, column=column - 1),
                        ws.cell(row=row_idx, column=column),
                    )
        else:
            for column in range(source_column, target_column):
                for row_idx in range(1, ws.max_row + 1):
                    self._copy_cell(
                        ws.cell(row=row_idx, column=column + 1),
                        ws.cell(row=row_idx, column=column),
                    )
        for row_idx, source_cell in enumerate(source_cells, start=1):
            self._copy_cell(source_cell, ws.cell(row=row_idx, column=target_column))

    def _ensure_summary_schema(self, ws) -> None:
        columns = {
            str(cell.value).strip(): cell.column
            for cell in ws[1]
            if cell.value is not None
        }
        type_column = columns.get("Advisory Type")
        heading_column = columns.get("Advisory Heading")
        if type_column and heading_column and type_column != heading_column - 1:
            target_column = (
                heading_column if type_column > heading_column else heading_column - 1
            )
            self._move_column(ws, type_column, target_column)

        columns = {
            str(cell.value).strip(): cell.column
            for cell in ws[1]
            if cell.value is not None
        }
        link_column = columns.get("Link of Advisory")
        if link_column and "View Report" not in columns:
            report_column = link_column + 1
            ws.insert_cols(report_column, 1)
            header = ws.cell(row=1, column=report_column, value="View Report")
            header.font = self.HEADER_FONT
            header.fill = self.HEADER_FILL
            header.alignment = Alignment(
                horizontal="center",
                vertical="center",
                wrap_text=True,
            )
            for row_idx in range(2, ws.max_row + 1):
                self._write_report_link(ws, row_idx, None, {"View Report": report_column})

        columns = {
            str(cell.value).strip(): cell.column
            for cell in ws[1]
            if cell.value is not None
        }
        if "View Report" in columns and "View Detailed Report" not in columns:
            detailed_column = columns["View Report"] + 1
            ws.insert_cols(detailed_column, 1)
            header = ws.cell(
                row=1,
                column=detailed_column,
                value="View Detailed Report",
            )
            header.font = self.HEADER_FONT
            header.fill = self.HEADER_FILL
            header.alignment = Alignment(
                horizontal="center",
                vertical="center",
                wrap_text=True,
            )
            ws.column_dimensions[get_column_letter(detailed_column)].width = 20
            for row_idx in range(2, ws.max_row + 1):
                self._write_detailed_report_link(
                    ws,
                    row_idx,
                    None,
                    {"View Detailed Report": detailed_column},
                )
            columns = {
                str(cell.value).strip(): cell.column
                for cell in ws[1]
                if cell.value is not None
            }
        for header, width, _alignment in self.COLUMNS:
            if header in columns:
                continue
            column = ws.max_column + 1
            cell = ws.cell(row=1, column=column, value=header)
            cell.font = self.HEADER_FONT
            cell.fill = self.HEADER_FILL
            cell.alignment = Alignment(
                horizontal="center",
                vertical="center",
                wrap_text=True,
            )
            ws.column_dimensions[get_column_letter(column)].width = width
            columns[header] = column

    def _ensure_review_columns(self, ws):
        columns = {
            str(cell.value).strip(): cell.column
            for cell in ws[1]
            if cell.value is not None
        }
        for header in self.REVIEW_COLUMNS + self.STORAGE_COLUMNS:
            if header in columns:
                continue
            column = ws.max_column + 1
            cell = ws.cell(row=1, column=column, value=header)
            cell.font = self.HEADER_FONT
            cell.fill = self.HEADER_FILL
            cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
            columns[header] = column

        decision_column = columns["Review Decision"]
        decision_target = columns.get("Advisory Heading", 1) + 1
        review_choices = '"☐ Pending,☑ Selected,☒ Rejected"'
        ws.data_validations.dataValidation = [
            validation for validation in ws.data_validations.dataValidation
            if not (
                validation.type == "list"
                and validation.formula1 in {
                    review_choices,
                    '"☐ Pending,☑ Selected,☒ Rejected,Previously Reported"',
                    '"Same Event,Keep Separate"',
                }
            )
        ]
        if decision_column != decision_target:
            shifted_decision_column = decision_column + (
                1 if decision_column >= decision_target else 0
            )
            ws.insert_cols(decision_target, 1)
            for row_idx in range(1, ws.max_row + 1):
                source_cell = ws.cell(row=row_idx, column=shifted_decision_column)
                target_cell = ws.cell(row=row_idx, column=decision_target)
                target_cell.value = source_cell.value
                if source_cell.has_style:
                    target_cell._style = copy(source_cell._style)
                target_cell.number_format = source_cell.number_format
                target_cell.protection = copy(source_cell.protection)
                if source_cell.hyperlink:
                    target_cell._hyperlink = copy(source_cell.hyperlink)
                if source_cell.comment:
                    target_cell.comment = copy(source_cell.comment)
            ws.delete_cols(shifted_decision_column, 1)
            columns = {
                str(cell.value).strip(): cell.column
                for cell in ws[1]
                if cell.value is not None
            }

        heading_column = columns.get("Advisory Heading")
        decision_column = columns["Review Decision"]
        if heading_column:
            for row_idx in range(2, ws.max_row + 1):
                decision_cell = ws.cell(row=row_idx, column=decision_column)
                if str(decision_cell.value or "").strip():
                    continue
                decision_cell.value = "☐ Pending"

        validation = DataValidation(
            type="list",
            formula1=review_choices,
            allow_blank=False,
        )
        validation.error = "Choose Pending, Selected, or Rejected."
        validation.errorTitle = "Invalid review decision"
        validation.prompt = "Choose ☑ Selected to mark the advisory for detailed reporting."
        validation.promptTitle = "Review advisory"
        ws.add_data_validation(validation)
        validation.add(
            f"{get_column_letter(decision_column)}2:"
            f"{get_column_letter(decision_column)}{max(ws.max_row, 5000)}"
        )
        duplicate_column = columns.get("Duplicate Check")
        if duplicate_column:
            duplicate_validation = DataValidation(
                type="list",
                formula1='"Same Event,Keep Separate"',
                allow_blank=True,
            )
            duplicate_validation.prompt = (
                "Choose Same Event or Keep Separate to remember a duplicate decision."
            )
            duplicate_validation.promptTitle = "Duplicate decision"
            ws.add_data_validation(duplicate_validation)
            duplicate_validation.add(
                f"{get_column_letter(duplicate_column)}2:"
                f"{get_column_letter(duplicate_column)}{max(ws.max_row, 5000)}"
            )

        for header in self.REVIEW_COLUMNS:
            column = columns[header]
            ws.column_dimensions[get_column_letter(column)].width = {
                "Review Decision": 22,
                "Model Suggestion": 24,
                "Relevance Score": 16,
            }[header]
        decision_letter = get_column_letter(columns["Review Decision"])
        ws.column_dimensions[decision_letter].hidden = False
        for row_idx in range(2, ws.max_row + 1):
            decision_cell = ws.cell(row=row_idx, column=columns["Review Decision"])
            decision_cell.alignment = Alignment(horizontal="center", vertical="center")
            self._style_review_decision(decision_cell)
        for header in self.STORAGE_COLUMNS:
            ws.column_dimensions[get_column_letter(columns[header])].hidden = True
        for header, column in columns.items():
            if (
                header.startswith("CVE Metrics JSON Part ")
                or header.startswith("Source References Part ")
            ):
                ws.column_dimensions[get_column_letter(column)].hidden = True
        return columns

    def _write_review_data(
        self,
        ws,
        row_idx: int,
        adv: Dict[str, Any],
        columns,
        preserve_review_decision: bool = False,
    ):
        existing_decision = (
            ws.cell(row=row_idx, column=columns["Review Decision"]).value
            if preserve_review_decision and columns.get("Review Decision")
            else None
        )
        decision = existing_decision or adv.get("review_decision", "☑ Selected")
        normalized_decision = AdvisoryRelevanceModel.normalize_decision(decision)
        if normalized_decision == "Pending":
            decision = "☐ Pending"
        elif normalized_decision == "Selected":
            decision = "☑ Selected"
        elif normalized_decision == "Rejected":
            decision = "☒ Rejected"
        elif normalized_decision == "Previously Reported":
            decision = "Previously Reported"
        else:
            decision = "☐ Pending"
        metrics_json = json.dumps(
            adv.get("cve_metrics") or {},
            separators=(",", ":"),
        )
        metric_chunks = [
            metrics_json[index:index + self.EXCEL_CELL_TEXT_LIMIT]
            for index in range(0, len(metrics_json), self.EXCEL_CELL_TEXT_LIMIT)
        ] or ["{}"]
        metrics_headers = ["CVE Metrics JSON"] + [
            f"CVE Metrics JSON Part {index + 2}"
            for index in range(len(metric_chunks) - 1)
        ]
        references_json = json.dumps(
            adv.get("source_references") or [],
            ensure_ascii=True,
            separators=(",", ":"),
        )
        reference_chunks = [
            references_json[index:index + self.EXCEL_CELL_TEXT_LIMIT]
            for index in range(0, len(references_json), self.EXCEL_CELL_TEXT_LIMIT)
        ] or ["[]"]
        reference_headers = ["Source References"] + [
            f"Source References Part {index + 2}"
            for index in range(len(reference_chunks) - 1)
        ]
        existing_metric_parts = {
            header: column
            for header, column in columns.items()
            if header.startswith("CVE Metrics JSON Part ")
        }
        existing_reference_parts = {
            header: column
            for header, column in columns.items()
            if header.startswith("Source References Part ")
        }
        for header in metrics_headers + reference_headers:
            if header not in columns:
                column = ws.max_column + 1
                header_cell = ws.cell(row=1, column=column, value=header)
                header_cell.font = self.HEADER_FONT
                header_cell.fill = self.HEADER_FILL
                header_cell.alignment = Alignment(
                    horizontal="center",
                    vertical="center",
                    wrap_text=True,
                )
                columns[header] = column
            ws.column_dimensions[get_column_letter(columns[header])].hidden = True
        values = {
            "Review Decision": decision,
            "Model Suggestion": adv.get("model_suggestion", "Collecting labels"),
            "Relevance Score": adv.get("relevance_score", ""),
            "Article ID": adv.get("id", ""),
            "Advisory ID": adv.get("advisory_id", ""),
            "Detailed Report Path": adv.get("detailed_report_path", ""),
            "Member Article IDs": json.dumps(
                adv.get("member_article_ids")
                or [adv.get("id")] + list(adv.get("_deduplicated_article_ids") or []),
                ensure_ascii=True,
                separators=(",", ":"),
            ),
            "Duplicate Candidate IDs": json.dumps(
                adv.get("duplicate_candidate_ids") or [],
                ensure_ascii=True,
                separators=(",", ":"),
            ),
            "Summary Conflicts": json.dumps(
                adv.get("summary_conflicts") or [],
                ensure_ascii=True,
                separators=(",", ":"),
            ),
            "Delivery Status": adv.get("delivery_status", ""),
            "Update Summary": adv.get("update_summary", ""),
            "Content Hash": adv.get("content_hash", ""),
            "Initial Triage": adv.get("initial_triage", "Accepted"),
            "Triage Note": adv.get("triage_note", ""),
            "Recommendation": adv.get("recommendation", ""),
            "Affected Products": adv.get("affected_products", ""),
            "Affected Versions": adv.get("affected_versions", ""),
            "Report Summary": adv.get("report_summary", ""),
            "Source Content": str(adv.get("source_content") or "")[:32000],
            "Matched Vendor": adv.get("matched_vendor", ""),
        }
        values.update({
            header: metric_chunks[index]
            for index, header in enumerate(metrics_headers)
        })
        values.update({
            header: reference_chunks[index]
            for index, header in enumerate(reference_headers)
        })
        for header in existing_metric_parts.keys() - set(metrics_headers):
            ws.cell(row=row_idx, column=existing_metric_parts[header], value=None)
        for header in existing_reference_parts.keys() - set(reference_headers):
            ws.cell(row=row_idx, column=existing_reference_parts[header], value=None)
        for header, value in values.items():
            column = columns.get(header)
            if column:
                cell = ws.cell(row=row_idx, column=column, value=value)
                if header in self.REVIEW_COLUMNS:
                    cell.font = self.DATA_FONT
                    cell.border = self.THIN_BORDER
                    cell.alignment = Alignment(vertical="center", wrap_text=True)
                    if header == "Review Decision":
                        self._style_review_decision(cell)

    def _style_review_decision(self, cell):
        decision = AdvisoryRelevanceModel.normalize_decision(cell.value)
        fill_colors = {
            "Pending": "FFF0BA",
            "Selected": "D1E7DD",
            "Rejected": "F8D7DA",
        }
        cell.fill = PatternFill(
            fill_type="solid",
            fgColor=fill_colors.get(decision, "FFFFFF"),
        )
        cell.font = Font(name="Calibri", size=10, bold=True)

    def _apply_relevance_model(self, ws, columns):
        row_records = [
            (row_idx, self._summary_record_from_row(ws, row_idx))
            for row_idx in range(2, ws.max_row + 1)
            if ws.cell(row=row_idx, column=columns.get("Advisory Heading", 1)).value
        ]
        model = AdvisoryRelevanceModel()
        counts = model.fit(record for _, record in row_records)
        for row_idx, record in row_records:
            decision = AdvisoryRelevanceModel.normalize_decision(record.get("review_decision"))
            if decision in {"Selected", "Rejected"}:
                continue
            score = model.predict(record)
            suggestion = "Collecting labels"
            score_value = ""
            if score is not None:
                score_value = round(score * 100, 1)
                suggestion = (
                    "Likely relevant" if score >= 0.7
                    else "Likely not relevant" if score <= 0.3
                    else "Needs review"
                )
            ws.cell(row=row_idx, column=columns["Model Suggestion"], value=suggestion)
            ws.cell(row=row_idx, column=columns["Relevance Score"], value=score_value)
        return model, counts

    def _set_relevance_suggestion(self, model, advisory: Dict[str, Any]) -> None:
        score = model.predict(advisory)
        if score is None:
            advisory.setdefault("model_suggestion", "Collecting labels")
            advisory.setdefault("relevance_score", "")
            return
        advisory["relevance_score"] = round(score * 100, 1)
        advisory["model_suggestion"] = (
            "Likely relevant" if score >= 0.7
            else "Likely not relevant" if score <= 0.3
            else "Needs review"
        )

    def apply_relevance_suggestions(
        self,
        advisories: List[Dict[str, Any]],
        training_records: List[Dict[str, Any]],
    ) -> None:
        model = AdvisoryRelevanceModel()
        model.fit(training_records)
        for advisory in advisories:
            self._set_relevance_suggestion(model, advisory)

    @staticmethod
    def _other_sources_display(adv: Dict[str, Any]) -> str:
        references = adv.get("source_references")
        if not isinstance(references, list):
            return ""
        primary_link = str(adv.get("link") or "").strip().casefold()
        others = list(references)
        if primary_link:
            primary_index = next(
                (
                    index
                    for index, reference in enumerate(others)
                    if isinstance(reference, dict)
                    and str(reference.get("link") or "").strip().casefold() == primary_link
                ),
                None,
            )
            if primary_index is not None:
                others.pop(primary_index)
        elif len(others) > 1:
            others = others[1:]
        other_sources = []
        for reference in others:
            if not isinstance(reference, dict):
                continue
            source_name = str(reference.get("source_name") or "Source").strip()
            link = str(reference.get("link") or "").strip()
            title = str(reference.get("title") or "").strip()
            detail = f"{source_name}: {link}" if link else source_name
            if title and title.casefold() != str(adv.get("advisory_heading") or "").casefold():
                detail = f"{detail} ({title})"
            if detail not in other_sources:
                other_sources.append(detail)
        return "\n".join(other_sources)

    def _advisory_impact_display(self, adv: Dict[str, Any]) -> str:
        impact = adv.get("impact_summary") or adv.get("summary", "")
        had_impact = bool(str(impact or "").strip())
        heading = adv.get("advisory_heading") or adv.get("title", "")
        source_text = self._clean_page_script_noise(
            f"{heading}\n{adv.get('source_content') or ''}"
        )
        impact = self._sanitize_report_claims(impact, source_text)
        if had_impact and not impact:
            return "No technical impact could be verified from the source content."
        return impact

    def _write_advisory_row(
        self,
        ws,
        row_idx: int,
        adv: Dict[str, Any],
        is_master: bool = False,
        preserve_review_decision: bool = False,
        preserve_report_link: bool = False,
    ):
        ws.row_dimensions[row_idx].height = 36

        source = adv.get("source_name", "Security Advisory")
        heading = adv.get("advisory_heading") or adv.get("title", "")
        link = adv.get("link", "")
        severity = str(adv.get("severity", "MEDIUM")).upper()
        cvss = adv.get("cvss_score", "N/A")
        pub_ts = adv.get("published_timestamp")
        if isinstance(pub_ts, (int, float)):
            pub_date_str = datetime.fromtimestamp(pub_ts).strftime("%Y-%m-%d %H:%M")
        else:
            pub_date_str = str(pub_ts or datetime.now().strftime("%Y-%m-%d %H:%M"))

        impact = self._advisory_impact_display(adv)
        matched_component = adv.get("matched_app_name", "")
        if adv.get("matched_vendor"):
            matched_component = f"{adv.get('matched_vendor')} - {matched_component}"

        category = str(adv.get("advisory_type", "Information")).strip().title()
        values = {
            "Source Name": source,
            "Advisory Type": category,
            "Advisory Heading": heading,
            "Link of Advisory": "View Advisory" if link.startswith(("http://", "https://")) else "N/A",
            "View Report": "Not generated",
            "View Detailed Report": "Not generated",
            "Other Sources": self._other_sources_display(adv),
            "Duplicate Check": adv.get("duplicate_note", ""),
            "Severity": severity,
            "CVSS": cvss,
            "Published Date & Time": pub_date_str,
            "Security Impact / Summary": impact,
            "Matched Application / Component": matched_component,
            "CVE Details": adv.get("cve_details", "NA"),
            "CVE Risk Score": adv.get("cve_risk_score", "NA") if category == "Patching" else "NA",
            "Attack Vector": adv.get("attack_vector", "NA"),
            "AV Type": adv.get("av_type", "NA"),
            "IOCs": self.defang_ioc_text(adv.get("iocs", "NA")),
        }
        columns = {
            str(cell.value).strip(): cell.column
            for cell in ws[1]
            if cell.value is not None
        }
        centered_headers = {
            "Link of Advisory", "Severity", "CVSS", "Published Date & Time",
            "CVE Risk Score", "Attack Vector", "AV Type", "View Detailed Report",
        }
        for header, value in values.items():
            if header == "View Report" and preserve_report_link:
                continue
            column = columns.get(header)
            if not column:
                continue
            cell = ws.cell(row=row_idx, column=column, value=value)
            cell.font = self.DATA_FONT
            cell.border = self.THIN_BORDER
            if header in centered_headers:
                cell.alignment = Alignment(horizontal="center", vertical="center")
            else:
                cell.alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)
            if header == "Severity":
                style = self.SEVERITY_STYLES.get(severity, self.SEVERITY_STYLES["UNASSESSED"])
                cell.fill = style["fill"]
                cell.font = style["font"]
        self._write_advisory_link(ws, row_idx, adv, columns)
        self._write_detailed_report_link(ws, row_idx, adv, columns)
        if not preserve_report_link:
            self._write_report_link(ws, row_idx, None, columns)
        self._write_review_data(
            ws,
            row_idx,
            adv,
            columns,
            preserve_review_decision=preserve_review_decision,
        )
        self._fit_summary_row(ws, row_idx)

    def _write_advisory_link(self, ws, row_idx: int, adv: Dict[str, Any], columns) -> bool:
        column = columns.get("Link of Advisory")
        if not column:
            return False
        references = adv.get("source_references")
        if not isinstance(references, list):
            references = []
        primary_link = str(adv.get("link") or "").strip()
        urls = []
        if primary_link.startswith(("http://", "https://")):
            urls.append(primary_link)
        for reference in references:
            if not isinstance(reference, dict):
                continue
            url = str(reference.get("link") or "").strip()
            if url.startswith(("http://", "https://")) and url not in urls:
                urls.append(url)
        cell = ws.cell(row=row_idx, column=column)
        cell.hyperlink = None
        if not urls:
            cell.value = str(adv.get("link") or "N/A")
            return False
        cell.value = "\n".join(urls)
        cell.hyperlink = urls[0]
        cell.font = Font(name="Calibri", size=10, color="0000EE", underline="single")
        cell.alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)
        return True

    def _write_report_link(self, ws, row_idx: int, report_ws, columns) -> None:
        column = columns.get("View Report")
        if not column:
            return
        cell = ws.cell(row=row_idx, column=column)
        cell.hyperlink = None
        if report_ws:
            escaped_title = report_ws.title.replace("'", "''")
            cell.value = "Open Report"
            cell.hyperlink = Hyperlink(
                ref=cell.coordinate,
                location=f"'{escaped_title}'!A1",
            )
            cell.fill = PatternFill(fill_type="solid", fgColor="1B365D")
            cell.font = Font(name="Calibri", size=10, bold=True, color="FFFFFF")
        else:
            cell.value = "Not generated"
            cell.fill = PatternFill(fill_type="solid", fgColor="E2E3E5")
            cell.font = Font(name="Calibri", size=10, color="666666")
        cell.border = self.THIN_BORDER
        cell.alignment = Alignment(horizontal="center", vertical="center")

    def _write_detailed_report_link(
        self,
        ws,
        row_idx: int,
        adv: Optional[Dict[str, Any]],
        columns,
    ) -> None:
        column = columns.get("View Detailed Report")
        if not column:
            return
        cell = ws.cell(row=row_idx, column=column)
        cell.hyperlink = None
        report_path = str((adv or {}).get("detailed_report_path") or "").strip()
        if report_path and Path(report_path).is_file():
            cell.value = "Open Word Report"
            cell.hyperlink = Path(report_path).resolve().as_uri()
            cell.fill = PatternFill(fill_type="solid", fgColor="1B365D")
            cell.font = Font(name="Calibri", size=10, bold=True, color="FFFFFF")
        else:
            cell.value = "Not generated"
            cell.fill = PatternFill(fill_type="solid", fgColor="E2E3E5")
            cell.font = Font(name="Calibri", size=10, color="666666")
        cell.border = self.THIN_BORDER
        cell.alignment = Alignment(horizontal="center", vertical="center")

    def _fit_summary_row(self, ws, row_idx: int):
        required_height = 36
        widths = {header: width for header, width, _ in self.COLUMNS}
        columns = {
            str(cell.value).strip(): cell.column
            for cell in ws[1]
            if cell.value is not None
        }
        for header, width in widths.items():
            column = columns.get(header)
            if not column:
                continue
            value = ws.cell(row=row_idx, column=column).value
            if value in (None, ""):
                continue
            lines = str(value).splitlines() or [""]
            wrapped_lines = sum(max(1, (len(line) + max(1, int(width * 1.1)) - 1) // max(1, int(width * 1.1))) for line in lines)
            required_height = max(required_height, wrapped_lines * 13 + 6)
        ws.row_dimensions[row_idx].height = min(required_height, 409.5)

    def _fit_reference_document_rows(self, ws):
        merged_ranges = list(ws.merged_cells.ranges)
        for row in ws.iter_rows():
            for cell in row:
                if cell.value in (None, "") or not isinstance(cell.value, str):
                    continue
                alignment = copy(cell.alignment)
                alignment.vertical = "top"
                alignment.wrap_text = True
                alignment.shrink_to_fit = False
                cell.alignment = alignment
                merged = next((item for item in merged_ranges if cell.coordinate in item), None)
                if merged:
                    min_col, min_row, max_col, max_row = merged.bounds
                else:
                    min_col = max_col = cell.column
                    min_row = max_row = cell.row
                total_width = sum(
                    ws.column_dimensions[get_column_letter(column)].width or 8.43
                    for column in range(min_col, max_col + 1)
                )
                chars_per_line = max(1, int(total_width * 1.1))
                line_count = sum(
                    max(1, (len(line) + chars_per_line - 1) // chars_per_line)
                    for line in cell.value.splitlines()
                )
                font_size = cell.font.sz or 11
                required_height = min(409.5, line_count * font_size * 1.35 + 6)
                existing_height = sum(
                    ws.row_dimensions[row_idx].height or 15
                    for row_idx in range(min_row, max_row + 1)
                )
                if required_height > existing_height:
                    extra_height = (required_height - existing_height) / (max_row - min_row + 1)
                    for row_idx in range(min_row, max_row + 1):
                        current_height = ws.row_dimensions[row_idx].height or 15
                        ws.row_dimensions[row_idx].height = min(409.5, current_height + extra_height)

    def _make_doc_sheet_name(
        self,
        index: int,
        heading: str,
        existing_names=None,
    ) -> str:
        safe = re.sub(r'[\[\]:*?/\\]+', ' ', str(heading or ""))
        safe = re.sub(r'\s+', ' ', safe).strip(" '")
        base = f"Report - {safe or f'Advisory {index}'}"[:31].rstrip()
        existing = {str(name).casefold() for name in (existing_names or [])}
        candidate = base
        suffix_number = 2
        while candidate.casefold() in existing:
            suffix = f" ({suffix_number})"
            candidate = f"{base[:31 - len(suffix)].rstrip()}{suffix}"
            suffix_number += 1
        return candidate

    def _advisory_document_sheets(self, wb, summary_ws):
        columns = {
            str(cell.value).strip(): cell.column
            for cell in summary_ws[1]
            if cell.value is not None
        }
        heading_column = columns.get("Advisory Heading")
        headings = {
            str(summary_ws.cell(row_idx, heading_column).value or "").strip().casefold()
            for row_idx in range(2, summary_ws.max_row + 1)
            if summary_ws.cell(row_idx, heading_column).value
        } if heading_column else set()
        return [
            worksheet for worksheet in wb.worksheets
            if (
                worksheet.title.startswith(("Advisory Document ", "Report - "))
                or re.match(r"^Advisory_\d+", worksheet.title)
                or (
                    worksheet.title not in {"Summary", "Learning Tracker"}
                    and str(worksheet["A2"].value or "").strip().casefold() in headings
                )
            )
        ]

    def _render_advisory_document(self, ws, adv: Dict[str, Any], index: int):
        ws.title = self._make_doc_sheet_name(index, adv.get("advisory_heading", ""))
        ws.sheet_view.showGridLines = False
        ws.freeze_panes = "A2"
        ws.column_dimensions['A'].width = 26
        ws.column_dimensions['B'].width = 95

        title = adv.get("advisory_heading") or adv.get("title", "")
        ws.merge_cells("A1:B1")
        ws["A1"] = "Advisory Document" 
        ws["A1"].font = Font(name="Calibri", size=16, bold=True, color="1B365D")

        template = [
            ("Advisory Type", adv.get("advisory_type", "Information")),
            ("Title", title),
            ("Source", adv.get("source_name", "Security Advisory")),
            ("Published Date", datetime.fromtimestamp(adv.get("published_timestamp", datetime.now().timestamp())).strftime("%Y-%m-%d %H:%M")),
            ("Severity", str(adv.get("severity", "MEDIUM")).upper()),
            ("CVSS", str(adv.get("cvss_score", "N/A"))),
            ("Matched Application", adv.get("matched_app_name", "")),
            ("CVE Details", adv.get("cve_details", "NA")),
            ("CVE Risk Score", adv.get("cve_risk_score", "NA")),
            ("Attack Vector", adv.get("attack_vector", "NA")),
            ("AV Type", adv.get("av_type", "NA")),
            ("IOCs", self.defang_ioc_text(adv.get("iocs", "NA"))),
        ]

        for row_idx, (label, value) in enumerate(template, start=3):
            ws.cell(row=row_idx, column=1, value=label)
            ws.cell(row=row_idx, column=1).font = self.BOLD_FONT
            ws.cell(row=row_idx, column=1).fill = PatternFill("solid", fgColor="EAF2FF")
            ws.cell(row=row_idx, column=2, value=value)
            ws.cell(row=row_idx, column=2).alignment = Alignment(wrap_text=True, vertical="top")
            ws.cell(row=row_idx, column=2).border = self.THIN_BORDER
            ws.cell(row=row_idx, column=1).border = self.THIN_BORDER

        ws.cell(row=len(template) + 5, column=1, value="Security Impact / Summary")
        ws.cell(row=len(template) + 5, column=1).font = self.BOLD_FONT
        ws.cell(row=len(template) + 5, column=1).fill = PatternFill("solid", fgColor="EAF2FF")
        ws.cell(row=len(template) + 5, column=2, value=adv.get("impact_summary") or "No summary provided.")
        ws.cell(row=len(template) + 5, column=2).alignment = Alignment(wrap_text=True, vertical="top")
        ws.cell(row=len(template) + 5, column=2).border = self.THIN_BORDER
        ws.cell(row=len(template) + 5, column=1).border = self.THIN_BORDER

    def _copy_reference_worksheet(self, source_ws, target_wb, title: Optional[str] = None):
        target_ws = target_wb.create_sheet(title=title or source_ws.title)
        for merged_range in source_ws.merged_cells.ranges:
            target_ws.merge_cells(str(merged_range))

        for row in source_ws.iter_rows():
            for source_cell in row:
                target_cell = target_ws.cell(source_cell.row, source_cell.column)
                if source_cell.value is not None:
                    target_cell.value = source_cell.value
                if source_cell.has_style:
                    target_cell.font = copy(source_cell.font)
                    target_cell.fill = copy(source_cell.fill)
                    target_cell.border = copy(source_cell.border)
                    target_cell.alignment = copy(source_cell.alignment)
                    target_cell.number_format = source_cell.number_format
                    target_cell.protection = copy(source_cell.protection)
                if source_cell.hyperlink:
                    target_cell._hyperlink = copy(source_cell.hyperlink)
                if source_cell.comment:
                    target_cell.comment = copy(source_cell.comment)

        for key, dimension in source_ws.column_dimensions.items():
            target_dimension = target_ws.column_dimensions[key]
            target_dimension.width = dimension.width
            target_dimension.hidden = dimension.hidden
            target_dimension.bestFit = dimension.bestFit
            target_dimension.outlineLevel = dimension.outlineLevel
            target_dimension.collapsed = dimension.collapsed
        for key, dimension in source_ws.row_dimensions.items():
            target_dimension = target_ws.row_dimensions[key]
            target_dimension.height = dimension.height
            target_dimension.hidden = dimension.hidden
            target_dimension.outlineLevel = dimension.outlineLevel
            target_dimension.collapsed = dimension.collapsed

        target_ws.sheet_view.showGridLines = source_ws.sheet_view.showGridLines
        target_ws.freeze_panes = source_ws.freeze_panes
        target_ws.sheet_properties = copy(source_ws.sheet_properties)
        target_ws.page_margins = copy(source_ws.page_margins)
        target_ws.page_setup = copy(source_ws.page_setup)
        target_ws.print_options = copy(source_ws.print_options)
        return target_ws

    def _summary_record_from_row(self, ws, row_idx: int) -> Dict[str, Any]:
        columns = {
            str(cell.value).strip(): cell.column
            for cell in ws[1]
            if cell.value is not None
        }

        def value(name: str, default: str = "NA"):
            column = columns.get(name)
            if not column:
                return default
            cell_value = ws.cell(row=row_idx, column=column).value
            return cell_value if cell_value not in (None, "") else default

        link_column = columns.get("Link of Advisory")
        link = ""
        if link_column:
            link_cell = ws.cell(row=row_idx, column=link_column)
            if link_cell.hyperlink:
                link = link_cell.hyperlink.target
            else:
                links = [
                    line.strip()
                    for line in str(link_cell.value or "").splitlines()
                    if line.strip().startswith(("http://", "https://"))
                ]
                link = links[0] if links else str(link_cell.value or "")

        category = str(value("Advisory Type", "Information")).strip().title()
        if category not in {"Actionable", "Patching", "Information"}:
            category = "Information"

        metric_columns = sorted(
            (
                (0 if header == "CVE Metrics JSON" else int(header.rsplit(" ", 1)[1]) - 1, column)
                for header, column in columns.items()
                if header == "CVE Metrics JSON" or header.startswith("CVE Metrics JSON Part ")
            ),
            key=lambda item: item[0],
        )
        metrics_value = "".join(
            str(ws.cell(row=row_idx, column=column).value or "")
            for _, column in metric_columns
        )
        try:
            cve_metrics = json.loads(metrics_value) if metrics_value else {}
        except (TypeError, ValueError):
            cve_metrics = self._recover_cve_metrics(metrics_value)
            print(
                f"[Advisories] CVE metrics cache is truncated or invalid in summary "
                f"row {row_idx}; recovered {len(cve_metrics)} entr"
                f"{'y' if len(cve_metrics) == 1 else 'ies'}."
            )
        if not isinstance(cve_metrics, dict):
            raise ValueError(f"CVE Metrics JSON in summary row {row_idx} must be an object.")
        reference_columns = sorted(
            (
                (0 if header == "Source References" else int(header.rsplit(" ", 1)[1]) - 1, column)
                for header, column in columns.items()
                if header == "Source References" or header.startswith("Source References Part ")
            ),
            key=lambda item: item[0],
        )
        source_references_raw = "".join(
            str(ws.cell(row=row_idx, column=column).value or "")
            for _, column in reference_columns
        ) or "[]"
        try:
            source_references = json.loads(source_references_raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"Source References JSON in summary row {row_idx} is invalid."
            ) from exc
        if not isinstance(source_references, list) or any(
            not isinstance(reference, dict) for reference in source_references
        ):
            raise ValueError(
                f"Source References JSON in summary row {row_idx} must be a list of objects."
            )

        def json_list(name: str, default: List[Any]) -> List[Any]:
            raw = str(value(name, "") or "").strip()
            if not raw:
                return default
            try:
                parsed = json.loads(raw)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{name} JSON in summary row {row_idx} is invalid.") from exc
            if not isinstance(parsed, list):
                raise ValueError(f"{name} JSON in summary row {row_idx} must be a list.")
            return parsed

        return {
            "recorded_date": value("Recorded Date", ""),
            "source_name": value("Source Name", "Security Advisory"),
            "advisory_heading": value("Advisory Heading", ""),
            "link": link,
            "severity": value("Severity", "MEDIUM"),
            "cvss_score": value("CVSS", "NA"),
            "published_timestamp": value("Published Date & Time", "NA"),
            "impact_summary": value("Security Impact / Summary", "NA"),
            "matched_app_name": value("Matched Application / Component", "NA"),
            "advisory_type": category,
            "cve_details": value("CVE Details", "NA"),
            "cve_risk_score": value("CVE Risk Score", "NA") if category == "Patching" else "NA",
            "attack_vector": value("Attack Vector", "NA"),
            "av_type": value("AV Type", "NA"),
            "iocs": self.defang_ioc_text(value("IOCs", "NA")),
            "review_decision": value("Review Decision", "Pending"),
            "model_suggestion": value("Model Suggestion", "Collecting labels"),
            "relevance_score": value("Relevance Score", ""),
            "id": value("Article ID", ""),
            "advisory_id": value("Advisory ID", ""),
            "detailed_report_path": value("Detailed Report Path", ""),
            "member_article_ids": json_list(
                "Member Article IDs",
                [value("Article ID", "")] if value("Article ID", "") else [],
            ),
            "duplicate_candidate_ids": json_list("Duplicate Candidate IDs", []),
            "summary_conflicts": json_list("Summary Conflicts", []),
            "delivery_status": value("Delivery Status", ""),
            "update_summary": value("Update Summary", ""),
            "content_hash": value("Content Hash", ""),
            "initial_triage": value("Initial Triage", "Accepted"),
            "triage_note": value("Triage Note", ""),
            "recommendation": value("Recommendation", ""),
            "affected_products": value("Affected Products", ""),
            "affected_versions": value("Affected Versions", ""),
            "report_summary": value("Report Summary", ""),
            "source_content": value("Source Content", ""),
            "cve_metrics": cve_metrics,
            "matched_vendor": value("Matched Vendor", ""),
            "source_references": source_references,
            "duplicate_note": value("Duplicate Check", ""),
        }

    def _recover_cve_metrics(self, raw: str) -> Dict[str, Any]:
        decoder = json.JSONDecoder()
        position = 0
        while position < len(raw) and raw[position].isspace():
            position += 1
        if position >= len(raw) or raw[position] != "{":
            return {}
        position += 1
        recovered = {}
        while position < len(raw):
            while position < len(raw) and (raw[position].isspace() or raw[position] == ","):
                position += 1
            if position >= len(raw) or raw[position] == "}":
                break
            try:
                key, position = decoder.raw_decode(raw, position)
                while position < len(raw) and raw[position].isspace():
                    position += 1
                if not isinstance(key, str) or position >= len(raw) or raw[position] != ":":
                    break
                value, position = decoder.raw_decode(raw, position + 1)
            except json.JSONDecodeError:
                break
            if isinstance(value, dict):
                recovered[key] = value
            else:
                break
        return recovered

    def _infer_threat_classification(self, record: Dict[str, Any]) -> str:
        text = f"{record.get('advisory_heading', '')} {record.get('impact_summary', '')}".lower()
        trusted_source = self._clean_page_script_noise(
            f"{record.get('advisory_heading', '')}\n{record.get('source_content') or ''}"
        )
        classifications = [
            ("Remote Code Execution (RCE)", r"remote code execution|\brce\b"),
            ("Denial-of-Service (DoS)", r"denial.of.service|\bdos\b"),
            ("Privilege Escalation", r"privilege escalation"),
            ("Authentication Bypass", r"authentication bypass|auth bypass"),
            ("Information Disclosure", r"information disclosure|data leakage"),
            ("Injection Vulnerability", r"command injection|sql injection|\bsqli\b"),
            ("Supply Chain Compromise", r"supply.chain"),
            ("Ransomware", r"ransomware"),
            ("Malware", r"malware|infostealer|backdoor"),
        ]
        matches = [
            label
            for label, pattern in classifications
            if re.search(pattern, text) and re.search(pattern, trusted_source, re.IGNORECASE)
        ]
        classification = " / ".join(matches) if matches else record.get("advisory_type", "Information")
        impact_detail = str(record.get("impact_summary") or "").strip()
        impact_detail = self._sanitize_report_claims(impact_detail, trusted_source)
        impact_detail = re.sub(r"^\[[^\]]+\]\s*", "", impact_detail)
        if impact_detail and impact_detail.casefold() not in classification.casefold():
            return f"{classification}: {impact_detail}"
        return classification

    def _build_report_summary(self, record: Dict[str, Any]) -> str:
        sentences = []
        seen = set()
        summary_cues = re.compile(
            r"\b(?:vulnerab\w*|flaw|weakness|exploit\w*|attacker|attack\w*|"
            r"unauth\w*|remote code execution|\brce\b|privilege escalation|"
            r"denial of service|authentication bypass|injection|disclos\w*|"
            r"compromise\w*|bypass|memory corruption|code execution|"
            r"versions?|releases?|cve-\d{4}-\d+|cvss|patch|"
            r"mitigat\w*|workaround)\b",
            re.IGNORECASE,
        )
        generic_guidance = re.compile(
            r"\b(?:consult|review|see)\b.*\b(?:vendor|advisory|patch guidance)\b",
            re.IGNORECASE,
        )

        trusted_source = self._clean_page_script_noise(
            f"{record.get('advisory_heading', '')}\n{record.get('source_content') or ''}"
        )

        def add_sentences(text: Any, require_security_context: bool = True) -> None:
            for sentence in re.split(
                r"\n+|(?<=[.!?])\s+(?=[A-Za-z])",
                str(text or ""),
            ):
                value = re.sub(r"^(?:[-*•]|\d+[.)])\s*", "", sentence).strip()
                if (
                    len(value) < 25
                    or value.casefold() in seen
                    or generic_guidance.search(value)
                    or PAGE_SCRIPT_NOISE.search(value)
                    or any(
                        pattern.search(value) and not pattern.search(trusted_source)
                        for pattern in REPORT_IMPACT_CLAIMS
                    )
                    or (
                        require_security_context
                        and not summary_cues.search(value)
                    )
                ):
                    continue
                sentences.append(value)
                seen.add(value.casefold())
                if len(sentences) == 4:
                    return

        add_sentences(record.get("report_summary"))
        add_sentences(record.get("impact_summary"))
        if len(sentences) < 3:
            add_sentences(record.get("source_content"))

        if len(sentences) < 4:
            product_details = self._affected_products_text(record)
            stated_details = [
                line for line in product_details.splitlines()
                if line.startswith(("Affected products:", "Affected versions:"))
            ]
            if stated_details:
                add_sentences(
                    ". ".join(stated_details) + ".",
                    require_security_context=False,
                )

        if len(sentences) < 4:
            recommendation = str(record.get("recommendation") or "").strip()
            if (
                recommendation
                and recommendation.casefold() not in {
                    "na",
                    "n/a",
                    "none",
                    self.RECOMMENDATION_FALLBACK.casefold(),
                }
                and re.search(
                    r"\b(?:upgrade|update|install|apply|patch|mitigate|"
                    r"workaround|disable|fix|contact)\b",
                    recommendation,
                    re.IGNORECASE,
                )
            ):
                add_sentences(recommendation, require_security_context=False)

        if len(sentences) < 3:
            severity = str(record.get("severity") or "").strip()
            cvss = str(record.get("cvss_score") or "").strip()
            if severity and severity.casefold() not in {"na", "n/a", "unknown"}:
                cvss = re.sub(r"\s*\(base\)\s*$", "", cvss, flags=re.IGNORECASE)
                severity_line = (
                    f"The issue is rated {severity} (CVSS {cvss})."
                    if cvss and cvss.casefold() not in {"na", "n/a", "unknown"}
                    else f"The issue is rated {severity}."
                )
                add_sentences(severity_line, require_security_context=False)

        summary = "\n".join(sentences[:4])
        summary = self._mask_report_indicators(record, summary)
        words = re.findall(r"\S+", str(summary or "").strip())
        if len(words) > 500:
            summary = " ".join(words[:500]).rstrip(" \t\r\n,.;:-") + "."
        return summary

    @staticmethod
    def _clean_page_script_noise(text: Any) -> str:
        value = str(text or "")
        value = re.sub(
            r"<(script|style|noscript|template)\b[^>]*>.*?</\1\s*>",
            " ",
            value,
            flags=re.IGNORECASE | re.DOTALL,
        )
        return re.sub(
            r"(?im)^.*(?:window\.(?:ytcfg|yterr|unhandledErrorMessages|unhandledErrorCount)\b"
            r"|function\s*\(\s*\)\s*\{\s*window\.).*$",
            "",
            value,
        ).strip()

    @staticmethod
    def _sanitize_report_claims(text: Any, trusted_source: str) -> str:
        sentences = []
        for sentence in re.split(r"\n+|(?<=[.!?])\s+", str(text or "")):
            sentence = sentence.strip()
            if not sentence or PAGE_SCRIPT_NOISE.search(sentence):
                continue
            if any(
                pattern.search(sentence) and not pattern.search(trusted_source)
                for pattern in REPORT_IMPACT_CLAIMS
            ):
                continue
            sentences.append(sentence)
        return "\n".join(sentences)

    def _format_as_bullets(self, text: Any, max_points: Optional[int] = 12) -> str:
        normalized = re.sub(r"[ \t]+", " ", str(text or "")).strip()
        if not normalized:
            return "Not available"
        parts = re.split(
            r"\n+|(?<!\d)(?<=[.!?])\s+(?=[A-Za-z])|(?<=;)\s+",
            normalized,
        )
        points = []
        seen = set()
        for part in parts:
            point = re.sub(r"^(?:[-*•]|\d+[.)])\s*", "", part).strip().rstrip(" ;")
            if len(point) < 3 or point.casefold() in seen:
                continue
            points.append(point)
            seen.add(point.casefold())
        if max_points is not None and len(points) > max_points:
            points = points[:max_points]
            points.append(
                f"Additional details are available at the reference link "
                f"({len(parts) - max_points} more points omitted here)."
            )
        return "\n".join(f"• {point}" for point in points) or f"• {normalized}"

    def _render_reference_document(self, reference_ws, wb, record: Dict[str, Any], index: int):
        sheet_name = self._make_doc_sheet_name(index, record.get("advisory_heading", ""), wb.sheetnames)
        worksheet = self._copy_reference_worksheet(reference_ws, wb, sheet_name)
        worksheet.sheet_view.showGridLines = False
        worksheet["A2"] = record.get("advisory_heading", "")

        category = record.get("advisory_type", "Information")
        summary = self._build_report_summary(record)
        details = self._format_as_bullets(
            self._mask_report_indicators(
                record,
                str(record.get("source_content") or record.get("impact_summary") or "NA")[:32000],
            ),
            max_points=12,
        )
        classification = self._mask_report_indicators(
            record,
            self._infer_threat_classification(record),
        )
        affected_products = self._format_as_bullets(
            self._mask_report_indicators(
                record,
                self._affected_products_text(record),
            ),
            max_points=None,
        )
        recommendation = self._format_as_bullets(
            self._mask_report_indicators(
                record,
                self._ensure_recommendation(record.get("recommendation")),
            ),
            max_points=6,
        )
        reference_link = record.get("link", "NA")

        if category == "Actionable":
            worksheet["B3"] = summary
            worksheet["B4"] = classification
            worksheet["B6"] = record.get("attack_vector", "NA")
            worksheet["B8"] = record.get("severity", "NA")
            worksheet["B10"] = details
            worksheet["B12"] = summary
            worksheet["B14"] = self._format_as_bullets(
                self._mask_report_indicators(record, record.get("toolkit", "NA")),
                max_points=8,
            )
            worksheet["B16"] = affected_products
            worksheet["B19"] = self._format_as_bullets(
                self.defang_ioc_text(record.get("iocs", "NA")),
                max_points=20,
            )
            worksheet["B20"] = recommendation
            worksheet["B21"] = reference_link
            self._fit_reference_document_rows(worksheet)
            return worksheet

        if category == "Patching":
            worksheet["B3"] = summary
            worksheet["B4"] = classification
            cvss = record.get("cvss_score", "NA")
            worksheet["B6"] = f"{record.get('severity', 'NA')} (CVSS {cvss})" if cvss not in ("", "NA") else record.get("severity", "NA")
            worksheet["B7"] = affected_products
            worksheet["B8"] = details

            cve_ids = self.extract_cves(str(record.get("cve_details", "")))
            if not cve_ids:
                cve_ids = self.extract_cves(details)
            extra_rows = max(0, len(cve_ids) - 3)
            if extra_rows:
                for merged_range in ("A9:A12", "F9:F12", "B13:E13", "B14:E14"):
                    if merged_range in {str(item) for item in worksheet.merged_cells.ranges}:
                        worksheet.unmerge_cells(merged_range)
                worksheet.insert_rows(13, extra_rows)
                for row_idx in range(13, 13 + extra_rows):
                    worksheet.row_dimensions[row_idx].height = worksheet.row_dimensions[12].height
                    for column in range(1, 7):
                        destination = worksheet.cell(row=row_idx, column=column)
                        source = worksheet.cell(row=12, column=column)
                        if source.has_style:
                            destination._style = copy(source._style)
                table_end = 9 + len(cve_ids)
                worksheet.merge_cells(f"A9:A{table_end}")
                worksheet.merge_cells(f"F9:F{table_end}")
                recommendation_row = 13 + extra_rows
                reference_row = recommendation_row + 1
                worksheet.merge_cells(f"B{recommendation_row}:E{recommendation_row}")
                worksheet.merge_cells(f"B{reference_row}:E{reference_row}")
            else:
                recommendation_row, reference_row = 13, 14

            for offset in range(3 + extra_rows):
                row_idx = 10 + offset
                for column in range(2, 6):
                    worksheet.cell(row=row_idx, column=column).value = None
                if offset < len(cve_ids):
                    worksheet.cell(row=row_idx, column=2, value=cve_ids[offset])
                    metrics = record.get("cve_metrics", {}).get(cve_ids[offset], {})
                    worksheet.cell(
                        row=row_idx,
                        column=3,
                        value=self._display_value(
                            metrics.get("cvss_score", record.get("cvss_score", "") if offset == 0 else "")
                        ),
                    )
                    worksheet.cell(
                        row=row_idx,
                        column=4,
                        value=self._display_value(
                            metrics.get("av_type", record.get("av_type", "") if offset == 0 else "")
                        ),
                    )
                    worksheet.cell(
                        row=row_idx,
                        column=5,
                        value=self._display_value(
                            metrics.get("risk_score", record.get("cve_risk_score", "") if offset == 0 else "")
                        ),
                    )
            worksheet.cell(row=recommendation_row, column=2, value=recommendation)
            worksheet.cell(row=reference_row, column=2, value=reference_link)
            self._fit_reference_document_rows(worksheet)
            return worksheet

        worksheet["B3"] = summary
        worksheet["B4"] = classification
        worksheet["B6"] = "NA"
        worksheet["B7"] = record.get("severity", "NA")
        worksheet["B8"] = self._format_as_bullets(
            f"{self._affected_products_text(record)}\n"
            f"{self._mask_report_indicators(record, record.get('source_content') or record.get('impact_summary') or 'NA')}",
            max_points=12,
        )
        worksheet["B9"] = recommendation
        worksheet["B10"] = reference_link
        self._fit_reference_document_rows(worksheet)
        return worksheet

    def _rebuild_advisory_documents(
        self,
        wb,
        summary_ws,
        advisories: List[Dict[str, Any]],
        refresh_enrichment: bool = False,
        generate_documents: bool = False,
        update_learning_tracker: bool = False,
    ):
        existing_document_sheets = self._advisory_document_sheets(wb, summary_ws)
        summary_columns = self._ensure_review_columns(summary_ws)
        if update_learning_tracker:
            model, _ = self._apply_relevance_model(summary_ws, summary_columns)
            model.update_tracker_sheet(wb)
        if not generate_documents:
            return len(existing_document_sheets)

        reference_path = Path(__file__).resolve().parent.parent / "Advisory Formats.xlsx"
        if not reference_path.exists():
            raise FileNotFoundError(f"Advisory format reference workbook not found: {reference_path}")
        reference_wb = openpyxl.load_workbook(reference_path)
        template_names = {
            "Actionable": "Actionable7",
            "Patching": "Patching4",
            "Information": "Information1",
        }
        for category, preferred_name in template_names.items():
            if preferred_name not in reference_wb.sheetnames:
                template_names[category] = next(
                    (name for name in reference_wb.sheetnames if name.startswith(category)), None
                )
            if not template_names[category]:
                reference_wb.close()
                raise ValueError(f"No {category} example sheet exists in {reference_path.name}")

        existing_document_data = {}
        for worksheet in existing_document_sheets:
            heading = str(worksheet["A2"].value or "").strip().casefold()
            if not heading:
                continue
            is_patching = str(worksheet["B9"].value or "").strip().casefold() == "cve id"
            is_actionable = str(worksheet["A20"].value or "").strip().casefold() == "recommendation"
            source_content = worksheet["B8"].value
            if is_actionable:
                source_content = worksheet["B10"].value
            if is_patching:
                cve_metrics = {}
                for row_idx in range(10, worksheet.max_row + 1):
                    cve_values = self.extract_cves(str(worksheet.cell(row=row_idx, column=2).value or ""))
                    if not cve_values:
                        continue
                    cve_id = cve_values[0]
                    cve_metrics[cve_id] = {
                        "cvss_score": str(worksheet.cell(row=row_idx, column=3).value or ""),
                        "av_type": str(worksheet.cell(row=row_idx, column=4).value or ""),
                        "risk_score": str(worksheet.cell(row=row_idx, column=5).value or ""),
                    }
                cve_count = len(cve_metrics)
                recommendation_row = 13 + max(0, cve_count - 3)
            else:
                cve_metrics = {}
                recommendation_row = 20 if worksheet["A20"].value == "Recommendation" else 9
            existing_document_data[heading] = {
                "source_content": str(source_content or ""),
                "recommendation": str(worksheet.cell(row=recommendation_row, column=2).value or ""),
                "cve_metrics": cve_metrics,
            }

        for worksheet in existing_document_sheets:
            wb.remove(worksheet)

        summary_columns = {
            str(cell.value).strip(): cell.column
            for cell in summary_ws[1]
            if cell.value is not None
        }
        heading_column = summary_columns.get("Advisory Heading")
        if heading_column:
            seen_headings = set()
            for row_idx in range(summary_ws.max_row, 1, -1):
                heading = str(summary_ws.cell(row=row_idx, column=heading_column).value or "").strip()
                heading_key = heading.casefold()
                if not heading or heading_key == "advisory heading" or heading_key in seen_headings:
                    summary_ws.delete_rows(row_idx, 1)
                    continue
                seen_headings.add(heading_key)

        report_column = summary_columns.get("View Report")
        if report_column:
            for row_idx in range(2, summary_ws.max_row + 1):
                if summary_ws.cell(row=row_idx, column=heading_column).value:
                    self._write_report_link(summary_ws, row_idx, None, summary_columns)

        type_column = summary_columns.get("Advisory Type")
        risk_column = summary_columns.get("CVE Risk Score")
        if type_column and risk_column:
            for row_idx in range(2, summary_ws.max_row + 1):
                category = str(summary_ws.cell(row=row_idx, column=type_column).value or "").strip().title()
                if category != "Patching":
                    summary_ws.cell(row=row_idx, column=risk_column, value="NA")

        supplied_records = {
            str(item.get("advisory_heading") or item.get("title", "")).strip().lower(): item
            for item in advisories
        }
        records = []
        missing_cves = []
        for row_idx in range(2, summary_ws.max_row + 1):
            record = self._summary_record_from_row(summary_ws, row_idx)
            if not record.get("advisory_heading"):
                continue
            existing = existing_document_data.get(str(record["advisory_heading"]).strip().casefold(), {})
            for key, value in existing.items():
                if key == "cve_metrics" and isinstance(value, dict):
                    record[key] = {**value, **record.get(key, {})}
                elif not record.get(key):
                    record[key] = value
            heading_key = str(record["advisory_heading"]).strip().lower()
            record.update(supplied_records.get(heading_key, {}))
            source_content = str(record.get("source_content") or "")
            recommendation = str(record.get("recommendation") or "")
            if source_content and not self._source_content_matches_record(record, source_content):
                source_content = ""
                recommendation = ""
            needs_recommendation = (
                not recommendation
                or recommendation.strip().upper() in {"NA", "N/A"}
                or recommendation.casefold() == self.RECOMMENDATION_FALLBACK.casefold()
            )
            if needs_recommendation:
                extracted = self.extract_recommendation(source_content)
                if extracted != "NA":
                    recommendation = extracted
            needs_recommendation = (
                not recommendation
                or recommendation.strip().upper() in {"NA", "N/A"}
                or recommendation.casefold() == self.RECOMMENDATION_FALLBACK.casefold()
            )
            cve_ids = self.extract_cves(str(record.get("cve_details", "")))
            review_decision = AdvisoryRelevanceModel.normalize_decision(
                record.get("review_decision")
            )
            report_eligible = review_decision == "Selected"
            needs_cve_metrics = any(
                any(
                    str(record.get("cve_metrics", {}).get(cve, {}).get(field, "")).strip().casefold()
                    in {"", "na", "n/a", "not available"}
                    for field in ("cvss_score", "av_type")
                )
                for cve in cve_ids
            )
            record["source_content"] = source_content
            record["recommendation"] = recommendation
            record.setdefault("cve_metrics", {})
            record["_refresh_cve_metrics"] = bool(
                refresh_enrichment or (report_eligible and needs_cve_metrics)
            )
            record["_refresh_source_content"] = bool(
                report_eligible and (refresh_enrichment or needs_recommendation)
            )
            record["_summary_row_idx"] = row_idx
            record["_needs_recommendation"] = needs_recommendation
            if cve_ids and report_eligible:
                if refresh_enrichment:
                    missing_cves.extend(cve_ids)
                elif needs_cve_metrics:
                    for cve in cve_ids:
                        metric = record["cve_metrics"].get(cve, {})
                        if any(
                            str(metric.get(field, "")).strip().casefold()
                            in {"", "na", "n/a", "not available"}
                            for field in ("cvss_score", "av_type")
                        ):
                            missing_cves.append(cve)
            records.append(record)

        self._nvd_cve_lookup_many(missing_cves)
        fetch_targets = [
            record for record in records
            if record.get("link")
            and AdvisoryRelevanceModel.normalize_decision(record.get("review_decision"))
            == "Selected"
            and record["_needs_recommendation"]
            and record["_refresh_source_content"]
        ]
        failed_before_fetch = self._source_fetch_failures
        rejected_source_content = 0
        if fetch_targets:
            with ThreadPoolExecutor(max_workers=8) as executor:
                fetched_content = list(executor.map(
                    lambda item: self._fetch_source_content(str(item["link"])),
                    fetch_targets,
                ))
            for record, fetched in zip(fetch_targets, fetched_content):
                if fetched:
                    if not self._source_content_matches_record(record, fetched):
                        rejected_source_content += 1
                        continue
                    record["source_content"] = "\n".join(
                        part for part in (record.get("source_content", ""), fetched) if part
                    )
                    extracted = self.extract_recommendation(record["source_content"])
                    if extracted != "NA":
                        record["recommendation"] = extracted
        if self.tenable_client:
            for record in records:
                if (
                    record["_needs_recommendation"]
                    and record["recommendation"] == self.RECOMMENDATION_FALLBACK
                ):
                    cve_ids = self.extract_cves(str(record.get("cve_details", "")))
                    tenable_recommendation = self._tenable_recommendation(cve_ids)
                    if tenable_recommendation:
                        record["recommendation"] = tenable_recommendation
        failed_fetches = self._source_fetch_failures - failed_before_fetch
        if failed_fetches:
            print(
                f"[Advisories] Source text unavailable for {failed_fetches} item(s); "
                "vendor links are retained in the reports."
            )
        if rejected_source_content:
            print(
                f"[Advisories] Rejected source text for {rejected_source_content} item(s) "
                "because it did not match the advisory."
            )

        documents = []
        document_index = 0
        for record in records:
            cve_ids = self.extract_cves(str(record.get("cve_details", "")))
            refresh_cve_metrics = record.pop("_refresh_cve_metrics", False)
            record.pop("_refresh_source_content", None)
            record.pop("_needs_recommendation", None)
            record["recommendation"] = self._ensure_recommendation(record.get("recommendation"))
            if cve_ids and refresh_cve_metrics:
                existing_metrics = record.get("cve_metrics", {})
                refreshed_metrics = self._build_cve_metrics(
                    cve_ids,
                    f"{record.get('advisory_heading', '')}\n{record.get('source_content', '')}",
                )
                for cve, metric in refreshed_metrics.items():
                    existing = existing_metrics.get(cve, {})
                    nvd_score = str(metric.get("nvd_score", "")).strip()
                    nvd_vector = str(metric.get("nvd_vector", "")).strip()
                    if nvd_score.casefold() not in {"", "na", "n/a", "not available"}:
                        existing["cvss_score"] = nvd_score
                        existing["risk_score"] = nvd_score
                    if nvd_vector.casefold() not in {"", "na", "n/a", "not available"}:
                        existing["attack_vector"] = nvd_vector
                        existing["av_type"] = metric.get("av_type", "Not available")
                    existing["nvd_score"] = metric.get("nvd_score", "NA")
                    existing["nvd_vector"] = metric.get("nvd_vector", "NA")
                    for field, value in metric.items():
                        if field in {"cvss_score", "risk_score", "attack_vector", "av_type"} and (
                            nvd_score.casefold() not in {"", "na", "n/a", "not available"}
                            or nvd_vector.casefold() not in {"", "na", "n/a", "not available"}
                        ):
                            continue
                        if str(existing.get(field, "")).strip().casefold() in {
                            "", "na", "n/a", "not available",
                        } and str(value).strip().casefold() not in {
                            "", "na", "n/a", "not available",
                        }:
                            existing[field] = value
                    existing_metrics[cve] = existing
                record["cve_metrics"] = existing_metrics
                first_metrics = existing_metrics.get(cve_ids[0], {})
                nvd_score = str(first_metrics.get("nvd_score", "")).strip()
                if nvd_score.casefold() not in {"", "na", "n/a", "not available"}:
                    record["cvss_score"] = nvd_score
                    record["cve_risk_score"] = nvd_score
                    record["attack_vector"] = first_metrics.get(
                        "nvd_vector", record.get("attack_vector", "Not available")
                    )
                    record["av_type"] = self.infer_attack_vector(record["attack_vector"])
                    row_idx = record.get("_summary_row_idx")
                    if row_idx:
                        for column_name, value in (
                            ("CVSS", nvd_score),
                            ("CVE Risk Score", nvd_score),
                            ("Attack Vector", record["attack_vector"]),
                            ("AV Type", record["av_type"]),
                        ):
                            column = summary_columns.get(column_name)
                            if column:
                                summary_ws.cell(row=row_idx, column=column, value=value)
            summary_row_idx = record.get("_summary_row_idx")
            if summary_row_idx:
                self._write_review_data(summary_ws, summary_row_idx, record, summary_columns)
            if str(record.get("severity", "")).strip().upper() == "LOW":
                continue
            if AdvisoryRelevanceModel.normalize_decision(record.get("review_decision")) not in {
                "Selected",
            }:
                continue
            category = record.get("advisory_type", "Information")
            if category == "Information":
                continue
            if category not in template_names:
                category = "Information"
                record["advisory_type"] = category
            document_index += 1
            summary_row_idx = record.pop("_summary_row_idx", None)
            document = self._render_reference_document(
                reference_wb[template_names[category]], wb, record, document_index
            )
            if summary_row_idx:
                self._write_report_link(
                    summary_ws,
                    summary_row_idx,
                    document,
                    summary_columns,
                )
            documents.append(document)

        template_sheet_names = set(reference_wb.sheetnames)
        reference_wb.close()
        for sheet_name in template_sheet_names:
            if sheet_name in wb.sheetnames and wb[sheet_name] is not summary_ws:
                wb.remove(wb[sheet_name])
        document_ids = {id(sheet) for sheet in documents}
        other_sheets = [
            sheet for sheet in wb.worksheets
            if sheet is not summary_ws and id(sheet) not in document_ids
        ]
        wb._sheets = [summary_ws] + documents + other_sheets
        wb.active = 0
        return document_index

    def _ensure_summary_sheet(self, wb, sheet_name: str = "Summary"):
        if sheet_name in wb.sheetnames:
            return wb[sheet_name]
        return wb.active

    def export_daily(
        self,
        output_path: str,
        advisories: List[Dict[str, Any]],
        refresh_enrichment: bool = False,
        generate_documents: bool = False,
        replace_existing: bool = False,
        informational_only: bool = False,
        preserve_review_decisions: bool = True,
    ) -> str:
        daily_file = Path(output_path)
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Summary"
        self._render_headers(ws, [col[0] for col in self.COLUMNS])

        if daily_file.exists() and not replace_existing:
            existing_wb = self._load_existing_workbook(daily_file)
            if "Summary" in existing_wb.sheetnames:
                wb = existing_wb
                ws = wb["Summary"]
            else:
                ws = existing_wb.active
                ws.title = "Summary"
                self._render_headers(ws, [col[0] for col in self.COLUMNS])

        if informational_only:
            actionable = advisories
        else:
            informational = [
                adv for adv in advisories
                if str(adv.get("advisory_type", "")).strip().title() == "Information"
            ]
            actionable = [
                adv for adv in advisories
                if str(adv.get("advisory_type", "")).strip().title() != "Information"
            ]
            migration_columns = {
                str(cell.value).strip(): cell.column
                for cell in ws[1]
                if cell.value is not None
            }
            migration_heading = migration_columns.get("Advisory Heading")
            migration_type = migration_columns.get("Advisory Type")
            if migration_heading and migration_type:
                for row_idx in range(ws.max_row, 1, -1):
                    category = str(
                        ws.cell(row=row_idx, column=migration_type).value or ""
                    ).strip().title()
                    if category == "Information":
                        existing_informational = self._summary_record_from_row(ws, row_idx)
                        if existing_informational.get("advisory_heading"):
                            supplied_headings = {
                                str(item.get("advisory_heading") or item.get("title", "")).strip().casefold()
                                for item in informational
                            }
                            heading = str(
                                existing_informational.get("advisory_heading") or ""
                            ).strip().casefold()
                            if heading not in supplied_headings:
                                informational.append(existing_informational)
                        ws.delete_rows(row_idx, 1)

            if informational:
                if "Informational" in wb.sheetnames:
                    wb.remove(wb["Informational"])
                info_ws = wb.create_sheet("Informational")
                self._render_headers(info_ws, [col[0] for col in self.COLUMNS])
                info_columns = self._ensure_review_columns(info_ws)
                for adv_index, adv in enumerate(informational, start=2):
                    self._write_advisory_row(info_ws, adv_index, adv, is_master=False)
                    self._write_review_data(info_ws, adv_index, adv, info_columns)
                self._auto_fit_columns(info_ws)
                info_ws.freeze_panes = "A2"
            elif "Informational" in wb.sheetnames:
                wb.remove(wb["Informational"])

        self._ensure_summary_schema(ws)
        summary_columns = self._ensure_review_columns(ws)
        for header in self.REVIEW_COLUMNS + self.STORAGE_COLUMNS:
            column = summary_columns.get(header)
            if column:
                ws.column_dimensions[get_column_letter(column)].hidden = header != "Review Decision"
        heading_column = summary_columns.get("Advisory Heading")
        existing_keys = {
            str(ws.cell(row=row_idx, column=heading_column).value or "").strip().lower()
            for row_idx in range(2, ws.max_row + 1)
            if heading_column and ws.cell(row=row_idx, column=heading_column).value
        }
        existing_rows = {}
        article_id_column = summary_columns.get("Article ID")
        for row_idx in range(2, ws.max_row + 1):
            heading_key = str(ws.cell(row=row_idx, column=heading_column).value or "").strip().lower()
            if heading_key:
                existing_rows[heading_key] = row_idx
            article_id = (
                str(ws.cell(row_idx, article_id_column).value or "").strip()
                if article_id_column else ""
            )
            if article_id:
                existing_rows[f"id:{article_id}"] = row_idx

        start_row = ws.max_row + 1 if ws.max_row > 1 else 2
        added_count = 0
        for adv in actionable:
            heading_key = str(adv.get("advisory_heading") or adv.get("title", "")).strip().lower()
            article_id = str(adv.get("id") or "").strip()
            id_key = f"id:{article_id}"
            if heading_key in existing_keys or (article_id and id_key in existing_rows):
                row_idx = existing_rows.get(heading_key) or existing_rows.get(id_key)
                if row_idx:
                    self._write_advisory_row(
                        ws,
                        row_idx,
                        adv,
                        is_master=False,
                        preserve_review_decision=preserve_review_decisions,
                        preserve_report_link=True,
                    )
                    existing_rows[heading_key] = row_idx
                continue
            existing_keys.add(heading_key)
            self._write_advisory_row(ws, start_row + added_count, adv, is_master=False)
            added_count += 1

        document_count = self._rebuild_advisory_documents(
            wb,
            ws,
            advisories,
            refresh_enrichment=refresh_enrichment,
            generate_documents=generate_documents,
        )
        self._auto_fit_columns(ws)
        ws.freeze_panes = "A2"
        saved_file = self._safe_save(
            wb,
            daily_file,
            replace_existing=replace_existing,
        )
        return saved_file

    def append_to_master(
        self,
        master_path: str,
        advisories: List[Dict[str, Any]],
        refresh_enrichment: bool = False,
        generate_documents: bool = False,
        update_learning_tracker: bool = False,
        preserve_review_decisions: bool = True,
        replace_existing: bool = False,
        replace_recorded_date: Optional[date] = None,
    ) -> str:
        master_file = Path(master_path)
        master_columns = ["Recorded Date"] + [col[0] for col in self.COLUMNS]
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Summary"
        self._render_headers(ws, master_columns)

        if master_file.exists():
            existing_wb = self._load_existing_workbook(master_file)
            if "Summary" in existing_wb.sheetnames:
                wb = existing_wb
                ws = wb["Summary"]
            else:
                ws = existing_wb.active
                ws.title = "Summary"
                self._render_headers(ws, master_columns)

        if replace_recorded_date:
            for sheet_name in ("Summary", "Informational"):
                if sheet_name not in wb.sheetnames:
                    continue
                dated_ws = wb[sheet_name]
                headers = {
                    str(cell.value).strip(): cell.column
                    for cell in dated_ws[1]
                    if cell.value is not None
                }
                recorded_date_column = headers.get("Recorded Date")
                if not recorded_date_column:
                    continue
                for row_idx in range(dated_ws.max_row, 1, -1):
                    if self._recorded_on_date(
                        dated_ws.cell(row_idx, recorded_date_column).value,
                        replace_recorded_date,
                    ):
                        dated_ws.delete_rows(row_idx, 1)

        informational = [
            adv for adv in advisories
            if str(adv.get("advisory_type", "")).strip().title() == "Information"
        ]
        actionable = [
            adv for adv in advisories
            if str(adv.get("advisory_type", "")).strip().title() != "Information"
        ]

        if informational:
            if "Informational" in wb.sheetnames:
                info_ws = wb["Informational"]
                self._ensure_summary_schema(info_ws)
            else:
                info_ws = wb.create_sheet("Informational")
                info_columns = ["Recorded Date"] + [col[0] for col in self.COLUMNS]
                self._render_headers(info_ws, info_columns)
            info_columns = self._ensure_review_columns(info_ws)
            existing_info_rows = {}
            heading_column = info_columns.get("Advisory Heading")
            article_id_column = info_columns.get("Article ID")
            for row_idx in range(2, info_ws.max_row + 1):
                heading_key = str(
                    info_ws.cell(row_idx, heading_column).value or ""
                ).strip().casefold() if heading_column else ""
                article_id = str(
                    info_ws.cell(row_idx, article_id_column).value or ""
                ).strip() if article_id_column else ""
                if heading_key:
                    existing_info_rows[heading_key] = row_idx
                if article_id:
                    existing_info_rows[f"id:{article_id}"] = row_idx
            start_info_row = info_ws.max_row + 1 if info_ws.max_row > 1 else 2
            added_info_count = 0
            for adv in informational:
                heading_key = str(
                    adv.get("advisory_heading") or adv.get("title", "")
                ).strip().casefold()
                article_id = str(adv.get("id") or "").strip()
                row_idx = existing_info_rows.get(heading_key)
                if not row_idx and article_id:
                    row_idx = existing_info_rows.get(f"id:{article_id}")
                if row_idx:
                    self._write_advisory_row(info_ws, row_idx, adv, is_master=True)
                else:
                    row_idx = start_info_row + added_info_count
                    recorded_date = adv.get("recorded_date") or datetime.now().strftime(
                        "%Y-%m-%d %H:%M"
                    )
                    info_ws.cell(row=row_idx, column=1, value=recorded_date)
                    self._write_advisory_row(info_ws, row_idx, adv, is_master=True)
                    added_info_count += 1
                existing_info_rows[heading_key] = row_idx
                if article_id:
                    existing_info_rows[f"id:{article_id}"] = row_idx
                recorded_date = adv.get("recorded_date") or datetime.now().strftime("%Y-%m-%d %H:%M")
                if not info_ws.cell(row_idx, 1).value:
                    info_ws.cell(row=row_idx, column=1, value=recorded_date)
                self._write_review_data(
                    info_ws,
                    row_idx,
                    adv,
                    info_columns,
                    preserve_review_decision=preserve_review_decisions,
                )
            self._auto_fit_columns(info_ws)
            info_ws.freeze_panes = "B2"

        self._ensure_summary_schema(ws)
        columns = self._ensure_review_columns(ws)
        model, _ = self._apply_relevance_model(ws, columns)
        existing_keys = set()
        existing_rows = {}
        heading_column = columns.get("Advisory Heading")
        article_id_column = columns.get("Article ID")
        if heading_column:
            for row_idx in range(2, ws.max_row + 1):
                heading_key = str(ws.cell(row_idx, heading_column).value or "").strip().lower()
                if heading_key:
                    existing_keys.add(heading_key)
                    existing_rows[heading_key] = row_idx
                article_id = (
                    str(ws.cell(row_idx, article_id_column).value or "").strip()
                    if article_id_column else ""
                )
                if article_id:
                    existing_rows[f"id:{article_id}"] = row_idx

        start_row = ws.max_row + 1 if ws.max_row > 1 else 2
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M")
        added_count = 0
        for adv in actionable:
            self._set_relevance_suggestion(model, adv)
            heading_key = str(adv.get("advisory_heading") or adv.get("title", "")).strip().lower()
            article_id = str(adv.get("id") or "").strip()
            id_key = f"id:{article_id}"
            if heading_key in existing_keys or (article_id and id_key in existing_rows):
                row_idx = existing_rows.get(heading_key) or existing_rows.get(id_key)
                if row_idx:
                    self._write_advisory_row(
                        ws,
                        row_idx,
                        adv,
                        is_master=True,
                        preserve_review_decision=preserve_review_decisions,
                        preserve_report_link=True,
                    )
                    existing_rows[heading_key] = row_idx
                continue
            existing_keys.add(heading_key)
            row_idx = start_row + added_count
            recorded_date = adv.get("recorded_date") or now_str
            rec_cell = ws.cell(row=row_idx, column=1, value=recorded_date)
            rec_cell.font = self.DATA_FONT
            rec_cell.border = self.THIN_BORDER
            rec_cell.alignment = Alignment(horizontal="center", vertical="center")
            self._write_advisory_row(ws, row_idx, adv, is_master=True)
            added_count += 1

        document_count = self._rebuild_advisory_documents(
            wb,
            ws,
            advisories,
            refresh_enrichment=refresh_enrichment,
            generate_documents=generate_documents,
            update_learning_tracker=update_learning_tracker,
        )
        self._auto_fit_columns(ws)
        ws.freeze_panes = "B2"
        saved_file = self._safe_save(
            wb,
            master_file,
            replace_existing=replace_existing,
        )
        return saved_file

    def read_summary_records(self, workbook_path: str) -> List[Dict[str, Any]]:
        report_path = Path(workbook_path)
        if not report_path.exists():
            return []
        workbook = openpyxl.load_workbook(report_path, data_only=False)
        try:
            if "Summary" not in workbook.sheetnames:
                raise ValueError(f"Summary sheet not found in {report_path.name}.")
            worksheet = workbook["Summary"]
            return [
                self._summary_record_from_row(worksheet, row_idx)
                for row_idx in range(2, worksheet.max_row + 1)
                if worksheet.cell(row=row_idx, column=1).value
                or worksheet.cell(row=row_idx, column=2).value
            ]
        finally:
            workbook.close()

    def _auto_fit_columns(self, ws):
        fixed_widths = {
            "Source Name": 24,
            "Advisory Heading": 42,
            "Link of Advisory": 48,
            "View Report": 16,
            "View Detailed Report": 20,
            "Other Sources": 48,
            "Duplicate Check": 48,
            "Severity": 14,
            "CVSS": 10,
            "Published Date & Time": 20,
            "Security Impact / Summary": 65,
            "Matched Application / Component": 32,
            "Recorded Date": 18,
            "Advisory Type": 16,
            "CVE Details": 26,
            "CVE Risk Score": 16,
            "Attack Vector": 18,
            "AV Type": 14,
            "IOCs": 48,
        }
        ws.column_dimensions.clear()
        for col in ws.columns:
            header_val = str(col[0].value or "")
            col_letter = get_column_letter(col[0].column)
            width = fixed_widths.get(header_val, 22)
            dimension = ws.column_dimensions[col_letter]
            dimension.width = width
            dimension.hidden = (
                header_val in self.STORAGE_COLUMNS
                or header_val.startswith("CVE Metrics JSON Part ")
                or header_val in self.REVIEW_COLUMNS[1:]
            )
