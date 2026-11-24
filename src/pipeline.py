import sys
import argparse
import base64
import hashlib
import json
import logging
import os
import re
import subprocess
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, time, timedelta
from itertools import combinations
from pathlib import Path
from typing import List, Optional

# Add src to path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from config import Config, BASE_DIR
from advisory_deduplicator import AdvisoryDeduplicator
from advisory_deduplicator import split_advisory_cluster
from inventory_manager import ApplicationInventory, NameListMatcher
from inoreader_client import InoreaderClient
from ai_evaluator import SecurityAIEvaluator
from excel_exporter import AdvisoryExcelExporter
from detailed_report_generator import DetailedAdvisoryReportGenerator
from relevance_model import AdvisoryRelevanceModel
from cache_db import AdvisoryCacheDB
from create_sample_inventory import generate_inventory
from tenable_client import TenableClient

def resolve_path(p_str: str) -> Path:
    p = Path(p_str)
    if not p.is_absolute():
        p = BASE_DIR / p
    return p.resolve()


def calculate_scan_window(
    now: Optional[datetime] = None,
    hours: int = 24,
):
    if hours <= 0:
        raise ValueError("The scan window must be a positive number of hours.")
    current_time = now or datetime.now()
    window_end = datetime.combine(current_time.date(), time.min)
    window_start = window_end - timedelta(hours=hours)
    return int(window_start.timestamp()), int(window_end.timestamp())


def is_in_scan_window(published_timestamp: int, window_start: int, window_end: int) -> bool:
    return not published_timestamp or window_start <= published_timestamp < window_end


def _is_recorded_on_date(recorded_date, target_date: date) -> bool:
    if isinstance(recorded_date, datetime):
        return recorded_date.date() == target_date
    if isinstance(recorded_date, date):
        return recorded_date == target_date
    return str(recorded_date or "").strip()[:10] == target_date.isoformat()


def create_exporter(config: Config) -> AdvisoryExcelExporter:
    tenable_cfg = config.get("tenable", default={})
    return AdvisoryExcelExporter(
        nvd_api_key=config.get("nvd", "api_key", default=""),
        tenable_client=TenableClient(
            access_key=tenable_cfg.get("access_key", ""),
            secret_key=tenable_cfg.get("secret_key", ""),
            base_url=tenable_cfg.get("base_url", "https://cloud.tenable.com"),
        ),
    )


def create_ai_evaluator(config: Config) -> SecurityAIEvaluator:
    gemini_cfg = config.get("gemini", default={})
    openai_cfg = config.get("openai", default={})
    return SecurityAIEvaluator(
        api_key=gemini_cfg.get("api_key", ""),
        model_name=gemini_cfg.get("model", "gemini-3.5-flash-lite"),
        openai_api_key=openai_cfg.get("api_key", ""),
        gemini_requests_per_minute=gemini_cfg.get("requests_per_minute", 12),
        allow_openai=openai_cfg.get("enabled", False),
        verify_ssl=gemini_cfg.get("verify_ssl", False),
    )


def _close_excel_workbook_if_open(workbook_path: Path) -> None:
    """Close a matching workbook in Excel, saving its current edits before processing."""
    if os.name != "nt":
        return
    target_path = str(workbook_path.resolve()).replace("'", "''")
    script = f"""
$ErrorActionPreference = 'Stop'
try {{
    $excel = [Runtime.InteropServices.Marshal]::GetActiveObject('Excel.Application')
}} catch [System.Runtime.InteropServices.COMException] {{
    Write-Output 'NO_EXCEL'
    exit 0
}}
$target = [IO.Path]::GetFullPath('{target_path}')
for ($index = $excel.Workbooks.Count; $index -ge 1; $index--) {{
    $workbook = $excel.Workbooks.Item($index)
    if ([string]::Equals(
        [IO.Path]::GetFullPath($workbook.FullName),
        $target,
        [StringComparison]::OrdinalIgnoreCase
    )) {{
        $workbook.Close($true)
        Write-Output 'CLOSED'
        exit 0
    }}
}}
Write-Output 'NOT_OPEN'
"""
    encoded_script = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    try:
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                encoded_script,
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(
            f"Could not check or close Excel workbook '{workbook_path}': {exc}"
        ) from exc
    if result.returncode != 0:
        raise RuntimeError(
            f"Could not close Excel workbook '{workbook_path}': "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )
    status = result.stdout.strip().splitlines()[-1:] or [""]
    if status[0] not in {"CLOSED", "NOT_OPEN", "NO_EXCEL"}:
        raise RuntimeError(
            f"Unexpected response while checking Excel workbook "
            f"'{workbook_path}': {result.stdout.strip()}"
        )


def build_report_groups(config: Config, daily_dir: Path, today_str: str):
    dated_daily_dir = daily_dir / today_str
    return {
        "telecom": {
            "label": "Telecom",
            "daily_path": dated_daily_dir / f"Daily_Telecom_Advisories_{today_str}.xlsx",
            "master_path": resolve_path(
                config.get(
                    "paths",
                    "master_telecom_excel",
                    default=str(BASE_DIR / "reports" / "Master_Telecom_Advisories.xlsx"),
                )
            ),
        },
        "vendor": {
            "label": "Vendor",
            "daily_path": dated_daily_dir / f"Daily_Vendor_Advisories_{today_str}.xlsx",
            "master_path": resolve_path(
                config.get(
                    "paths",
                    "master_vendor_excel",
                    default=str(BASE_DIR / "reports" / "Master_Vendor_Advisories.xlsx"),
                )
            ),
        },
        "miscellaneous": {
            "label": "Miscellaneous",
            "daily_path": dated_daily_dir / f"Daily_Miscellaneous_Advisories_{today_str}.xlsx",
            "master_path": resolve_path(
                config.get(
                    "paths",
                    "master_miscellaneous_excel",
                    default=str(BASE_DIR / "reports" / "Master_Miscellaneous_Advisories.xlsx"),
                )
            ),
        },
    }


def _primary_advisory_content(content: str) -> str:
    footer = re.search(
        r"\b(?:related\s+(?:posts?|stories|articles?)|follow me on "
        r"(?:twitter|x|facebook|mastodon))\b",
        content,
        re.IGNORECASE,
    )
    return content[:footer.start()] if footer else content


def route_advisory(
    article: dict,
    telecom_matcher: NameListMatcher,
    vendor_matcher: NameListMatcher,
    inventory: ApplicationInventory,
):
    title = str(article.get("title") or "")
    content = _primary_advisory_content(str(article.get("content") or ""))
    full_text = f"{title}\n{content}"

    application_matches = inventory.match(title, content)
    if not application_matches:
        return None

    telecom_matches = telecom_matcher.match(full_text)
    if telecom_matches:
        return "telecom", application_matches

    vendor_matches = vendor_matcher.match(full_text)
    if vendor_matches:
        return "vendor", application_matches

    return "miscellaneous", application_matches


def route_existing_record(
    record: dict,
    telecom_matcher: NameListMatcher,
    vendor_matcher: NameListMatcher,
):
    text = "\n".join(
        str(record.get(field) or "")
        for field in (
            "advisory_heading",
            "impact_summary",
            "report_summary",
            "affected_products",
            "matched_vendor",
        )
    )
    telecom_matches = telecom_matcher.match(text)
    if telecom_matches:
        return "telecom"
    vendor_matches = vendor_matcher.match(text)
    if vendor_matches:
        return "vendor"
    return "miscellaneous"


def _record_identity(record: dict) -> str:
    article_id = str(record.get("id") or "").strip()
    if article_id:
        return f"id:{article_id.casefold()}"
    link = str(record.get("link") or "").strip().rstrip("/").casefold()
    if link:
        return f"link:{link}"
    heading = " ".join(
        str(record.get("advisory_heading") or "").split()
    ).casefold()
    return f"heading:{heading}" if heading else ""


def _article_ids(record: dict) -> set:
    values = [
        record.get("id"),
        *(record.get("member_article_ids") or []),
        *(record.get("_deduplicated_article_ids") or []),
    ]
    for reference in record.get("source_references") or []:
        if isinstance(reference, dict):
            values.append(reference.get("article_id"))
    return {
        str(value).strip()
        for value in values
        if str(value or "").strip()
    }


def _duplicate_override(record: dict) -> str:
    value = str(record.get("duplicate_note") or "").strip().casefold()
    if value == "same event":
        return "same"
    if value == "keep separate":
        return "different"
    return ""


def _persist_human_duplicate_decisions(record: dict, cache_db: AdvisoryCacheDB) -> bool:
    decision = _duplicate_override(record)
    if not decision:
        return False
    member_ids = sorted(_article_ids(record))
    candidate_ids = {
        str(value).strip()
        for value in (record.get("duplicate_candidate_ids") or [])
        if str(value or "").strip()
    }
    if candidate_ids:
        pairs = {
            tuple(sorted((member_id, candidate_id)))
            for member_id in member_ids
            for candidate_id in candidate_ids
            if member_id != candidate_id
        }
    else:
        pairs = set(combinations(member_ids, 2)) if len(member_ids) > 1 else set()
    for left_id, right_id in pairs:
        cache_db.record_pair_decision(
            left_id,
            right_id,
            same_event=decision == "same",
            decided_by="human",
            reason="Human workbook decision: " + str(record.get("duplicate_note")),
        )
    return decision == "different" and len(member_ids) > 1


def _load_pending_daily_records(
    exporter: AdvisoryExcelExporter,
    daily_dir: Path,
    pending_days: int,
    today: date,
    archived_ids: set,
    close_open_workbooks: bool = True,
) -> List[dict]:
    if pending_days <= 0 or not daily_dir.exists():
        return []
    first_day = today - timedelta(days=pending_days - 1)
    pending = []
    for date_dir in sorted(daily_dir.iterdir()):
        if not date_dir.is_dir():
            continue
        try:
            workbook_date = date.fromisoformat(date_dir.name)
        except ValueError:
            continue
        if not first_day <= workbook_date <= today:
            continue
        expected_suffix = f"_{workbook_date.isoformat()}.xlsx"
        for workbook_path in sorted(date_dir.glob(f"Daily_*{expected_suffix}")):
            if close_open_workbooks:
                _close_excel_workbook_if_open(workbook_path)
            filename = workbook_path.name.casefold()
            if "telecom" in filename:
                group = "telecom"
            elif "vendor" in filename:
                group = "vendor"
            elif "informational" in filename:
                group = "miscellaneous"
            else:
                group = "miscellaneous"
            records = exporter.read_summary_records(str(workbook_path))
            for record in records:
                if _article_ids(record) & archived_ids:
                    continue
                record["_pending_daily_group"] = group
                record["_pending_daily_path"] = str(workbook_path)
                record["_pending_daily_date"] = workbook_date.isoformat()
                record["_today_date"] = today.isoformat()
                record["_pending_review_decision"] = record.get(
                    "review_decision",
                    "☐ Pending",
                )
                pending.append(record)
    return pending


def _validate_threshold(config: Config, key: str, default: float) -> float:
    value = config.get("deduplication", key, default=default)
    try:
        threshold = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"deduplication.{key} must be a number from 0 to 1.") from exc
    if not 0 <= threshold <= 1:
        raise ValueError(f"deduplication.{key} must be a number from 0 to 1.")
    return threshold


def _pending_days(config: Config) -> int:
    value = config.get("deduplication", "pending_days", default=7)
    try:
        days = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("deduplication.pending_days must be a positive integer.") from exc
    if days < 1:
        raise ValueError("deduplication.pending_days must be a positive integer.")
    return days


def _configure_merge_logging(config: Config) -> None:
    log_dir = config.get("paths", "log_dir", default=None)
    if not log_dir:
        return
    log_path = resolve_path(str(log_dir)) / "advisory_deduplication.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("advisory_deduplicator")
    logger.setLevel(logging.INFO)
    if any(
        isinstance(handler, logging.FileHandler)
        and Path(handler.baseFilename).resolve() == log_path.resolve()
        for handler in logger.handlers
    ):
        return
    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s %(message)s"
    ))
    logger.addHandler(handler)


def _prepare_delivery_metadata(record: dict, cache_db: AdvisoryCacheDB) -> None:
    advisory_id = str(record.get("advisory_id") or "").strip()
    if not advisory_id:
        seed = str(
            record.get("id")
            or record.get("link")
            or record.get("advisory_heading")
            or "unknown-advisory"
        ).strip().casefold()
        advisory_id = "ADV-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:20].upper()
        record["advisory_id"] = advisory_id
    ledger = cache_db.get_sent_ledger(advisory_id)
    if not isinstance(ledger, list):
        ledger = []
    new_information = [
        str(value).strip()
        for value in (record.get("_new_source_information") or [])
        if str(value or "").strip()
    ]
    if ledger and new_information:
        record["delivery_status"] = "UPDATE"
        record["update_summary"] = "\n".join(dict.fromkeys(new_information))
    elif ledger:
        record["delivery_status"] = "NO CHANGE"
        record["update_summary"] = ""
    else:
        record["delivery_status"] = "NEW"
        record["update_summary"] = ""
    hashed_content = {
        "advisory_id": advisory_id,
        "status": record["delivery_status"],
        "summary": record.get("update_summary")
        if record["delivery_status"] == "UPDATE"
        else record.get("report_summary"),
        "impact": record.get("impact_summary"),
        "recommendation": record.get("recommendation"),
        "links": [
            str(reference.get("link") or "")
            for reference in (record.get("source_references") or [])
            if isinstance(reference, dict)
        ],
    }
    record["content_hash"] = hashlib.sha256(
        json.dumps(hashed_content, sort_keys=True, ensure_ascii=True).encode("utf-8")
    ).hexdigest()


def split_existing_workbooks(
    exporter: AdvisoryExcelExporter,
    legacy_master_path: Path,
    legacy_daily_path: Path,
    report_groups: dict,
    telecom_matcher: NameListMatcher,
    vendor_matcher: NameListMatcher,
):
    """Copy the existing single-file archive and today's review queue into routed workbooks."""
    migrated_counts = {"master": {}, "daily": {}}
    if legacy_master_path.exists():
        records = exporter.read_summary_records(str(legacy_master_path))
        routed_records = {group: [] for group in report_groups}
        seen = set()
        for record in records:
            identity = _record_identity(record)
            if identity and identity in seen:
                continue
            if identity:
                seen.add(identity)
            group = route_existing_record(
                record,
                telecom_matcher,
                vendor_matcher,
            )
            routed_records[group].append(record)

        for group, group_records in routed_records.items():
            exporter.append_to_master(
                str(report_groups[group]["master_path"]),
                group_records,
                generate_documents=False,
                update_learning_tracker=True,
                preserve_review_decisions=True,
            )
            migrated_counts["master"][group] = len(group_records)

    if legacy_daily_path.exists():
        records = exporter.read_summary_records(str(legacy_daily_path))
        routed_records = {group: [] for group in report_groups}
        seen = set()
        for record in records:
            identity = _record_identity(record)
            if identity and identity in seen:
                continue
            if identity:
                seen.add(identity)
            group = route_existing_record(
                record,
                telecom_matcher,
                vendor_matcher,
            )
            routed_records[group].append(record)

        for group, group_records in routed_records.items():
            exporter.export_daily(
                str(report_groups[group]["daily_path"]),
                group_records,
                generate_documents=False,
            )
            migrated_counts["daily"][group] = len(group_records)
    return migrated_counts


def process_reviewed_advisories(
    exporter: AdvisoryExcelExporter,
    daily_path: Path,
    master_file: Path,
    ai_evaluator: Optional[SecurityAIEvaluator] = None,
):
    if not daily_path.exists():
        raise FileNotFoundError(
            f"Today's daily review workbook was not found: {daily_path}"
        )

    _close_excel_workbook_if_open(daily_path)
    _close_excel_workbook_if_open(master_file)
    daily_records = exporter.read_summary_records(str(daily_path))
    saved_daily = exporter.export_daily(
        str(daily_path),
        daily_records,
        generate_documents=True,
        replace_existing=True,
    )

    # Read back the successfully saved daily workbook so enrichment is carried into the archive.
    reviewed_records = exporter.read_summary_records(saved_daily)
    if _create_detailed_advisory_reports(
        reviewed_records,
        daily_path,
        ai_evaluator,
    ):
        saved_daily = exporter.export_daily(
            saved_daily,
            reviewed_records,
            generate_documents=False,
            preserve_review_decisions=True,
        )
        reviewed_records = exporter.read_summary_records(saved_daily)
    recorded_date = None
    for candidate in (daily_path.parent.name, daily_path.stem.rsplit("_", 1)[-1]):
        try:
            recorded_date = date.fromisoformat(candidate)
            break
        except ValueError:
            continue
    if recorded_date is None:
        recorded_date = datetime.now().date()
    recorded_at = f"{recorded_date.isoformat()} {datetime.now():%H:%M}"
    for record in reviewed_records:
        record["recorded_date"] = recorded_at
    archive_records = [
        record
        for record in reviewed_records
        if AdvisoryRelevanceModel.normalize_decision(
            record.get("review_decision")
        ) != "Previously Reported"
    ]
    saved_master = exporter.append_to_master(
        str(master_file),
        archive_records,
        generate_documents=True,
        update_learning_tracker=True,
        preserve_review_decisions=False,
        replace_existing=True,
        replace_recorded_date=recorded_date,
    )

    selected_count = sum(
        1 for record in reviewed_records
        if AdvisoryRelevanceModel.normalize_decision(record.get("review_decision")) == "Selected"
    )
    report_count = sum(
        1 for record in reviewed_records
        if AdvisoryRelevanceModel.normalize_decision(record.get("review_decision")) == "Selected"
        and str(record.get("severity") or "").strip().upper() != "LOW"
    )
    return saved_daily, saved_master, selected_count, report_count


def _create_detailed_advisory_reports(
    records: List[dict],
    daily_path: Path,
    ai_evaluator: Optional[SecurityAIEvaluator] = None,
) -> bool:
    report_folder = daily_path.parent / "Detailed Advisory Reports"
    eligible_records = [
        record
        for record in records
        if (
            AdvisoryRelevanceModel.normalize_decision(
                record.get("review_decision")
            ) == "Selected"
            and str(record.get("severity") or "").strip().upper() != "LOW"
            and str(record.get("advisory_type") or "").strip().title()
            in {"Actionable", "Patching"}
        )
    ]
    generator = None
    changed = False
    eligible_record_ids = {id(record) for record in eligible_records}
    if eligible_records:
        template_path = BASE_DIR / "Detailed Advisory Report Format.docx"
        generator = DetailedAdvisoryReportGenerator(template_path, ai_evaluator)
        print(
            f"Creating {len(eligible_records)} detailed Word report(s) in "
            f"{report_folder}.",
            flush=True,
        )
    for record in records:
        if id(record) not in eligible_record_ids:
            if record.get("detailed_report_path"):
                record["detailed_report_path"] = ""
                changed = True
            continue
        if generator is None:
            raise RuntimeError("The detailed advisory report generator was not initialized.")
        record["detailed_report_path"] = str(
            generator.generate(record, report_folder)
        )
        changed = True
    return changed


def process_reviewed_advisory_groups(
    exporter: AdvisoryExcelExporter,
    report_groups: dict,
    pending_days: int = 7,
    ai_evaluator: Optional[SecurityAIEvaluator] = None,
):
    results = []
    today = date.today()
    first_day = today - timedelta(days=pending_days - 1)
    for group, paths in report_groups.items():
        current_path = paths["daily_path"]
        daily_root = current_path.parent.parent
        dated_paths = []
        if daily_root.exists():
            for date_dir in sorted(daily_root.iterdir()):
                if not date_dir.is_dir():
                    continue
                try:
                    workbook_date = date.fromisoformat(date_dir.name)
                except ValueError:
                    continue
                if first_day <= workbook_date <= today:
                    dated_path = date_dir / current_path.name.replace(
                        current_path.stem.rsplit("_", 1)[-1],
                        workbook_date.isoformat(),
                    )
                    if dated_path.exists():
                        dated_paths.append((workbook_date, dated_path))
        if not dated_paths and current_path.exists():
            dated_paths.append((today, current_path))
        if not dated_paths:
            legacy_candidates = [daily_root / current_path.name]
            if group == "miscellaneous":
                legacy_candidates.append(
                    daily_root
                    / current_path.name.replace(
                        "Daily_Miscellaneous_Advisories_",
                        "Daily_Application_Advisories_",
                    )
                )
            legacy_path = next(
                (candidate for candidate in legacy_candidates if candidate.exists()),
                None,
            )
            if legacy_path:
                dated_paths.append((today, legacy_path))
        for workbook_date, daily_path in dated_paths:
            label = paths["label"]
            if workbook_date != today:
                label = f"{label} ({workbook_date.isoformat()})"
            if ai_evaluator is not None:
                processed = process_reviewed_advisories(
                    exporter,
                    daily_path,
                    paths["master_path"],
                    ai_evaluator,
                )
            else:
                processed = process_reviewed_advisories(
                    exporter,
                    daily_path,
                    paths["master_path"],
                )
            results.append((label, *processed))
    if not results:
        raise FileNotFoundError(
            "No category daily review workbooks were found to process."
        )
    return results


def run_pipeline(
    force_reprocess: bool = False,
    hours: Optional[int] = None,
    refresh_reports: bool = False,
    process_reviewed: bool = False,
    dry_run_merges: bool = False,
):
    print(f"Advisory monitor started ({datetime.now().strftime('%Y-%m-%d %H:%M')}).")

    # 1. Load Configuration
    config = Config()
    _configure_merge_logging(config)
    if dry_run_merges and (refresh_reports or process_reviewed):
        raise ValueError("--dry-run-merges cannot be combined with report-only actions.")
    pending_days = _pending_days(config)

    inventory_file = resolve_path(config.get("paths", "inventory_excel"))
    if not inventory_file.exists():
        local_inventory = BASE_DIR / "inventory.xlsx"
        if local_inventory.exists():
            inventory_file = local_inventory

    master_file = resolve_path(config.get("paths", "master_excel"))
    daily_dir = resolve_path(config.get("paths", "daily_reports_dir"))
    cache_db_path = resolve_path(config.get("paths", "cache_db"))

    time_window_hours = (
        hours if hours is not None
        else config.get("time_window_hours", default=24)
    )
    window_start_ts, window_end_ts = calculate_scan_window(
        hours=time_window_hours,
    )
    window_start = datetime.fromtimestamp(window_start_ts)
    window_end = datetime.fromtimestamp(window_end_ts)
    today_str = window_end.strftime("%Y-%m-%d")
    legacy_daily_path = daily_dir / f"Daily_Advisories_{today_str}.xlsx"
    report_groups = build_report_groups(config, daily_dir, today_str)
    informational_daily_path = report_groups["miscellaneous"]["daily_path"].with_name(
        f"Daily_Informational_Advisories_{today_str}.xlsx"
    )
    legacy_application_daily_path = (
        daily_dir
        / report_groups["miscellaneous"]["daily_path"].name.replace(
            "Daily_Miscellaneous_Advisories_",
            "Daily_Application_Advisories_",
        )
    )
    legacy_category_paths = [
        daily_dir / f"Daily_{label}_Advisories_{today_str}.xlsx"
        for label in ("Telecom", "Vendor", "Miscellaneous")
    ]
    rebuild_daily = (
        legacy_daily_path.exists()
        or legacy_application_daily_path.exists()
        or any(path.exists() for path in legacy_category_paths)
        or any(
            paths["daily_path"].exists() for paths in report_groups.values()
        )
        or informational_daily_path.exists()
    )
    reprocess_cached = force_reprocess or rebuild_daily

    exporter = create_exporter(config)
    if process_reviewed:
        ai_evaluator = create_ai_evaluator(config)
        results = process_reviewed_advisory_groups(
            exporter,
            report_groups,
            pending_days=pending_days,
            ai_evaluator=ai_evaluator,
        )
        for label, saved_daily, saved_master, selected_count, report_count in results:
            print(
                f"{label} review complete: {selected_count} selected; "
                f"{report_count} eligible for detailed reports. "
                f"Daily report saved: {Path(saved_daily).name}; "
                f"master archive updated: {Path(saved_master).name}."
            )
        print("See each master workbook's Learning Tracker sheet.")
        return

    if refresh_reports:
        existing_reports = []
        report_targets = [
            (
                paths["daily_path"],
                paths["master_path"],
                paths["label"],
            )
            for paths in report_groups.values()
        ]
        report_targets.extend(
            (daily_path, None, "Legacy category")
            for daily_path in legacy_category_paths
        )
        report_targets.append((legacy_daily_path, master_file, "Legacy"))
        report_targets.append((legacy_application_daily_path, None, "Legacy Application"))
        report_targets.append(
            (informational_daily_path, None, "Informational")
        )
        for daily_path, master_path, label in report_targets:
            if daily_path.exists():
                informational_only = daily_path == informational_daily_path
                saved_daily = exporter.export_daily(
                    str(daily_path),
                    [],
                    refresh_enrichment=True,
                    generate_documents=not informational_only,
                    informational_only=informational_only,
                )
                existing_reports.append(f"{label}: {Path(saved_daily).name}")
            if master_path and master_path.exists():
                saved_master = exporter.append_to_master(
                    str(master_path),
                    [],
                    refresh_enrichment=True,
                    generate_documents=True,
                    update_learning_tracker=True,
                )
                existing_reports.append(f"{label}: {Path(saved_master).name}")
        if not existing_reports:
            raise FileNotFoundError(
                f"No existing daily or master reports were found to refresh for {today_str}."
            )
        print(f"Reports refreshed: {', '.join(existing_reports)}")
        return
    if rebuild_daily and not force_reprocess:
        print(
            f"Rebuilding category workbooks for {today_str} from the full scan window; "
            "available pending review decisions will be preserved."
        )

    # Fallback to local inventory.xlsx if configured path does not exist
    if not inventory_file.exists():
        fallback = BASE_DIR / "inventory.xlsx"
        if fallback.exists():
            inventory_file = fallback
        else:
            print(f"Inventory not found; creating sample inventory at {fallback.name}.")
            generate_inventory(str(fallback))
            inventory_file = fallback

    # 2. Initialize Components
    inventory = ApplicationInventory(str(inventory_file))
    if not inventory.applications:
        raise RuntimeError(f"No applications loaded from inventory: {inventory_file}")

    telecom_list_path = resolve_path(
        config.get(
            "paths",
            "telecom_list_excel",
            default=str(BASE_DIR / "Global Telecom List.xlsx"),
        )
    )
    if not telecom_list_path.exists():
        parent_telecom_list = BASE_DIR.parent / "Global Telecom List.xlsx"
        if parent_telecom_list.exists():
            telecom_list_path = parent_telecom_list
    vendor_list_path = resolve_path(
        config.get(
            "paths",
            "vendor_list_excel",
            default=str(BASE_DIR / "Vendor List.xlsx"),
        )
    )
    telecom_matcher = NameListMatcher(
        str(telecom_list_path),
        ["company operator", "telecom company", "company name", "company"],
    )
    vendor_matcher = NameListMatcher(
        str(vendor_list_path),
        ["vendor", "vendor name", "company name", "company", "supplier"],
    )

    cache_db = AdvisoryCacheDB(str(cache_db_path))
    inoreader_cfg = config.get("inoreader", default={})
    client = InoreaderClient(
        email=inoreader_cfg.get("email", ""),
        password=inoreader_cfg.get("password", ""),
        app_id=inoreader_cfg.get("app_id", ""),
        app_key=inoreader_cfg.get("app_key", ""),
        token=inoreader_cfg.get("token", ""),
        stream_id=inoreader_cfg.get("stream_id", "user/-/state/com.google/reading-list"),
        verify_ssl=inoreader_cfg.get("verify_ssl", False),
        fetch_full_web=inoreader_cfg.get("fetch_full_web", True),
        use_mock_if_missing=inoreader_cfg.get("use_mock_if_missing", False),
    )

    ai_evaluator = create_ai_evaluator(config)

    exporter = create_exporter(config)

    # 3. Fetch Stream Articles from Inoreader (Last 24 Hours)
    print(
        "Fetching Inoreader articles from "
        f"{window_start:%Y-%m-%d %H:%M} to {window_end:%Y-%m-%d %H:%M} local time..."
    )
    raw_articles = client.fetch_articles(since_timestamp=window_start_ts)

    # 4. Filter & Match Against Application Inventory
    unseen_matched = []
    skipped_outside_window = 0
    skipped_cached = 0
    skipped_no_match = 0
    seen_article_ids = set()

    for article in raw_articles:
        art_id = str(article.get("id") or "").strip()
        pub_ts = article.get("published_timestamp", 0)
        scan_ts = article.get("scan_timestamp", pub_ts)

        if not is_in_scan_window(scan_ts, window_start_ts, window_end_ts):
            skipped_outside_window += 1
            continue

        if not reprocess_cached and cache_db.is_seen(art_id):
            skipped_cached += 1
            continue

        if art_id and art_id in seen_article_ids:
            continue
        if art_id:
            seen_article_ids.add(art_id)

        route = route_advisory(
            article,
            telecom_matcher,
            vendor_matcher,
            inventory,
        )
        if route:
            group, matches = route
            unseen_matched.append((group, article, matches[0], matches))
        else:
            skipped_no_match += 1

    if unseen_matched:
        with ThreadPoolExecutor(max_workers=8) as executor:
            enriched_articles = list(executor.map(
                lambda item: client.enrich_article_content(item[1]),
                unseen_matched,
            ))
        enriched_matched = []
        for (old_group, _, primary_match, all_matches), article in zip(
            unseen_matched,
            enriched_articles,
        ):
            route = route_advisory(
                article,
                telecom_matcher,
                vendor_matcher,
                inventory,
            )
            if route:
                group, matches = route
                enriched_matched.append((group, article, matches[0], matches))
            else:
                enriched_matched.append((
                    old_group,
                    article,
                    primary_match,
                    all_matches,
                ))
        unseen_matched = enriched_matched
        if client.web_fetch_failures:
            print(
                f"Source-page content unavailable for {client.web_fetch_failures} candidate(s); "
                "feed summaries will be used."
            )

    print(
        f"Feed: {len(raw_articles)} articles; {len(unseen_matched)} new candidates; "
        f"{skipped_cached} already processed; "
        f"{skipped_outside_window + skipped_no_match} excluded."
    )

    if not unseen_matched:
        if dry_run_merges:
            print("Dry run: no newly matched articles; no workbooks or cache entries changed.")
            return
        for paths in report_groups.values():
            exporter.export_daily(
                str(paths["daily_path"]),
                [],
                generate_documents=False,
                replace_existing=False,
            )
        exporter.export_daily(
            str(informational_daily_path),
            [],
            generate_documents=False,
            replace_existing=False,
            informational_only=True,
        )
        print("No matching advisories; empty daily workbooks were saved.")
        return

    # 5. Security Impact Analysis & Precision Triage
    print(
        f"Evaluating {len(unseen_matched)} matched candidates; "
        "Gemini free-tier pacing is enabled.",
        flush=True,
    )
    with ThreadPoolExecutor(max_workers=4) as executor:
        evaluations = list(executor.map(
            lambda item: ai_evaluator.evaluate_advisory(item[1], item[2]),
            unseen_matched,
        ))
    print("Candidate evaluation complete; starting duplicate checks.", flush=True)

    scanned_records = []
    for (group, art, primary_match, all_matches), evaluation in zip(unseen_matched, evaluations):
        initially_actionable = bool(evaluation.get("is_actionable_vulnerability", True))
        art = {
            **art,
            "title": evaluation.get("translated_title", art.get("title", "")),
            "content": evaluation.get("translated_content", art.get("content", "")),
        }
        all_app_names = [m["application_name"] for m in all_matches]
        combined_apps = ", ".join(dict.fromkeys(all_app_names))

        enriched = exporter.build_advisory_record(
            {
                "title": art.get("title", ""),
                "content": art.get("content", ""),
                "source_name": art.get("source_name", "Inoreader Feed"),
                "link": art.get("link", ""),
                "published_timestamp": art.get("published_timestamp", int(datetime.now().timestamp())),
                "matched_app_name": combined_apps,
                "matched_vendor": primary_match.get("vendor", "")
            },
            evaluation,
            enrich_cves=False,
        )
        triage_note = str(evaluation.get("rejection_reason") or "")
        if not initially_actionable:
            enriched["severity"] = "UNASSESSED"
            enriched["impact_summary"] = (
                f"Automated triage flagged this item for human review: {triage_note} "
                "Check the linked source before selecting it."
            )

        record = {
            "id": art["id"],
            "source_name": enriched["source_name"],
            "advisory_heading": enriched["advisory_heading"],
            "link": enriched["link"],
            "severity": enriched["severity"],
            "cvss_score": enriched["cvss_score"],
            "published_timestamp": enriched["published_timestamp"],
            "impact_summary": enriched["impact_summary"],
            "telecom_applicability": enriched["impact_summary"],
            "matched_app_name": combined_apps,
            "matched_vendor": primary_match.get("vendor", ""),
            "advisory_type": enriched["advisory_type"],
            "cve_details": enriched["cve_details"],
            "cve_risk_score": enriched["cve_risk_score"],
            "cve_metrics": enriched["cve_metrics"],
            "attack_vector": enriched["attack_vector"],
            "av_type": enriched["av_type"],
            "iocs": enriched["iocs"],
            "affected_products": enriched["affected_products"],
            "affected_versions": enriched["affected_versions"],
            "report_summary": enriched["report_summary"],
            "recommendation": enriched["recommendation"],
            "source_content": enriched["source_content"],
            "initial_triage": "Accepted" if initially_actionable else "Flagged",
            "triage_note": triage_note,
            "review_decision": "☑ Selected",
            "_dedupe_group": group,
        }
        scanned_records.append(record)

    training_records = []
    archived_records = []
    for group, paths in report_groups.items():
        if not paths["master_path"].exists():
            continue
        master_records = [
            record
            for record in exporter.read_summary_records(str(paths["master_path"]))
            if not _is_recorded_on_date(
                record.get("recorded_date"),
                window_end.date(),
            )
        ]
        training_records.extend(master_records)
        for master_record in master_records:
            master_record["_archive_group"] = group
            archived_records.append(master_record)

    archived_ids = set().union(*(_article_ids(record) for record in archived_records)) \
        if archived_records else set()
    today = window_end.date()
    pending_records = _load_pending_daily_records(
        exporter,
        daily_dir,
        pending_days,
        today,
        archived_ids,
        close_open_workbooks=not dry_run_merges,
    )
    split_records = []
    manual_same_event_records = []
    manual_old_row_updates = []
    split_old_row_updates = []
    preserved_current_records = []
    eligible_pending = []
    pending_by_id = {}
    for pending in pending_records:
        for article_id in _article_ids(pending):
            pending_by_id[article_id] = pending
    for pending in pending_records:
        duplicate_override = _duplicate_override(pending)
        if not dry_run_merges:
            split_requested = _persist_human_duplicate_decisions(pending, cache_db)
        else:
            split_requested = duplicate_override == "different" and len(_article_ids(pending)) > 1
        pending_status = AdvisoryRelevanceModel.normalize_decision(
            pending.get("review_decision")
        )
        pending_date = str(pending.get("_pending_daily_date") or "")
        pending_group = str(pending.get("_pending_daily_group") or "miscellaneous")
        pending_path = str(pending.get("_pending_daily_path") or "")
        if split_requested:
            split_members = split_advisory_cluster(pending)
            if split_members:
                for member in split_members:
                    member["_dedupe_group"] = pending_group
                    member["review_decision"] = pending.get(
                        "_pending_review_decision",
                        "☐ Pending",
                    )
                    member["duplicate_note"] = ""
                split_records.extend(split_members)
                pending["review_decision"] = "Previously Reported"
                pending["duplicate_note"] = (
                    "Merged advisory split into separate source advisories by human review."
                )
                if pending_date < today.isoformat():
                    split_old_row_updates.append(pending)
                continue
        if pending_status in {"Rejected", "Previously Reported"}:
            if pending_date == today.isoformat():
                pending["_dedupe_group"] = pending_group
                preserved_current_records.append(pending)
            continue
        eligible_pending.append(pending)
        if duplicate_override == "same":
            candidate_ids = {
                str(value).strip()
                for value in (pending.get("duplicate_candidate_ids") or [])
                if str(value or "").strip()
            }
            for candidate_id in candidate_ids:
                other = pending_by_id.get(candidate_id)
                if (
                    other is None
                    or other is pending
                    or any(other is item for item in manual_same_event_records)
                ):
                    continue
                if AdvisoryRelevanceModel.normalize_decision(
                    other.get("review_decision")
                ) in {"Rejected", "Previously Reported"}:
                    continue
                manual_same_event_records.extend([pending, other])

    manual_same_event_records = list({
        id(record): record for record in manual_same_event_records
    }.values())
    manual_same_ids = {
        id(record)
        for record in manual_same_event_records
    }
    for record in manual_same_event_records:
        record["_dedupe_group"] = record.get(
            "_pending_daily_group",
            "miscellaneous",
        )
        if str(record.get("_pending_daily_date") or "") < today.isoformat():
            old_row = deepcopy(record)
            old_row["review_decision"] = "Previously Reported"
            old_row["duplicate_note"] = (
                "Merged into a human-confirmed advisory in the current review queue."
            )
            manual_old_row_updates.append(old_row)
    eligible_pending = [
        record for record in eligible_pending
        if id(record) not in manual_same_ids
    ]

    pipeline_records = scanned_records + split_records + manual_same_event_records
    pair_decisions = cache_db.get_pair_decisions()
    if not isinstance(pair_decisions, dict):
        pair_decisions = {}
    deduplicator = AdvisoryDeduplicator()
    print(
        f"Checking duplicates for {len(pipeline_records)} candidate records "
        f"against {len(archived_records) + len(eligible_pending)} existing records.",
        flush=True,
    )
    deduplicated_records, archived_updates = deduplicator.deduplicate(
        pipeline_records,
        archived_records,
        pending_records=eligible_pending,
        pair_decisions=pair_decisions,
        decision_callback=(
            None if dry_run_merges else cache_db.record_pair_decision
        ),
        adjudicator=ai_evaluator.adjudicate_duplicate_pair,
        summarizer=(
            None if dry_run_merges else ai_evaluator.summarize_merged_advisory
        ),
        same_event_threshold=_validate_threshold(
            config,
            "same_event_confidence_threshold",
            0.85,
        ),
        candidate_threshold=_validate_threshold(
            config,
            "candidate_similarity_threshold",
            0.18,
        ),
    )
    if dry_run_merges:
        for proposal in deduplicator.proposals:
            print(
                "Dry-run decision: "
                f"{proposal['decision']} "
                f"{proposal['left_id']} <-> {proposal['right_id']} "
                f"(score={proposal['score']:.3f}; {proposal['reason']})"
            )
        print("Dry run complete; no workbook or cache writes were made.")
        return
    deduplicated_records.extend(preserved_current_records)
    daily_updates_by_path = {}
    for pending in eligible_pending:
        pending_date = str(pending.get("_pending_daily_date") or "")
        pending_path = str(pending.get("_pending_daily_path") or "")
        if (
            pending.get("_pending_daily_updated")
            and pending_path
            and pending_date < today.isoformat()
        ):
            daily_updates_by_path.setdefault(pending_path, []).append(pending)
    for record in manual_old_row_updates + split_old_row_updates:
        pending_path = str(record.get("_pending_daily_path") or "")
        if pending_path:
            daily_updates_by_path.setdefault(pending_path, []).append(record)
    for record in deduplicated_records:
        for key in (
            "_pending_daily_group",
            "_pending_daily_path",
            "_pending_daily_date",
            "_today_date",
            "_pending_review_decision",
            "_pending_daily_updated",
            "_pending_archive_merged",
        ):
            record.pop(key, None)
    processed_by_group = {group: [] for group in report_groups}
    informational_advisories = []
    for record in deduplicated_records:
        group = record.pop("_dedupe_group")
        if record["advisory_type"] == "Information":
            informational_advisories.append(record)
        else:
            processed_by_group[group].append(record)

    candidate_count = (
        sum(len(records) for records in processed_by_group.values())
        + len(informational_advisories)
    )
    flagged_by_triage = sum(
        1
        for record in deduplicated_records
        if str(record.get("initial_triage") or "").casefold() == "flagged"
    )
    print(
        f"Review queue: {candidate_count} candidates; "
        f"{flagged_by_triage} flagged by initial triage."
    )

    processed_advisories = [
        record
        for records in processed_by_group.values()
        for record in records
    ] + informational_advisories
    for record in processed_advisories:
        _prepare_delivery_metadata(record, cache_db)
    for updates in archived_updates.values():
        for record in updates:
            _prepare_delivery_metadata(record, cache_db)
    training_records = [
        {
            key: value
            for key, value in record.items()
            if not key.startswith("_")
        }
        for record in training_records
    ]
    exporter.apply_relevance_suggestions(processed_advisories, training_records)

    for group, updates in archived_updates.items():
        master_path = report_groups[group]["master_path"]
        _close_excel_workbook_if_open(master_path)
        exporter.append_to_master(
            str(master_path),
            updates,
            generate_documents=False,
            preserve_review_decisions=True,
            replace_existing=True,
        )

    for daily_path, updates in daily_updates_by_path.items():
        _close_excel_workbook_if_open(Path(daily_path))
        exporter.export_daily(
            daily_path,
            updates,
            generate_documents=False,
            replace_existing=False,
            preserve_review_decisions=False,
        )

    saved_daily_reports = []
    for group, group_records in processed_by_group.items():
        saved_daily_reports.append(exporter.export_daily(
            str(report_groups[group]["daily_path"]),
            group_records,
            generate_documents=False,
            replace_existing=True,
        ))
    saved_daily_reports.append(exporter.export_daily(
        str(informational_daily_path),
        informational_advisories,
        generate_documents=False,
        replace_existing=True,
        informational_only=True,
    ))

    # Record in cache database
    for item in processed_advisories:
        article_ids = _article_ids(item)
        for article_id in dict.fromkeys(
            str(value).strip() for value in article_ids if str(value or "").strip()
        ):
            cache_db.mark_seen(
                article_id=article_id,
                title=item["advisory_heading"],
                source=item["source_name"],
                matched_app=item["matched_app_name"],
                severity=item["severity"],
                timestamp=item["published_timestamp"],
            )
    for updates in archived_updates.values():
        for item in updates:
            for article_id in dict.fromkeys(
                str(value).strip()
                for value in _article_ids(item)
                if str(value or "").strip()
            ):
                cache_db.mark_seen(
                    article_id=article_id,
                    title=item["advisory_heading"],
                    source=item["source_name"],
                    matched_app=item["matched_app_name"],
                    severity=item["severity"],
                    timestamp=item["published_timestamp"],
                )

    print(
        "Daily summaries saved: "
        + ", ".join(Path(path).name for path in saved_daily_reports)
    )
    print(
        "Review the category workbooks, then run with --process-reviewed. "
        "Each master archive is updated after its reports finish."
    )

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Security Advisory & Vulnerability Automated Surveillance")
    parser.add_argument("--force", action="store_true", help="Force re-processing of already cached advisories")
    parser.add_argument(
        "--hours",
        type=int,
        default=None,
        help="Scan-window length ending at local midnight (default: previous calendar day)",
    )
    parser.add_argument(
        "--dry-run-merges",
        action="store_true",
        help="Evaluate duplicate decisions and print proposals without writing workbooks or cache entries",
    )
    report_actions = parser.add_mutually_exclusive_group()
    report_actions.add_argument(
        "--refresh-reports",
        action="store_true",
        help="Rebuild existing daily and master reports without fetching new feed articles",
    )
    report_actions.add_argument(
        "--process-reviewed",
        action="store_true",
        help="Generate reports from available category workbooks, then update their master archives",
    )
    args = parser.parse_args()
    run_pipeline(
        force_reprocess=args.force,
        hours=args.hours,
        refresh_reports=args.refresh_reports,
        process_reviewed=args.process_reviewed,
        dry_run_merges=args.dry_run_merges,
    )
