import sys
import argparse
import base64
import os
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, time, timedelta
from pathlib import Path
from typing import Optional

# Add src to path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from config import Config, BASE_DIR
from advisory_deduplicator import AdvisoryDeduplicator
from inventory_manager import ApplicationInventory, NameListMatcher
from inoreader_client import InoreaderClient
from ai_evaluator import SecurityAIEvaluator
from excel_exporter import AdvisoryExcelExporter
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
    saved_master = exporter.append_to_master(
        str(master_file),
        reviewed_records,
        generate_documents=True,
        update_learning_tracker=True,
        preserve_review_decisions=False,
        replace_existing=True,
        replace_recorded_date=datetime.now().date(),
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


def process_reviewed_advisory_groups(exporter: AdvisoryExcelExporter, report_groups: dict):
    results = []
    for group, paths in report_groups.items():
        daily_path = paths["daily_path"]
        if not daily_path.exists():
            legacy_candidates = [
                daily_path.parent.parent / daily_path.name,
            ]
            if group == "miscellaneous":
                legacy_candidates.append(
                    daily_path.parent.parent
                    / daily_path.name.replace(
                        "Daily_Miscellaneous_Advisories_",
                        "Daily_Application_Advisories_",
                    )
                )
            daily_path = next(
                (candidate for candidate in legacy_candidates if candidate.exists()),
                daily_path,
            )
        if not daily_path.exists():
            continue
        results.append((
            paths["label"],
            *process_reviewed_advisories(
                exporter,
                daily_path,
                paths["master_path"],
            ),
        ))
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
):
    print(f"Advisory monitor started ({datetime.now().strftime('%Y-%m-%d %H:%M')}).")

    # 1. Load Configuration
    config = Config()

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
        results = process_reviewed_advisory_groups(exporter, report_groups)
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
            "existing review decisions will be discarded."
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

    gemini_cfg = config.get("gemini", default={})
    openai_cfg = config.get("openai", default={})
    ai_evaluator = SecurityAIEvaluator(
        api_key=gemini_cfg.get("api_key", ""),
        model_name=gemini_cfg.get("model", "gemini-2.5-flash"),
        openai_api_key=openai_cfg.get("api_key", ""),
        verify_ssl=gemini_cfg.get("verify_ssl", False)
    )

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
        for paths in report_groups.values():
            exporter.export_daily(
                str(paths["daily_path"]),
                [],
                generate_documents=False,
                replace_existing=True,
            )
        exporter.export_daily(
            str(informational_daily_path),
            [],
            generate_documents=False,
            replace_existing=True,
            informational_only=True,
        )
        print("No matching advisories; empty daily workbooks were saved.")
        return

    # 5. Security Impact Analysis & Precision Triage
    with ThreadPoolExecutor(max_workers=4) as executor:
        evaluations = list(executor.map(
            lambda item: ai_evaluator.evaluate_advisory(item[1], item[2]),
            unseen_matched,
        ))

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

    deduplicated_records, archived_updates = AdvisoryDeduplicator().deduplicate(
        scanned_records,
        archived_records,
    )
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
        article_ids = [item.get("id"), *item.get("_deduplicated_article_ids", [])]
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
                for value in item.get("_deduplicated_article_ids", [])
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
    )
