import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

import pipeline
from pipeline import calculate_scan_window, is_in_scan_window


class ScanWindowTests(unittest.TestCase):
    def test_today_archive_records_can_be_identified_for_reruns(self):
        today = datetime.now().date()

        self.assertTrue(pipeline._is_recorded_on_date(
            f"{today.isoformat()} 08:15",
            today,
        ))
        self.assertFalse(pipeline._is_recorded_on_date(
            f"{(today - timedelta(days=1)).isoformat()} 08:15",
            today,
        ))

    def test_default_window_is_previous_local_calendar_day(self):
        start, end = calculate_scan_window(datetime(2026, 11, 12, 16, 45))

        self.assertEqual(datetime.fromtimestamp(start), datetime(2026, 11, 11, 0, 0))
        self.assertEqual(datetime.fromtimestamp(end), datetime(2026, 11, 12, 0, 0))

    def test_window_does_not_depend_on_report_generation_time(self):
        early_start, early_end = calculate_scan_window(datetime(2026, 11, 12, 5, 0))
        late_start, late_end = calculate_scan_window(datetime(2026, 11, 12, 23, 59))

        self.assertEqual((early_start, early_end), (late_start, late_end))

    def test_scan_window_includes_start_and_excludes_next_midnight(self):
        start, end = calculate_scan_window(datetime(2026, 11, 12, 8, 0))

        self.assertTrue(is_in_scan_window(start, start, end))
        self.assertTrue(is_in_scan_window(end - 1, start, end))
        self.assertFalse(is_in_scan_window(start - 1, start, end))
        self.assertFalse(is_in_scan_window(end, start, end))

    def test_custom_hours_end_at_local_midnight(self):
        start, end = calculate_scan_window(datetime(2026, 11, 12, 15, 0), hours=6)

        self.assertEqual(datetime.fromtimestamp(start), datetime(2026, 11, 11, 18, 0))
        self.assertEqual(datetime.fromtimestamp(end), datetime(2026, 11, 12, 0, 0))

    def test_non_positive_scan_window_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "positive"):
            calculate_scan_window(datetime(2026, 11, 12, 8, 0), hours=0)

    def test_no_candidates_creates_all_four_daily_workbooks(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            inventory_path = root / "inventory.xlsx"
            inventory_path.touch()
            daily_dir = root / "daily"
            config_paths = {
                ("paths", "inventory_excel"): str(inventory_path),
                ("paths", "master_excel"): str(root / "master.xlsx"),
                ("paths", "master_telecom_excel"): str(root / "master-telecom.xlsx"),
                ("paths", "master_vendor_excel"): str(root / "master-vendor.xlsx"),
                ("paths", "master_miscellaneous_excel"): str(root / "master-miscellaneous.xlsx"),
                ("paths", "daily_reports_dir"): str(daily_dir),
                ("paths", "cache_db"): str(root / "cache.db"),
            }

            class TestConfig:
                def get(self, *keys, default=None):
                    return config_paths.get(keys, default)

            class EmptyInventory:
                applications = ["Example"]

                def __init__(self, _path):
                    pass

                def match(self, _title, _content):
                    return []

            exporter = Mock()
            client = Mock()
            client.fetch_articles.return_value = []
            today_str = datetime.fromtimestamp(
                pipeline.calculate_scan_window()[1]
            ).strftime("%Y-%m-%d")
            with (
                patch.object(pipeline, "Config", return_value=TestConfig()),
                patch.object(pipeline, "resolve_path", side_effect=Path),
                patch.object(pipeline, "create_exporter", return_value=exporter),
                patch.object(pipeline, "ApplicationInventory", EmptyInventory),
                patch.object(pipeline, "AdvisoryCacheDB"),
                patch.object(pipeline, "InoreaderClient", return_value=client),
            ):
                pipeline.run_pipeline()

            self.assertEqual(exporter.export_daily.call_count, 4)
            self.assertEqual(
                {
                    Path(call.args[0]).name
                    for call in exporter.export_daily.call_args_list
                },
                {
                    f"Daily_Telecom_Advisories_{today_str}.xlsx",
                    f"Daily_Vendor_Advisories_{today_str}.xlsx",
                    f"Daily_Miscellaneous_Advisories_{today_str}.xlsx",
                    f"Daily_Informational_Advisories_{today_str}.xlsx",
                },
            )
            self.assertTrue(
                all(
                    Path(call.args[0]).parent == daily_dir / today_str
                    for call in exporter.export_daily.call_args_list
                )
            )
            self.assertTrue(
                all(not call.args[1] for call in exporter.export_daily.call_args_list)
            )
            informational_call = next(
                call for call in exporter.export_daily.call_args_list
                if "Informational" in Path(call.args[0]).name
            )
            self.assertTrue(informational_call.kwargs["informational_only"])
            self.assertFalse(daily_dir.exists())

    def test_existing_daily_workbook_is_rebuilt_from_cached_candidates(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            inventory_path = root / "inventory.xlsx"
            inventory_path.touch()
            daily_dir = root / "daily"
            daily_dir.mkdir()
            daily_date = datetime.fromtimestamp(200).strftime("%Y-%m-%d")
            daily_path = daily_dir / f"Daily_Advisories_{daily_date}.xlsx"
            daily_path.touch()
            config_paths = {
                ("paths", "inventory_excel"): str(inventory_path),
                ("paths", "master_excel"): str(root / "master.xlsx"),
                ("paths", "master_telecom_excel"): str(root / "master-telecom.xlsx"),
                ("paths", "master_vendor_excel"): str(root / "master-vendor.xlsx"),
                ("paths", "master_miscellaneous_excel"): str(root / "master-miscellaneous.xlsx"),
                ("paths", "daily_reports_dir"): str(daily_dir),
                ("paths", "cache_db"): str(root / "cache.db"),
            }

            class TestConfig:
                def get(self, *keys, default=None):
                    return config_paths.get(keys, default)

            class MatchingInventory:
                applications = ["Example"]

                def __init__(self, _path):
                    pass

                def match(self, _title, _content):
                    return [{"application_name": "Example", "vendor": "Vendor"}]

            article = {
                "id": "cached-article",
                "title": "Cached same-day advisory",
                "content": "Advisory content",
                "source_name": "Vendor",
                "link": "",
                "published_timestamp": 50,
                "scan_timestamp": 150,
            }
            enriched = {
                "source_name": "Vendor",
                "advisory_heading": "Cached same-day advisory",
                "link": "",
                "severity": "HIGH",
                "cvss_score": "7.5",
                "published_timestamp": 150,
                "impact_summary": "Advisory impact",
                "advisory_type": "Information",
                "cve_details": "NA",
                "cve_risk_score": "NA",
                "cve_metrics": {},
                "attack_vector": "NA",
                "av_type": "NA",
                "iocs": "NA",
                "affected_products": "",
                "affected_versions": "NA",
                "report_summary": "",
                "recommendation": "",
                "source_content": "Advisory content",
            }
            exporter = Mock()
            exporter.build_advisory_record.return_value = enriched
            exporter.export_daily.return_value = str(daily_path)
            cache = Mock()
            cache.is_seen.return_value = True
            client = Mock()
            client.fetch_articles.return_value = [article]
            client.enrich_article_content.return_value = article
            client.web_fetch_failures = 0
            evaluator = Mock()
            evaluator.evaluate_advisory.return_value = {
                "is_actionable_vulnerability": True,
            }

            with (
                patch.object(pipeline, "Config", return_value=TestConfig()),
                patch.object(pipeline, "resolve_path", side_effect=Path),
                patch.object(pipeline, "calculate_scan_window", return_value=(100, 200)),
                patch.object(pipeline, "create_exporter", return_value=exporter),
                patch.object(pipeline, "ApplicationInventory", MatchingInventory),
                patch.object(pipeline, "AdvisoryCacheDB", return_value=cache),
                patch.object(pipeline, "InoreaderClient", return_value=client),
                patch.object(pipeline, "SecurityAIEvaluator", return_value=evaluator),
            ):
                pipeline.run_pipeline()

            cache.is_seen.assert_not_called()
            evaluator.evaluate_advisory.assert_called_once()
            today_str = datetime.fromtimestamp(200).strftime("%Y-%m-%d")
            exports = {
                Path(call.args[0]).name: (
                    Path(call.args[0]),
                    call.args[1],
                    call.kwargs,
                )
                for call in exporter.export_daily.call_args_list
            }
            info_path, info_records, info_options = exports[
                f"Daily_Informational_Advisories_{today_str}.xlsx"
            ]
            self.assertEqual(
                info_records[0]["advisory_heading"],
                "Cached same-day advisory",
            )
            self.assertEqual(info_records[0]["review_decision"], "☑ Selected")
            self.assertTrue(info_options["informational_only"])
            self.assertFalse(
                any(
                    record.get("advisory_type") == "Information"
                    for filename, (_, records, _) in exports.items()
                    if "Informational" not in filename
                    for record in records
                )
            )
            self.assertEqual(info_path.name, f"Daily_Informational_Advisories_{today_str}.xlsx")
            self.assertEqual(info_path.parent, daily_dir / today_str)
            self.assertTrue(all(path.parent == info_path.parent for path, _, _ in exports.values()))
            self.assertTrue(info_options["replace_existing"])

    def test_same_issue_from_two_sources_is_queued_once_with_both_sources(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            inventory_path = root / "inventory.xlsx"
            inventory_path.touch()
            daily_dir = root / "daily"
            config_paths = {
                ("paths", "inventory_excel"): str(inventory_path),
                ("paths", "master_excel"): str(root / "master.xlsx"),
                ("paths", "master_telecom_excel"): str(root / "master-telecom.xlsx"),
                ("paths", "master_vendor_excel"): str(root / "master-vendor.xlsx"),
                ("paths", "master_miscellaneous_excel"): str(root / "master-miscellaneous.xlsx"),
                ("paths", "daily_reports_dir"): str(daily_dir),
                ("paths", "cache_db"): str(root / "cache.db"),
            }

            class TestConfig:
                def get(self, *keys, default=None):
                    return config_paths.get(keys, default)

            class MatchingInventory:
                applications = ["Apache Ignite"]

                def __init__(self, _path):
                    pass

                def match(self, _title, _content):
                    return [{
                        "application_name": "Apache Ignite",
                        "vendor": "Apache",
                    }]

            class EmptyNameMatcher:
                def __init__(self, *_args, **_kwargs):
                    pass

                def match(self, _text):
                    return []

            articles = [
                {
                    "id": "source-a",
                    "title": "Apache Ignite RCE CVE-2026-12345",
                    "content": "Remote code execution affects Apache Ignite CVE-2026-12345.",
                    "source_name": "Source A",
                    "link": "https://a.example/advisory",
                    "published_timestamp": 150,
                },
                {
                    "id": "source-b",
                    "title": "Ignite vulnerability CVE-2026-12345",
                    "content": "Apache Ignite CVE-2026-12345 permits remote code execution.",
                    "source_name": "Source B",
                    "link": "https://b.example/advisory",
                    "published_timestamp": 150,
                },
            ]
            exporter = Mock()
            exporter.build_advisory_record.side_effect = (
                lambda advisory, evaluation, **_kwargs: {
                    "source_name": advisory["source_name"],
                    "advisory_heading": evaluation["advisory_heading"],
                    "link": advisory["link"],
                    "severity": "HIGH",
                    "cvss_score": "8.5",
                    "published_timestamp": advisory["published_timestamp"],
                    "impact_summary": evaluation["impact_summary"],
                    "matched_app_name": advisory["matched_app_name"],
                    "matched_vendor": advisory["matched_vendor"],
                    "advisory_type": "Actionable",
                    "cve_details": "CVE-2026-12345",
                    "cve_risk_score": "NA",
                    "cve_metrics": {},
                    "attack_vector": "NA",
                    "av_type": "NA",
                    "iocs": "NA",
                    "affected_products": "Apache Ignite",
                    "affected_versions": "2.0.0",
                    "report_summary": evaluation["report_summary"],
                    "recommendation": "",
                    "source_content": advisory["content"],
                }
            )
            exporter.export_daily.side_effect = lambda path, *_args, **_kwargs: path
            cache = Mock()
            cache.is_seen.return_value = False
            client = Mock()
            client.fetch_articles.return_value = articles
            client.enrich_article_content.side_effect = lambda article: article
            client.web_fetch_failures = 0
            evaluator = Mock()
            evaluator.evaluate_advisory.side_effect = lambda article, _match: {
                "is_actionable_vulnerability": True,
                "translated_title": article["title"],
                "translated_content": article["content"],
                "advisory_heading": article["title"],
                "impact_summary": "Remote code execution affects Apache Ignite.",
                "report_summary": article["content"],
            }

            with (
                patch.object(pipeline, "Config", return_value=TestConfig()),
                patch.object(pipeline, "resolve_path", side_effect=Path),
                patch.object(pipeline, "calculate_scan_window", return_value=(100, 200)),
                patch.object(pipeline, "create_exporter", return_value=exporter),
                patch.object(pipeline, "ApplicationInventory", MatchingInventory),
                patch.object(pipeline, "NameListMatcher", EmptyNameMatcher),
                patch.object(pipeline, "AdvisoryCacheDB", return_value=cache),
                patch.object(pipeline, "InoreaderClient", return_value=client),
                patch.object(pipeline, "SecurityAIEvaluator", return_value=evaluator),
            ):
                pipeline.run_pipeline()

            miscellaneous = next(
                call.args[1]
                for call in exporter.export_daily.call_args_list
                if "Daily_Miscellaneous_Advisories_" in call.args[0]
            )

        self.assertEqual(len(miscellaneous), 1)
        self.assertEqual(
            [reference["source_name"] for reference in miscellaneous[0]["source_references"]],
            ["Source A", "Source B"],
        )
        self.assertEqual(cache.mark_seen.call_count, 2)


if __name__ == "__main__":
    unittest.main()
