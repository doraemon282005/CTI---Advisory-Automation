import sys
import tempfile
import unittest
from pathlib import Path

import openpyxl

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from inventory_manager import ApplicationInventory, NameListMatcher
from excel_exporter import AdvisoryExcelExporter
from pipeline import (
    process_reviewed_advisory_groups,
    route_advisory,
    route_existing_record,
    split_existing_workbooks,
)


class RoutingTests(unittest.TestCase):
    def _write_workbook(self, path, rows):
        workbook = openpyxl.Workbook()
        worksheet = workbook.active
        for row in rows:
            worksheet.append(row)
        workbook.save(path)
        workbook.close()

    def test_name_matcher_uses_named_column_and_word_boundaries(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "telecom.xlsx"
            self._write_workbook(path, [
                ["Priority", "Company / Operator"],
                [1, "Example Telecom"],
                [2, "V.tal"],
            ])

            matcher = NameListMatcher(
                str(path),
                ["company operator", "company"],
            )

            self.assertEqual(
                matcher.match("EXAMPLE TELECOM issued a security advisory."),
                ["Example Telecom"],
            )
            self.assertEqual(matcher.match("Example Telecommunications"), [])
            self.assertEqual(matcher.match("V.tal security advisory"), ["V.tal"])

    def test_inventory_additions_are_loaded_from_updated_workbook(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "inventory.xlsx"
            self._write_workbook(path, [
                ["Application Name"],
                ["Newly Added Platform"],
            ])

            inventory = ApplicationInventory(str(path))

            matches = inventory.match(
                "Newly Added Platform security advisory CVE-2026-54321",
                "A vulnerability affects this platform.",
            )

        self.assertEqual(matches[0]["application_name"], "Newly Added Platform")

    def test_headerless_vendor_workbook_keeps_first_name(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "vendors.xlsx"
            self._write_workbook(path, [
                ["FIRST VENDOR LIMITED"],
                ["SECOND VENDOR LIMITED"],
            ])

            matcher = NameListMatcher(
                str(path),
                ["vendor", "vendor name", "company"],
            )

            self.assertEqual(
                matcher.match("A security advisory affects First Vendor Limited."),
                ["FIRST VENDOR LIMITED"],
            )

    def test_name_matcher_avoids_common_words_in_company_lists(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "telecom.xlsx"
            self._write_workbook(path, [
                ["BASE"],
                ["du"],
                ["Local"],
                ["NOW"],
                ["LEARN"],
                ["R"],
                ["48"],
            ])

            matcher = NameListMatcher(str(path), ["company"])

            self.assertEqual(
                matcher.match(
                    "CVSS Base score; Local privilege escalation; "
                    "it works now; Learn more; R version 2; 48 hours; du régiment."
                ),
                [],
            )
            self.assertEqual(matcher.match("The BASE network issued an advisory."), ["BASE"])
            self.assertEqual(matcher.match("du mobile network advisory"), ["du"])

    def test_vendor_match_is_not_overridden_by_common_telecom_words(self):
        class FakeInventory:
            def match(self, _title, _content):
                return [{"application_name": "Example App"}]

        with tempfile.TemporaryDirectory() as temp_dir:
            telecom_path = Path(temp_dir) / "telecom.xlsx"
            vendor_path = Path(temp_dir) / "vendors.xlsx"
            self._write_workbook(
                telecom_path,
                [["du"], ["SES"], ["NOW"], ["BASE"]],
            )
            self._write_workbook(vendor_path, [["IBM"]])
            telecom = NameListMatcher(str(telecom_path), ["company"])
            vendor = NameListMatcher(str(vendor_path), ["vendor"])

            route = route_advisory(
                {
                    "title": "Zoom security advisory",
                    "content": (
                        "A security issue affects Zoom. The article mentions IBM; "
                        "the update is available now and discusses a base score."
                    ),
                },
                telecom,
                vendor,
                FakeInventory(),
            )

        self.assertEqual(route[0], "vendor")
        self.assertEqual(route[1][0]["application_name"], "Example App")

    def test_company_names_in_related_links_do_not_route_the_advisory(self):
        class FakeInventory:
            def match(self, _title, _content):
                return [{"application_name": "Example App"}]

        with tempfile.TemporaryDirectory() as temp_dir:
            telecom_path = Path(temp_dir) / "telecom.xlsx"
            vendor_path = Path(temp_dir) / "vendors.xlsx"
            self._write_workbook(telecom_path, [["Cisco"]])
            self._write_workbook(vendor_path, [["IBM"]])
            telecom = NameListMatcher(str(telecom_path), ["company"])
            vendor = NameListMatcher(str(vendor_path), ["vendor"])

            route = route_advisory(
                {
                    "title": "Example App security advisory",
                    "content": (
                        "The advisory body. Related stories mention IBM and Cisco."
                    ),
                },
                telecom,
                vendor,
                FakeInventory(),
            )

        self.assertEqual(route[0], "miscellaneous")

    def test_inventory_match_is_required_before_telecom_vendor_routing(self):
        class FakeInventory:
            def match(self, _title, _content):
                return [{"application_name": "Example App", "vendor": "Example"}]

        class NoMatchInventory:
            def match(self, _title, _content):
                return []

        with tempfile.TemporaryDirectory() as temp_dir:
            telecom_path = Path(temp_dir) / "telecom.xlsx"
            vendor_path = Path(temp_dir) / "vendor.xlsx"
            self._write_workbook(telecom_path, [["Telecom Name"], ["Global Telecom"]])
            self._write_workbook(vendor_path, [["Vendor Name"], ["Global Vendor"]])
            telecom = NameListMatcher(str(telecom_path), ["telecom name"])
            vendor = NameListMatcher(str(vendor_path), ["vendor name"])
            inventory = FakeInventory()

            both = route_advisory(
                {"title": "Global Telecom and Global Vendor advisory", "content": ""},
                telecom,
                vendor,
                inventory,
            )
            vendor_and_app = route_advisory(
                {"title": "Global Vendor security advisory", "content": ""},
                telecom,
                vendor,
                inventory,
            )
            app_only = route_advisory(
                {"title": "Application advisory", "content": ""},
                telecom,
                vendor,
                inventory,
            )
            no_application_match = route_advisory(
                {"title": "Global Telecom advisory", "content": ""},
                telecom,
                vendor,
                NoMatchInventory(),
            )

            self.assertEqual(both[0], "telecom")
            self.assertEqual(both[1][0]["application_name"], "Example App")
            self.assertEqual(vendor_and_app[0], "vendor")
            self.assertEqual(app_only[0], "miscellaneous")
            self.assertIsNone(no_application_match)

    def test_existing_records_are_split_once_by_priority(self):
        records = [
            {
                "id": "both",
                "advisory_heading": "Global Telecom and Global Vendor",
                "source_content": "Advisory text",
                "matched_app_name": "Example App",
            },
            {
                "id": "vendor",
                "advisory_heading": "Global Vendor security advisory",
                "source_content": "Advisory text",
            },
            {
                "id": "application",
                "advisory_heading": "Example application advisory",
                "source_content": "Advisory text",
            },
            {
                "id": "both",
                "advisory_heading": "Duplicate",
                "source_content": "",
            },
        ]

        class FakeExporter:
            def __init__(self):
                self.master_records = {}
                self.daily_records = {}

            def read_summary_records(self, _path):
                return [dict(record) for record in records]

            def append_to_master(self, path, routed, **_kwargs):
                self.master_records[Path(path).name] = routed

            def export_daily(self, path, routed, **_kwargs):
                self.daily_records[Path(path).name] = routed

        class FixedMatcher:
            def __init__(self, names):
                self.names = names

            def match(self, text):
                return self.names if any(name in text for name in self.names) else []

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            legacy_master = root / "legacy-master.xlsx"
            legacy_daily = root / "legacy-daily.xlsx"
            legacy_master.touch()
            legacy_daily.touch()
            groups = {
                group: {
                    "master_path": root / f"{group}-master.xlsx",
                    "daily_path": root / f"{group}-daily.xlsx",
                }
                for group in ("telecom", "vendor", "miscellaneous")
            }
            exporter = FakeExporter()
            counts = split_existing_workbooks(
                exporter,
                legacy_master,
                legacy_daily,
                groups,
                FixedMatcher(["Global Telecom"]),
                FixedMatcher(["Global Vendor"]),
            )

        self.assertEqual(counts["master"], {
            "telecom": 1,
            "vendor": 1,
            "miscellaneous": 1,
        })
        self.assertEqual(counts["daily"], {
            "telecom": 1,
            "vendor": 1,
            "miscellaneous": 1,
        })
        self.assertEqual(
            exporter.master_records["telecom-master.xlsx"][0]["id"],
            "both",
        )
        self.assertEqual(
            exporter.master_records["telecom-master.xlsx"][0]["matched_app_name"],
            "Example App",
        )
        self.assertEqual(
            exporter.master_records["vendor-master.xlsx"][0]["id"],
            "vendor",
        )
        self.assertEqual(
            exporter.master_records["miscellaneous-master.xlsx"][0]["id"],
            "application",
        )

    def test_existing_record_routing_ignores_unrelated_page_links(self):
        class FixedMatcher:
            def __init__(self, names):
                self.names = names

            def match(self, text):
                lowered = text.casefold()
                return [name for name in self.names if name.casefold() in lowered]

        record = {
            "advisory_heading": "Example App security advisory",
            "report_summary": "A vulnerability affects Example App.",
            "impact_summary": "Remote code execution in Example App.",
            "source_content": (
                "The advisory body. Related stories mention IBM and Local privilege escalation."
            ),
        }

        self.assertEqual(
            route_existing_record(
                record,
                FixedMatcher(["Local"]),
                FixedMatcher(["IBM"]),
            ),
            "miscellaneous",
        )

    def test_review_command_processes_each_available_category_workbook(self):
        class FakeExporter:
            def __init__(self):
                self.daily_paths = []
                self.master_paths = []

            def read_summary_records(self, _path):
                return []

            def export_daily(self, path, _records, **_kwargs):
                self.daily_paths.append(Path(path).name)
                return path

            def append_to_master(self, path, _records, **_kwargs):
                self.master_paths.append(Path(path).name)
                return path

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            groups = {}
            for group in ("telecom", "vendor", "miscellaneous"):
                daily_path = root / f"{group}-daily.xlsx"
                if group != "vendor":
                    daily_path.touch()
                groups[group] = {
                    "label": group.title(),
                    "daily_path": daily_path,
                    "master_path": root / f"{group}-master.xlsx",
                }

            exporter = FakeExporter()
            results = process_reviewed_advisory_groups(
                exporter, groups, pending_days=7, ai_evaluator=None
            )

        self.assertEqual([result[0] for result in results], ["Telecom", "Miscellaneous"])
        self.assertEqual(
            exporter.daily_paths,
            ["telecom-daily.xlsx", "miscellaneous-daily.xlsx"],
        )
        self.assertEqual(
            exporter.master_paths,
            ["telecom-master.xlsx", "miscellaneous-master.xlsx"],
        )

    def test_master_migration_preserves_recorded_date(self):
        record = {
            "recorded_date": "2021-06-15 09:30",
            "id": "legacy-advisory",
            "source_name": "Example Vendor",
            "advisory_heading": "Example security advisory",
            "link": "",
            "severity": "HIGH",
            "cvss_score": "7.5",
            "published_timestamp": 1623749400,
            "impact_summary": "An example vulnerability.",
            "matched_app_name": "Example App",
            "advisory_type": "Information",
            "cve_details": "NA",
            "cve_risk_score": "NA",
            "attack_vector": "NA",
            "av_type": "NA",
            "iocs": "NA",
            "review_decision": "☑ Selected",
            "source_content": "An example vulnerability affects Example App.",
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "master.xlsx"
            exporter = AdvisoryExcelExporter()
            exporter.append_to_master(
                str(path),
                [record],
                generate_documents=False,
            )
            workbook = openpyxl.load_workbook(path, data_only=True)
            informational = workbook["Informational"]
            columns = {
                cell.value: cell.column
                for cell in informational[1]
                if cell.value
            }
            self.assertEqual(
                informational.cell(2, columns["Recorded Date"]).value,
                "2021-06-15 09:30",
            )
            self.assertEqual(
                informational.cell(2, columns["Review Decision"]).value,
                "☑ Selected",
            )
            workbook.close()


if __name__ == "__main__":
    unittest.main()
