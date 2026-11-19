import sys
import tempfile
import unittest
from pathlib import Path

import openpyxl

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from excel_exporter import AdvisoryExcelExporter
from pipeline import process_reviewed_advisories


class ReviewFlowTests(unittest.TestCase):
    def test_daily_reports_are_saved_before_master_is_updated(self):
        record = {
            "advisory_heading": "Selected platform advisory",
            "review_decision": "☑ Selected",
            "severity": "HIGH",
        }

        class Exporter:
            def __init__(self):
                self.events = []
                self.master_records = None
                self.master_options = None

            def read_summary_records(self, path):
                self.events.append(("read", Path(path).name))
                return [dict(record)]

            def export_daily(self, path, records, **kwargs):
                self.events.append(("daily", kwargs))
                return path

            def append_to_master(self, path, records, **kwargs):
                self.events.append(("master", kwargs))
                self.master_records = records
                self.master_options = kwargs
                return path

        with tempfile.TemporaryDirectory() as temp_dir:
            daily_path = Path(temp_dir) / "daily.xlsx"
            daily_path.touch()
            master_path = Path(temp_dir) / "master.xlsx"
            exporter = Exporter()

            saved_daily, saved_master, selected_count, report_count = (
                process_reviewed_advisories(exporter, daily_path, master_path)
            )

        self.assertEqual([event[0] for event in exporter.events], [
            "read", "daily", "read", "master",
        ])
        self.assertEqual(exporter.master_records[0]["review_decision"], "☑ Selected")
        self.assertTrue(exporter.master_options["generate_documents"])
        self.assertFalse(exporter.master_options["preserve_review_decisions"])
        self.assertEqual((selected_count, report_count), (1, 1))
        self.assertEqual(saved_daily, str(daily_path))
        self.assertEqual(saved_master, str(master_path))

    def test_daily_report_failure_prevents_master_update(self):
        class Exporter:
            def read_summary_records(self, _path):
                return []

            def export_daily(self, _path, _records, **_kwargs):
                raise RuntimeError("daily report generation failed")

            def append_to_master(self, *_args, **_kwargs):
                raise AssertionError(
                    "Master archive must not be updated after a daily failure"
                )

        with tempfile.TemporaryDirectory() as temp_dir:
            daily_path = Path(temp_dir) / "daily.xlsx"
            daily_path.touch()
            with self.assertRaisesRegex(RuntimeError, "daily report generation failed"):
                process_reviewed_advisories(
                    Exporter(),
                    daily_path,
                    Path(temp_dir) / "master.xlsx",
                )

    def test_real_daily_review_generates_reports_before_master_record(self):
        exporter = AdvisoryExcelExporter()
        record = {
            "id": "article-daily-selected-001",
            "source_name": "Vendor",
            "advisory_heading": "Example Platform Security Advisory",
            "link": "",
            "severity": "HIGH",
            "cvss_score": "7.5",
            "published_timestamp": 1790000000,
            "impact_summary": "A vulnerability affects Example Platform.",
            "matched_app_name": "Example Platform",
            "advisory_type": "Actionable",
            "cve_details": "NA",
            "cve_risk_score": "NA",
            "attack_vector": "NA",
            "av_type": "NA",
            "iocs": "NA",
            "affected_versions": "1.x",
            "recommendation": "Upgrade Example Platform to version 2.0.",
            "source_content": (
                "A vulnerability affects Example Platform. "
                "Upgrade Example Platform to version 2.0."
            ),
            "review_decision": "☐ Pending",
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            daily_path = Path(temp_dir) / "daily.xlsx"
            master_path = Path(temp_dir) / "master.xlsx"
            exporter.export_daily(str(daily_path), [record])

            workbook = openpyxl.load_workbook(daily_path)
            summary = workbook["Summary"]
            columns = {cell.value: cell.column for cell in summary[1] if cell.value}
            summary.cell(2, columns["Review Decision"], "☑ Selected")
            workbook.save(daily_path)
            workbook.close()

            process_reviewed_advisories(exporter, daily_path, master_path)

            daily_workbook = openpyxl.load_workbook(daily_path, data_only=True)
            master_workbook = openpyxl.load_workbook(master_path, data_only=True)
            self.assertTrue(any(
                sheet.title.startswith("Report - ")
                for sheet in daily_workbook.worksheets
            ))
            self.assertTrue(any(
                sheet.title.startswith("Report - ")
                for sheet in master_workbook.worksheets
            ))
            master_summary = master_workbook["Summary"]
            master_columns = {
                cell.value: cell.column for cell in master_summary[1] if cell.value
            }
            self.assertEqual(
                master_summary.cell(
                    2,
                    master_columns["Review Decision"],
                ).value,
                "☑ Selected",
            )
            daily_workbook.close()
            master_workbook.close()


if __name__ == "__main__":
    unittest.main()
