import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import openpyxl

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from excel_exporter import AdvisoryExcelExporter
from tenable_client import TenableClient
from ai_evaluator import SecurityAIEvaluator


class ReportEnrichmentTests(unittest.TestCase):
    def test_extracts_remediation_and_cve_specific_scores(self):
        exporter = AdvisoryExcelExporter()
        content = (
            "CVE-2026-126170 carries a CVSS score of 9.8.\n"
            "Another flaw, CVE-2026-126261, is rated 9.0.\n"
            "CVE-2026-126254 is a 9.6-rated vulnerability.\n"
            "CVE-2026-126255 has a CVSS score of 10.0.\n"
            "Fixed releases are 8.0.1 and 7.6.8. Disable unused JSON API access."
        )

        self.assertEqual(exporter._extract_cve_score(content, "CVE-2026-126170"), "9.8")
        self.assertEqual(exporter._extract_cve_score(content, "CVE-2026-126261"), "9.0")
        self.assertEqual(exporter._extract_cve_score(content, "CVE-2026-126254"), "9.6")
        self.assertEqual(exporter._extract_cve_score(content, "CVE-2026-126255"), "10.0")
        recommendation = exporter.extract_recommendation(content)
        self.assertIn("Fixed releases are 8.0.1 and 7.6.8.", recommendation)
        self.assertIn("Disable unused JSON API access.", recommendation)
        xen_recommendation = exporter.extract_recommendation(
            "Xen Security Advisory. Attachment: xsa532-linux.patch Description:"
        )
        self.assertIn("xsa532-linux.patch", xen_recommendation)
        airflow_recommendation = exporter.extract_recommendation(
            "The flaw affects Apache Airflow versions before 3.4.0 using CeleryExecutor."
        )
        self.assertIn("Upgrade Apache Airflow to version 3.4.0 or later", airflow_recommendation)

    def test_missing_remediation_uses_visible_vendor_advisory_fallback(self):
        exporter = AdvisoryExcelExporter()

        recommendation = exporter._ensure_recommendation("  ")

        self.assertIn("Consult the linked vendor advisory", recommendation)
        self.assertTrue(recommendation.strip())
        self.assertEqual(exporter._display_value(""), "Not available")
        self.assertEqual(exporter._display_value("9.8"), "9.8")

    def test_rule_based_evaluation_provides_report_summary_and_products(self):
        evaluator = SecurityAIEvaluator(api_key="", openai_api_key="")
        evaluation = evaluator._rule_based_fallback(
            {
                "title": "Example Platform RCE Vulnerability CVE-2026-12345",
                "content": (
                    "The vulnerability in Example Platform allows remote code execution. "
                    "It affects versions 4.1 through 4.3. CVSS score is 9.8."
                ),
            },
            {"application_name": "Example Platform"},
        )

        self.assertIn("Example Platform", evaluation["affected_products"])
        self.assertIn("4.1 through 4.3", "\n".join(evaluation["report_summary"].splitlines()))
        self.assertGreaterEqual(len(evaluation["report_summary"].splitlines()), 3)
        self.assertLessEqual(len(evaluation["report_summary"].splitlines()), 4)

    def test_report_summary_is_limited_to_500_words(self):
        evaluator = SecurityAIEvaluator(api_key="", openai_api_key="")
        long_summary = " ".join(f"word{index}" for index in range(600))

        limited = evaluator.limit_summary_words(long_summary)

        self.assertLessEqual(len(limited.split()), 500)

    def test_information_only_workbook_lists_records_on_its_summary(self):
        exporter = AdvisoryExcelExporter()
        records = [{
            "id": "informational-1",
            "advisory_heading": "General platform update",
            "advisory_type": "Information",
            "review_decision": "☑ Selected",
        }]

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "Daily_Informational_Advisories_2026-11-19.xlsx"
            exporter.export_daily(
                str(output),
                records,
                informational_only=True,
                replace_existing=True,
            )

            workbook = openpyxl.load_workbook(output, data_only=True)
            self.assertEqual(workbook.sheetnames, ["Summary"])
            summary = workbook["Summary"]
            summary_columns = {
                cell.value: cell.column
                for cell in summary[1]
                if cell.value
            }
            self.assertEqual(
                summary.cell(2, summary_columns["Advisory Heading"]).value,
                "General platform update",
            )
            self.assertEqual(
                summary.cell(2, summary_columns["Advisory Type"]).value,
                "Information",
            )
            workbook.close()

    def test_missing_affected_versions_are_not_filled_with_placeholders(self):
        evaluator = SecurityAIEvaluator(api_key="", openai_api_key="")
        evaluation = evaluator._rule_based_fallback(
            {
                "title": "Example Platform Remote Code Execution Vulnerability",
                "content": (
                    "A vulnerability in Example Platform allows remote code execution. "
                    "The vendor has not published an affected version range."
                ),
            },
            {"application_name": "Example Platform"},
        )

        self.assertEqual(evaluation["affected_products"], "Example Platform")
        self.assertEqual(evaluation["affected_versions"], "")
        self.assertNotIn("See vendor advisory", evaluation["report_summary"])
        extracted_products, extracted_versions = evaluator._extract_affected_details(
            "Chips boast up to 256 cores, clocks up to 5.3 GHz, and IPC gains "
            "of 20 to 31 percent. Mint 27 launches before Christmas with "
            "Cinnamon 6.8 upgrades.",
            "axis",
        )
        self.assertEqual(extracted_products, "axis")
        self.assertEqual(extracted_versions, "")

        exporter = AdvisoryExcelExporter()
        details = exporter._affected_products_text(
            {
                "affected_products": (
                    "Example Platform: See vendor advisory for affected versions"
                ),
                "affected_versions": "Check vendor bulletin",
                "matched_app_name": "Example Platform",
            }
        )
        self.assertEqual(details, "Affected products: Example Platform")
        self.assertEqual(
            exporter._normalize_affected_versions(
                "Chips boast up to 256 cores, clocks up to 5.3 GHz; "
                "Cinnamon 6.8 upgrades"
            ),
            "",
        )

    def test_report_summary_prefers_security_facts_over_release_background(self):
        exporter = AdvisoryExcelExporter()
        summary = exporter._build_report_summary(
            {
                "report_summary": (
                    "Ubuntu 26.10 adds certificate checks to curl.\n"
                    "Announced on November 10, this change brings support to the package.\n"
                    "It marks an initial step toward broader checks."
                ),
                "impact_summary": (
                    "A memory corruption flaw permits unauthenticated remote code execution."
                ),
                "source_content": (
                    "A memory corruption flaw in Example Platform allows remote code execution. "
                    "Attackers can execute code remotely without authentication."
                ),
                "affected_products": "Example Platform",
                "affected_versions": "NA",
                "matched_app_name": "Example Platform",
                "severity": "HIGH",
                "cvss_score": "8.2 (Base)",
            }
        )

        self.assertIn("memory corruption", summary.casefold())
        self.assertIn("remote code execution", summary.casefold())
        self.assertNotIn("announced on november", summary.casefold())
        self.assertNotIn("initial step", summary.casefold())
        self.assertNotIn("version", summary.casefold())

    def test_long_report_content_is_rendered_as_meaningful_bullets(self):
        exporter = AdvisoryExcelExporter()
        result = exporter._format_as_bullets(
            "Threat details:\n"
            "Unauthenticated access allows remote code execution. "
            "CVE-2026-12345 affects versions before 3.4.0; upgrade to 3.4.0."
        )

        self.assertIn("• Threat details:", result)
        self.assertIn("• Unauthenticated access allows remote code execution.", result)
        self.assertIn("• CVE-2026-12345 affects versions before 3.4.0", result)
        self.assertIn("• upgrade to 3.4.0.", result)

    def test_daily_rebuild_replaces_old_workbook_and_generated_sheets(self):
        exporter = AdvisoryExcelExporter()
        old_record = {
            "id": "old-article",
            "advisory_heading": "Old same-day advisory",
            "review_decision": "☒ Rejected",
        }
        new_record = {
            "id": "new-article",
            "advisory_heading": "New same-day advisory",
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "daily.xlsx"
            exporter.export_daily(str(output), [old_record])
            workbook = openpyxl.load_workbook(output)
            workbook.create_sheet("Advisory Document Old")
            workbook.save(output)
            workbook.close()

            exporter.export_daily(
                str(output),
                [new_record],
                replace_existing=True,
            )

            workbook = openpyxl.load_workbook(output, data_only=True)
            summary = workbook["Summary"]
            columns = {cell.value: cell.column for cell in summary[1] if cell.value}
            headings = [
                summary.cell(row_idx, columns["Advisory Heading"]).value
                for row_idx in range(2, summary.max_row + 1)
            ]
            decisions = [
                summary.cell(row_idx, columns["Review Decision"]).value
                for row_idx in range(2, summary.max_row + 1)
            ]
            self.assertEqual(headings, ["New same-day advisory"])
            self.assertEqual(decisions, ["☑ Selected"])
            self.assertNotIn("Advisory Document Old", workbook.sheetnames)
            workbook.close()

    def test_summary_layout_and_report_button_link_to_the_generated_sheet(self):
        exporter = AdvisoryExcelExporter()
        record = {
            "advisory_heading": "Example Platform Remote Code Execution",
            "source_name": "Vendor",
            "link": "https://example.test/advisory",
            "severity": "HIGH",
            "cvss_score": "7.5",
            "published_timestamp": 1790000000,
            "impact_summary": "A remote code execution flaw affects Example Platform.",
            "matched_app_name": "Example Platform",
            "advisory_type": "Information",
            "cve_details": "CVE-2026-12345",
            "cve_risk_score": "NA",
            "attack_vector": "Network",
            "av_type": "Network",
            "iocs": "NA",
            "recommendation": "Apply the vendor update.",
            "source_content": "Apply the vendor update.",
            "review_decision": "☑ Selected",
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "daily.xlsx"
            exporter.export_daily(str(output), [record], generate_documents=True)

            workbook = openpyxl.load_workbook(output)
            summary = workbook["Summary"]
            columns = {cell.value: cell.column for cell in summary[1] if cell.value}
            self.assertEqual(
                columns["Advisory Type"],
                columns["Advisory Heading"] - 1,
            )
            self.assertEqual(
                columns["View Report"],
                columns["Link of Advisory"] + 1,
            )
            informational = workbook["Informational"]
            info_columns = {
                cell.value: cell.column
                for cell in informational[1]
                if cell.value
            }
            self.assertEqual(informational.max_row, 2)
            self.assertEqual(
                informational.cell(2, info_columns["Advisory Heading"]).value,
                record["advisory_heading"],
            )
            self.assertFalse(
                any(
                    sheet.title.startswith("Report - ")
                    for sheet in workbook.worksheets
                )
            )
            workbook.close()

    def test_existing_summary_columns_are_migrated_to_the_new_layout(self):
        exporter = AdvisoryExcelExporter()
        legacy_headers = [
            "Source Name",
            "Advisory Heading",
            "Link of Advisory",
            "Severity",
            "CVSS",
            "Published Date & Time",
            "Security Impact / Summary",
            "Matched Application / Component",
            "Advisory Type",
            "CVE Details",
            "CVE Risk Score",
            "Attack Vector",
            "AV Type",
            "IOCs",
        ]
        legacy_row = [
            "Vendor",
            "Legacy platform advisory",
            "View Advisory",
            "HIGH",
            "7.5",
            "2026-11-13 00:00",
            "An example security issue.",
            "Example Platform",
            "Information",
            "NA",
            "NA",
            "Network",
            "Network",
            "NA",
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "daily.xlsx"
            workbook = openpyxl.Workbook()
            summary = workbook.active
            summary.title = "Summary"
            summary.append(legacy_headers)
            summary.append(legacy_row)
            workbook.save(output)
            workbook.close()

            exporter.export_daily(str(output), [])

            workbook = openpyxl.load_workbook(output, data_only=True)
            summary = workbook["Summary"]
            columns = {cell.value: cell.column for cell in summary[1] if cell.value}
            self.assertEqual(
                columns["Advisory Type"],
                columns["Advisory Heading"] - 1,
            )
            self.assertEqual(
                columns["View Report"],
                columns["Link of Advisory"] + 1,
            )
            self.assertEqual(
                workbook["Informational"].cell(
                    2,
                    {
                        cell.value: cell.column
                        for cell in workbook["Informational"][1]
                        if cell.value
                    }["Advisory Heading"],
                ).value,
                "Legacy platform advisory",
            )
            self.assertEqual(
                workbook["Informational"].cell(
                    2,
                    {
                        cell.value: cell.column
                        for cell in workbook["Informational"][1]
                        if cell.value
                    }["View Report"],
                ).value,
                "Not generated",
            )
            workbook.close()

    def test_source_content_is_checked_against_advisory_identity(self):
        exporter = AdvisoryExcelExporter()
        record = {
            "advisory_heading": (
                "Critical Apache Airflow Flaw CVE-2026-68982 Enables "
                "Unauthenticated Remote Code Execution"
            ),
            "cve_details": "CVE-2026-68982",
            "matched_app_name": "python",
        }

        self.assertTrue(exporter._source_content_matches_record(
            record,
            "Apache Airflow versions before 3.4.0 are affected by CVE-2026-68982.",
        ))
        self.assertFalse(exporter._source_content_matches_record(
            record,
            "The CyberXero tool wp2shell exploits the WordPress REST API.",
        ))
        self.assertFalse(exporter._source_content_matches_record(
            record,
            "CVE-2026-99286 affects Xen Linux network statistics.",
        ))

    @patch.object(AdvisoryExcelExporter, "_nvd_cve_lookup_many")
    @patch.object(
        AdvisoryExcelExporter,
        "_fetch_source_content",
        return_value="The CyberXero tool wp2shell exploits the WordPress REST API.",
    )
    def test_rebuild_rejects_mismatched_page_and_uses_fallback(
        self, _fetch, _nvd_lookup
    ):
        exporter = AdvisoryExcelExporter()
        record = {
            "advisory_heading": (
                "Critical Apache Airflow Flaw CVE-2026-68982 Enables "
                "Unauthenticated Remote Code Execution"
            ),
            "source_name": "GBHackers On Security",
            "link": "https://example.test/advisory",
            "severity": "CRITICAL",
            "cvss_score": "9.8",
            "published_timestamp": 1790000000,
            "impact_summary": "An unauthenticated remote code execution flaw affects Airflow.",
            "matched_app_name": "python",
            "advisory_type": "Patching",
            "cve_details": "CVE-2026-68982",
            "cve_risk_score": "9.8",
            "attack_vector": "NA",
            "av_type": "NA",
            "iocs": "NA",
            "affected_versions": "Before 3.4.0",
            "recommendation": "NA",
            "source_content": "",
            "review_decision": "Selected",
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "daily.xlsx"
            exporter.export_daily(
                str(output),
                [record],
                refresh_enrichment=True,
                generate_documents=True,
            )

            workbook = openpyxl.load_workbook(output, data_only=True)
            document = next(
                sheet for sheet in workbook.worksheets
                if sheet.title.startswith("Report - ")
            )
            self.assertNotIn("wp2shell", str(document["B8"].value).casefold())
            self.assertNotIn("wp2shell", str(document["B13"].value).casefold())
            self.assertIn("Consult the linked vendor advisory", document["B13"].value)
            workbook.close()
        _fetch.assert_called_once()

    def test_rebuild_preserves_matching_feed_content_over_corrupt_history(self):
        exporter = AdvisoryExcelExporter()
        content = (
            "Apache Airflow versions before 3.4.0 using CeleryExecutor are affected "
            "by CVE-2026-68982. Upgrade Apache Airflow to version 3.4.0 or later."
        )
        record = {
            "advisory_heading": (
                "Critical Apache Airflow Flaw CVE-2026-68982 Enables "
                "Unauthenticated Remote Code Execution"
            ),
            "source_name": "GBHackers On Security",
            "link": "https://example.test/advisory",
            "severity": "CRITICAL",
            "cvss_score": "9.8",
            "published_timestamp": 1790000000,
            "impact_summary": "An unauthenticated remote code execution flaw affects Airflow.",
            "matched_app_name": "python",
            "advisory_type": "Patching",
            "cve_details": "CVE-2026-68982",
            "cve_risk_score": "9.8",
            "attack_vector": "NA",
            "av_type": "NA",
            "iocs": "NA",
            "affected_versions": "Before 3.4.0",
            "recommendation": "Upgrade Apache Airflow to version 3.4.0 or later.",
            "source_content": content,
            "review_decision": "Selected",
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "daily.xlsx"
            exporter.export_daily(str(output), [record], generate_documents=True)

            workbook = openpyxl.load_workbook(output)
            document = next(
                sheet for sheet in workbook.worksheets
                if sheet.title.startswith("Report - ")
            )
            document["B8"] = "Unrelated CyberXero wp2shell WordPress content."
            document["B13"] = "Investigate the unrelated wp2shell tool."
            workbook.save(output)
            workbook.close()

            exporter.export_daily(
                str(output),
                [record],
                refresh_enrichment=True,
                generate_documents=True,
            )

            workbook = openpyxl.load_workbook(output, data_only=True)
            document = next(
                sheet for sheet in workbook.worksheets
                if sheet.title.startswith("Report - ")
            )
            self.assertIn("CVE-2026-68982", document["B8"].value)
            self.assertNotIn("wp2shell", document["B8"].value.casefold())
            self.assertIn("Upgrade Apache Airflow", document["B13"].value)
            self.assertNotIn("wp2shell", document["B13"].value.casefold())
            workbook.close()

    def test_existing_master_entry_refreshes_its_advisory_link(self):
        exporter = AdvisoryExcelExporter()
        record = {
            "advisory_heading": "Example platform advisory",
            "source_name": "Vendor",
            "link": "https://example.test/old-advisory",
            "severity": "HIGH",
            "cvss_score": "NA",
            "published_timestamp": 1790000000,
            "impact_summary": "An update is available for the example platform.",
            "matched_app_name": "Example platform",
            "advisory_type": "Information",
            "cve_details": "NA",
            "cve_risk_score": "NA",
            "attack_vector": "NA",
            "av_type": "NA",
            "iocs": "NA",
            "affected_versions": "NA",
            "recommendation": "Install the vendor update.",
            "source_content": "Example platform advisory: install the vendor update.",
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "master.xlsx"
            exporter.append_to_master(str(output), [record])

            updated_record = dict(record, link="https://example.test/current-advisory")
            exporter.append_to_master(str(output), [updated_record])

            workbook = openpyxl.load_workbook(output)
            summary = workbook["Summary"]
            columns = {cell.value: cell.column for cell in summary[1] if cell.value}
            info_sheet = workbook["Informational"]
            link_cell = info_sheet.cell(
                row=2,
                column={
                    cell.value: cell.column
                    for cell in info_sheet[1]
                    if cell.value
                }["Link of Advisory"],
            )
            self.assertEqual(link_cell.hyperlink.target, updated_record["link"])
            self.assertEqual(info_sheet.max_row, 2)
            workbook.close()

    def test_master_deduplicates_by_article_id_when_heading_changes(self):
        exporter = AdvisoryExcelExporter()
        original = {
            "id": "article-unique-001",
            "advisory_heading": "Original advisory heading",
            "source_name": "Vendor",
            "link": "",
            "severity": "HIGH",
            "review_decision": "☐ Pending",
        }
        refreshed = dict(
            original,
            advisory_heading="Refined advisory heading",
            link="https://example.test/article-unique-001",
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "master.xlsx"
            exporter.append_to_master(str(output), [original])
            exporter.append_to_master(str(output), [refreshed])

            workbook = openpyxl.load_workbook(output)
            summary = workbook["Summary"]
            columns = {cell.value: cell.column for cell in summary[1] if cell.value}
            link_cell = summary.cell(2, columns["Link of Advisory"])
            self.assertEqual(summary.max_row, 2)
            self.assertEqual(link_cell.hyperlink.target, refreshed["link"])
            workbook.close()

    def test_existing_daily_entry_refreshes_advisory_link(self):
        exporter = AdvisoryExcelExporter()
        record = {
            "advisory_heading": "Daily link recovery advisory",
            "source_name": "Vendor",
            "link": "",
            "severity": "HIGH",
            "review_decision": "☐ Pending",
        }
        updated_record = dict(record, link="https://example.test/recovered-advisory")

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "daily.xlsx"
            exporter.export_daily(str(output), [record])
            exporter.export_daily(str(output), [updated_record])

            workbook = openpyxl.load_workbook(output)
            summary = workbook["Summary"]
            columns = {cell.value: cell.column for cell in summary[1] if cell.value}
            link_cell = summary.cell(row=2, column=columns["Link of Advisory"])
            self.assertEqual(link_cell.hyperlink.target, updated_record["link"])
            self.assertEqual(summary.max_row, 2)
            workbook.close()

    def test_daily_reprocessing_preserves_human_review_decision(self):
        exporter = AdvisoryExcelExporter()
        record = {
            "advisory_heading": "Reviewed daily advisory",
            "source_name": "Vendor",
            "link": "https://example.test/reviewed",
            "severity": "HIGH",
            "review_decision": "☑ Selected",
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "daily.xlsx"
            exporter.export_daily(str(output), [record])
            exporter.export_daily(
                str(output),
                [dict(record, review_decision="☐ Pending")],
            )

            workbook = openpyxl.load_workbook(output, data_only=True)
            summary = workbook["Summary"]
            columns = {cell.value: cell.column for cell in summary[1] if cell.value}
            informational = workbook["Informational"]
            info_columns = {
                cell.value: cell.column
                for cell in informational[1]
                if cell.value
            }
            self.assertEqual(
                informational.cell(2, info_columns["Review Decision"]).value,
                "☑ Selected",
            )
            workbook.close()

    def test_daily_review_decision_updates_existing_master_entry(self):
        exporter = AdvisoryExcelExporter()
        record = {
            "id": "article-reviewed-001",
            "advisory_heading": "Reviewed platform advisory",
            "source_name": "Vendor",
            "link": "",
            "severity": "HIGH",
            "review_decision": "☒ Rejected",
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "master.xlsx"
            exporter.append_to_master(str(output), [record])
            exporter.append_to_master(
                str(output),
                [dict(record, review_decision="☑ Selected")],
                preserve_review_decisions=False,
            )

            saved_record = exporter.read_summary_records(str(output))[0]
            self.assertEqual(saved_record["review_decision"], "☑ Selected")

    def test_unreadable_existing_workbook_is_not_replaced(self):
        exporter = AdvisoryExcelExporter()

        with tempfile.TemporaryDirectory() as temp_dir:
            for name, update in (
                ("daily.xlsx", lambda path: exporter.export_daily(str(path), [])),
                ("master.xlsx", lambda path: exporter.append_to_master(str(path), [])),
            ):
                path = Path(temp_dir) / name
                original_content = b"corrupt workbook content"
                path.write_bytes(original_content)

                with self.subTest(workbook=name):
                    with self.assertRaisesRegex(RuntimeError, "it was not modified"):
                        update(path)
                    self.assertEqual(path.read_bytes(), original_content)

    def test_new_daily_candidates_default_to_selected(self):
        exporter = AdvisoryExcelExporter()
        record = {
            "advisory_heading": "Auto-selected platform advisory",
            "source_name": "Vendor",
            "severity": "HIGH",
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "daily.xlsx"
            exporter.export_daily(str(output), [record])

            saved_record = exporter.read_summary_records(str(output))[0]
            self.assertEqual(saved_record["review_decision"], "☑ Selected")

    @patch.object(AdvisoryExcelExporter, "_nvd_cve_lookup_many")
    def test_report_summary_classification_and_affected_versions(self, _nvd_lookup):
        exporter = AdvisoryExcelExporter()
        additional_products = "; ".join(
            f"Example Product {index} versions {index}.1 through {index}.3"
            for index in range(3, 13)
        )
        record = {
            "advisory_heading": "Example Platform Remote Code Execution Vulnerability",
            "source_name": "Vendor",
            "link": "https://example.test/advisory",
            "severity": "CRITICAL",
            "cvss_score": "9.8",
            "published_timestamp": 1790000000,
            "impact_summary": (
                "The memory corruption flaw permits unauthenticated remote code execution."
            ),
            "report_summary": (
                "Example Platform contains a memory corruption flaw.\n"
                "A remote attacker can execute code without authentication.\n"
                "The issue affects Example Platform versions 4.1 through 4.3.\n"
                "The vendor has released a security update."
            ),
            "matched_app_name": "Example Platform",
            "affected_products": (
                "Example Platform 4.1 through 4.3; "
                "Example Gateway 2.0 through 2.2; "
                f"{additional_products}"
            ),
            "affected_versions": "Example Platform 4.1-4.3; Example Gateway 2.0-2.2",
            "advisory_type": "Patching",
            "cve_details": "CVE-2026-12345",
            "cve_risk_score": "9.8",
            "attack_vector": "Network",
            "av_type": "Network",
            "iocs": "NA",
            "recommendation": "Upgrade to the fixed vendor release.",
            "source_content": (
                "A memory corruption flaw affects Example Platform 4.1 through 4.3. "
                "Example Gateway versions 2.0 through 2.2 are also affected."
            ),
            "review_decision": "☑ Selected",
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "daily.xlsx"
            exporter.export_daily(str(output), [record], generate_documents=True)

            workbook = openpyxl.load_workbook(output, data_only=True)
            document = next(
                sheet for sheet in workbook.worksheets
                if sheet.title.startswith("Report - ")
            )
            summary_lines = document["B3"].value.splitlines()
            self.assertGreaterEqual(len(summary_lines), 3)
            self.assertLessEqual(len(summary_lines), 4)
            self.assertIn("Remote Code Execution (RCE)", document["B4"].value)
            self.assertIn(record["impact_summary"], document["B4"].value)
            self.assertIn("Example Platform 4.1 through 4.3", document["B7"].value)
            self.assertIn("Example Gateway 2.0 through 2.2", document["B7"].value)
            self.assertIn("Example Product 12 versions 12.1 through 12.3", document["B7"].value)
            workbook.close()

    def test_iocs_are_defanged_in_summary_and_report(self):
        exporter = AdvisoryExcelExporter()
        raw_ip = "192.168.34.5"
        raw_url = "https://malicious.example/path"
        record = {
            "id": "article-ioc-defang-001",
            "source_name": "Vendor",
            "advisory_heading": "Example Platform Security Advisory",
            "link": "https://vendor.example/advisory",
            "severity": "HIGH",
            "cvss_score": "7.5",
            "published_timestamp": 1790000000,
            "impact_summary": "An attacker may exploit Example Platform.",
            "report_summary": (
                "Example Platform contains a vulnerability.\n"
                "The issue may allow remote access to the service.\n"
                f"Observed indicators include {raw_ip} and {raw_url}.\n"
                "Review the vendor advisory for mitigation."
            ),
            "matched_app_name": "Example Platform",
            "affected_products": "Example Platform 4.1",
            "affected_versions": "4.1",
            "advisory_type": "Actionable",
            "cve_details": "NA",
            "cve_risk_score": "NA",
            "attack_vector": "Network",
            "av_type": "Network",
            "iocs": f"{raw_ip}; {raw_url}",
            "recommendation": "Apply the vendor update.",
            "source_content": (
                f"Example Platform vulnerability. Indicator: {raw_ip}, {raw_url}."
            ),
            "review_decision": "☑ Selected",
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "daily.xlsx"
            exporter.export_daily(str(output), [record], generate_documents=True)

            workbook = openpyxl.load_workbook(output, data_only=True)
            summary = workbook["Summary"]
            columns = {cell.value: cell.column for cell in summary[1] if cell.value}
            summary_iocs = summary.cell(2, columns["IOCs"]).value
            document = next(
                sheet for sheet in workbook.worksheets
                if sheet.title.startswith("Report - ")
            )
            for value in (summary_iocs, document["B19"].value, document["B10"].value):
                self.assertIn("192[.]168[.]34[.]5", value)
                self.assertIn("hxxps://malicious[.]example/path", value)
                self.assertNotIn(raw_ip, value)
                self.assertNotIn(raw_url, value)
            workbook.close()

    def test_only_selected_non_low_advisories_receive_report_sheets(self):
        exporter = AdvisoryExcelExporter()

        def make_record(heading, severity):
            return {
                "advisory_heading": heading,
                "source_name": "Vendor",
                "link": f"https://example.test/{heading.split()[0].lower()}",
                "severity": severity,
                "cvss_score": "7.5",
                "published_timestamp": 1790000000,
                "impact_summary": f"{heading} describes a platform vulnerability and its impact.",
                "matched_app_name": "Test Platform",
                "advisory_type": "Patching",
                "cve_details": "CVE-2026-12345",
                "cve_risk_score": "NA",
                "attack_vector": "Network",
                "av_type": "Network",
                "iocs": "NA",
                "affected_versions": "1.x",
                "recommendation": "Upgrade Test Platform to version 2.0.",
                "source_content": f"{heading}. Upgrade Test Platform to version 2.0.",
                "review_decision": "Pending",
            }

        records = [
            make_record("Relevant Example Advisory", "HIGH"),
            make_record("Rejected Example Advisory", "HIGH"),
            make_record("Low Example Advisory", "LOW"),
            dict(
                make_record("Previously Reported Example Advisory", "HIGH"),
                review_decision="Previously Reported",
            ),
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            master_path = Path(temp_dir) / "master.xlsx"
            exporter.append_to_master(
                str(master_path),
                records,
                update_learning_tracker=True,
            )

            workbook = openpyxl.load_workbook(master_path)
            summary = workbook["Summary"]
            columns = {cell.value: cell.column for cell in summary[1] if cell.value}
            self.assertEqual(
                columns["Review Decision"],
                columns["Advisory Heading"] + 1,
            )
            if "Informational" in workbook.sheetnames:
                informational = workbook["Informational"]
            else:
                informational = summary
            info_columns = {
                cell.value: cell.column
                for cell in informational[1]
                if cell.value
            }
            decisions = {
                str(informational.cell(row, info_columns["Advisory Heading"]).value): row
                for row in range(2, informational.max_row + 1)
            }
            self.assertEqual(
                informational.cell(
                    decisions["Relevant Example Advisory"],
                    info_columns["Review Decision"],
                ).value,
                "☐ Pending",
            )
            validation = next(iter(summary.data_validations.dataValidation))
            self.assertIn("☑ Selected", validation.formula1)
            summary.cell(decisions["Relevant Example Advisory"], columns["Review Decision"], "☑ Selected")
            summary.cell(decisions["Rejected Example Advisory"], columns["Review Decision"], "☒ Rejected")
            summary.cell(decisions["Low Example Advisory"], columns["Review Decision"], "☑ Selected")
            workbook.save(master_path)
            workbook.close()

            exporter.append_to_master(
                str(master_path),
                [],
                generate_documents=True,
                update_learning_tracker=True,
            )

            workbook = openpyxl.load_workbook(master_path, data_only=True)
            document_headings = {
                str(sheet["A2"].value or "")
                for sheet in workbook.worksheets
                if sheet.title.startswith("Report - ")
            }
            self.assertEqual(document_headings, {"Relevant Example Advisory"})
            document = next(
                sheet for sheet in workbook.worksheets
                if sheet.title.startswith("Report - ")
            )
            self.assertEqual(
                {sheet.title for sheet in workbook.worksheets},
                {"Summary", "Learning Tracker", document.title},
            )
            self.assertGreaterEqual(len(document["B3"].value.splitlines()), 3)
            self.assertLessEqual(len(document["B3"].value.splitlines()), 4)
            tracker = workbook["Learning Tracker"]
            tracker_values = {
                tracker.cell(row, 1).value: tracker.cell(row, 2).value
                for row in range(2, tracker.max_row + 1)
            }
            self.assertEqual(tracker_values["Selected labels"], 2)
            self.assertEqual(tracker_values["Rejected labels"], 1)
            workbook.close()

    def test_daily_staging_hides_controls_and_does_not_publish_pending_items(self):
        exporter = AdvisoryExcelExporter()
        record = {
            "advisory_heading": "Pending Example Advisory",
            "source_name": "Vendor",
            "link": "https://example.test/pending",
            "severity": "HIGH",
            "cvss_score": "7.5",
            "published_timestamp": 1790000000,
            "impact_summary": "An example infrastructure security issue.",
            "matched_app_name": "Example Platform",
            "advisory_type": "Patching",
            "cve_details": "CVE-2026-12001",
            "cve_risk_score": "7.5",
            "recommendation": "Upgrade to the fixed version.",
            "source_content": "Upgrade to the fixed version.",
            "review_decision": "☐ Pending",
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "daily.xlsx"
            exporter.export_daily(str(output), [record])

            workbook = openpyxl.load_workbook(output)
            summary = workbook["Summary"]
            columns = {cell.value: cell.column for cell in summary[1] if cell.value}
            self.assertEqual(
                summary.cell(2, columns["Review Decision"]).value,
                "☐ Pending",
            )
            self.assertFalse(
                summary.column_dimensions[
                    openpyxl.utils.get_column_letter(columns["Review Decision"])
                ].hidden
            )
            self.assertEqual(
                columns["Review Decision"],
                columns["Advisory Heading"] + 1,
            )
            for header in ("Model Suggestion", "Relevance Score"):
                self.assertTrue(
                    summary.column_dimensions[
                        openpyxl.utils.get_column_letter(columns[header])
                    ].hidden
                )
            self.assertFalse(any(
                sheet.title.startswith("Report - ")
                for sheet in workbook.worksheets
            ))
            workbook.close()

    def test_large_cve_metrics_are_chunked_and_reassembled(self):
        exporter = AdvisoryExcelExporter()
        workbook = openpyxl.Workbook()
        summary = workbook.active
        summary.title = "Summary"
        exporter._render_headers(summary, [column[0] for column in exporter.COLUMNS])
        columns = exporter._ensure_review_columns(summary)
        metrics = {
            f"CVE-2026-{index:06d}": {
                "cvss_score": "9.8",
                "av_type": "Network",
                "risk_score": "9.8",
                "nvd_score": "9.8",
                "nvd_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            }
            for index in range(1200)
        }

        exporter._write_review_data(
            summary,
            2,
            {"advisory_heading": "Large CVE list", "cve_metrics": metrics},
            columns,
        )

        recovered = exporter._summary_record_from_row(summary, 2)["cve_metrics"]
        part_columns = [
            column for header, column in columns.items()
            if header.startswith("CVE Metrics JSON Part ")
        ]
        self.assertGreater(len(part_columns), 0)
        self.assertEqual(recovered, metrics)
        self.assertTrue(all(
            len(str(summary.cell(2, column).value or "")) <= exporter.EXCEL_CELL_TEXT_LIMIT
            for column in [columns["CVE Metrics JSON"], *part_columns]
        ))
        self.assertTrue(all(
            summary.column_dimensions[openpyxl.utils.get_column_letter(column)].hidden
            for column in [columns["CVE Metrics JSON"], *part_columns]
        ))
        workbook.close()

    def test_truncated_legacy_cve_metrics_recover_complete_entries(self):
        exporter = AdvisoryExcelExporter()
        workbook = openpyxl.Workbook()
        summary = workbook.active
        summary.title = "Summary"
        exporter._render_headers(summary, [column[0] for column in exporter.COLUMNS])
        columns = exporter._ensure_review_columns(summary)
        summary.cell(2, columns["Advisory Heading"], "Truncated CVE list")
        summary.cell(
            2,
            columns["CVE Metrics JSON"],
            '{"CVE-2026-000001":{"cvss_score":"9.8"},'
            '"CVE-2026-000002":{"cvss_score":"8.8"},'
            '"CVE-2026-000003":{"cvss_score":"7.',
        )

        recovered = exporter._summary_record_from_row(summary, 2)["cve_metrics"]

        self.assertEqual(
            recovered,
            {
                "CVE-2026-000001": {"cvss_score": "9.8"},
                "CVE-2026-000002": {"cvss_score": "8.8"},
            },
        )
        workbook.close()

    def test_nvd_score_takes_precedence_over_ai_estimate(self):
        exporter = AdvisoryExcelExporter()
        exporter._nvd_cache["CVE-2026-126261"] = {
            "score": "9.8",
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }

        record = exporter.build_advisory_record(
            {
                "title": "CVE-2026-126261 security advisory",
                "content": "Install the vendor patch.",
                "link": "https://example.test/advisory",
            },
            {"cvss_score": "8.2", "severity": "HIGH"},
        )

        self.assertEqual(record["cvss_score"], "9.8")
        self.assertEqual(record["cve_metrics"]["CVE-2026-126261"]["nvd_score"], "9.8")
        self.assertEqual(record["attack_vector"], "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    @patch.object(AdvisoryExcelExporter, "_tenable_recommendation")
    @patch.object(AdvisoryExcelExporter, "_build_cve_metrics")
    def test_candidate_staging_defers_external_cve_enrichment(
        self, build_metrics, tenable_recommendation
    ):
        exporter = AdvisoryExcelExporter()

        record = exporter.build_advisory_record(
            {
                "title": "CVE-2026-126261 security advisory",
                "content": "Install the vendor patch.",
                "link": "https://example.test/advisory",
            },
            {"cvss_score": "8.2", "severity": "HIGH"},
            enrich_cves=False,
        )

        self.assertEqual(record["cvss_score"], "8.2")
        self.assertEqual(record["cve_metrics"], {})
        build_metrics.assert_not_called()
        tenable_recommendation.assert_not_called()

    @patch.object(AdvisoryExcelExporter, "_save_nvd_cache")
    @patch("excel_exporter.requests.get")
    def test_nvd_v4_metrics_use_api_key(self, get, _save_cache):
        response = Mock(status_code=200)
        response.json.return_value = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2026-126170",
                    "metrics": {
                        "cvssMetricV40": [{
                            "cvssData": {
                                "baseScore": 9.8,
                                "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H",
                            }
                        }]
                    }
                }
            }]
        }
        get.return_value = response
        exporter = AdvisoryExcelExporter(nvd_api_key="test-nvd-key")
        exporter._nvd_cache.clear()
        exporter._nvd_cache_checked_at.clear()
        exporter._nvd_failed_cves.clear()

        result = exporter._nvd_cve_lookup("CVE-2026-126170")

        self.assertEqual(result["score"], "9.8")
        self.assertTrue(result["vector"].startswith("CVSS:4.0/AV:N"))
        self.assertEqual(get.call_args.kwargs["headers"], {"apiKey": "test-nvd-key"})

    @patch.object(AdvisoryExcelExporter, "_save_nvd_cache")
    @patch("excel_exporter.requests.get")
    def test_nvd_bulk_lookup_batches_and_maps_records_by_cve_id(self, get, _save_cache):
        response = Mock(status_code=200)
        response.json.return_value = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2026-126261",
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "baseScore": 9.8,
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            }
                        }]
                    },
                }
            }]
        }
        get.return_value = response
        exporter = AdvisoryExcelExporter(nvd_api_key="test-nvd-key")
        exporter._nvd_cache.clear()
        exporter._nvd_cache_checked_at.clear()
        exporter._nvd_failed_cves.clear()

        cve_ids = ["CVE-2026-126261"] + [
            f"CVE-2026-{index:06d}" for index in range(200)
        ]
        exporter._nvd_cve_lookup_many(cve_ids)

        self.assertEqual(get.call_count, 3)
        self.assertEqual(exporter._nvd_cve_lookup("CVE-2026-126261")["score"], "9.8")
        self.assertEqual(exporter._nvd_cve_lookup("CVE-2026-000001"), {})
        self.assertEqual(get.call_args_list[0].kwargs["headers"], {"apiKey": "test-nvd-key"})

    @patch("excel_exporter.requests.get")
    def test_nvd_cache_prevents_repeated_network_lookup(self, get):
        response = Mock(status_code=200)
        response.json.return_value = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2026-126261",
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "baseScore": 9.8,
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            }
                        }]
                    },
                }
            }]
        }
        get.return_value = response
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_path = Path(temp_dir) / "nvd-cache.json"
            exporter = AdvisoryExcelExporter()
            exporter._nvd_cache_path = cache_path
            exporter._nvd_cache.clear()
            exporter._nvd_cache_checked_at.clear()
            exporter._nvd_failed_cves.clear()
            exporter._nvd_cve_lookup_many(["CVE-2026-126261"])

            cached_exporter = AdvisoryExcelExporter()
            cached_exporter._nvd_cache_path = cache_path
            cached_exporter._nvd_cache.clear()
            cached_exporter._nvd_cache_checked_at.clear()
            cached_exporter._nvd_failed_cves.clear()
            cached_exporter._load_nvd_cache()
            result = cached_exporter._nvd_cve_lookup("CVE-2026-126261")

        self.assertEqual(result["score"], "9.8")
        get.assert_called_once()

    @patch.object(AdvisoryExcelExporter, "_save_nvd_cache")
    @patch("excel_exporter.requests.get")
    def test_normal_report_rebuild_skips_nvd_lookups_for_history(self, get, _save_cache):
        response = Mock(status_code=200)
        response.json.return_value = {"vulnerabilities": []}
        get.return_value = response
        exporter = AdvisoryExcelExporter()
        record = {
            "advisory_heading": "Historical CVE advisory",
            "source_name": "Vendor",
            "link": "https://example.test/advisory",
            "severity": "HIGH",
            "cvss_score": "Not available",
            "published_timestamp": 1790000000,
            "impact_summary": "Security fixes are available.",
            "matched_app_name": "Test App",
            "advisory_type": "Patching",
            "cve_details": "CVE-2026-10001",
            "cve_risk_score": "Not available",
            "cve_metrics": {
                "CVE-2026-10001": {
                    "cvss_score": "Not available",
                    "av_type": "Not available",
                    "risk_score": "Not available",
                }
            },
            "recommendation": "Install the vendor patch.",
            "source_content": "Vendor fix for CVE-2026-10001: Install the vendor patch.",
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "daily.xlsx"
            exporter.export_daily(str(output), [record], generate_documents=True)

            exporter_without_cache = AdvisoryExcelExporter()
            get.reset_mock()
            exporter_without_cache.export_daily(str(output), [])

        get.assert_not_called()

    @patch("tenable_client.requests.get")
    def test_tenable_uses_api_keys_and_returns_plugin_solution(self, get):
        catalog_response = Mock(status_code=200)
        catalog_response.json.return_value = {
            "data": {
                "plugin_details": [{
                    "id": 12345,
                    "name": "Example vulnerability",
                    "attributes": {
                        "cve": ["CVE-2026-126170"],
                        "solution": "Upgrade to the fixed version.",
                        "cvss3_base_score": 8.8,
                        "cvss_vector": {"raw": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
                    },
                }]
            }
        }
        get.return_value = catalog_response
        client = TenableClient("access-key", "secret-key")

        results = client.lookup_cve("CVE-2026-126170")

        self.assertEqual(results[0]["solution"], "Upgrade to the fixed version.")
        self.assertEqual(results[0]["cvss_base_score"], 8.8)
        self.assertTrue(results[0]["cvss_vector"].startswith("CVSS:3.1/AV:N"))
        self.assertIn("accessKey=access-key; secretKey=secret-key", get.call_args.kwargs["headers"]["X-ApiKeys"])
        self.assertEqual(get.call_args.kwargs["params"], {"size": 10000, "page": 1})

    @patch("tenable_client.requests.get")
    def test_tenable_catalog_failure_is_not_retried_for_each_cve(self, get):
        response = Mock(status_code=403, text="forbidden")
        get.return_value = response
        client = TenableClient("access-key", "secret-key")

        with self.assertRaisesRegex(RuntimeError, "HTTP 403"):
            client.lookup_cve("CVE-2026-126170")
        with self.assertRaisesRegex(RuntimeError, "HTTP 403"):
            client.lookup_cve("CVE-2026-126171")

        get.assert_called_once()

    @patch.object(AdvisoryExcelExporter, "_fetch_source_content", return_value="")
    def test_rebuild_recovers_previous_recommendation_and_cve_rows(self, _fetch):
        exporter = AdvisoryExcelExporter()
        exporter._nvd_cache.update({
            "CVE-2026-10001": {
                "score": "9.8",
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            },
            "CVE-2026-10002": {
                "score": "8.6",
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            },
        })
        content = (
            "CVE-2026-10001 carries a CVSS score of 9.8.\n"
            "CVE-2026-10002 is rated 8.6.\n"
            "Install the fixed release and disable the vulnerable endpoint."
        )
        record = {
            "advisory_heading": "Multiple vulnerability advisory",
            "source_name": "Vendor",
            "link": "https://example.test/advisory",
            "severity": "HIGH",
            "cvss_score": "9.8",
            "published_timestamp": 1790000000,
            "impact_summary": "Security fixes are available.",
            "matched_app_name": "Test App",
            "advisory_type": "Patching",
            "cve_details": "CVE-2026-10001, CVE-2026-10002",
            "cve_risk_score": "9.8",
            "cve_metrics": exporter._build_cve_metrics(
                ["CVE-2026-10001", "CVE-2026-10002"], content
            ),
            "attack_vector": "Network",
            "av_type": "Network",
            "iocs": "NA",
            "affected_versions": "1.x",
            "recommendation": "NA",
            "source_content": content,
            "review_decision": "Selected",
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "daily.xlsx"
            exporter.export_daily(str(output), [record], generate_documents=True)

            workbook = openpyxl.load_workbook(output)
            document = next(sheet for sheet in workbook.worksheets if sheet.title.startswith("Report - "))
            document["B13"] = "NA"
            document["C10"] = "NA"
            document["D10"] = "NA"
            document["E10"] = "NA"
            document["C11"] = "NA"
            document["D11"] = "NA"
            document["E11"] = "NA"
            workbook.save(output)
            workbook.close()

            exporter.export_daily(
                str(output),
                [],
                refresh_enrichment=True,
                generate_documents=True,
            )
            workbook = openpyxl.load_workbook(output, data_only=True)
            document = next(sheet for sheet in workbook.worksheets if sheet.title.startswith("Report - "))
            self.assertIn("Install the fixed release", document["B13"].value)
            self.assertEqual(document["C10"].value, "9.8")
            self.assertEqual(document["C11"].value, "8.6")
            self.assertEqual(document["D10"].value, "Network")
            self.assertEqual(document["D11"].value, "Network")
            workbook.close()


if __name__ == "__main__":
    unittest.main()
