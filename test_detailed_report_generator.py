import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest.mock import Mock, patch

from docx import Document
import openpyxl

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

import pipeline
from detailed_report_generator import DetailedAdvisoryReportGenerator
from excel_exporter import AdvisoryExcelExporter
from ai_evaluator import SecurityAIEvaluator


ROOT = Path(__file__).resolve().parent
TEMPLATE = ROOT / "Detailed Advisory Report Format.docx"


def valid_generated_content():
    return {
        "threat_actors": [],
        "summary_points": ["Generated summary supported by the source."],
        "why_it_matters": "The source describes a risk to protected functions.",
        "scope_note": "Check the affected product and version with its owner.",
        "products": "Example Platform",
        "versions": "4.1 through 4.3",
        "cves": "CVE-2026-12345",
        "severity": "High",
        "confidence": "The source explicitly describes the vulnerability.",
        "ioc_limitations": "The source does not publish network indicators.",
        "iocs": [{"type": "SHA256", "value": "abcdef0123456789", "note": "Source listed"}],
        "ttps": [{
            "tactic": "Source-described behavior",
            "technique": "Authentication bypass",
            "detail": "The source states that authentication can be bypassed.",
        }],
        "attack_mapping_note": "No ATT&CK ID was assigned.",
        "hunt_enterprise": ["Inventory managed Example Platform instances."],
        "hunt_technical": ["Review authentication logs for anomalous access."],
        "detection_summary": "No validated detection rule was supplied.",
        "yara_content": "No file signature was supplied.",
        "sigma_content": "Suggested hunt hypothesis; validate before deployment.",
        "tooling_notes": "Local security-tool coverage was not supplied.",
        "tooling_checks": [{
            "technology": "Application inventory",
            "tool": "Example Platform",
            "signature_status": "Not assessed",
            "remarks": "Confirm coverage with the local owner.",
            "applicable": "Owner to verify",
        }],
        "controls_intro": "Suggested checks; deployment state is not assessed.",
        "compensating_controls": [{
            "control": "Version inventory",
            "verify": "Compare deployed versions with vendor guidance.",
        }],
        "secops_instructions": [{
            "control": "Remediation",
            "instruction": "Apply the vendor-supported update after validation.",
        }],
        "incident_response": ["Preserve logs if exploitation is suspected."],
        "immediate_actions": ["Confirm whether the affected product is deployed."],
        "short_term_actions": ["Apply the supported update where required."],
        "source_limitations": "No confirmed exploitation status was provided.",
    }


class DetailedReportTests(unittest.TestCase):
    def test_word_report_uses_template_without_carrying_sample_facts(self):
        record = {
            "id": "article-1",
            "advisory_id": "advisory-1",
            "advisory_heading": "Example Platform authentication bypass",
            "severity": "HIGH",
            "report_summary": "The issue permits authentication bypass.",
            "impact_summary": "An unauthenticated attacker may access protected functions.",
            "affected_products": "Example Platform",
            "affected_versions": "4.1 through 4.3",
            "cve_details": "CVE-2026-12345",
            "iocs": "SHA256: abcdef0123456789",
            "attack_vector": "Network",
            "av_type": "Network",
            "recommendation": "Apply the vendor-provided update.",
            "source_name": "Vendor",
            "link": "https://vendor.example/advisory",
            "source_references": [{
                "source_name": "Vendor",
                "link": "https://vendor.example/advisory",
                "published_timestamp": 1795382400,
                "content": "The authentication bypass affects CVE-2026-12345.",
            }],
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            path = DetailedAdvisoryReportGenerator(TEMPLATE).generate(
                record,
                Path(temp_dir) / "Detailed Advisory Reports",
            )
            document = Document(str(path))

        paragraph_text = "\n".join(paragraph.text for paragraph in document.paragraphs)
        table_text = "\n".join(
            cell.text
            for table in document.tables
            for row in table.rows
            for cell in row.cells
        )
        all_text = f"{paragraph_text}\n{table_text}"
        self.assertIn("Example Platform authentication bypass", all_text)
        self.assertIn("CVE-2026-12345", all_text)
        self.assertIn("Apply the vendor-supported fix", all_text)
        self.assertIn("Suggested hunt hypothesis", all_text)
        self.assertIn("CTI Advisory Automation", all_text)
        self.assertEqual(len(document.tables), 7)
        self.assertEqual(
            [len(table.columns) for table in document.tables],
            [2, 1, 3, 3, 5, 4, 3],
        )
        self.assertNotIn("SilentAir", all_text)
        self.assertNotIn("35f0d4d0c5519a2957338e448fce53bc", all_text)
        header_text = "\n".join(
            paragraph.text for paragraph in document.sections[0].header.paragraphs
        )
        self.assertNotIn("TLP:AMBER", header_text)
        hyperlink_targets = [
            relation.target_ref
            for relation in document.part.rels.values()
            if relation.reltype.endswith("/hyperlink")
        ]
        self.assertIn("https://vendor.example/advisory", hyperlink_targets)

    def test_ai_generated_sections_are_used_in_reference_layout(self):
        record = {
            "id": "article-ai",
            "advisory_id": "advisory-ai",
            "advisory_heading": "Example Platform authentication bypass",
            "source_name": "Vendor",
            "link": "https://vendor.example/advisory",
            "source_references": [{
                "source_name": "Vendor",
                "title": "Example Platform authentication bypass",
                "link": "https://vendor.example/advisory",
                "content": "The source states authentication can be bypassed.",
            }],
        }
        evaluator = Mock()
        evaluator.generate_detailed_advisory_report.return_value = valid_generated_content()

        with tempfile.TemporaryDirectory() as temp_dir:
            path = DetailedAdvisoryReportGenerator(
                TEMPLATE,
                evaluator,
            ).generate(record, Path(temp_dir))
            document = Document(str(path))

        text = "\n".join(
            [paragraph.text for paragraph in document.paragraphs]
            + [
                cell.text
                for table in document.tables
                for row in table.rows
                for cell in row.cells
            ]
        )
        self.assertIn("Generated summary supported by the source.", text)
        self.assertIn("Suggested hunt hypothesis; validate before deployment.", text)
        self.assertIn("Version inventory", text)
        self.assertEqual(len(document.tables), 7)
        evaluator.generate_detailed_advisory_report.assert_called_once_with(record)

    def test_ai_evaluator_requires_structured_report_json(self):
        evaluator = SecurityAIEvaluator()
        generated = valid_generated_content()
        record = {
            "advisory_heading": "Example Platform authentication bypass",
            "source_references": [{
                "source_name": "Vendor",
                "title": "Example Platform authentication bypass",
                "link": "https://vendor.example/advisory",
                "content": "The source states authentication can be bypassed.",
            }],
        }
        with patch.object(
            evaluator,
            "_call_structured_json",
            return_value=generated,
        ) as structured_call:
            result = evaluator.generate_detailed_advisory_report(record)

        self.assertEqual(result, generated)
        prompt = structured_call.call_args.args[0]
        self.assertIn("Required JSON shape", prompt)
        self.assertIn("The source states authentication can be bypassed.", prompt)

    def test_digest_and_unstructured_fields_are_not_presented_as_facts(self):
        record = {
            "id": "article-digest",
            "advisory_id": "advisory-digest",
            "advisory_heading": (
                "Security Affairs newsletter Round 605 (CVE-2026-23871)"
            ),
            "severity": "CRITICAL",
            "report_summary": "Unrelated breach and vulnerability headlines.",
            "impact_summary": (
                "[Remote Code Execution] Systems running Cisco are affected. "
                "Review vendor patch guidance."
            ),
            "affected_products": (
                "CISA adds Cisco, SAP and Apache flaws to its Known Exploited "
                "Vulnerabilities catalog; unrelated newsletter content"
            ),
            "affected_versions": "Versions named in several unrelated articles",
            "cve_details": "CVE-2026-23871, CVE-2026-76466",
            "iocs": "hxxps://unrelated[.]example; hxxps://cve[.]example",
            "recommendation": (
                "PHP Warns of Critical Security Flaws, WhatsApp Fixes a Flaw"
            ),
            "source_name": "Security Affairs",
            "link": "https://security.example/newsletter",
            "source_references": [{
                "source_name": "Security Affairs",
                "title": "Security Affairs newsletter Round 605 (CVE-2026-23871)",
                "link": "https://security.example/newsletter",
                "content": (
                    "CVE-2026-76466 and CVE-2026-129448 appear in unrelated "
                    "newsletter headlines."
                ),
            }],
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            path = DetailedAdvisoryReportGenerator(TEMPLATE).generate(
                record,
                Path(temp_dir),
            )
            document = Document(str(path))

        all_text = "\n".join(
            [paragraph.text for paragraph in document.paragraphs]
            + [
                cell.text
                for table in document.tables
                for row in table.rows
                for cell in row.cells
            ]
        )
        self.assertIn("CVE-2026-23871", all_text)
        self.assertNotIn("CVE-2026-76466", all_text)
        self.assertNotIn("Cisco", all_text)
        self.assertNotIn("CRITICAL", all_text)
        self.assertNotIn("unrelated[.]example", all_text)
        self.assertNotIn("WhatsApp Fixes a Flaw", all_text)
        self.assertNotIn("WhatsApp", all_text)

    def test_process_reviewed_creates_word_file_and_master_link(self):
        exporter = AdvisoryExcelExporter()
        with tempfile.TemporaryDirectory() as temp_dir:
            daily_path = (
                Path(temp_dir)
                / "reports"
                / "daily"
                / date.today().isoformat()
                / f"Daily_Miscellaneous_Advisories_{date.today().isoformat()}.xlsx"
            )
            master_path = Path(temp_dir) / "reports" / "Master_Miscellaneous.xlsx"
            record = {
                "id": "article-1",
                "advisory_id": "advisory-1",
                "member_article_ids": ["article-1"],
                "source_name": "Vendor",
                "advisory_heading": "Example Platform authentication bypass",
                "link": "https://vendor.example/advisory",
                "severity": "HIGH",
                "published_timestamp": 1795382400,
                "impact_summary": "The flaw permits authentication bypass.",
                "advisory_type": "Actionable",
                "cve_details": "NA",
                "cve_risk_score": "NA",
                "attack_vector": "Network",
                "av_type": "Network",
                "iocs": "NA",
                "affected_products": "Example Platform",
                "affected_versions": "4.1 through 4.3",
                "report_summary": "The issue permits authentication bypass.",
                "recommendation": "Apply the vendor-provided update.",
                "source_content": (
                    "Example Platform versions 4.1 through 4.3 permit "
                    "authentication bypass."
                ),
                "review_decision": "☑ Selected",
                "source_references": [{
                    "article_id": "article-1",
                    "source_name": "Vendor",
                    "title": "Example Platform authentication bypass",
                    "link": "https://vendor.example/advisory",
                    "published_timestamp": 1795382400,
                    "content": "The flaw permits authentication bypass.",
                }],
            }
            exporter.export_daily(
                str(daily_path),
                [record],
                generate_documents=False,
                replace_existing=True,
            )

            with patch.object(pipeline, "_close_excel_workbook_if_open"):
                saved_daily, saved_master, selected, report_count = (
                    pipeline.process_reviewed_advisories(
                        exporter,
                        daily_path,
                        master_path,
                    )
                )

            report_path = (
                daily_path.parent
                / "Detailed Advisory Reports"
                / "Example_Platform_authentication_bypass_advisory-1.docx"
            )
            self.assertTrue(report_path.is_file())
            self.assertEqual(selected, 1)
            self.assertEqual(report_count, 1)
            self.assertTrue(Path(saved_daily).is_file())
            self.assertTrue(Path(saved_master).is_file())

            archived = exporter.read_summary_records(saved_master)
            self.assertEqual(len(archived), 1)
            self.assertEqual(
                Path(archived[0]["detailed_report_path"]),
                report_path.resolve(),
            )
            workbook = openpyxl.load_workbook(saved_master, data_only=False)
            try:
                sheet = workbook["Summary"]
                columns = {
                    str(cell.value): cell.column
                    for cell in sheet[1]
                    if cell.value
                }
                self.assertEqual(
                    columns["View Detailed Report"],
                    columns["View Report"] + 1,
                )
                word_link = sheet.cell(2, columns["View Detailed Report"])
                self.assertEqual(word_link.value, "Open Word Report")
                self.assertEqual(
                    word_link.hyperlink.target,
                    report_path.resolve().as_uri(),
                )
            finally:
                workbook.close()


if __name__ == "__main__":
    unittest.main()
