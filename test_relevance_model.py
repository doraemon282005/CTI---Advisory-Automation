import sys
import unittest
from pathlib import Path

import openpyxl

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from relevance_model import AdvisoryRelevanceModel


class AdvisoryRelevanceModelTests(unittest.TestCase):
    def _examples(self, decision, prefix, count):
        return [
            {
                "review_decision": decision,
                "advisory_heading": f"{prefix} infrastructure security notice {index}",
                "impact_summary": f"{prefix} platform vulnerability requires review.",
                "matched_app_name": prefix,
                "severity": "HIGH",
                "advisory_type": "Patching",
                "cve_details": f"CVE-2026-{10000 + index}" if decision == "Selected" else "NA",
            }
            for index in range(count)
        ]

    def test_suggestions_wait_for_minimum_labels_and_remain_explainable(self):
        model = AdvisoryRelevanceModel()
        examples = self._examples("Selected", "Fortinet", 4)
        examples += self._examples("Rejected", "UnrelatedNews", 4)
        counts = model.fit(examples)

        self.assertEqual(counts, {"Selected": 4, "Rejected": 4})
        self.assertFalse(model.ready)
        self.assertIsNone(model.predict(examples[0]))

        examples.extend(self._examples("Selected", "Fortinet", 1))
        examples.extend(self._examples("Rejected", "UnrelatedNews", 1))
        model.fit(examples)

        self.assertTrue(model.ready)
        selected_score = model.predict(self._examples("Selected", "Fortinet", 1)[0])
        rejected_score = model.predict(self._examples("Rejected", "UnrelatedNews", 1)[0])
        self.assertGreater(selected_score, rejected_score)
        self.assertIsNotNone(model.tracker_summary()["accuracy"])

    def test_checkbox_like_review_values_map_to_model_labels(self):
        self.assertEqual(
            AdvisoryRelevanceModel.normalize_decision("☑ Selected"),
            "Selected",
        )
        self.assertEqual(
            AdvisoryRelevanceModel.normalize_decision("☒ Rejected"),
            "Rejected",
        )
        self.assertEqual(
            AdvisoryRelevanceModel.normalize_decision("☐ Pending"),
            "Pending",
        )

    def test_tracker_documents_training_counts_and_publication_safeguard(self):
        model = AdvisoryRelevanceModel()
        model.fit(
            self._examples("Selected", "Fortinet", 5)
            + self._examples("Rejected", "UnrelatedNews", 5)
        )
        workbook = openpyxl.Workbook()
        summary = workbook.active
        summary.title = "Summary"
        summary.append(["Advisory Heading", "Review Decision", "Severity"])
        summary.append(["Selected high", "☑ Selected", "HIGH"])
        summary.append(["Pending low", "☐ Pending", "LOW"])
        summary.append(["Rejected high", "☒ Rejected", "HIGH"])
        summary.append(["Old low", "Previously Reported", "LOW"])
        workbook.create_sheet("Advisory Document 1")
        summary = model.update_tracker_sheet(workbook)

        self.assertTrue(summary["ready"])
        tracker = workbook["Learning Tracker"]
        rows = {tracker.cell(row, 1).value: tracker.cell(row, 2).value
                for row in range(2, tracker.max_row + 1)}
        self.assertEqual(rows["Advisories in master list"], 4)
        self.assertEqual(rows["Awaiting human review"], 1)
        self.assertEqual(rows["Selected by a person"], 1)
        self.assertEqual(rows["Selected and eligible for reports"], 1)
        self.assertEqual(rows["Rejected by a person"], 1)
        self.assertEqual(rows["Previously reported"], 1)
        self.assertEqual(rows["Detailed report sheets in workbook"], 1)
        self.assertTrue(rows["Last updated"])
        self.assertEqual(rows["Selected labels"], 5)
        self.assertEqual(rows["Rejected labels"], 5)
        self.assertIn("cannot publish", rows["Publishing safeguard"])
        self.assertIn("fortinet", rows["Patterns learned"])
        workbook.close()


if __name__ == "__main__":
    unittest.main()
