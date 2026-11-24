import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from advisory_deduplicator import AdvisoryDeduplicator, split_advisory_cluster
from cache_db import AdvisoryCacheDB
from pipeline import _prepare_delivery_metadata


class AdvisoryCacheDBTests(unittest.TestCase):
    def test_pair_decisions_round_trip_with_canonical_ids_and_human_source(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            cache = AdvisoryCacheDB(str(Path(temp_dir) / "cache.db"))
            cache.record_pair_decision(
                "article-b",
                "article-a",
                same_event=False,
                decided_by="human",
                reason="Keep Separate",
                confidence=1.0,
            )

            decisions = cache.get_pair_decisions()

        self.assertEqual(
            decisions[("article-a", "article-b")]["same_event"],
            False,
        )
        self.assertEqual(
            decisions[("article-a", "article-b")]["decided_by"],
            "human",
        )

    def test_sent_ledger_deduplicates_content_but_allows_distinct_updates(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            cache = AdvisoryCacheDB(str(Path(temp_dir) / "cache.db"))
            self.assertTrue(cache.record_sent(
                "ADV-1",
                "SOC",
                "2026-01-01T10:00:00",
                "hash-1",
            ))
            self.assertFalse(cache.record_sent(
                "ADV-1",
                "SOC",
                "2026-01-02T10:00:00",
                "hash-1",
            ))
            self.assertTrue(cache.record_sent(
                "ADV-1",
                "SOC",
                "2026-01-02T10:00:00",
                "hash-2",
            ))
            ledger = cache.get_sent_ledger("ADV-1")
            has_initial_content = cache.has_sent_content("ADV-1", "SOC", "hash-1")

        self.assertEqual(len(ledger), 2)
        self.assertEqual(
            {item["content_hash"] for item in ledger},
            {"hash-1", "hash-2"},
        )
        self.assertTrue(has_initial_content)

    def test_human_keep_separate_decision_splits_a_stored_cluster(self):
        merged = {
            "id": "article-a",
            "member_article_ids": ["article-a", "article-b"],
            "source_references": [
                {
                    "article_id": "article-a",
                    "source_name": "Source A",
                    "link": "https://a.example/advisory",
                    "title": "Issue report A",
                    "content": "Source A technical details.",
                },
                {
                    "article_id": "article-b",
                    "source_name": "Source B",
                    "link": "https://b.example/advisory",
                    "title": "Issue report B",
                    "content": "Source B technical details.",
                },
            ],
        }

        split_records = split_advisory_cluster(merged)

        self.assertEqual([record["id"] for record in split_records], ["article-a", "article-b"])
        self.assertEqual(
            [record["source_content"] for record in split_records],
            ["Source A technical details.", "Source B technical details."],
        )
        self.assertTrue(all(len(record["source_references"]) == 1 for record in split_records))

    def test_late_duplicate_of_sent_advisory_is_an_update_with_only_new_facts(self):
        def record(article_id, source_name, link, report_summary):
            return {
                "id": article_id,
                "source_name": source_name,
                "link": link,
                "advisory_heading": "Example Platform CVE-2026-12345",
                "advisory_type": "Actionable",
                "severity": "HIGH",
                "cve_details": "CVE-2026-12345",
                "matched_app_name": "Example Platform",
                "affected_products": "Example Platform",
                "affected_versions": "2.0.0",
                "impact_summary": "The flaw permits remote code execution.",
                "report_summary": report_summary,
                "recommendation": "Upgrade to the fixed version.",
                "source_content": report_summary,
            }

        first = record(
            "article-a",
            "Source A",
            "https://a.example/advisory",
            "The flaw permits remote code execution in Example Platform.",
        )
        canonical, _ = AdvisoryDeduplicator().deduplicate([first], [])

        with tempfile.TemporaryDirectory() as temp_dir:
            cache = AdvisoryCacheDB(str(Path(temp_dir) / "cache.db"))
            cache.record_sent(
                canonical[0]["advisory_id"],
                "SOC",
                "2026-01-01T10:00:00",
                "initial-hash",
            )
            late_source = record(
                "article-b",
                "Source B",
                "https://b.example/advisory",
                "The flaw permits remote code execution in Example Platform. "
                "The vulnerability also exposes stored API tokens.",
            )
            _, updates = AdvisoryDeduplicator().deduplicate(
                [late_source],
                canonical,
            )
            updated = updates["miscellaneous"][0] if "miscellaneous" in updates else canonical[0]
            _prepare_delivery_metadata(updated, cache)

        self.assertEqual(updated["advisory_id"], canonical[0]["advisory_id"])
        self.assertEqual(updated["delivery_status"], "UPDATE")
        self.assertIn("stored API tokens", updated["update_summary"])
        self.assertNotIn("remote code execution", updated["update_summary"])


if __name__ == "__main__":
    unittest.main()
