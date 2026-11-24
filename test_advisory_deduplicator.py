import sys
import unittest
from pathlib import Path
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from advisory_deduplicator import AdvisoryDeduplicator


class AdvisoryDeduplicatorTests(unittest.TestCase):
    def _record(self, article_id, source_name, link, **updates):
        record = {
            "id": article_id,
            "source_name": source_name,
            "link": link,
            "advisory_heading": "Apache Ignite remote code execution CVE-2026-12345",
            "cve_details": "CVE-2026-12345",
            "matched_app_name": "Apache Ignite",
            "affected_versions": "2.0.0",
            "impact_summary": "Remote code execution affects Apache Ignite.",
            "report_summary": "Attackers can execute arbitrary code in Apache Ignite.",
            "source_content": (
                "Apache Ignite CVE-2026-12345 allows remote code execution "
                "in version 2.0.0."
            ),
        }
        record.update(updates)
        return record

    def test_exact_issue_from_multiple_sources_keeps_one_record_and_all_references(self):
        deduplicated, archive_updates = AdvisoryDeduplicator().deduplicate(
            [
                self._record("article-a", "Source A", "https://a.example/advisory"),
                self._record(
                    "article-b",
                    "Source B",
                    "https://b.example/advisory",
                    advisory_heading="Ignite vulnerability CVE-2026-12345",
                    source_content=(
                        "Apache Ignite CVE-2026-12345 allows remote code execution "
                        "in version 2.0.0. The issue also exposes stored credentials."
                    ),
                    report_summary=(
                        "Attackers can execute arbitrary code in Apache Ignite. "
                        "The issue also exposes stored credentials."
                    ),
                ),
            ],
            [],
        )

        self.assertEqual(len(deduplicated), 1)
        self.assertEqual(archive_updates, {})
        self.assertEqual(
            [reference["source_name"] for reference in deduplicated[0]["source_references"]],
            ["Source A", "Source B"],
        )
        self.assertEqual(
            [reference["link"] for reference in deduplicated[0]["source_references"]],
            ["https://a.example/advisory", "https://b.example/advisory"],
        )
        self.assertIn("stored credentials", deduplicated[0]["report_summary"])
        self.assertIn("stored credentials", deduplicated[0]["source_content"])
        self.assertEqual(deduplicated[0]["_deduplicated_article_ids"], ["article-b"])

    def test_matching_archive_updates_its_source_references_without_new_queue_item(self):
        archived = self._record("article-a", "Source A", "https://a.example/advisory")
        archived["_archive_group"] = "miscellaneous"
        archived["impact_summary"] = "Attackers can remotely execute arbitrary code in Apache Ignite."
        archived["report_summary"] = (
            "Attackers can remotely execute arbitrary code in Apache Ignite. "
            "Successful exploitation may expose database credentials."
        )
        deduplicated, archive_updates = AdvisoryDeduplicator().deduplicate(
            [
                self._record(
                    "article-b",
                    "Source B",
                    "https://b.example/advisory",
                    impact_summary=(
                        "Attackers can remotely execute arbitrary code in Apache Ignite."
                    ),
                    report_summary=(
                        "Attackers can remotely execute arbitrary code in Apache Ignite. "
                        "The flaw also permits attackers to access sensitive configuration."
                    ),
                    recommendation=(
                        "Upgrade to the fixed version. "
                        "Upgrade to the fixed version."
                    ),
                )
            ],
            [archived],
        )

        self.assertEqual(deduplicated, [])
        self.assertEqual(len(archive_updates["miscellaneous"]), 1)
        self.assertEqual(
            [reference["source_name"] for reference in archived["source_references"]],
            ["Source A", "Source B"],
        )
        self.assertEqual(archived["_deduplicated_article_ids"], ["article-b"])
        self.assertEqual(
            archived["impact_summary"].count("remotely execute arbitrary code"),
            1,
        )
        self.assertEqual(
            archived["report_summary"].count("remotely execute arbitrary code"),
            0,
        )
        self.assertIn("database credentials", archived["report_summary"])
        self.assertIn("sensitive configuration", archived["report_summary"])
        self.assertEqual(
            archived["recommendation"],
            "Upgrade to the fixed version.",
        )

    def test_confident_match_merges_even_when_another_candidate_is_only_possible(self):
        matching_archive = self._record(
            "article-a",
            "Source A",
            "https://a.example/advisory",
        )
        matching_archive["_archive_group"] = "miscellaneous"
        conflicting_archive = self._record(
            "article-b",
            "Source B",
            "https://b.example/advisory",
            affected_versions="3.0.0",
        )
        conflicting_archive["_archive_group"] = "miscellaneous"

        deduplicated, archive_updates = AdvisoryDeduplicator().deduplicate(
            [
                self._record(
                    "article-c",
                    "Source C",
                    "https://c.example/advisory",
                )
            ],
            [matching_archive, conflicting_archive],
        )

        self.assertEqual(deduplicated, [])
        self.assertEqual(len(archive_updates["miscellaneous"]), 1)
        self.assertEqual(
            [reference["source_name"] for reference in matching_archive["source_references"]],
            ["Source A", "Source C"],
        )

    def test_scanned_duplicates_merge_distinct_summary_facts_without_repetition(self):
        deduplicated, _ = AdvisoryDeduplicator().deduplicate(
            [
                self._record(
                    "article-a",
                    "Source A",
                    "https://a.example/advisory",
                    report_summary=(
                        "The vulnerability affects Apache Ignite 2.0.0. "
                        "Attackers can remotely execute arbitrary code in Apache Ignite."
                    ),
                ),
                self._record(
                    "article-b",
                    "Source B",
                    "https://b.example/advisory",
                    report_summary=(
                        "Attackers can remotely execute arbitrary code in Apache Ignite "
                        "without authentication. "
                        "The flaw can also expose stored credentials."
                    ),
                ),
            ],
            [],
        )

        self.assertEqual(len(deduplicated), 1)
        summary = deduplicated[0]["report_summary"]
        self.assertEqual(
            summary.count("remotely execute arbitrary code"),
            1,
        )
        self.assertIn("without authentication", summary)
        self.assertIn("Apache Ignite 2.0.0", summary)
        self.assertIn("stored credentials", summary)

    def test_bridge_advisory_consolidates_multiple_matching_scan_candidates(self):
        deduplicated, _ = AdvisoryDeduplicator().deduplicate(
            [
                self._record(
                    "article-a",
                    "Source A",
                    "https://a.example/advisory",
                    advisory_heading=(
                        "Apache Ignite remote code execution CVE-2026-11111"
                    ),
                    cve_details="CVE-2026-11111",
                ),
                self._record(
                    "article-b",
                    "Source B",
                    "https://b.example/advisory",
                    advisory_heading=(
                        "Apache Ignite remote code execution CVE-2026-22222"
                    ),
                    cve_details="CVE-2026-22222",
                ),
                self._record(
                    "article-c",
                    "Source C",
                    "https://c.example/advisory",
                    advisory_heading=(
                        "Apache Ignite remote code execution "
                        "CVE-2026-11111 and CVE-2026-22222"
                    ),
                    cve_details="CVE-2026-11111, CVE-2026-22222",
                ),
            ],
            [],
        )

        self.assertEqual(len(deduplicated), 1)
        self.assertEqual(
            deduplicated[0]["cve_details"],
            "CVE-2026-11111, CVE-2026-22222",
        )
        self.assertEqual(
            [reference["source_name"] for reference in deduplicated[0]["source_references"]],
            ["Source A", "Source B", "Source C"],
        )

    def test_shared_cve_merges_different_cve_sets_and_ignores_cvss_as_version(self):
        deduplicated, _ = AdvisoryDeduplicator().deduplicate(
            [
                self._record(
                    "article-a",
                    "Source A",
                    "https://a.example/advisory",
                    advisory_heading="NGINX HTTP/2 remote code execution CVE-2026-123007",
                    cve_details="CVE-2026-123007",
                    matched_app_name="nginx",
                    affected_versions="NGINX 1.9.5 through 1.31.8.",
                    source_content=(
                        "CVE-2026-123007 affects NGINX HTTP/2 and allows remote "
                        "code execution."
                    ),
                ),
                self._record(
                    "article-b",
                    "Source B",
                    "https://b.example/advisory",
                    advisory_heading="Five NGINX flaws include CVE-2026-123007",
                    cve_details="CVE-2026-123007, CVE-2026-123633",
                    matched_app_name="nginx",
                    affected_versions=(
                        "98.9% of 11.94 million NGINX servers; CVSS score: 9.2."
                    ),
                    source_content=(
                        "Researchers disclosed CVE-2026-123007 and "
                        "CVE-2026-123633 in NGINX. The HTTP/2 flaw allows "
                        "remote code execution."
                    ),
                ),
            ],
            [],
        )

        self.assertEqual(len(deduplicated), 1)
        self.assertEqual(
            deduplicated[0]["cve_details"],
            "CVE-2026-123007, CVE-2026-123633",
        )
        self.assertEqual(
            [reference["source_name"] for reference in deduplicated[0]["source_references"]],
            ["Source A", "Source B"],
        )

    def test_patch_versions_with_same_major_minor_are_compatible(self):
        deduplicated, _ = AdvisoryDeduplicator().deduplicate(
            [
                self._record(
                    "article-a",
                    "Source A",
                    "https://a.example/advisory",
                    advisory_heading="PHP security vulnerability CVE-2026-115560",
                    cve_details="CVE-2026-115560",
                    matched_app_name="PHP",
                    affected_versions="PHP 8.2, 8.3, 8.4, and 8.5.",
                ),
                self._record(
                    "article-b",
                    "Source B",
                    "https://b.example/advisory",
                    advisory_heading="PHP CVE-2026-115560 security fixes",
                    cve_details="CVE-2026-115560",
                    matched_app_name="PHP",
                    affected_versions="PHP 8.2.35, 8.3.36, 8.4.27, and 8.5.12.",
                ),
            ],
            [],
        )

        self.assertEqual(len(deduplicated), 1)

    def test_incidental_cve_and_inventory_product_match_do_not_merge_different_products(self):
        deduplicated, _ = AdvisoryDeduplicator().deduplicate(
            [
                self._record(
                    "article-a",
                    "Source A",
                    "https://a.example/advisory",
                    advisory_heading="NGINX HTTP/2 RCE CVE-2026-123007",
                    cve_details="CVE-2026-123007",
                    matched_app_name="nginx, Linux, Container",
                    source_content="NGINX HTTP/2 allows remote code execution.",
                ),
                self._record(
                    "article-b",
                    "Source B",
                    "https://b.example/advisory",
                    advisory_heading="Synology NAS security advisory CVE-2026-120382",
                    cve_details="CVE-2026-120382, CVE-2026-123007",
                    matched_app_name="nginx, Linux, Container",
                    report_summary="CVE-2026-123007 is mentioned in related coverage.",
                    source_content="Synology NAS security update for CVE-2026-120382.",
                ),
            ],
            [],
        )

        self.assertEqual(len(deduplicated), 2)
        self.assertEqual(
            [
                [reference["source_name"] for reference in record["source_references"]]
                for record in deduplicated
            ],
            [["Source A"], ["Source B"]],
        )

    def test_comparison_uses_article_text_beyond_first_six_thousand_characters(self):
        shared_details = (
            "The HTTP/2 request processing flaw causes a heap buffer overflow. "
            "A remote attacker can execute code on the affected server."
        )
        prefix_a = "sourcealpha " * 700
        prefix_b = "sourcebravo " * 700
        deduplicated, _ = AdvisoryDeduplicator().deduplicate(
            [
                self._record(
                    "article-a",
                    "Source A",
                    "https://a.example/advisory",
                    id="article-a",
                    advisory_heading="Example Product HTTP/2 remote code execution",
                    cve_details="NA",
                    matched_app_name="Example Product",
                    impact_summary="Source alpha reported a heap issue.",
                    report_summary="Source alpha published technical analysis.",
                    source_content=prefix_a + shared_details,
                ),
                self._record(
                    "article-b",
                    "Source B",
                    "https://b.example/advisory",
                    id="article-b",
                    advisory_heading="Example Product HTTP/2 remote code execution",
                    cve_details="NA",
                    matched_app_name="Example Product",
                    impact_summary="Source bravo described a memory issue.",
                    report_summary="Source bravo published implementation notes.",
                    source_content=prefix_b + shared_details,
                ),
            ],
            [],
        )

        self.assertEqual(len(deduplicated), 1)

    def test_long_unique_article_context_does_not_hide_matching_issue_details(self):
        context_a = (
            "alpha bravo charlie delta echo foxtrot golf hotel india juliet "
            "kilo lima mike november oscar papa quebec romeo sierra tango "
            "uniform victor whiskey xray yankee zulu"
        )
        context_b = (
            "copper silver bronze iron steel timber cotton wool leather plastic "
            "glass paper marble granite cement ceramic rubber nylon silk velvet linen"
        )
        deduplicated, _ = AdvisoryDeduplicator().deduplicate(
            [
                self._record(
                    "article-a",
                    "Source A",
                    "https://a.example/advisory",
                    advisory_heading="Example Product HTTP/2 parser RCE",
                    cve_details="NA",
                    matched_app_name="Example Product",
                    impact_summary=(
                        "Crafted HTTP/2 frames can overflow the request parser "
                        "and permit code execution."
                    ),
                    report_summary=(
                        "Attackers can corrupt the parser heap and execute code."
                    ),
                    source_content=(
                        f"{context_a}. HTTP/2 request parser mishandles crafted "
                        "frames, causing a heap buffer overflow. Remote attackers "
                        "can execute arbitrary code."
                    ),
                ),
                self._record(
                    "article-b",
                    "Source B",
                    "https://b.example/advisory",
                    advisory_heading="Example Product malformed frame processing",
                    cve_details="NA",
                    matched_app_name="Example Product",
                    impact_summary=(
                        "Malformed HTTP/2 stream frames corrupt decoder memory."
                    ),
                    report_summary=(
                        "The decoder flaw can lead to arbitrary command execution."
                    ),
                    source_content=(
                        f"{context_b}. The HTTP/2 decoder mishandles crafted frames "
                        "and causes a heap-based buffer overflow. Unauthenticated "
                        "remote attackers can execute arbitrary code."
                    ),
                ),
            ],
            [],
        )

        self.assertEqual(len(deduplicated), 1)
        self.assertEqual(
            [reference["source_name"] for reference in deduplicated[0]["source_references"]],
            ["Source A", "Source B"],
        )

    def test_semantically_related_articles_merge_without_a_cve(self):
        deduplicated, _ = AdvisoryDeduplicator().deduplicate(
            [
                self._record(
                    "article-a",
                    "Source A",
                    "https://a.example/advisory",
                    advisory_heading="Ruby2Shell: critical Ruby string vulnerability",
                    cve_details="NA",
                    matched_app_name="Ruby",
                    impact_summary="Ruby string case conversion can lead to remote code execution.",
                    report_summary=(
                        "The Ruby string case conversion operation allows unauthenticated "
                        "remote code execution in Rails applications."
                    ),
                    source_content=(
                        "Ruby2Shell exploits string case conversion in Ruby applications "
                        "to achieve remote code execution."
                    ),
                ),
                self._record(
                    "article-b",
                    "Source B",
                    "https://b.example/advisory",
                    advisory_heading="Ruby security fixes include a string conversion RCE",
                    cve_details="NA",
                    matched_app_name="Ruby",
                    impact_summary=(
                        "A string case conversion flaw can cause remote code execution."
                    ),
                    report_summary=(
                        "Ruby fixes include a string case conversion issue that causes "
                        "code execution in Rails apps."
                    ),
                    source_content=(
                        "The Ruby patch fixes a string case conversion bug that permits "
                        "remote code execution in Rails."
                    ),
                ),
            ],
            [],
        )

        self.assertEqual(len(deduplicated), 1)
        self.assertEqual(
            [reference["source_name"] for reference in deduplicated[0]["source_references"]],
            ["Source A", "Source B"],
        )

    def test_same_product_alone_does_not_merge_unrelated_articles(self):
        deduplicated, _ = AdvisoryDeduplicator().deduplicate(
            [
                self._record(
                    "article-a",
                    "Source A",
                    "https://a.example/advisory",
                    advisory_heading="Microsoft To Do will soon become Microsoft Done",
                    cve_details="NA",
                    matched_app_name="Microsoft To Do",
                    impact_summary="To Do apps will retire in June 2027.",
                    report_summary="Users must move their task lists to Planner.",
                    source_content=(
                        "Microsoft is retiring its To Do apps and recommending Planner."
                    ),
                ),
                self._record(
                    "article-b",
                    "Source B",
                    "https://b.example/advisory",
                    advisory_heading="Microsoft confirms app installation issues after hotpatch",
                    cve_details="NA",
                    matched_app_name="Microsoft To Do",
                    impact_summary="Windows applications may fail to start.",
                    report_summary="A hotpatch update caused installation problems.",
                    source_content=(
                        "Microsoft released a workaround for application installation "
                        "and launch issues after a Windows hotpatch."
                    ),
                ),
            ],
            [],
        )

        self.assertEqual(len(deduplicated), 2)

    def test_conflicting_versions_are_flagged_for_review_instead_of_merged(self):
        deduplicated, _ = AdvisoryDeduplicator().deduplicate(
            [
                self._record("article-a", "Source A", "https://a.example/advisory"),
                self._record(
                    "article-b",
                    "Source B",
                    "https://b.example/advisory",
                    affected_versions="3.0.0",
                ),
            ],
            [],
        )

        self.assertEqual(len(deduplicated), 2)
        candidate = deduplicated[1]
        self.assertEqual(candidate["review_decision"], "☐ Pending")
        self.assertEqual(candidate["initial_triage"], "Flagged")
        self.assertIn("Possible duplicate", candidate["duplicate_note"])

    def test_different_cves_are_not_merged(self):
        deduplicated, _ = AdvisoryDeduplicator().deduplicate(
            [
                self._record("article-a", "Source A", "https://a.example/advisory"),
                self._record(
                    "article-b",
                    "Source B",
                    "https://b.example/advisory",
                    advisory_heading="Apache Ignite denial of service CVE-2026-54321",
                    cve_details="CVE-2026-54321",
                    impact_summary="Denial of service affects Apache Ignite.",
                    report_summary="Attackers can cause service disruption.",
                    source_content="Apache Ignite CVE-2026-54321 causes denial of service.",
                ),
            ],
            [],
        )

        self.assertEqual(len(deduplicated), 2)
        self.assertEqual(
            [record.get("duplicate_note", "") for record in deduplicated],
            ["", ""],
        )

    def test_reworded_campaign_without_cve_uses_entity_candidate_and_llm(self):
        source_a = self._record(
            "article-a",
            "Source A",
            "https://a.example/campaign",
            advisory_heading="APT28 targets Acme Health in credential theft campaign",
            cve_details="NA",
            matched_app_name="",
            affected_products="",
            affected_versions="",
            impact_summary=(
                "APT28 operators accessed the Acme Health patient portal through "
                "credential theft and exfiltrated medical records."
            ),
            report_summary=(
                "The intrusion used stolen credentials to compromise Acme Health "
                "and extract patient records."
            ),
            source_content=(
                "APT28 accessed Acme Health patient systems with stolen credentials. "
                "The operators exfiltrated medical records."
            ),
        )
        source_b = self._record(
            "article-b",
            "Source B",
            "https://b.example/breach",
            advisory_heading="Acme Health breach linked to APT28 intrusion",
            cve_details="NA",
            matched_app_name="",
            affected_products="",
            affected_versions="",
            impact_summary=(
                "A campaign attributed to APT28 compromised the Acme Health portal, "
                "stealing login credentials and taking patient records."
            ),
            report_summary=(
                "The attackers used stolen credentials to access Acme Health and "
                "remove medical records."
            ),
            source_content=(
                "APT28 compromised Acme Health patient services with stolen credentials "
                "and removed medical records."
            ),
        )
        adjudicator = Mock(return_value={
            "same_event": True,
            "confidence": 0.96,
            "reason": "Both reports describe the same Acme Health intrusion.",
            "conflicts": [],
        })

        deduplicated, _ = AdvisoryDeduplicator().deduplicate(
            [source_a, source_b],
            [],
            adjudicator=adjudicator,
        )

        self.assertEqual(len(deduplicated), 1)
        adjudicator.assert_called_once()
        self.assertEqual(
            [reference["article_id"] for reference in deduplicated[0]["source_references"]],
            ["article-a", "article-b"],
        )

    def test_no_product_name_match_can_be_adjudicated_from_shared_cve(self):
        source_a = self._record(
            "article-a",
            "Source A",
            "https://a.example/advisory",
            advisory_heading="Azure Kubernetes Service control-plane flaw CVE-2026-76543",
            matched_app_name="Azure Kubernetes Service",
            affected_products="Azure Kubernetes Service",
        )
        source_b = self._record(
            "article-b",
            "Source B",
            "https://b.example/advisory",
            advisory_heading="AKS control plane vulnerability CVE-2026-76543",
            matched_app_name="AKS",
            affected_products="AKS",
            source_content=(
                "CVE-2026-76543 allows remote code execution in the Kubernetes control "
                "plane, affecting managed clusters."
            ),
            report_summary=(
                "The Kubernetes control plane is vulnerable to remote code execution "
                "in managed clusters."
            ),
        )
        adjudicator = Mock(return_value={
            "same_event": True,
            "confidence": 0.93,
            "reason": "The reports describe the same CVE in the same control plane.",
            "conflicts": [],
        })

        deduplicated, _ = AdvisoryDeduplicator().deduplicate(
            [source_a, source_b],
            [],
            adjudicator=adjudicator,
        )

        self.assertEqual(len(deduplicated), 1)
        adjudicator.assert_called_once()

    def test_conflicting_versions_are_explicit_in_fallback_summary(self):
        source_a = self._record(
            "article-a",
            "Source A",
            "https://a.example/advisory",
            affected_versions="2.0.0",
            severity="HIGH",
        )
        source_b = self._record(
            "article-b",
            "Source B",
            "https://b.example/advisory",
            affected_versions="3.0.0",
            severity="CRITICAL",
        )
        adjudicator = Mock(return_value={
            "same_event": True,
            "confidence": 0.98,
            "reason": "The shared CVE identifies the same underlying issue.",
            "conflicts": [],
        })

        deduplicated, _ = AdvisoryDeduplicator().deduplicate(
            [source_a, source_b],
            [],
            adjudicator=adjudicator,
        )

        self.assertEqual(len(deduplicated), 1)
        self.assertIn("different affected versions", deduplicated[0]["report_summary"])
        self.assertIn("different severities", deduplicated[0]["report_summary"])
        self.assertEqual(len(deduplicated[0]["summary_conflicts"]), 2)

    def test_same_cve_different_lifecycle_stages_remains_separate(self):
        disclosure = self._record(
            "article-disclosure",
            "Source A",
            "https://a.example/disclosure",
            advisory_heading="Apache Ignite vulnerability disclosed CVE-2026-12345",
            impact_summary="A vulnerability in Apache Ignite was disclosed.",
            report_summary="Researchers disclosed the flaw in Apache Ignite.",
            source_content="The vulnerability was disclosed on 2026-01-01.",
        )
        exploitation = self._record(
            "article-exploitation",
            "Source B",
            "https://b.example/exploitation",
            advisory_heading="Apache Ignite CVE-2026-12345 actively exploited",
            impact_summary="Attackers are actively exploiting the Apache Ignite flaw.",
            report_summary="The vulnerability is exploited in the wild.",
            source_content="The flaw is actively exploited in the wild.",
        )
        decision_callback = Mock()
        adjudicator = Mock(return_value={
            "same_event": True,
            "confidence": 0.99,
            "reason": "Both articles mention the same CVE.",
            "conflicts": [],
        })

        deduplicated, _ = AdvisoryDeduplicator().deduplicate(
            [disclosure, exploitation],
            [],
            adjudicator=adjudicator,
            decision_callback=decision_callback,
        )

        self.assertEqual(len(deduplicated), 2)
        self.assertIn("lifecycle stages", deduplicated[1]["duplicate_note"])
        self.assertTrue(any(
            call.kwargs.get("same_event") is False
            for call in decision_callback.call_args_list
        ))

    def test_previously_decided_different_pair_is_not_reflagged(self):
        source_a = self._record("article-a", "Source A", "https://a.example/advisory")
        source_b = self._record("article-b", "Source B", "https://b.example/advisory")

        deduplicated, _ = AdvisoryDeduplicator().deduplicate(
            [source_b],
            [source_a],
            pair_decisions={
                ("article-a", "article-b"): {
                    "same_event": False,
                    "decided_by": "human",
                    "reason": "Human chose Keep Separate.",
                },
            },
        )

        self.assertEqual(len(deduplicated), 1)
        self.assertEqual(deduplicated[0].get("duplicate_note", ""), "")

    def test_merge_summary_callback_receives_every_source_record(self):
        source_a = self._record("article-a", "Source A", "https://a.example/advisory")
        source_b = self._record(
            "article-b",
            "Source B",
            "https://b.example/advisory",
            report_summary=(
                "Attackers can execute arbitrary code in Apache Ignite. "
                "The issue also exposes stored credentials."
            ),
        )
        generated_summary = {
            "impact_summary": "The flaw enables remote code execution.",
            "report_summary": "The issue exposes stored credentials.",
            "recommendation": "Upgrade to the fixed version.",
            "affected_products": "Apache Ignite",
            "affected_versions": "2.0.0",
            "severity": "HIGH",
            "cve_details": "CVE-2026-12345",
            "iocs": "example[.]com",
            "conflicts": [],
        }
        summarizer = Mock(return_value=generated_summary)

        deduplicated, _ = AdvisoryDeduplicator().deduplicate(
            [source_a, source_b],
            [],
            summarizer=summarizer,
        )

        self.assertEqual(len(deduplicated), 1)
        summarizer.assert_called_once()
        summarized_record = summarizer.call_args.args[0]
        self.assertEqual(
            [reference["source_name"] for reference in summarized_record["source_references"]],
            ["Source A", "Source B"],
        )
        self.assertEqual(
            deduplicated[0]["report_summary"],
            generated_summary["report_summary"],
        )


if __name__ == "__main__":
    unittest.main()
