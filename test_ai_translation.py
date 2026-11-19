import json
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from ai_evaluator import SecurityAIEvaluator


class AdvisoryTranslationTests(unittest.TestCase):
    @patch("ai_evaluator.requests.post")
    def test_foreign_advisory_is_translated_before_context_filtering(self, post):
        source_content = "Détails de sécurité. " * 300 + "Fin du bulletin."
        response_data = {
            "is_actionable_vulnerability": True,
            "rejection_reason": "",
            "translated_title": "Example Platform security vulnerability",
            "translated_content": "A vulnerability affects Example Platform.",
            "advisory_heading": "Example Platform security vulnerability",
            "severity": "HIGH",
            "cvss_score": "8.8",
            "affected_products": "Example Platform",
            "affected_versions": "",
            "impact_summary": "A vulnerability affects Example Platform.",
            "report_summary": "A vulnerability affects Example Platform.",
        }
        response = Mock(status_code=200)
        response.json.return_value = {
            "candidates": [{
                "content": {
                    "parts": [{"text": json.dumps(response_data)}],
                },
            }],
        }
        post.return_value = response

        evaluator = SecurityAIEvaluator(api_key="test-key")
        result = evaluator.evaluate_advisory(
            {"title": "Avis de sécurité", "content": source_content},
            {"application_name": "Example Platform", "vendor": "Example"},
        )

        self.assertEqual(
            result["translated_title"],
            "Example Platform security vulnerability",
        )
        self.assertEqual(
            result["translated_content"],
            "A vulnerability affects Example Platform.",
        )
        prompt = post.call_args.kwargs["json"]["contents"][0]["parts"][0]["text"]
        self.assertIn("do not omit or summarize any source content", prompt.lower())
        self.assertIn("Fin du bulletin.", prompt)


if __name__ == "__main__":
    unittest.main()
