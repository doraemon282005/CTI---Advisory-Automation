import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from inoreader_client import InoreaderClient


class InoreaderClientTests(unittest.TestCase):
    def test_html_cleaning_removes_embedded_page_scripts(self):
        client = InoreaderClient()

        cleaned = client._clean_html(
            "<p>Example product has a security flaw.</p>"
            "<script>window.ytcfg.set('EMERGENCY_BASE_URL', '/error');</script>"
            "<p>Apply the vendor's patch.</p>"
        )

        self.assertIn("Example product has a security flaw.", cleaned)
        self.assertIn("Apply the vendor's patch.", cleaned)
        self.assertNotIn("window.ytcfg", cleaned)

    def test_normalization_keeps_published_time_and_adds_crawl_time_for_scanning(self):
        client = InoreaderClient(fetch_full_web=False)

        article = client._normalize_item({
            "id": "article-1",
            "title": "Example advisory",
            "published": 100,
            "timestampUsec": "150000000",
            "crawlTimeMsec": "175000",
        })

        self.assertEqual(article["published_timestamp"], 100)
        self.assertEqual(article["scan_timestamp"], 150)

    def test_normalization_uses_crawl_time_when_microsecond_timestamp_is_missing(self):
        client = InoreaderClient(fetch_full_web=False)

        article = client._normalize_item({
            "id": "article-1",
            "title": "Example advisory",
            "published": 100,
            "crawlTimeMsec": "175000",
        })

        self.assertEqual(article["published_timestamp"], 100)
        self.assertEqual(article["scan_timestamp"], 175)

    def test_missing_authentication_does_not_substitute_sample_articles(self):
        client = InoreaderClient()

        with patch.object(client, "authenticate", return_value=False):
            with self.assertRaisesRegex(RuntimeError, "no sample data was substituted"):
                client.fetch_articles()

    @patch("inoreader_client.requests.get")
    def test_feed_http_error_does_not_return_partial_or_sample_articles(self, get):
        response = Mock(status_code=502, text="gateway unavailable")
        get.return_value = response
        client = InoreaderClient(token="test-token")

        with self.assertRaisesRegex(RuntimeError, "HTTP 502"):
            client.fetch_articles()

        get.assert_called_once()

    @patch("inoreader_client.requests.get")
    def test_transient_connection_error_is_retried(self, get):
        response = Mock(status_code=200)
        response.json.return_value = {"items": []}
        get.side_effect = [
            requests.ConnectionError("remote disconnected"),
            response,
        ]
        client = InoreaderClient(token="test-token")

        with patch("inoreader_client.time.sleep") as sleep:
            self.assertEqual(client.fetch_articles(), [])

        self.assertEqual(get.call_count, 2)
        sleep.assert_called_once_with(1)

    @patch(
        "inoreader_client.requests.get",
        side_effect=requests.ConnectionError("remote disconnected"),
    )
    def test_connection_error_is_reported_after_retries(self, get):
        client = InoreaderClient(token="test-token")

        with patch("inoreader_client.time.sleep") as sleep:
            with self.assertRaisesRegex(
                RuntimeError,
                "Inoreader feed fetch failed; no sample data was substituted",
            ):
                client.fetch_articles()

        self.assertEqual(get.call_count, 3)
        self.assertEqual([item.args[0] for item in sleep.call_args_list], [1, 2])

    @patch("inoreader_client.requests.get")
    def test_repeated_continuation_is_reported_as_incomplete(self, get):
        response = Mock(status_code=200)
        response.json.return_value = {
            "items": [{"title": "test", "canonical": {"href": "https://example.test"}}],
            "continuation": "same-page",
        }
        get.return_value = response
        client = InoreaderClient(token="test-token")

        with self.assertRaisesRegex(RuntimeError, "incomplete feed"):
            client.fetch_articles()

        self.assertEqual(get.call_count, 2)


if __name__ == "__main__":
    unittest.main()
