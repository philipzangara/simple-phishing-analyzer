import unittest

from analyzer.headers import HeaderAnalysis, DisplaySpoofAnalysis
from analyzer.iocs import IOCCollection
from json_output import build_json_output, SCHEMA_VERSION


class TestJsonOutput(unittest.TestCase):

    def setUp(self):
        """Create reusable analysis data for JSON output tests."""

        self.headers = HeaderAnalysis(
            subject="Account notification",
            spf="pass",
            dkim="pass",
            dmarc="pass",
            display_name_spoof=DisplaySpoofAnalysis(
                display_name="Example Support",
                from_domain="example.com",
                spoofed=False,
            ),
            reply_to_domain="example.com",
            reply_to_from_domain="example.com",
            reply_to_mismatch=False,
            received_origin_domain="example.com",
            received_from_domain="example.com",
            received_mismatch=False,
            received_hops=3,
        )

        self.observables = IOCCollection(
            urls=["https://example.com/login"],
            domains=["example.com"],
            ips=["192.0.2.1"],
            attachments=[
                {
                    "filename": "invoice.pdf",
                    "content_type": "application/pdf",
                    "md5": "test-md5",
                    "sha1": "test-sha1",
                    "sha256": "test-sha256",
                }
            ],
        )

        self.score = {
            "score": 25,
            "verdict": "MEDIUM",
            "reasons": ["Test reason"],
        }

        self.result = build_json_output(
            file_name="sample.eml",
            file_size=12345,
            headers=self.headers,
            observables=self.observables,
            score=self.score,
        )

    def test_schema_version(self):
        self.assertEqual(SCHEMA_VERSION, "1.0")
        self.assertEqual(self.result["schema_version"], "1.0")

    def test_file_info(self):
        self.assertEqual(self.result["file"]["name"], "sample.eml")
        self.assertEqual(self.result["file"]["size"], 12345)

    def test_header_info(self):
        headers = self.result["headers"]

        self.assertEqual(
            headers["subject"],
            "Account notification"
        )
        self.assertEqual(
            headers["from"]["display_name"],
            "Example Support"
        )
        self.assertEqual(
            headers["from"]["domain"],
            "example.com"
        )
        self.assertEqual(
            headers["reply_to_domain"],
            "example.com"
        )
        self.assertEqual(
            headers["origin_domain"],
            "example.com"
        )
        self.assertEqual(headers["hops"], 3)

    def test_authentication_results(self):
        authentication = self.result["headers"]["authentication"]

        self.assertEqual(authentication["spf"], "pass")
        self.assertEqual(authentication["dkim"], "pass")
        self.assertEqual(authentication["dmarc"], "pass")

    def test_header_flags(self):
        flags = self.result["headers"]["flags"]

        self.assertFalse(flags["display_name_spoof"])
        self.assertFalse(flags["reply_to_mismatch"])
        self.assertFalse(flags["received_chain_mismatch"])

    def test_observables(self):
        observables = self.result["observables"]

        self.assertEqual(
            observables["urls"],
            ["https://example.com/login"]
        )
        self.assertEqual(
            observables["domains"],
            ["example.com"]
        )
        self.assertEqual(
            observables["ip_addresses"],
            ["192.0.2.1"]
        )
        self.assertEqual(
            observables["attachments"][0]["filename"],
            "invoice.pdf"
        )

    def test_score(self):
        score = self.result["score"]

        self.assertEqual(score["score"], 25)
        self.assertEqual(score["verdict"], "MEDIUM")
        self.assertEqual(score["reasons"], ["Test reason"])

    def test_top_level_schema_keys(self):
        self.assertEqual(
            set(self.result.keys()),
            {
                "schema_version",
                "file",
                "headers",
                "observables",
                "score",
            },
        )

    def test_missing_display_name_analysis(self):
        headers = HeaderAnalysis(
            subject="No display name",
            display_name_spoof=None,
        )

        result = build_json_output(
            file_name="sample.eml",
            file_size=100,
            headers=headers,
            observables=IOCCollection(
                urls=[],
                domains=[],
                ips=[],
                attachments=[],
            ),
            score={
                "score": 0,
                "verdict": "LOW",
                "reasons": [],
            },
        )

        self.assertIsNone(
            result["headers"]["from"]["display_name"]
        )
        self.assertIsNone(
            result["headers"]["from"]["domain"]
        )
        self.assertIsNone(
            result["headers"]["flags"]["display_name_spoof"]
        )


if __name__ == "__main__":
    unittest.main()