import unittest
from email.message import EmailMessage

from analyzer.headers import (
    analyze_headers,
    check_display_name_spoof,
    check_reply_to,
    received_chain_analysis,
)


class TestHeaders(unittest.TestCase):

    def create_message(
        self,
        *,
        from_header="Microsoft Support <support@microsoft.com>",
        reply_to=None,
        subject="Test email",
        authentication_results=None,
        received=None,
    ):
        """Create an EmailMessage with configurable headers."""
        msg = EmailMessage()
        msg["From"] = from_header
        msg["Subject"] = subject

        if reply_to:
            msg["Reply-To"] = reply_to

        if authentication_results:
            msg["Authentication-Results"] = authentication_results

        for received_header in received or []:
            msg["Received"] = received_header

        return msg

    # ------------------------------------------------------------------
    # Display-name analysis
    # ------------------------------------------------------------------

    def test_display_name_matches_from_domain(self):
        msg = self.create_message(
            from_header="Microsoft Support <support@microsoft.com>"
        )

        result = check_display_name_spoof(msg)

        self.assertFalse(result["spoofed"])
        self.assertEqual(result["display_name"], "Microsoft Support")
        self.assertEqual(result["from_domain"], "microsoft.com")

    def test_display_name_does_not_match_from_domain(self):
        msg = self.create_message(
            from_header="Microsoft Support <support@example.com>"
        )

        result = check_display_name_spoof(msg)

        self.assertTrue(result["spoofed"])
        self.assertEqual(result["display_name"], "Microsoft Support")
        self.assertEqual(result["from_domain"], "example.com")

    def test_missing_display_name(self):
        msg = self.create_message(
            from_header="support@example.com"
        )

        result = check_display_name_spoof(msg)

        self.assertIsNone(result["spoofed"])
        self.assertEqual(result["reason"], "No display name present")

    # ------------------------------------------------------------------
    # Reply-To analysis
    # ------------------------------------------------------------------

    def test_reply_to_domain_matches_from_domain(self):
        msg = self.create_message(
            from_header="Support <support@example.com>",
            reply_to="Help Desk <help@example.com>",
        )

        result = check_reply_to(msg)

        self.assertFalse(result["mismatch"])
        self.assertEqual(result["from_domain"], "example.com")
        self.assertEqual(result["replyto_domain"], "example.com")

    def test_reply_to_domain_does_not_match_from_domain(self):
        msg = self.create_message(
            from_header="Support <support@example.com>",
            reply_to="Attacker <reply@malicious.net>",
        )

        result = check_reply_to(msg)

        self.assertTrue(result["mismatch"])
        self.assertEqual(result["from_domain"], "example.com")
        self.assertEqual(result["replyto_domain"], "malicious.net")

    def test_missing_reply_to_header(self):
        msg = self.create_message()

        result = check_reply_to(msg)

        self.assertIsNone(result["mismatch"])
        self.assertEqual(result["reason"], "No Reply-To header")

    # ------------------------------------------------------------------
    # Received-chain analysis
    # ------------------------------------------------------------------

    def test_received_origin_matches_from_domain(self):
        msg = self.create_message(
            from_header="Support <support@example.com>",
            received=[
                "from relay.example.com by destination.come",
                "from mail.example.com by relay.example.com",
            ],
        )

        result = received_chain_analysis(msg)

        self.assertEqual(result.origin_domain, "example.com")
        self.assertEqual(result.from_domain, "example.com")
        self.assertFalse(result.mismatch)
        self.assertEqual(result.hops, 2)
        self.assertEqual(result.reason, "N/A")

    def test_received_origin_does_not_match_from_domain(self):
        msg = self.create_message(
            from_header="Microsoft Support <support@microsoft.com>",
            received=[
                "from relay.destination.net by destination.net",
                "from attacker.malicious.net by relay.destination.net",
            ],
        )

        result = received_chain_analysis(msg)

        self.assertEqual(result.origin_domain, "malicious.net")
        self.assertEqual(result.from_domain, "microsoft.com")
        self.assertTrue(result.mismatch)
        self.assertEqual(result.hops, 2)
        self.assertEqual(result.reason, "N/A")

    def test_received_chain_uses_oldest_header_as_origin(self):
        msg = self.create_message(
            from_header="Support <support@example.com>",
            received=[
                "from newest.relay.net by destination.net",
                "from middle.relay.net by newest.relay.net",
                "from original.example.com by middle.relay.net",
            ],
        )

        result = received_chain_analysis(msg)

        self.assertEqual(result.origin_domain, "example.com")
        self.assertEqual(result.hops, 3)

    def test_missing_received_headers(self):
        msg = self.create_message()

        result = received_chain_analysis(msg)

        self.assertIsNone(result.origin_domain)
        self.assertIsNone(result.from_domain)
        self.assertIsNone(result.mismatch)
        self.assertEqual(result.hops, 0)
        self.assertEqual(result.reason, "No Received headers")

    # ------------------------------------------------------------------
    # Complete header analysis
    # ------------------------------------------------------------------

    def test_analyze_headers_returns_combined_results(self):
        msg = self.create_message(
            from_header="Example Support <support@example.com>",
            reply_to="Help Desk <help@example.com>",
            subject="Account notification",
            authentication_results=(
                "mail.example.com; "
                "spf=pass smtp.mailfrom=example.com; "
                "dkim=pass header.d=example.com; "
                "dmarc=pass action=none"
            ),
            received=[
                "from original.example.com by destination.net"
            ],
        )

        result = analyze_headers(msg)

        self.assertEqual(result["spf"], "pass")
        self.assertEqual(result["dkim"], "pass")
        self.assertEqual(result["dmarc"], "pass")
        self.assertEqual(result["subject"], "Account notification")

        self.assertIn("display_name_spoof", result)
        self.assertIn("reply_to", result)
        self.assertIn("received_chain", result)

        self.assertFalse(result["reply_to"]["mismatch"])
        self.assertFalse(result["received_chain"].mismatch)

if __name__ == "__main__":
    unittest.main()