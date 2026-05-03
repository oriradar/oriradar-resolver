from __future__ import annotations

import unittest

from oritypo_solver.services.enrichment_policy import should_capture_screenshot, should_crawl_finding
from oritypo_solver.services.oridigest import build_digest_payload
from oritypo_solver.store import ScanRecord


class EnrichmentPolicyTests(unittest.TestCase):
    def test_screenshot_policy_triggers_for_login_page(self) -> None:
        finding = {
            "score": 40,
            "prediction_score": 50,
            "http": {
                "reachable": True,
                "login_page": True,
                "parking_page": False,
                "final_host_matches_input": True,
                "redirects": 0,
                "requested_url": "https://example-login.com",
            },
            "fqdn": "example-login.com",
        }
        self.assertTrue(should_capture_screenshot(finding))

    def test_screenshot_policy_skips_parking_without_high_prediction(self) -> None:
        finding = {
            "score": 88,
            "prediction_score": 70,
            "http": {
                "reachable": True,
                "login_page": False,
                "parking_page": True,
                "final_host_matches_input": True,
                "redirects": 0,
                "requested_url": "https://example-parked.com",
            },
            "fqdn": "example-parked.com",
        }
        self.assertFalse(should_capture_screenshot(finding))

    def test_crawl_policy_triggers_for_suspicious_http(self) -> None:
        finding = {
            "score": 35,
            "prediction_score": 70,
            "http": {
                "reachable": True,
                "login_page": False,
                "parking_page": False,
                "final_host_matches_input": False,
                "redirects": 1,
                "requested_url": "https://example-redirect.com",
            },
            "fqdn": "example-redirect.com",
        }
        self.assertTrue(should_crawl_finding(finding))


class DigestPayloadTests(unittest.TestCase):
    def test_digest_payload_counts_signals(self) -> None:
        scan = ScanRecord(id="scan-1", target="example.com", status="completed")
        scan.findings = [
            {
                "fqdn": "example-login.com",
                "score": 90,
                "prediction_score": 88,
                "risk_level": "critical",
                "prediction_level": "critical",
                "http": {"login_page": True},
                "screenshot": {"status": "completed"},
                "crawl": {"status": "completed"},
            }
        ]
        payload = build_digest_payload(scans=[scan])
        self.assertEqual(payload["critical_findings_count"], 1)
        self.assertEqual(payload["login_like_count"], 1)
        self.assertEqual(payload["screenshot_completed_count"], 1)
        self.assertEqual(payload["crawl_completed_count"], 1)


if __name__ == "__main__":
    unittest.main()
