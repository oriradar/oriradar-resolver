from __future__ import annotations

import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from oritypo_solver.main import app
from oritypo_solver.services.permutations import Variant
from oritypo_solver.services.scan_engine import run_scan
from oritypo_solver.services.scoring import score_finding
from oritypo_solver.store import create_scan, get_scan


class OriScoreTests(unittest.TestCase):
    def test_score_finding_marks_active_close_domain_as_high_risk(self) -> None:
        dns_records = {
            "A": ["1.1.1.1"],
            "AAAA": [],
            "MX": ["10 mail.examplea.com"],
            "NS": ["ns1.examplea.com"],
            "CNAME": [],
        }
        http_result = {
            "reachable": True,
            "scheme": "https",
            "status_code": 200,
            "title": "Example Login",
        }
        score, reasons, level = score_finding(
            distance=1,
            kind="orifold:Homoglyph",
            dns_records=dns_records,
            http_result=http_result,
        )

        self.assertGreaterEqual(score, 70)
        self.assertIn(level, {"high", "critical"})
        self.assertIn("resolves to an IP address", reasons)

    def test_score_finding_penalizes_parked_domains(self) -> None:
        dns_records = {
            "A": ["1.1.1.1"],
            "AAAA": [],
            "MX": ["0 localhost"],
            "NS": ["ns1.examplea.com"],
            "CNAME": [],
        }
        http_result = {
            "reachable": True,
            "scheme": "https",
            "status_code": 200,
            "title": "examplea.com - This website is for sale!",
            "parking_page": True,
            "challenge_page": False,
            "login_page": False,
            "redirects": 0,
            "final_host_matches_input": True,
        }
        score, reasons, level = score_finding(
            distance=1,
            kind="orifold:Bitsquatting",
            dns_records=dns_records,
            http_result=http_result,
        )

        self.assertLess(score, 90)
        self.assertIn(level, {"high", "medium"})
        self.assertIn("looks like a parked or for-sale domain", reasons)
        self.assertGreaterEqual(score, 50)

    def test_score_finding_rewards_crawl_metadata_brand_hits(self) -> None:
        dns_records = {"A": ["1.1.1.1"], "AAAA": [], "MX": [], "NS": ["ns1.examplea.com"], "CNAME": []}
        crawl_result = {
            "status": "completed",
            "meta_brand_hits": 2,
            "external_http_urls": ["https://evil.example/phish"],
        }
        score, reasons, _level = score_finding(
            distance=2,
            kind="orifold:Addition",
            dns_records=dns_records,
            crawl_result=crawl_result,
        )
        self.assertGreaterEqual(score, 10)
        self.assertTrue(any("metadata" in r for r in reasons))
        self.assertTrue(any("external" in r for r in reasons))


    def test_score_finding_rewards_high_similarity(self) -> None:
        dns_records = {"A": ["1.1.1.1"], "AAAA": [], "MX": [], "NS": ["ns1.x.com"], "CNAME": []}
        crawl_result = {"status": "completed", "similarity": 0.92}
        ref = {"content_embedding": [0.1] * 384}
        score, reasons, _level = score_finding(
            distance=1,
            kind="orifold:Homoglyph",
            dns_records=dns_records,
            crawl_result=crawl_result,
            reference_data=ref,
        )
        self.assertTrue(any("closely resembles" in r for r in reasons))
        self.assertGreaterEqual(score, 60)

    def test_score_finding_rewards_moderate_similarity(self) -> None:
        dns_records = {"A": ["1.1.1.1"], "AAAA": [], "MX": [], "NS": [], "CNAME": []}
        crawl_result = {"status": "completed", "similarity": 0.70}
        ref = {"content_embedding": [0.1] * 384}
        score, reasons, _level = score_finding(
            distance=2,
            kind="orifold:Addition",
            dns_records=dns_records,
            crawl_result=crawl_result,
            reference_data=ref,
        )
        self.assertTrue(any("moderately resembles" in r for r in reasons))

    def test_score_finding_rewards_favicon_match(self) -> None:
        dns_records = {"A": ["1.1.1.1"], "AAAA": [], "MX": [], "NS": [], "CNAME": []}
        http_result = {
            "reachable": True,
            "scheme": "https",
            "status_code": 200,
            "title": "Fake",
            "favicon_hash": "12345",
            "cert_sans": [],
        }
        ref = {"target": "example.com", "favicon_hash": "12345", "cert_sans": []}
        score, reasons, _level = score_finding(
            distance=1,
            kind="orifold:Homoglyph",
            dns_records=dns_records,
            http_result=http_result,
            reference_data=ref,
        )
        self.assertTrue(any("favicon" in r for r in reasons))

    def test_score_finding_rewards_tls_brand(self) -> None:
        dns_records = {"A": ["1.1.1.1"], "AAAA": [], "MX": [], "NS": [], "CNAME": []}
        http_result = {
            "reachable": True,
            "scheme": "https",
            "status_code": 200,
            "title": "Fake",
            "favicon_hash": None,
            "cert_sans": ["example-secure.com", "login.example-secure.com"],
        }
        ref = {"target": "example.com", "favicon_hash": None, "cert_sans": []}
        score, reasons, _level = score_finding(
            distance=1,
            kind="orifold:Homoglyph",
            dns_records=dns_records,
            http_result=http_result,
            reference_data=ref,
        )
        self.assertTrue(any("TLS certificate" in r for r in reasons))

    def test_score_finding_penalizes_error_status(self) -> None:
        dns_records = {"A": ["1.1.1.1"], "AAAA": [], "MX": [], "NS": [], "CNAME": []}
        http_result = {
            "reachable": True,
            "scheme": "http",
            "status_code": 503,
            "title": None,
        }
        score, reasons, _level = score_finding(
            distance=2,
            kind="orifold:Addition",
            dns_records=dns_records,
            http_result=http_result,
        )
        self.assertTrue(any("error status" in r for r in reasons))

    def test_score_finding_penalizes_minimal_crawl_content(self) -> None:
        dns_records = {"A": ["1.1.1.1"], "AAAA": [], "MX": [], "NS": [], "CNAME": []}
        crawl_result = {"status": "completed", "content_snippet": "hi"}
        score, reasons, _level = score_finding(
            distance=2,
            kind="orifold:Addition",
            dns_records=dns_records,
            crawl_result=crawl_result,
        )
        self.assertTrue(any("minimal content" in r for r in reasons))

    def test_prediction_score_rewards_similarity(self) -> None:
        from oritypo_solver.services.scoring import score_prediction_finding

        dns_records = {"A": ["1.1.1.1"], "AAAA": [], "MX": [], "NS": [], "CNAME": []}
        crawl_result = {"status": "completed", "similarity": 0.90}
        ref = {"content_embedding": [0.1] * 384}
        score, reasons, _level = score_prediction_finding(
            distance=1,
            kind="orifold:Homoglyph",
            dns_records=dns_records,
            crawl_result=crawl_result,
            reference_data=ref,
        )
        self.assertTrue(any("closely resembles" in r for r in reasons))

    def test_prediction_score_rewards_favicon_match(self) -> None:
        from oritypo_solver.services.scoring import score_prediction_finding

        dns_records = {"A": ["1.1.1.1"], "AAAA": [], "MX": [], "NS": [], "CNAME": []}
        http_result = {
            "reachable": True,
            "scheme": "https",
            "status_code": 200,
            "favicon_hash": "abc",
            "cert_sans": [],
        }
        ref = {"target": "example.com", "favicon_hash": "abc", "cert_sans": []}
        score, reasons, _level = score_prediction_finding(
            distance=1,
            kind="orifold:Homoglyph",
            dns_records=dns_records,
            http_result=http_result,
            reference_data=ref,
        )
        self.assertTrue(any("favicon" in r for r in reasons))


    def test_score_finding_penalizes_low_similarity(self) -> None:
        dns_records = {"A": ["1.1.1.1"], "AAAA": [], "MX": [], "NS": ["ns1.x.com"], "CNAME": []}
        crawl_result = {"status": "completed", "similarity": 0.18}
        ref = {"content_embedding": [0.1] * 384, "favicon_hash": "official_fav"}
        http_result = {
            "reachable": True,
            "scheme": "https",
            "status_code": 200,
            "title": "Some Site",
            "favicon_hash": "other_fav",
            "cert_sans": [],
        }
        score, reasons, level = score_finding(
            distance=1,
            kind="orifold:Omission",
            dns_records=dns_records,
            http_result=http_result,
            crawl_result=crawl_result,
            reference_data=ref,
        )
        self.assertTrue(any("no resemblance" in r for r in reasons))
        self.assertTrue(any("legitimacy" in r for r in reasons))
        self.assertLess(score, 70)

    def test_score_finding_legitimacy_old_domain(self) -> None:
        dns_records = {"A": ["1.1.1.1"], "AAAA": [], "MX": [], "NS": [], "CNAME": []}
        rdap_result = {
            "available": True,
            "registrar": "SomeRegistrar",
            "registered_at": "2010-01-01T00:00:00Z",
        }
        crawl_result = {"status": "completed", "similarity": 0.20}
        ref = {"content_embedding": [0.1] * 384}
        score, reasons, _level = score_finding(
            distance=1,
            kind="orifold:Omission",
            dns_records=dns_records,
            rdap_result=rdap_result,
            crawl_result=crawl_result,
            reference_data=ref,
        )
        self.assertTrue(any("legitimacy" in r for r in reasons))
        self.assertLess(score, 60)

    def test_prediction_score_penalizes_low_similarity(self) -> None:
        from oritypo_solver.services.scoring import score_prediction_finding

        dns_records = {"A": ["1.1.1.1"], "AAAA": [], "MX": [], "NS": [], "CNAME": []}
        crawl_result = {"status": "completed", "similarity": 0.15}
        ref = {"content_embedding": [0.1] * 384}
        score, reasons, _level = score_prediction_finding(
            distance=1,
            kind="orifold:Homoglyph",
            dns_records=dns_records,
            crawl_result=crawl_result,
            reference_data=ref,
        )
        self.assertTrue(any("no resemblance" in r for r in reasons))

    def test_score_finding_legit_site_not_critical(self) -> None:
        """A functional site with low similarity and no malicious signals should not be critical."""
        dns_records = {
            "A": ["1.1.1.1"],
            "AAAA": [],
            "MX": ["10 mail.oogle.com"],
            "NS": ["ns1.oogle.com"],
            "CNAME": [],
        }
        http_result = {
            "reachable": True,
            "scheme": "https",
            "status_code": 200,
            "title": "Oogle - Independent Search",
            "favicon_hash": "different_fav",
            "cert_sans": ["oogle.com"],
            "login_page": False,
            "parking_page": False,
            "challenge_page": False,
        }
        crawl_result = {"status": "completed", "similarity": 0.18}
        ref = {
            "target": "google.com",
            "content_embedding": [0.1] * 384,
            "favicon_hash": "google_fav",
        }
        score, reasons, level = score_finding(
            distance=1,
            kind="orifold:Omission",
            dns_records=dns_records,
            http_result=http_result,
            crawl_result=crawl_result,
            reference_data=ref,
        )
        self.assertNotEqual(level, "critical")
        self.assertLess(score, 80)


class OriScanEngineTests(unittest.TestCase):
    @patch("oritypo_solver.services.scan_engine.emit_scan_completed", return_value=None)
    @patch("oritypo_solver.services.scan_engine.rdap_enabled", return_value=False)
    @patch("oritypo_solver.services.scan_engine.http_probe_limit_from_env", return_value=1)
    @patch("oritypo_solver.services.scan_engine.probe_hosts")
    @patch("oritypo_solver.services.scan_engine.resolve_records_batch")
    @patch("oritypo_solver.services.scan_engine.generate_variants")
    def test_run_scan_enriches_registered_findings(
        self,
        mock_generate_variants,
        mock_resolve_records_batch,
        mock_probe_hosts,
        _mock_http_limit,
        _mock_rdap_enabled,
        mock_emit,
    ) -> None:
        mock_generate_variants.return_value = [
            Variant(fqdn="example.com", kind="orifold:Original", distance=0),
            Variant(fqdn="examplea.com", kind="orifold:Addition", distance=1),
            Variant(fqdn="examplea.com", kind="orifold:Bitsquatting", distance=1),
        ]
        mock_resolve_records_batch.return_value = {
            "examplea.com": {
                "A": ["1.1.1.1"],
                "AAAA": [],
                "MX": [],
                "NS": ["ns1.examplea.com"],
                "CNAME": [],
            }
        }
        mock_probe_hosts.return_value = {
            "examplea.com": {
                "reachable": True,
                "scheme": "https",
                "status_code": 200,
                "requested_url": "https://examplea.com",
                "final_url": "https://examplea.com/",
                "redirects": 0,
                "server": "nginx",
                "content_type": "text/html",
                "content_length": "1234",
                "title": "Example Login",
                "final_host": "examplea.com",
                "final_host_matches_input": True,
                "login_page": True,
                "parking_page": False,
                "challenge_page": False,
            }
        }

        rec = create_scan("example.com")
        run_scan(rec.id, "example.com")

        saved = get_scan(rec.id)
        self.assertIsNotNone(saved)
        assert saved is not None
        self.assertEqual(saved.status, "completed")
        self.assertEqual(saved.summary["registered_count"], 1)
        self.assertEqual(saved.summary["http_probed_count"], 1)
        self.assertEqual(len(saved.findings), 1)
        self.assertEqual(saved.findings[0]["fqdn"], "examplea.com")
        self.assertTrue(saved.findings[0]["http"]["reachable"])
        self.assertGreater(saved.findings[0]["score"], 0)
        self.assertGreater(saved.findings[0]["prediction_score"], 0)
        self.assertIn(saved.findings[0]["prediction_level"], {"medium", "high", "critical"})
        mock_emit.assert_called_once()

    @patch("oritypo_solver.services.scan_engine.emit_scan_completed", return_value=None)
    @patch("oritypo_solver.services.scan_engine.enqueue_crawl_job")
    @patch("oritypo_solver.services.scan_engine.enqueue_screenshot_job")
    @patch("oritypo_solver.services.scan_engine.queue_enabled", return_value=True)
    @patch("oritypo_solver.services.scan_engine.rdap_enabled", return_value=False)
    @patch("oritypo_solver.services.scan_engine.probe_hosts")
    @patch("oritypo_solver.services.scan_engine.resolve_records_batch")
    @patch("oritypo_solver.services.scan_engine.generate_variants")
    def test_run_scan_queues_enrichments_when_enabled(
        self,
        mock_generate_variants,
        mock_resolve_records_batch,
        mock_probe_hosts,
        _mock_rdap_enabled,
        _mock_queue_enabled,
        mock_enqueue_screenshot_job,
        mock_enqueue_crawl_job,
        _mock_emit,
    ) -> None:
        mock_generate_variants.return_value = [
            Variant(fqdn="example-login.com", kind="orifold:Homoglyph", distance=1)
        ]
        mock_resolve_records_batch.return_value = {
            "example-login.com": {
                "A": ["1.1.1.1"],
                "AAAA": [],
                "MX": ["10 mail.example-login.com"],
                "NS": ["ns1.example-login.com"],
                "CNAME": [],
            }
        }
        mock_probe_hosts.return_value = {
            "example-login.com": {
                "reachable": True,
                "scheme": "https",
                "status_code": 200,
                "requested_url": "https://example-login.com",
                "final_url": "https://example-login.com/login",
                "redirects": 1,
                "server": "nginx",
                "content_type": "text/html",
                "content_length": "1234",
                "title": "Sign in",
                "final_host": "example-login.com",
                "final_host_matches_input": True,
                "login_page": True,
                "parking_page": False,
                "challenge_page": False,
            }
        }

        rec = create_scan("example.com")
        run_scan(rec.id, "example.com")

        saved = get_scan(rec.id)
        self.assertIsNotNone(saved)
        assert saved is not None
        self.assertEqual(saved.summary["screenshot_queued_count"], 1)
        self.assertEqual(saved.summary["crawl_queued_count"], 1)
        mock_enqueue_screenshot_job.assert_called_once()
        mock_enqueue_crawl_job.assert_called_once()


class OriApiQueueTests(unittest.TestCase):
    @patch("oritypo_solver.routers.scans.enqueue_scan_job")
    @patch("oritypo_solver.routers.scans.queue_enabled", return_value=True)
    def test_create_scan_enqueues_when_queue_mode_enabled(
        self,
        _mock_queue_enabled,
        mock_enqueue_scan_job,
    ) -> None:
        client = TestClient(app)
        response = client.post("/v1/scans", json={"target": "example.com"})

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "pending")
        mock_enqueue_scan_job.assert_called_once()


if __name__ == "__main__":
    unittest.main()
