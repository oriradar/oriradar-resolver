"""Tests for oricert (Certificate Transparency lookup)."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from oritypo_solver.services.oricert import (
    _normalize_fqdn,
    _split_san_field,
    discover_ct_candidates,
)


class NormalizeFqdnTests(unittest.TestCase):
    def test_strips_wildcards_and_dots(self):
        self.assertEqual(_normalize_fqdn("*.example.com"), "example.com")
        self.assertEqual(_normalize_fqdn("example.com."), "example.com")
        self.assertEqual(_normalize_fqdn("  EXAMPLE.com "), "example.com")

    def test_rejects_no_dot(self):
        self.assertEqual(_normalize_fqdn("localhost"), "")

    def test_rejects_spaces(self):
        self.assertEqual(_normalize_fqdn("foo bar.com"), "")

    def test_rejects_urls_and_ports(self):
        self.assertEqual(_normalize_fqdn("https://example.com/path"), "")
        self.assertEqual(_normalize_fqdn("example.com:443"), "")

    def test_keeps_idn_punycode(self):
        self.assertEqual(_normalize_fqdn("xn--exmple-cua.com"), "xn--exmple-cua.com")

    def test_rejects_idn_without_dot(self):
        self.assertEqual(_normalize_fqdn("xn--bar"), "")


class SplitSanFieldTests(unittest.TestCase):
    def test_splits_multiline_sans(self):
        raw = "example.com\nwww.example.com\n*.example.com"
        result = list(_split_san_field(raw))
        self.assertEqual(result, ["example.com", "www.example.com", "example.com"])

    def test_handles_carriage_return(self):
        raw = "a.com\r\nb.com"
        result = list(_split_san_field(raw))
        self.assertEqual(result, ["a.com", "b.com"])

    def test_skips_invalid_entries(self):
        raw = "valid.com\n   \nno-dot\n*.wild.com"
        result = list(_split_san_field(raw))
        self.assertEqual(result, ["valid.com", "wild.com"])


class DiscoverCtCandidatesTests(unittest.TestCase):
    def _mock_response(self, entries: list[dict]):
        return entries

    @patch("oritypo_solver.services.oricert._fetch_crt_sh")
    def test_discovers_typosquats_with_brand_in_label(self, mock_fetch):
        mock_fetch.return_value = [
            {"common_name": "mizuno-chaussures.fr", "name_value": "mizuno-chaussures.fr"},
            {"common_name": "mizunoshop.com", "name_value": "mizunoshop.com"},
            {"common_name": "mizuno.com", "name_value": "mizuno.com"},
            {"common_name": "www.mizuno.com", "name_value": "www.mizuno.com"},
        ]
        candidates = discover_ct_candidates("mizuno.com")
        fqdns = {c[0] for c in candidates}
        self.assertIn("mizuno-chaussures.fr", fqdns)
        self.assertIn("mizunoshop.com", fqdns)
        self.assertNotIn("mizuno.com", fqdns)
        self.assertNotIn("www.mizuno.com", fqdns)

    @patch("oritypo_solver.services.oricert._fetch_crt_sh")
    def test_kind_is_oricert_ct(self, mock_fetch):
        mock_fetch.return_value = [
            {"common_name": "mizuno-shop.fr", "name_value": "mizuno-shop.fr"},
        ]
        candidates = discover_ct_candidates("mizuno.com")
        self.assertTrue(all(kind == "oricert:CT" for _, kind, _ in candidates))

    @patch("oritypo_solver.services.oricert._fetch_crt_sh")
    def test_distance_for_close_typo(self, mock_fetch):
        mock_fetch.return_value = [
            {"common_name": "mizno.com", "name_value": "mizno.com"},
        ]
        candidates = discover_ct_candidates("mizuno.com")
        self.assertEqual(len(candidates), 1)
        # distance entre 'mizuno' et 'mizno' (omission de 'u') = 1
        self.assertEqual(candidates[0][2], 1)

    @patch("oritypo_solver.services.oricert._fetch_crt_sh")
    def test_filters_short_brand_label(self, mock_fetch):
        mock_fetch.return_value = [{"common_name": "go-evil.com", "name_value": "go-evil.com"}]
        candidates = discover_ct_candidates("go.io")
        self.assertEqual(candidates, [])
        mock_fetch.assert_not_called()

    @patch("oritypo_solver.services.oricert._fetch_crt_sh")
    def test_handles_san_with_multiple_entries(self, mock_fetch):
        mock_fetch.return_value = [
            {
                "common_name": "celiofrance.fr",
                "name_value": "celiofrance.fr\nwww.celiofrance.fr\ncelio-france.fr",
            },
        ]
        candidates = discover_ct_candidates("celio.com")
        fqdns = {c[0] for c in candidates}
        self.assertIn("celiofrance.fr", fqdns)
        self.assertIn("celio-france.fr", fqdns)

    @patch("oritypo_solver.services.oricert._fetch_crt_sh")
    def test_ignores_unrelated_far_domains(self, mock_fetch):
        mock_fetch.return_value = [
            {"common_name": "totally-unrelated.com", "name_value": "totally-unrelated.com"},
            {"common_name": "delivro.fr", "name_value": "delivro.fr"},
        ]
        candidates = discover_ct_candidates("deliveroo.fr")
        fqdns = {c[0] for c in candidates}
        self.assertNotIn("totally-unrelated.com", fqdns)
        self.assertIn("delivro.fr", fqdns)

    @patch("oritypo_solver.services.oricert._fetch_crt_sh")
    def test_empty_response_returns_empty_list(self, mock_fetch):
        mock_fetch.return_value = []
        self.assertEqual(discover_ct_candidates("brand.com"), [])

    @patch("oritypo_solver.services.oricert._fetch_crt_sh")
    def test_respects_max_results(self, mock_fetch):
        mock_fetch.return_value = [
            {"common_name": f"mizuno-{i}.com", "name_value": f"mizuno-{i}.com"}
            for i in range(50)
        ]
        candidates = discover_ct_candidates("mizuno.com", max_results=10)
        self.assertEqual(len(candidates), 10)

    @patch("oritypo_solver.services.oricert._fetch_crt_sh")
    def test_deduplicates_fqdns(self, mock_fetch):
        mock_fetch.return_value = [
            {"common_name": "mizuno-shop.fr", "name_value": "mizuno-shop.fr"},
            {"common_name": "mizuno-shop.fr", "name_value": "mizuno-shop.fr"},
            {"common_name": "MIZUNO-SHOP.FR", "name_value": "MIZUNO-SHOP.FR"},
        ]
        candidates = discover_ct_candidates("mizuno.com")
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0][0], "mizuno-shop.fr")


if __name__ == "__main__":
    unittest.main()
