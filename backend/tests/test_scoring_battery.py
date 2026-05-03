"""Batterie de scenarios realistes pour valider la coherence du scoring oriscore.

Couvre :
- Phishing bancaire, e-commerce, SaaS, crypto, gouvernement
- Sites legitimes ressemblants (faux positifs a eviter)
- Parking / vente de domaine
- Edge cases (erreurs HTTP, TLS, distance, kind)
- Pre-crawl vs post-crawl
- Score predictif sur typosquats endormis
"""
from __future__ import annotations

import unittest

from oritypo_solver.services.scoring import score_finding, score_prediction_finding

REF_EMBEDDING = [0.1] * 384


def _make_dns(*, a: bool = True, mx: list[str] | None = None, ns: bool = True, cname: list[str] | None = None) -> dict:
    return {
        "A": ["1.2.3.4"] if a else [],
        "AAAA": [],
        "MX": mx if mx is not None else [],
        "NS": ["ns1.example.com"] if ns else [],
        "CNAME": cname or [],
    }


def _make_http(
    *,
    reachable: bool = True,
    status: int = 200,
    https: bool = True,
    title: str | None = "A site",
    login: bool = False,
    parking: bool = False,
    challenge: bool = False,
    favicon: str | None = None,
    cert_sans: list[str] | None = None,
    redirects: int = 0,
    same_host: bool = True,
) -> dict:
    return {
        "reachable": reachable,
        "scheme": "https" if https else "http",
        "status_code": status,
        "title": title,
        "login_page": login,
        "parking_page": parking,
        "challenge_page": challenge,
        "favicon_hash": favicon,
        "cert_sans": cert_sans or [],
        "redirects": redirects,
        "final_host_matches_input": same_host,
    }


def _make_rdap(*, registered_at: str | None = None, registrar: str | None = "Generic Registrar") -> dict:
    return {
        "available": True,
        "registrar": registrar,
        "registered_at": registered_at,
    }


def _make_crawl(
    *,
    similarity: float | None = None,
    password_forms: int = 0,
    forms: int = 0,
    login_urls: list[str] | None = None,
    payment_urls: list[str] | None = None,
    meta_brand_hits: int = 0,
    brand_term_hits: int = 0,
    snippet: str | None = "Some real content " * 20,
) -> dict:
    return {
        "status": "completed",
        "similarity": similarity,
        "password_forms_count": password_forms,
        "forms_count": forms,
        "login_urls": login_urls or [],
        "payment_urls": payment_urls or [],
        "meta_brand_hits": meta_brand_hits,
        "brand_term_hits": brand_term_hits,
        "content_snippet": snippet,
    }


def _make_ref(*, target: str = "example.com", favicon: str | None = None, with_embedding: bool = True) -> dict:
    return {
        "target": target,
        "favicon_hash": favicon,
        "cert_sans": [],
        "content_embedding": REF_EMBEDDING if with_embedding else None,
    }


def _score(**kwargs) -> tuple[int, str, list[str]]:
    s, reasons, level = score_finding(**kwargs)
    return s, level, reasons


def _pred(**kwargs) -> tuple[int, str]:
    s, _, level = score_prediction_finding(**kwargs)
    return s, level


# ========================================================================
# CATEGORIE 1 : VRAIS PHISHING (doivent etre critical 80-100)
# ========================================================================
class TruePhishingTests(unittest.TestCase):
    """Sites de phishing avere : doivent ressortir comme critical."""

    def test_phishing_paypal_complete(self):
        s, lvl, _ = _score(
            distance=1, kind="orifold:Homoglyph",
            dns_records=_make_dns(mx=["10 mail.x.com"]),
            http_result=_make_http(login=True, favicon="PAYPAL", title="Login - PayPal"),
            rdap_result=_make_rdap(registered_at="2026-04-01T00:00:00Z"),
            crawl_result=_make_crawl(similarity=0.92, password_forms=1, login_urls=["x"]),
            reference_data=_make_ref(target="paypal.com", favicon="PAYPAL"),
        )
        self.assertGreaterEqual(s, 85)
        self.assertEqual(lvl, "critical")

    def test_phishing_bank_payment_forms(self):
        s, lvl, _ = _score(
            distance=1, kind="orifold:Bitsquatting",
            dns_records=_make_dns(),
            http_result=_make_http(login=True, title="Bank Login"),
            rdap_result=_make_rdap(registered_at="2026-03-01T00:00:00Z"),
            crawl_result=_make_crawl(similarity=0.75, password_forms=1, payment_urls=["pay"], login_urls=["lg"]),
            reference_data=_make_ref(target="mabanque.fr"),
        )
        self.assertGreaterEqual(s, 80)
        self.assertEqual(lvl, "critical")

    def test_phishing_amazon_cross_host_redirect(self):
        s, lvl, _ = _score(
            distance=1, kind="orifold:Homoglyph",
            dns_records=_make_dns(),
            http_result=_make_http(login=True, redirects=2, same_host=False, title="Account Verify"),
            rdap_result=_make_rdap(registered_at="2026-04-05T00:00:00Z"),
            crawl_result=None,
            reference_data=_make_ref(target="amazon.com"),
        )
        self.assertGreaterEqual(s, 75)

    def test_phishing_crypto_wallet(self):
        s, lvl, _ = _score(
            distance=1, kind="orifold:Homoglyph",
            dns_records=_make_dns(),
            http_result=_make_http(login=True, title="Sign in to Wallet", favicon="META"),
            rdap_result=_make_rdap(registered_at="2026-04-08T00:00:00Z"),
            crawl_result=_make_crawl(similarity=0.88, password_forms=1, login_urls=["x"]),
            reference_data=_make_ref(target="metamask.io", favicon="META"),
        )
        self.assertGreaterEqual(s, 85)
        self.assertEqual(lvl, "critical")

    def test_phishing_microsoft_o365_login(self):
        s, lvl, _ = _score(
            distance=1, kind="orifold:CommonMisspelling",
            dns_records=_make_dns(mx=["10 mail.x.com"]),
            http_result=_make_http(login=True, title="Microsoft 365 Sign In", favicon="MS"),
            rdap_result=_make_rdap(registered_at="2026-02-01T00:00:00Z"),
            crawl_result=_make_crawl(similarity=0.81, password_forms=1, meta_brand_hits=2, brand_term_hits=5),
            reference_data=_make_ref(target="microsoft.com", favicon="MS"),
        )
        self.assertGreaterEqual(s, 85)

    def test_phishing_with_challenge_page_still_critical(self):
        """Un phishing derriere Cloudflare doit rester high meme avec -6 challenge."""
        s, lvl, _ = _score(
            distance=1, kind="orifold:Homoglyph",
            dns_records=_make_dns(),
            http_result=_make_http(login=True, challenge=True, favicon="OFF"),
            rdap_result=_make_rdap(registered_at="2026-04-01T00:00:00Z"),
            crawl_result=_make_crawl(similarity=0.85, password_forms=1, login_urls=["x"]),
            reference_data=_make_ref(target="example.com", favicon="OFF"),
        )
        self.assertGreaterEqual(s, 75)


# ========================================================================
# CATEGORIE 2 : SITES LEGITIMES RESSEMBLANTS (eviter faux positifs)
# ========================================================================
class LegitimateSiteTests(unittest.TestCase):
    """Sites independants legit : ne doivent PAS etre critical."""

    def test_legit_old_independent_low_similarity(self):
        """oogle.com independant ancien : doit etre <60."""
        s, lvl, _ = _score(
            distance=1, kind="orifold:Omission",
            dns_records=_make_dns(mx=["10 mail.x.com"]),
            http_result=_make_http(title="Independent Site", favicon="OWN", cert_sans=["oogle.com"]),
            rdap_result=_make_rdap(registered_at="2008-01-01T00:00:00Z"),
            crawl_result=_make_crawl(similarity=0.18, snippet="Independent search platform " * 15),
            reference_data=_make_ref(target="google.com", favicon="GOOGLE"),
        )
        self.assertLess(s, 55)
        self.assertNotEqual(lvl, "critical")

    def test_legit_5y_old_moderate_similarity(self):
        """Site etabli avec sim 0.50 (zone grise) : ne doit pas etre critical."""
        s, lvl, _ = _score(
            distance=2, kind="orifold:Addition",
            dns_records=_make_dns(mx=["10 mail.x.com"]),
            http_result=_make_http(title="My Site"),
            rdap_result=_make_rdap(registered_at="2020-01-01T00:00:00Z"),
            crawl_result=_make_crawl(similarity=0.50, snippet="Real content " * 30),
            reference_data=_make_ref(target="example.com"),
        )
        self.assertLess(s, 80)
        self.assertNotEqual(lvl, "critical")

    def test_legit_blog_distance_3(self):
        s, lvl, _ = _score(
            distance=3, kind="orifold:Omission",
            dns_records=_make_dns(),
            http_result=_make_http(title="Personal blog"),
            rdap_result=_make_rdap(registered_at="2015-06-01T00:00:00Z"),
            crawl_result=_make_crawl(similarity=0.22, snippet="Welcome to my blog " * 20),
            reference_data=_make_ref(target="example.com"),
        )
        self.assertLess(s, 50)

    def test_legit_distance_5_unrelated(self):
        """Domaine distance 5+ = signal trop faible meme si actif."""
        s, lvl, _ = _score(
            distance=5, kind="orifold:Keyword",
            dns_records=_make_dns(),
            http_result=_make_http(title="Random Site"),
            rdap_result=None, crawl_result=None,
            reference_data=_make_ref(target="example.com"),
        )
        self.assertLess(s, 40)
        self.assertIn(lvl, {"low", "medium"})

    def test_legit_http_500_error(self):
        """503 sur domaine proche : la penalite -12 doit le sortir de critical."""
        s, lvl, _ = _score(
            distance=2, kind="orifold:Addition",
            dns_records=_make_dns(),
            http_result=_make_http(status=503, title=None),
            rdap_result=None, crawl_result=None,
            reference_data=_make_ref(target="example.com"),
        )
        self.assertLess(s, 50)

    def test_legit_404_close_domain(self):
        s, lvl, _ = _score(
            distance=1, kind="orifold:Homoglyph",
            dns_records=_make_dns(),
            http_result=_make_http(status=404, title="Not Found"),
            rdap_result=None, crawl_result=None,
            reference_data=_make_ref(target="example.com"),
        )
        self.assertNotEqual(lvl, "critical")


# ========================================================================
# CATEGORIE 3 : PARKING / VENTE
# ========================================================================
class ParkingTests(unittest.TestCase):
    """Parking et vente : ne doivent pas etre critical, mais predictif eleve OK."""

    def test_parked_domain_for_sale(self):
        s, lvl, _ = _score(
            distance=1, kind="orifold:Bitsquatting",
            dns_records=_make_dns(ns=True, cname=["sedoparking.com"]),
            http_result=_make_http(title="domain - This website is for sale!", parking=True),
            rdap_result=None, crawl_result=None,
            reference_data=_make_ref(target="example.com"),
        )
        self.assertLess(s, 55)

    def test_parking_with_recent_registration_predictive_high(self):
        """Parking + recent = predictif eleve (cible potentielle)."""
        pred, lvl = _pred(
            distance=1, kind="orifold:Homoglyph",
            dns_records=_make_dns(),
            http_result=_make_http(parking=True),
            rdap_result=_make_rdap(registered_at="2026-04-01T00:00:00Z"),
            crawl_result=None, reference_data=_make_ref(target="example.com"),
        )
        self.assertGreaterEqual(pred, 55)

    def test_cname_to_parking_provider(self):
        s, _, _ = _score(
            distance=1, kind="orifold:Homoglyph",
            dns_records=_make_dns(cname=["parkingcrew.com"]),
            http_result=None, rdap_result=None, crawl_result=None,
            reference_data=_make_ref(target="example.com"),
        )
        self.assertLess(s, 55)


# ========================================================================
# CATEGORIE 4 : PRE-CRAWL (DNS + HTTP seulement, score temporaire)
# ========================================================================
class PreCrawlTests(unittest.TestCase):
    """Score avant que le crawl ne renvoie ses donnees : tolerable mais pas absurde."""

    def test_active_close_domain_pre_crawl(self):
        s, lvl, _ = _score(
            distance=1, kind="orifold:Homoglyph",
            dns_records=_make_dns(),
            http_result=_make_http(),
            rdap_result=None, crawl_result=None,
            reference_data=_make_ref(target="example.com"),
        )
        self.assertLessEqual(s, 90)
        self.assertGreaterEqual(s, 55)

    def test_unresolvable_domain(self):
        """Sans DNS du tout : score doit etre minimal."""
        s, lvl, _ = _score(
            distance=1, kind="orifold:Homoglyph",
            dns_records={"A":[],"AAAA":[],"MX":[],"NS":[],"CNAME":[]},
            http_result=None, rdap_result=None, crawl_result=None,
            reference_data=None,
        )
        self.assertLess(s, 55)

    def test_only_ns_no_infrastructure(self):
        """NS seuls (delegation sans hosting) : signal faible."""
        s, _, _ = _score(
            distance=1, kind="orifold:Homoglyph",
            dns_records=_make_dns(a=False, ns=True),
            http_result=None, rdap_result=None, crawl_result=None,
            reference_data=None,
        )
        self.assertLess(s, 50)


# ========================================================================
# CATEGORIE 5 : SIGNAUX MIXTES / CAS LIMITES
# ========================================================================
class EdgeCasesTests(unittest.TestCase):

    def test_ambiguous_recent_no_login(self):
        """Recent + sim ambigue 0.40 sans login = ne doit pas etre critical."""
        s, lvl, _ = _score(
            distance=1, kind="orifold:Omission",
            dns_records=_make_dns(),
            http_result=_make_http(),
            rdap_result=_make_rdap(registered_at="2026-02-01T00:00:00Z"),
            crawl_result=_make_crawl(similarity=0.40, snippet="Random content " * 30),
            reference_data=_make_ref(target="example.com"),
        )
        self.assertLess(s, 80)
        self.assertNotEqual(lvl, "critical")

    def test_favicon_match_alone_strong_signal(self):
        """Favicon copie meme sans autre signal = critical (vraie copie de marque)."""
        s, lvl, _ = _score(
            distance=1, kind="orifold:Bitsquatting",
            dns_records=_make_dns(),
            http_result=_make_http(favicon="OFFICIAL"),
            rdap_result=None, crawl_result=None,
            reference_data=_make_ref(target="example.com", favicon="OFFICIAL"),
        )
        self.assertGreaterEqual(s, 65)

    def test_generic_wildcard_cert_penalized(self):
        """Wildcard generique = hosting mutualise = -8."""
        s1, _, _ = _score(
            distance=1, kind="orifold:Omission",
            dns_records=_make_dns(),
            http_result=_make_http(cert_sans=["*.parking.example", "parking.example"]),
            rdap_result=None, crawl_result=None,
            reference_data=_make_ref(target="example.com"),
        )
        s2, _, _ = _score(
            distance=1, kind="orifold:Omission",
            dns_records=_make_dns(),
            http_result=_make_http(cert_sans=[]),
            rdap_result=None, crawl_result=None,
            reference_data=_make_ref(target="example.com"),
        )
        self.assertLess(s1, s2)

    def test_old_domain_with_phishing_signals(self):
        """Vieux domaine compromis avec login : la legitimite ne doit PAS sauver."""
        s, lvl, _ = _score(
            distance=1, kind="orifold:Homoglyph",
            dns_records=_make_dns(),
            http_result=_make_http(login=True, favicon="OFFICIAL"),
            rdap_result=_make_rdap(registered_at="2010-01-01T00:00:00Z"),
            crawl_result=_make_crawl(similarity=0.85, password_forms=1, login_urls=["x"]),
            reference_data=_make_ref(target="example.com", favicon="OFFICIAL"),
        )
        self.assertGreaterEqual(s, 75)

    def test_minimal_crawl_content(self):
        """Site avec presque pas de contenu : suspect."""
        s, _, reasons = _score(
            distance=2, kind="orifold:Addition",
            dns_records=_make_dns(),
            http_result=_make_http(),
            rdap_result=None,
            crawl_result=_make_crawl(similarity=0.30, snippet="hi"),
            reference_data=_make_ref(target="example.com"),
        )
        self.assertTrue(any("minimal content" in r for r in reasons))

    def test_extreme_low_distance_no_other_signals(self):
        """Distance 0 (impossible apres dedup) ne doit pas crasher."""
        s, _, _ = _score(
            distance=0, kind="orifold:Original",
            dns_records=_make_dns(),
            http_result=None, rdap_result=None, crawl_result=None,
            reference_data=None,
        )
        self.assertGreaterEqual(s, 0)
        self.assertLessEqual(s, 100)


# ========================================================================
# CATEGORIE 6 : SCORE PREDICTIF (typosquat endormi)
# ========================================================================
class PredictiveScoreTests(unittest.TestCase):

    def test_dormant_recent_no_infra_lower_than_active(self):
        """Sans infra, le predictif doit etre limite (pas une menace imminente)."""
        pred_dormant, lvl_dormant = _pred(
            distance=1, kind="orifold:Homoglyph",
            dns_records=_make_dns(a=False, ns=True),
            http_result=None,
            rdap_result=_make_rdap(registered_at="2026-04-01T00:00:00Z"),
            crawl_result=None, reference_data=None,
        )
        pred_active, _ = _pred(
            distance=1, kind="orifold:Homoglyph",
            dns_records=_make_dns(),
            http_result=_make_http(),
            rdap_result=_make_rdap(registered_at="2026-04-01T00:00:00Z"),
            crawl_result=None, reference_data=None,
        )
        self.assertLess(pred_dormant, pred_active)
        self.assertLess(pred_dormant, 65)

    def test_active_recent_high_predictive(self):
        pred, lvl = _pred(
            distance=1, kind="orifold:Homoglyph",
            dns_records=_make_dns(mx=["10 mail.x.com"]),
            http_result=_make_http(parking=True),
            rdap_result=_make_rdap(registered_at="2026-04-01T00:00:00Z"),
            crawl_result=None, reference_data=None,
        )
        self.assertGreaterEqual(pred, 70)

    def test_old_domain_low_predictive(self):
        pred, lvl = _pred(
            distance=1, kind="orifold:Homoglyph",
            dns_records=_make_dns(),
            http_result=_make_http(),
            rdap_result=_make_rdap(registered_at="2005-01-01T00:00:00Z"),
            crawl_result=None, reference_data=None,
        )
        self.assertLess(pred, 70)

    def test_predictive_distance_5_low(self):
        pred, _ = _pred(
            distance=5, kind="orifold:Keyword",
            dns_records=_make_dns(),
            http_result=_make_http(),
            rdap_result=None, crawl_result=None, reference_data=None,
        )
        self.assertLess(pred, 35)


# ========================================================================
# CATEGORIE 7 : PROGRESSION / MONOTONICITE (regle metier)
# ========================================================================
class MonotonicityTests(unittest.TestCase):
    """Verifie que les scores progressent dans le bon sens."""

    def test_login_increases_score(self):
        base = _score(
            distance=1, kind="orifold:Homoglyph",
            dns_records=_make_dns(),
            http_result=_make_http(login=False),
            rdap_result=None, crawl_result=None, reference_data=None,
        )[0]
        with_login = _score(
            distance=1, kind="orifold:Homoglyph",
            dns_records=_make_dns(),
            http_result=_make_http(login=True),
            rdap_result=None, crawl_result=None, reference_data=None,
        )[0]
        self.assertGreater(with_login, base)

    def test_higher_similarity_higher_score(self):
        ref = _make_ref(target="x.com")
        low = _score(
            distance=1, kind="orifold:Homoglyph",
            dns_records=_make_dns(),
            http_result=_make_http(),
            rdap_result=None,
            crawl_result=_make_crawl(similarity=0.50),
            reference_data=ref,
        )[0]
        high = _score(
            distance=1, kind="orifold:Homoglyph",
            dns_records=_make_dns(),
            http_result=_make_http(),
            rdap_result=None,
            crawl_result=_make_crawl(similarity=0.95),
            reference_data=ref,
        )[0]
        self.assertGreater(high, low)

    def test_recent_registration_higher_than_old_when_active(self):
        active_old = _score(
            distance=1, kind="orifold:Homoglyph",
            dns_records=_make_dns(),
            http_result=_make_http(),
            rdap_result=_make_rdap(registered_at="2008-01-01T00:00:00Z"),
            crawl_result=None, reference_data=None,
        )[0]
        active_recent = _score(
            distance=1, kind="orifold:Homoglyph",
            dns_records=_make_dns(),
            http_result=_make_http(),
            rdap_result=_make_rdap(registered_at="2026-04-01T00:00:00Z"),
            crawl_result=None, reference_data=None,
        )[0]
        self.assertGreater(active_recent, active_old)

    def test_password_forms_increase_score(self):
        ref = _make_ref(target="x.com")
        no_pwd = _score(
            distance=1, kind="orifold:Homoglyph",
            dns_records=_make_dns(),
            http_result=_make_http(),
            rdap_result=None,
            crawl_result=_make_crawl(similarity=0.70, password_forms=0),
            reference_data=ref,
        )[0]
        with_pwd = _score(
            distance=1, kind="orifold:Homoglyph",
            dns_records=_make_dns(),
            http_result=_make_http(),
            rdap_result=None,
            crawl_result=_make_crawl(similarity=0.70, password_forms=1, login_urls=["x"]),
            reference_data=ref,
        )[0]
        self.assertGreater(with_pwd, no_pwd)

    def test_score_bounded_0_100(self):
        """Aucun scenario ne doit jamais sortir de [0, 100]."""
        scenarios = [
            dict(distance=1, kind="orifold:Homoglyph",
                 dns_records=_make_dns(mx=["10 m.x.com"]),
                 http_result=_make_http(login=True, favicon="A", cert_sans=["brand-x.com"]),
                 rdap_result=_make_rdap(registered_at="2026-04-01T00:00:00Z"),
                 crawl_result=_make_crawl(similarity=0.95, password_forms=2,
                                          login_urls=["a","b"], payment_urls=["c"],
                                          forms=3, brand_term_hits=10, meta_brand_hits=5),
                 reference_data=_make_ref(target="brand-x.com", favicon="A")),
            dict(distance=10, kind="unknown",
                 dns_records={"A":[],"AAAA":[],"MX":[],"NS":[],"CNAME":[]},
                 http_result=None, rdap_result=None, crawl_result=None, reference_data=None),
        ]
        for sc in scenarios:
            s = _score(**sc)[0]
            self.assertGreaterEqual(s, 0)
            self.assertLessEqual(s, 100)
            p = _pred(**sc)[0]
            self.assertGreaterEqual(p, 0)
            self.assertLessEqual(p, 100)


# ========================================================================
# CATEGORIE 8 : MULTI-SECTEURS (banque / e-commerce / SaaS / gov)
# ========================================================================
class SectorialTests(unittest.TestCase):

    def test_banking_sector_phishing(self):
        s, lvl, _ = _score(
            distance=1, kind="orifold:Homoglyph",
            dns_records=_make_dns(mx=["10 mail.x.com"]),
            http_result=_make_http(login=True, title="Online Banking"),
            rdap_result=_make_rdap(registered_at="2026-03-15T00:00:00Z"),
            crawl_result=_make_crawl(similarity=0.78, password_forms=1, login_urls=["lg"], payment_urls=["pay"]),
            reference_data=_make_ref(target="bnpparibas.fr"),
        )
        self.assertEqual(lvl, "critical")

    def test_ecommerce_fake_shop(self):
        s, lvl, _ = _score(
            distance=2, kind="orifold:Addition",
            dns_records=_make_dns(),
            http_result=_make_http(title="Shop Online"),
            rdap_result=_make_rdap(registered_at="2026-04-01T00:00:00Z"),
            crawl_result=_make_crawl(similarity=0.72, payment_urls=["checkout"], forms=2,
                                     brand_term_hits=8, meta_brand_hits=3),
            reference_data=_make_ref(target="zalando.fr"),
        )
        self.assertGreaterEqual(s, 70)

    def test_saas_credential_harvest(self):
        s, lvl, _ = _score(
            distance=1, kind="orifold:CommonMisspelling",
            dns_records=_make_dns(),
            http_result=_make_http(login=True, title="Slack Sign In", favicon="SLACK"),
            rdap_result=_make_rdap(registered_at="2026-04-05T00:00:00Z"),
            crawl_result=_make_crawl(similarity=0.84, password_forms=1, login_urls=["x"]),
            reference_data=_make_ref(target="slack.com", favicon="SLACK"),
        )
        self.assertEqual(lvl, "critical")

    def test_government_impersonation(self):
        s, lvl, _ = _score(
            distance=1, kind="orifold:Homoglyph",
            dns_records=_make_dns(),
            http_result=_make_http(title="Service Public", favicon="GOV"),
            rdap_result=_make_rdap(registered_at="2026-02-15T00:00:00Z"),
            crawl_result=_make_crawl(similarity=0.81, forms=2, brand_term_hits=6, meta_brand_hits=4),
            reference_data=_make_ref(target="service-public.fr", favicon="GOV"),
        )
        self.assertGreaterEqual(s, 75)


if __name__ == "__main__":
    unittest.main()
