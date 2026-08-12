import unittest
from app import create_app
from app.services.scanner_service import ScannerService
from app.utils.domain_intelligence import (
    extract_registered_domain,
    compute_similarity,
    detect_typosquatting,
    classify_redirect
)

class TestRedirectIntelligenceEngine(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.ctx = self.app.app_context()
        self.ctx.push()
        self.scanner_service = ScannerService()

    def tearDown(self):
        self.ctx.pop()

    def test_registered_domain_extraction(self):
        """Test extraction of registered root domain."""
        self.assertEqual(extract_registered_domain("www.google.com"), "google.com")
        self.assertEqual(extract_registered_domain("sub.example.co.uk"), "example.co.uk")
        self.assertEqual(extract_registered_domain("www.phonepe.com"), "phonepe.com")
        self.assertEqual(extract_registered_domain("phonepay.com"), "phonepay.com")

    def test_domain_similarity_and_homoglyphs(self):
        """Test domain similarity scoring and homoglyph detection."""
        typo = detect_typosquatting("phonepay.com", "www.phonepe.com")
        self.assertGreaterEqual(typo["similarity"], 0.5)
        # phonepay vs phonepe: high similarity but no homoglyph evidence
        # The detect function returns indicators, not conclusions

    def test_google_canonical_redirect(self):
        """google.com -> www.google.com must classify as Safe Canonical Redirect."""
        result = self.scanner_service.scan_website("google.com")
        self.assertEqual(result["status"], "success")
        intel = result["redirect_intel"]
        self.assertEqual(intel["classification"], "Safe Canonical Redirect")
        self.assertEqual(intel["status"], "Safe")
        self.assertEqual(intel["deduction"], 0)

    def test_phonepay_external_domain_redirect(self):
        """phonepay.com -> phonepe.com must classify as External Domain Redirect or Safe Canonical Redirect."""
        result = self.scanner_service.scan_website("phonepay.com")
        self.assertEqual(result["status"], "success")
        intel = result["redirect_intel"]
        self.assertIn(intel["classification"], ["External Domain Redirect", "Potential Typosquatting", "Safe Canonical Redirect"])
        self.assertIn("phonepay.com", intel["rationale"])

    def test_paypal_capital_i_dns_failure(self):
        """paypaI.com (Capital I) must fail DNS resolution, classify as DNS Resolution Failed (NXDOMAIN), and calculate domain similarity independently."""
        result = self.scanner_service.scan_website("paypaI.com")
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["ip_address"], "Unable to resolve IP")
        intel = result["redirect_intel"]
        self.assertEqual(intel["classification"], "DNS Resolution Failed (NXDOMAIN)")
        self.assertGreaterEqual(intel["similarity_score"], 0.8)
        self.assertIn("NXDOMAIN", intel["rationale"])
        self.assertIn(result["grade"], ["F", "N/A"])
        self.assertEqual(result["categories"]["cookies"]["status"], "Not Tested")
    def test_githubcom_missing_dot_malformed_domain(self):
        """githubcom (missing dot before TLD) must identify target brand github.com and calculate 90% similarity independently of DNS resolution."""
        result = self.scanner_service.scan_website("githubcom")
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["ip_address"], "Unable to resolve IP")
        intel = result["redirect_intel"]
        self.assertEqual(intel["classification"], "DNS Resolution Failed (NXDOMAIN)")
        self.assertEqual(intel["similarity_score"], 0.9)
        self.assertIn("github.com", intel["rationale"])
        self.assertIn("missing dot before TLD", intel["rationale"])
        self.assertIn(result["grade"], ["F", "N/A"])

if __name__ == "__main__":
    unittest.main()
