import unittest
from app import create_app
from app.services.scanner_service import ScannerService

class TestURLValidationAndRedirects(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.ctx = self.app.app_context()
        self.ctx.push()
        self.scanner_service = ScannerService()

    def tearDown(self):
        self.ctx.pop()

    def test_nxdomain_handling(self):
        """NXDOMAIN domain (e.g. invalid-nxdomain-test999999.com) must immediately stop and report DNS failure."""
        unresolvable_url = "invalid-nxdomain-test999999.com"
        result = self.scanner_service.scan_website(unresolvable_url)

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["original_url"], "invalid-nxdomain-test999999.com")
        self.assertEqual(result["resolved_hostname"], "invalid-nxdomain-test999999.com")
        self.assertEqual(result["ip_address"], "Unable to resolve IP")
        self.assertEqual(result["grade"], "N/A")
        self.assertEqual(result["threat_level"], "Unreachable")
        
        # Verify DNS category fails and other categories marked Not Tested
        categories = result["categories"]
        self.assertEqual(categories["dns"]["status"], "DNS Resolution Failed (NXDOMAIN)")
        self.assertEqual(categories["dns"]["score"], "N/A")
        self.assertEqual(categories["ssl"]["status"], "Not Tested")
        self.assertEqual(categories["headers"]["status"], "Not Tested")

    def test_phonepay_cross_host_redirect(self):
        """Scanning phonepay.com preserves phonepay.com as resolved hostname and flags external domain redirect to phonepe.com."""
        target_url = "phonepay.com"
        result = self.scanner_service.scan_website(target_url)

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["original_url"], "phonepay.com")
        self.assertEqual(result["resolved_hostname"], "phonepay.com")
        
        # Check that cross-host redirection to phonepe.com is captured and flagged as External Domain Redirect
        intel = result["redirect_intel"]
        self.assertEqual(intel["classification"], "External Domain Redirect")
        self.assertIn("phonepay.com", intel["rationale"])

    def test_canonical_redirect(self):
        """http://google.com -> https://www.google.com should be classified as Safe Canonical Redirect."""
        redirect_target = "http://google.com"
        result = self.scanner_service.scan_website(redirect_target)

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["original_url"], "http://google.com")
        self.assertEqual(result["resolved_hostname"], "google.com")
        self.assertIn("www.google.com", result["final_url"].lower())
        
        # Verify canonical classification
        intel = result["redirect_intel"]
        self.assertEqual(intel["classification"], "Safe Canonical Redirect")
        self.assertEqual(intel["status"], "Safe")

    def test_valid_domain_preservation(self):
        """Valid target should preserve exact user input and resolved host."""
        target = "https://cloudflare.com"
        result = self.scanner_service.scan_website(target)

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["original_url"], "https://cloudflare.com")
        self.assertEqual(result["resolved_hostname"], "cloudflare.com")
        self.assertNotEqual(result["ip_address"], "Unable to resolve IP")
        self.assertIn(result["grade"], ["A+", "A", "B"])

    def test_uppercase_url_scheme_parsing(self):
        """RFC 3986: Uppercase URL schemes (HTTP://, HTTPS://) must resolve to domain hostname, not 'HTTP'."""
        for input_url in ["HTTP://google.com", "HTTPS://google.com"]:
            result = self.scanner_service.scan_website(input_url)
            self.assertEqual(result["status"], "success")
            self.assertEqual(result["resolved_hostname"], "google.com")
            self.assertEqual(result["domain"], "google.com")

if __name__ == "__main__":
    unittest.main()
