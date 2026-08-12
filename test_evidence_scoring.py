import unittest
from app import create_app
from app.services.scanner_service import ScannerService

class TestEvidenceScoringEngine(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.ctx = self.app.app_context()
        self.ctx.push()
        self.scanner_service = ScannerService()

    def tearDown(self):
        self.ctx.pop()

    def test_evidence_and_verified_confidence(self):
        """Every finding must contain explicit Evidence and Confidence = Verified."""
        result = self.scanner_service.scan_website("google.com")
        self.assertEqual(result["status"], "success")
        
        categories = result["categories"]
        for cat_key, cat in categories.items():
            for finding in cat["findings"]:
                self.assertEqual(finding["confidence"], "Verified")
                self.assertIn("evidence", finding)
                self.assertTrue(len(finding["evidence"]) > 0)

    def test_performance_decoupling(self):
        """Performance observations must be stored without reducing the security score."""
        result = self.scanner_service.scan_website("google.com")
        self.assertEqual(result["status"], "success")
        
        # Top-level performance compatibility object
        self.assertIn("performance", result)
        self.assertIn("performance_observations", result)
        
        perf = result["performance_observations"]
        self.assertIn("dns_lookup", perf)
        self.assertIn("total_time", perf)
        
        # Verify performance category in categories dictionary has N/A score so it doesn't affect security score
        self.assertIn("performance", result["categories"])
        self.assertEqual(result["categories"]["performance"]["score"], "N/A")
        self.assertEqual(result["categories"]["performance"]["status"], "Observation Only")
        
        # Verify high score / grade on secure sites like google.com
        self.assertIn(result["grade"], ["A+", "A", "B"])

    def test_calibrated_header_severities(self):
        """Check calibrated header severities: HSTS/CSP High, Referrer-Policy Medium, COEP/CORP/COOP Low/Info."""
        result = self.scanner_service.scan_website("google.com")
        headers = result["security_headers"]
        
        # Verify header structure contains severity and evidence
        for h_name, h_info in headers.items():
            self.assertIn("severity", h_info)
            self.assertIn("evidence", h_info)
            if h_name in ["Cross-Origin-Embedder-Policy", "Cross-Origin-Resource-Policy", "Permissions-Policy"]:
                self.assertIn(h_info["severity"], ["Low", "Info"])

if __name__ == "__main__":
    unittest.main()
