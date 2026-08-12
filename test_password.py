import unittest
from app import create_app
from app.services.scanner_service import ScannerService

class TestPasswordChecker(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.ctx = self.app.app_context()
        self.ctx.push()
        self.service = ScannerService()

    def tearDown(self):
        self.ctx.pop()

    def test_empty_password(self):
        """Empty password should return score 0 and Very Weak rating."""
        res = self.service.scan_password("")
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["score"], 0)
        self.assertEqual(res["strength"], "Very Weak")

    def test_common_breached_password(self):
        """Common breached password ('password123') must be flagged with a breach or common risk factor."""
        res = self.service.scan_password("password123")
        self.assertEqual(res["status"], "success")
        self.assertLessEqual(res["score"], 30)
        self.assertIn(res["strength"], ["Very Weak", "Weak"])
        self.assertIn("breach_analysis", res)
        self.assertIn("crack_time_matrix", res)

    def test_strong_passphrase(self):
        """High entropy passphrase should receive a high score and Very Strong rating."""
        res = self.service.scan_password("Tr0ub4dor&3#CorrectHorseBatteryStaple!2026")
        self.assertEqual(res["status"], "success")
        self.assertGreaterEqual(res["score"], 80)
        self.assertEqual(res["strength"], "Very Strong")
        self.assertGreater(res["entropy"], 80.0)

    def test_character_composition_telemetry(self):
        """Composition dictionary should accurately count character types."""
        res = self.service.scan_password("Abc123!@# ")
        self.assertEqual(res["status"], "success")
        comp = res["composition"]
        self.assertEqual(comp["length"], 10)
        self.assertEqual(comp["lowercase_count"], 2)
        self.assertEqual(comp["uppercase_count"], 1)
        self.assertEqual(comp["digits_count"], 3)
        self.assertEqual(comp["symbols_count"], 3)
        self.assertEqual(comp["space_count"], 1)

    def test_crack_time_matrix_scenarios(self):
        """Crack time matrix must return estimates for 4 scenarios."""
        res = self.service.scan_password("ComplexPass#2026")
        matrix = res["crack_time_matrix"]
        self.assertIn("online_throttled", matrix)
        self.assertIn("online_unthrottled", matrix)
        self.assertIn("offline_slow_hash", matrix)
        self.assertIn("offline_fast_hash", matrix)

if __name__ == "__main__":
    unittest.main()
