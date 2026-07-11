import os
from app import create_app
from app.services.scanner_service import ScannerService

app = create_app()
with app.app_context():
    service = ScannerService()
    
    test_cases = [
        "google.com",
        "http://g00gle.com",
        "paypal.com",
        "http://paypaI.com",
        "http://faceb00k.com"
    ]
    
    for url in test_cases:
        print(f"\n--- Testing {url} ---")
        res = service.scan_phishing(url)
        print(f"Threat Level: {res.get('threat_level')}, Score: {res.get('risk_score')}")
        print("Reasons:")
        for r in res.get("reasons", []):
            print("  ", r)
