import os
from app import create_app
from app.services.scanner_service import ScannerService

app = create_app()
with app.app_context():
    service = ScannerService()
    
    print("Testing paypal.com...")
    res = service.scan_phishing("paypal.com")
    print(f"PayPal Threat Level: {res.get('threat_level')}, Score: {res.get('risk_score')}")
    print("Reasons:", res.get("reasons"))
    
    print("\nTesting paypaI.com...")
    res = service.scan_phishing("http://paypaI.com")
    print(f"paypaI.com Threat Level: {res.get('threat_level')}, Score: {res.get('risk_score')}")
    print("Reasons:", res.get("reasons"))

    print("\nTesting http://192.168.1.1/login...")
    res = service.scan_phishing("http://192.168.1.1/login")
    print(f"IP Threat Level: {res.get('threat_level')}, Score: {res.get('risk_score')}")
    print("Reasons:", res.get("reasons"))
