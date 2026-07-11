import os
from app import create_app
from app.services.scanner_service import ScannerService

app = create_app()
with app.app_context():
    service = ScannerService()
    print("Scanning google.com...")
    res = service.scan_website("google.com")
    print(f"Google Grade: {res.get('grade')}, Score: {res.get('risk_score')}")
    
    print("\nScanning neverssl.com...")
    res = service.scan_website("http://neverssl.com")
    print(f"NeverSSL Grade: {res.get('grade')}, Score: {res.get('risk_score')}")
    print("NeverSSL Recommendations:", res.get("recommendations"))

    print("\nRecent Scans in DB:")
    recent = service.scan_repo.get_recent_scans(limit=5)
    for s in recent:
        if s.scan_type == 'website':
            print(s.target, s.result_data.get('grade'), s.result_data.get('risk_score'))
