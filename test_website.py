import os
from app import create_app
from app.services.scanner_service import ScannerService

app = create_app()
with app.app_context():
    service = ScannerService()
    
    test_cases = [
        "https://google.com",
        "https://paypal.com",
        "https://github.com",
        "https://microsoft.com",
        "https://cloudflare.com",
        "https://expired.badssl.com",
        "https://self-signed.badssl.com",
        "https://wrong.host.badssl.com",
        "https://paypaI.com"
    ]
    
    for url in test_cases:
        print(f"\n--- Testing {url} ---")
        res = service.scan_website(url)
        print(f"Status Code: {res.get('status_code')}")
        print(f"Grade: {res.get('grade')}, Score: {res.get('risk_score')}")
        
        ssl = res.get('ssl', {})
        print(f"SSL Valid: {ssl.get('valid')}")
        print(f"SSL Error: {ssl.get('error')}")
        print(f"SSL Issuer: {ssl.get('issuer')}")
        print(f"SSL Subject: {ssl.get('subject')}")
        print(f"TLS Version: {ssl.get('tls_version')}")
        print(f"SSL Expiration: {ssl.get('expiration')}")
        print(f"Days Remaining: {ssl.get('days_remaining')}")
        print(f"SAN Domains: {ssl.get('san')}")
        
        print("Scoring Breakdown:")
        for step in res.get("scoring_breakdown", []):
            print(f"  {step}")
        print("Categories:")
        for cat_name, cat_data in res.get("categories", {}).items():
            print(f"  {cat_name}: {cat_data.get('score')} ({cat_data.get('status')})")
            
        headers = res.get('security_headers', {})
        print("Security Headers:")
        for k, v in headers.items():
            print(f"  {k}: {v}")
            
        print("Cookies:")
        for c in res.get("cookies", []):
            print(f"  Cookie: {c.get('name')} | HttpOnly: {c.get('http_only')} | Secure: {c.get('secure')} | SameSite: {c.get('same_site')} | Domain: {c.get('domain')} | Path: {c.get('path')} | Expires: {c.get('expires')} | Max-Age: {c.get('max_age')}")
