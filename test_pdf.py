import os
from app import create_app
from app.services.scanner_service import ScannerService
from app.utils.pdf_generator import PDFGenerator

app = create_app()
with app.app_context():
    service = ScannerService()
    pdf_gen = PDFGenerator()
    
    print("Scanning github.com...")
    result = service.scan_website("https://github.com")
    
    print("Generating PDF...")
    pdf_bytes = pdf_gen.generate_website_report(result)
    
    with open("test_report.pdf", "wb") as f:
        f.write(pdf_bytes)
    
    print("Done. Saved to test_report.pdf")
