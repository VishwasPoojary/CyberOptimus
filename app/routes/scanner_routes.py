from flask import Blueprint, render_template, request, send_file
import io
from app.services.scanner_service import ScannerService
from app.repositories.scan_repository import ScanRepository
from app.utils.pdf_generator import PDFGenerator

scanner_bp = Blueprint('scanner', __name__, url_prefix='/tools')
scanner_service = ScannerService()
scan_repo = ScanRepository()
pdf_generator = PDFGenerator()

@scanner_bp.route('/website', methods=['GET', 'POST'])
def website_scanner():
    result = None
    scan_id = request.args.get('scan_id', type=int)
    if scan_id:
        scan_record = scan_repo.get_scan_by_id(scan_id)
        if scan_record and scan_record.scan_type == 'website':
            result = scan_record.result_data
    elif request.method == 'POST':
        url = request.form.get('url')
        if url:
            result = scanner_service.scan_website(url)
            if result.get("status") == "success":
                scan_record = scan_repo.save('website', url, result)
                scan_id = scan_record.id
    return render_template('scanner.html', result=result, scan_id=scan_id)

@scanner_bp.route('/website/report/<int:scan_id>', methods=['GET'])
def download_website_report(scan_id):
    scan_record = scan_repo.get_scan_by_id(scan_id)
    if not scan_record or scan_record.scan_type != 'website':
        return "Report not found", 404
        
    pdf_bytes = pdf_generator.generate_website_report(scan_record.result_data)
    
    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f"CyberOptimus_Website_Report_{scan_id}.pdf"
    )

@scanner_bp.route('/phishing', methods=['GET', 'POST'])
def phishing_detector():
    result = None
    if request.method == 'POST':
        url = request.form.get('url')
        if url:
            result = scanner_service.scan_phishing(url)
    return render_template('phishing_detector.html', result=result)

@scanner_bp.route('/password', methods=['GET', 'POST'])
def password_checker():
    result = None
    if request.method == 'POST':
        password = request.form.get('password')
        if password:
            result = scanner_service.scan_password(password)
    return render_template('password_checker.html', result=result)

@scanner_bp.route('/file', methods=['GET', 'POST'])
def file_scanner():
    result = None
    if request.method == 'POST':
        if 'file' not in request.files:
            return render_template('file_scanner.html', error="No file uploaded.")
        
        file = request.files['file']
        if file.filename == '':
            return render_template('file_scanner.html', error="No file selected.")
            
        file_content = file.read()
        result = scanner_service.scan_file(file_content, file.filename)
        
    return render_template('file_scanner.html', result=result)
