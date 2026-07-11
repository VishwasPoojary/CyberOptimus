from flask import Blueprint, render_template, request
from app.repositories.scan_repository import ScanRepository
from app.reports.report_generator import ReportGenerator

main_bp = Blueprint('main', __name__)
scan_repo = ScanRepository()
report_generator = ReportGenerator(scan_repo)

@main_bp.route('/')
def home():
    return render_template('index.html')

@main_bp.route('/dashboard')
def dashboard():
    stats = report_generator.generate_stats()
    analytics = report_generator.generate_analytics()
    recent_scans = scan_repo.get_recent_scans()
    return render_template('dashboard.html', stats=stats, analytics=analytics, recent_scans=recent_scans)

@main_bp.route('/history')
def scan_history():
    query = request.args.get('query', '').strip()
    grade = request.args.get('grade', '').strip()
    date_filter = request.args.get('date', '').strip() # Expect YYYY-MM-DD
    
    # Get all website scans
    all_scans = scan_repo.get_all_scans()
    website_scans = [s for s in all_scans if s.scan_type == 'website']
    
    filtered_scans = []
    for s in website_scans:
        data = s.result_data or {}
        target = s.target or ''
        g = data.get('grade', 'N/A')
        score = data.get('risk_score', 'N/A')
        
        # Determine threat level
        tl = data.get('threat_level')
        if not tl:
            if isinstance(score, int):
                if score >= 90: tl = "Low"
                elif score >= 75: tl = "Medium"
                elif score >= 50: tl = "High"
                else: tl = "Critical"
            else:
                tl = "Unknown"
        
        # Apply filters
        if query and query.lower() not in target.lower():
            continue
        if grade and grade.upper() != g.upper():
            continue
        if date_filter:
            scan_date = s.created_at.strftime('%Y-%m-%d')
            if date_filter != scan_date:
                continue
                
        filtered_scans.append({
            'id': s.id,
            'target': target,
            'created_at': s.created_at,
            'grade': g,
            'risk_score': score,
            'threat_level': tl
        })
        
    return render_template('history.html', scans=filtered_scans, query=query, grade=grade, date_filter=date_filter)
