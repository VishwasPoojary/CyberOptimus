from app.repositories.scan_repository import ScanRepository

class ReportGenerator:
    def __init__(self, scan_repository: ScanRepository):
        self.scan_repo = scan_repository

    def generate_stats(self) -> dict:
        """Generates statistics for the dashboard based on scan results."""
        total_scans = self.scan_repo.count_scans()
        
        threats_found = 0
        secure_sites = 0
        
        scans = self.scan_repo.get_all_scans()
        for scan in scans:
            data = scan.result_data
            if scan.scan_type == 'website' and data.get('https') == 'Enabled':
                secure_sites += 1
            if scan.scan_type == 'phishing' and data.get('risk_level') == 'High':
                threats_found += 1
            if scan.scan_type == 'password' and data.get('score', 4) < 2:
                threats_found += 1
            if scan.scan_type == 'file' and data.get('is_suspicious'):
                threats_found += 1
                
        risk_score = 0
        if total_scans > 0:
            risk_score = min(int((threats_found / total_scans) * 100), 100)
            
        return {
            "total_scans": total_scans,
            "threats_found": threats_found,
            "secure_sites": secure_sites,
            "risk_score": f"{risk_score}%"
        }

    def generate_analytics(self) -> dict:
        """Generates detailed analytics including charts data."""
        scans = self.scan_repo.get_all_scans()
        website_scans = [s for s in scans if s.scan_type == 'website']
        
        # 1. Scans over time (last 7 days)
        from datetime import datetime, timedelta
        today = datetime.now().date()
        date_range = [today - timedelta(days=i) for i in range(6, -1, -1)]
        date_strings = [d.strftime('%Y-%m-%d') for d in date_range]
        scans_count = {d: 0 for d in date_strings}
        
        for s in website_scans:
            s_date = s.created_at.date().strftime('%Y-%m-%d')
            if s_date in scans_count:
                scans_count[s_date] += 1
                
        scans_over_time_labels = date_strings
        scans_over_time_data = [scans_count[d] for d in date_strings]
        
        # 2. Average security score
        scores = []
        for s in website_scans:
            score = (s.result_data or {}).get('risk_score')
            if isinstance(score, (int, float)):
                scores.append(score)
        avg_score = round(sum(scores) / len(scores), 1) if scores else 0
        
        # 3. Threat level distribution
        threats = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
        for s in website_scans:
            data = s.result_data or {}
            tl = data.get('threat_level')
            if not tl:
                # calculate fallback
                score = data.get('risk_score')
                if isinstance(score, int):
                    if score >= 90: tl = "Low"
                    elif score >= 75: tl = "Medium"
                    elif score >= 50: tl = "High"
                    else: tl = "Critical"
                else:
                    tl = "Low"
            if tl in threats:
                threats[tl] += 1
                
        return {
            "scans_over_time_labels": scans_over_time_labels,
            "scans_over_time_data": scans_over_time_data,
            "avg_security_score": avg_score,
            "threat_distribution": threats
        }
