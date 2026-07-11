from app import db
from datetime import datetime, timezone

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_type = db.Column(db.String(50), nullable=False) # 'website', 'password', 'phishing', 'file'
    target = db.Column(db.String(255), nullable=False)   # URL, File Hash, or masked password info
    result_data = db.Column(db.JSON, nullable=False)     # Store detailed results as JSON
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<ScanResult {self.scan_type} - {self.target}>"
