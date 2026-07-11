from app import db
from app.models.scan_result import ScanResult
from typing import List

class ScanRepository:
    def save(self, scan_type: str, target: str, result: dict) -> ScanResult:
        """Saves a scan result to the database."""
        scan_record = ScanResult(
            scan_type=scan_type,
            target=target,
            result_data=result
        )
        db.session.add(scan_record)
        db.session.commit()
        return scan_record

    def get_recent_scans(self, limit: int = 10) -> List[ScanResult]:
        """Retrieves the most recent scan results."""
        return ScanResult.query.order_by(ScanResult.created_at.desc()).limit(limit).all()

    def get_all_scans(self) -> List[ScanResult]:
        """Retrieves all scan results."""
        return ScanResult.query.all()
    
    def count_scans(self) -> int:
        """Returns the total number of scan results."""
        return ScanResult.query.count()

    def get_scan_by_id(self, scan_id: int) -> ScanResult:
        """Returns a scan result by its ID."""
        return ScanResult.query.get(scan_id)
