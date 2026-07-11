from app.scanners import WebsiteScanner, PhishingDetector, PasswordChecker, FileAnalyzer
from app.repositories.scan_repository import ScanRepository

class ScannerService:
    def __init__(self, scan_repository: ScanRepository = None):
        self.website_scanner = WebsiteScanner()
        self.phishing_detector = PhishingDetector()
        self.password_checker = PasswordChecker()
        self.file_analyzer = FileAnalyzer()
        self.scan_repo = scan_repository or ScanRepository()

    def scan_website(self, url: str) -> dict:
        result = self.website_scanner.scan(url)
        self.scan_repo.save('website', url, result)
        return result

    def scan_phishing(self, url: str) -> dict:
        result = self.phishing_detector.scan(url)
        self.scan_repo.save('phishing', url, result)
        return result

    def scan_password(self, password: str) -> dict:
        result = self.password_checker.scan(password)
        # Never store the raw password in the DB
        masked_pwd = "*" * len(password)
        self.scan_repo.save('password', masked_pwd, result)
        return result

    def scan_file(self, file_content: bytes, filename: str) -> dict:
        result = self.file_analyzer.scan_file(file_content, filename)
        # Store using file hash as target instead of raw bytes
        target = result.get('sha256', filename)
        self.scan_repo.save('file', target, result)
        return result
