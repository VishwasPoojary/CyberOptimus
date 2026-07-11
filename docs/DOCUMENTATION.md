# CyberOptimus Documentation

## Overview
CyberOptimus is an Enterprise Cybersecurity Assessment Platform built using Python and Flask. It provides a robust, extensible foundation for scanning and assessing security across various domains.

## Architecture
CyberOptimus leverages Clean Architecture:
- **`app/routes/`**: Flask Blueprint routing and view controllers.
- **`app/services/`**: Coordination layer for tying components together.
- **`app/scanners/`**: Core scanning logic for websites, phishing, files, and passwords.
- **`app/utils/`**: Reusable components, including `network.py` and `crypto.py`.
- **`app/repositories/`**: Abstraction over the database using the Repository Pattern.
- **`app/reports/`**: Generator logic for compiling statistical dashboard data.
- **`app/models/`**: SQLAlchemy database entities (e.g., `ScanResult`).

## Adding New Features
To add a new scanner:
1. Extend `app.scanners.base_scanner.BaseScanner`.
2. Implement the `scan(self, target: str) -> dict` method.
3. Integrate the scanner in `app/services/scanner_service.py`.
4. Add a new view in `app/routes/scanner_routes.py`.
5. Create a template extending `base.html`.

## Deployment
CyberOptimus is production-ready. Ensure you set the `SECRET_KEY` and `DATABASE_URL` environment variables before deploying to a production server (like Gunicorn or uWSGI).
