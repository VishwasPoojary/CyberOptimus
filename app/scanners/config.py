from dataclasses import dataclass

@dataclass
class ScanConfig:
    """
    Configuration object supporting feature toggles and options
    for the Website Security Scanner modular engine.
    """
    check_headers: bool = True
    check_ssl: bool = True
    check_typosquatting: bool = True
    check_dns: bool = True
    measure_performance: bool = True
    parse_html_meta: bool = True
    check_cookies: bool = True
    timeout: int = 5
