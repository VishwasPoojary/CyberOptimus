from typing import Dict, Any
from app.scanners.base_module import BaseModule
from app.scanners.config import ScanConfig
from app.utils.network import check_ssl_certificate

class SSLModule(BaseModule):
    name = "SSLModule"

    def run(self, context: Dict[str, Any], config: ScanConfig) -> Dict[str, Any]:
        if context.get("unreachable"):
            return {
                "ssl_info": {"valid": False, "error": "Target domain is unreachable"},
                "ssl_failed": True,
                "category_ssl": {
                    "score": "N/A",
                    "status": "Not Tested",
                    "weight": 0.25,
                    "findings": [],
                    "reasons": ["SSL analysis skipped because the target domain is unreachable."]
                }
            }

        domain = context.get("final_host", context.get("initial_domain", ""))
        ssl_info = check_ssl_certificate(domain)
        ssl_failed = not ssl_info.get("valid", False)

        findings = []
        deductions = 0

        if ssl_failed:
            findings.append({
                "severity": "Critical",
                "confidence": "Verified",
                "evidence": ssl_info.get("error", "SSL certificate validation failed"),
                "message": f"SSL/TLS Certificate is invalid or expired for {domain}.",
                "why_it_matters": "Invalid or expired SSL certificates break HTTPS encryption and expose users to Man-in-the-Middle eavesdropping.",
                "owasp_ref": "A02:2021-Cryptographic Failures",
                "remediation": "Obtain a valid SSL/TLS certificate from a trusted Certificate Authority (CA) such as Let's Encrypt.",
                "deduction": 100
            })
            deductions = 100
            score = 0
            status_str = "Failed"
        else:
            days_rem = ssl_info.get("days_remaining", 365)
            if isinstance(days_rem, int) and days_rem < 30:
                findings.append({
                    "severity": "Medium",
                    "confidence": "Verified",
                    "evidence": f"Certificate expires in {days_rem} days.",
                    "message": f"SSL Certificate is expiring soon ({days_rem} days remaining).",
                    "why_it_matters": "Expiring certificates risk service outages and security warnings for users.",
                    "owasp_ref": "A02:2021-Cryptographic Failures",
                    "remediation": "Renew the SSL/TLS certificate before expiration.",
                    "deduction": 15
                })
                deductions += 15

            # HSTS Evaluation under Transport/SSL Check based on response headers
            hsts_val = context.get("final_headers", {}).get("strict-transport-security") or context.get("merged_headers", {}).get("strict-transport-security")
            if hsts_val and "max-age=" in hsts_val.lower():
                has_preload = "preload" in hsts_val.lower()
                evidence_text = f"Strict-Transport-Security: {hsts_val}"
                msg_text = "HSTS header is present and active (includes preload directive)." if has_preload else "HSTS header is present and active."
                findings.append({
                    "severity": "Info",
                    "confidence": "Verified",
                    "evidence": evidence_text,
                    "message": msg_text,
                    "why_it_matters": "Enforces HTTPS connections on the browser, preventing protocol downgrade attacks.",
                    "owasp_ref": "A05:2021-Security Misconfiguration",
                    "remediation": "Maintain current HSTS configuration.",
                    "deduction": 0
                })

            score = max(0, 100 - deductions)
            status_str = "Passed" if score >= 90 else ("Warning" if score >= 75 else "Needs Improvement")

        return {
            "ssl_info": ssl_info,
            "ssl_failed": ssl_failed,
            "category_ssl": {
                "score": score,
                "status": status_str,
                "weight": 0.25,
                "findings": findings,
                "reasons": [f"[{f['severity']}] [-{f['deduction']}] {f['message']}" for f in findings]
            }
        }
