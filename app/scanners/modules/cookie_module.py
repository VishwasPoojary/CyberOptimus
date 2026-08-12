from typing import Dict, Any
from app.scanners.base_module import BaseModule
from app.scanners.config import ScanConfig

SESSION_PATTERNS = {"session", "sid", "token", "auth", "jwt", "pass", "login", "id_token", "access_token"}
FUNCTIONAL_PATTERNS = {"nid", "pref", "_ga", "_gid", "_gat", "lang", "theme", "locale", "consent", "cookieconsent", "_cf", "cf_clearance"}

def classify_cookie_sensitivity(c_name: str) -> str:
    if c_name.startswith("__Secure-"):
        return "__Secure- Prefix Cookie"
    if c_name.startswith("__Host-"):
        return "__Host- Prefix Cookie"
    name_lower = c_name.lower()
    if any(p in name_lower for p in FUNCTIONAL_PATTERNS):
        return "Functional / Analytics"
    if any(p in name_lower for p in SESSION_PATTERNS):
        return "Session / Authentication"
    return "Standard / Unclassified"

class CookieModule(BaseModule):
    name = "CookieModule"

    def run(self, context: Dict[str, Any], config: ScanConfig) -> Dict[str, Any]:
        if context.get("unreachable"):
            return {
                "cookies_list": [],
                "category_cookies": {
                    "score": "N/A",
                    "status": "Not Tested",
                    "weight": 0.10,
                    "findings": [],
                    "reasons": ["Cookie analysis skipped because the target domain is unreachable."]
                }
            }

        cookies_list = context.get("cookies_list", [])
        findings = []
        deductions = 0

        for c in cookies_list:
            c_name = c.get("name", "Cookie")
            c_type = classify_cookie_sensitivity(c_name)
            is_session = (c_type == "Session / Authentication")
            is_prefix = c_type.endswith("Prefix Cookie")

            # 1. Prefix Validation (__Secure- and __Host-)
            if c_name.startswith("__Secure-") and not c.get("secure"):
                deductions += 10
                findings.append({
                    "severity": "High",
                    "confidence": "Verified",
                    "evidence": f"Set-Cookie: {c_name}=... (missing Secure flag)",
                    "message": f"Cookie '{c_name}' uses __Secure- prefix but lacks the Secure attribute.",
                    "why_it_matters": "Browsers reject __Secure- cookies unless sent over HTTPS with the Secure attribute.",
                    "owasp_ref": "A05:2021-Security Misconfiguration",
                    "remediation": f"Add 'Secure' attribute to Set-Cookie header for {c_name}.",
                    "deduction": 10
                })

            if c_name.startswith("__Host-"):
                host_violations = []
                if not c.get("secure"):
                    host_violations.append("missing Secure flag")
                if c.get("domain"):
                    host_violations.append(f"contains Domain attribute ({c.get('domain')})")
                if c.get("path") != "/":
                    host_violations.append(f"Path is '{c.get('path')}' instead of '/'")

                if host_violations:
                    deductions += 10
                    findings.append({
                        "severity": "High",
                        "confidence": "Verified",
                        "evidence": f"Set-Cookie: {c_name}=... ({', '.join(host_violations)})",
                        "message": f"Cookie '{c_name}' uses __Host- prefix but violates prefix rules: {', '.join(host_violations)}.",
                        "why_it_matters": "Browsers reject __Host- cookies unless Secure is set, Domain is omitted, and Path=/.",
                        "owasp_ref": "A05:2021-Security Misconfiguration",
                        "remediation": "Set Secure, remove Domain attribute, and set Path=/ for __Host- cookies.",
                        "deduction": 10
                    })

            # 2. Secure Flag Evaluation (for non-prefix cookies, as prefix validation handles prefix cookies)
            if not is_prefix and not c.get("secure", False):
                if is_session:
                    deductions += 10
                    sev = "High"
                    ded = 10
                    msg = f"Session cookie '{c_name}' is missing the Secure attribute."
                    matters = "Authentication or session tokens transmitted over unencrypted HTTP are exposed to network interception."
                else:
                    deductions += 1
                    sev = "Low"
                    ded = 1
                    msg = f"Functional cookie '{c_name}' ({c_type}) is missing the Secure attribute."
                    matters = "Non-sensitive preference or analytics cookie without Secure attribute carries minimal exposure risk."

                findings.append({
                    "severity": sev,
                    "confidence": "Verified",
                    "evidence": f"Set-Cookie: {c_name}=... (missing Secure flag)",
                    "message": msg,
                    "why_it_matters": matters,
                    "owasp_ref": "A05:2021-Security Misconfiguration",
                    "remediation": f"Add 'Secure' attribute to Set-Cookie header for '{c_name}'.",
                    "deduction": ded
                })

            # 3. HttpOnly Flag Evaluation
            if not c.get("http_only", False):
                if is_session:
                    deductions += 5
                    sev = "Medium"
                    ded = 5
                    msg = f"Session cookie '{c_name}' is missing the HttpOnly attribute."
                    matters = "Session tokens missing HttpOnly can be accessed by client-side JavaScript, exposing them to XSS theft."
                else:
                    sev = "Info"
                    ded = 0
                    msg = f"Cookie '{c_name}' ({c_type}) does not set HttpOnly attribute."
                    matters = f"Client-readable cookie ({c_type}) intentionally allows JavaScript access if no sensitive session data is stored."

                findings.append({
                    "severity": sev,
                    "confidence": "Verified",
                    "evidence": f"Set-Cookie: {c_name}=... (missing HttpOnly flag)",
                    "message": msg,
                    "why_it_matters": matters,
                    "owasp_ref": "A07:2021-Identification and Authentication Failures",
                    "remediation": f"Add 'HttpOnly' attribute to Set-Cookie header for '{c_name}'." if is_session else "No action required for non-sensitive client scripts.",
                    "deduction": ded
                })

            # 4. SameSite Attribute Evaluation
            if not c.get("same_site"):
                ded = 2 if is_session else 1
                sev = "Low" if is_session else "Info"
                deductions += ded
                findings.append({
                    "severity": sev,
                    "confidence": "Verified",
                    "evidence": f"Set-Cookie: {c_name}=... (no SameSite attribute present)",
                    "message": f"Cookie '{c_name}' ({c_type}) does not specify a SameSite attribute.",
                    "why_it_matters": "Cookie does not specify SameSite attribute. Modern web browsers automatically default unflagged cookies to SameSite=Lax.",
                    "owasp_ref": "A01:2021-Broken Access Control",
                    "remediation": f"Explicitly set 'SameSite=Lax' or 'SameSite=Strict' on Set-Cookie header for '{c_name}'.",
                    "deduction": ded
                })

        score = max(0, 100 - deductions) if cookies_list else 100
        status_str = "Passed" if score >= 90 else ("Warning" if score >= 75 else "Needs Improvement")

        return {
            "cookies_list": cookies_list,
            "category_cookies": {
                "score": score,
                "status": status_str,
                "weight": 0.10,
                "findings": findings,
                "reasons": [f"[{f['severity']}] [-{f['deduction']}] {f['message']}" for f in findings]
            }
        }
