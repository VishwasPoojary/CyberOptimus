import re
from typing import Dict, Any
from app.scanners.base_module import BaseModule
from app.scanners.config import ScanConfig

HEADER_INTEL = {
    "Strict-Transport-Security": {
        "why_it_matters": "Enforces HTTPS connections on the browser, preventing protocol downgrade attacks (SSL stripping).",
        "risk": "Attackers can intercept HTTP traffic and redirect users to unencrypted sites.",
        "owasp_ref": "A05:2021-Security Misconfiguration",
        "example": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "impact": "Locks browser connections to HTTPS, mitigating Man-in-the-Middle (MITM) hijacking."
    },
    "Content-Security-Policy": {
        "why_it_matters": "Restricts resources (scripts, images, stylesheets) that the browser is allowed to load.",
        "risk": "Reduces browser-side protection against certain script-injection and unauthorized resource-loading scenarios.",
        "owasp_ref": "A03:2021-Injection",
        "example": "Formulate a Content-Security-Policy tailored to your application's actual scripts, stylesheets, fonts, images, and API endpoints (e.g. default-src 'self'; script-src 'self' https://trusted.cdn.com).",
        "impact": "Reduces the attack surface for certain script-injection and unauthorized resource-loading scenarios."
    },
    "X-Frame-Options": {
        "why_it_matters": "Instructs browsers whether the page is allowed to be rendered in a frame or iframe.",
        "risk": "Failing to restrict framing leaves pages vulnerable to clickjacking overlay exploits.",
        "owasp_ref": "A05:2021-Security Misconfiguration",
        "example": "X-Frame-Options: SAMEORIGIN",
        "impact": "Prevents malicious third-party framing, neutralizing clickjacking threats."
    },
    "X-Content-Type-Options": {
        "why_it_matters": "Enforces the declared MIME content types, preventing MIME-type sniffing.",
        "risk": "Browsers may execute uploaded non-executable files (like images) as active scripts.",
        "owasp_ref": "A05:2021-Security Misconfiguration",
        "example": "X-Content-Type-Options: nosniff",
        "impact": "Guarantees browsers respect declared content types, preventing MIME sniffing attacks."
    },
    "Referrer-Policy": {
        "why_it_matters": "Controls the disclosure of user navigation paths in the Referer request headers.",
        "risk": "Sensitive tokens or internal URL paths may be leaked to external sites via the Referer header.",
        "owasp_ref": "A05:2021-Security Misconfiguration",
        "example": "Referrer-Policy: strict-origin-when-cross-origin",
        "impact": "Shields navigation privacy and prevents accidental leakage of URL-based parameters."
    },
    "Permissions-Policy": {
        "why_it_matters": "Allows domains to explicitly declare which browser features and APIs (camera, geolocation, etc.) are allowed.",
        "risk": "Compromised pages or external scripts might trigger device sensor permissions without domain control.",
        "owasp_ref": "A05:2021-Security Misconfiguration",
        "example": "Permissions-Policy: geolocation=(), camera=(), microphone=()",
        "impact": "Restricts device sensors and APIs, reducing the potential attack surface of client browsers."
    },
    "Cross-Origin-Opener-Policy": {
        "why_it_matters": "Isolates the window's browsing context, preventing external sites from controlling or inspecting it.",
        "risk": "Exposes windows to cross-origin information leaks and side-channel (Spectre) attacks.",
        "owasp_ref": "A05:2021-Security Misconfiguration",
        "example": "Cross-Origin-Opener-Policy: same-origin",
        "impact": "Isolates top-level window contexts from cross-origin popups."
    },
    "Cross-Origin-Resource-Policy": {
        "why_it_matters": "Optional origin-isolation policy restricting cross-origin read access to static assets.",
        "risk": "Cross-origin attackers may leak sensitive data using speculative execution attacks.",
        "owasp_ref": "A05:2021-Security Misconfiguration",
        "example": "Cross-Origin-Resource-Policy: same-site (or same-origin depending on cross-domain resource needs)",
        "impact": "Protects static assets and APIs from cross-origin read access."
    },
    "Cross-Origin-Embedder-Policy": {
        "why_it_matters": "Optional origin-isolation policy requiring cross-origin resources to explicitly grant loading permission.",
        "risk": "Allows untrusted cross-origin resources to enter the document's memory space.",
        "owasp_ref": "A05:2021-Security Misconfiguration",
        "example": "Cross-Origin-Embedder-Policy: require-corp (Evaluate impact on external media/CDNs before deploying)",
        "impact": "Enforces process isolation for high-resolution timer access."
    },
    "Report-To": {
        "why_it_matters": "Enables browser/network security event reporting for monitoring and diagnostics.",
        "risk": "Absence of browser reporting endpoints limits real-time telemetry on network errors and policy violations.",
        "owasp_ref": "A05:2021-Security Misconfiguration",
        "example": "Report-To: {\"group\":\"default\",\"max_age\":10886400,\"endpoints\":[{\"url\":\"https://example.report-uri.com\"}]}",
        "impact": "Provides automated client-side error and security violation telemetry."
    },
    "NEL": {
        "why_it_matters": "Enables browser/network security event reporting for monitoring and diagnostics.",
        "risk": "Absence of NEL limits browser-level network error logging for client connections.",
        "owasp_ref": "A05:2021-Security Misconfiguration",
        "example": "NEL: {\"report_to\":\"default\",\"max_age\":31536000}",
        "impact": "Captures client-side network connection failures and latency telemetry."
    }
}

class HeaderModule(BaseModule):
    name = "HeaderModule"

    def run(self, context: Dict[str, Any], config: ScanConfig) -> Dict[str, Any]:
        if context.get("unreachable"):
            return {
                "security_headers": {},
                "category_headers": {
                    "score": "N/A",
                    "status": "Not Tested",
                    "weight": 0.25,
                    "findings": [],
                    "reasons": ["Header analysis skipped because the target domain is unreachable."]
                }
            }

        final_headers = context.get("final_headers", context.get("merged_headers", {}))
        html_recon = context.get("html_recon", {})
        html_meta_headers = html_recon.get("meta_security_headers", {}) if config.parse_html_meta else {}
        domain = context.get("final_host", context.get("initial_domain", ""))

        target_headers = [
            "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
            "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
            "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy",
            "Cross-Origin-Embedder-Policy", "Origin-Agent-Cluster", "Report-To", "NEL"
        ]

        lower_headers = {k.lower(): v for k, v in final_headers.items()}
        csp_val = lower_headers.get("content-security-policy", "")
        if not csp_val and html_meta_headers.get("content-security-policy"):
            csp_val = html_meta_headers.get("content-security-policy")
        has_frame_ancestors = "frame-ancestors" in csp_val.lower()

        security_headers = {}
        findings = []
        deductions = 0

        for h in target_headers:
            val = lower_headers.get(h.lower())

            if h == "Content-Security-Policy":
                meta_csp_val = html_meta_headers.get("content-security-policy")
                if val is not None:
                    security_headers[h] = {
                        "status": "Present", "value": val,
                        "reason": "Content-Security-Policy is active.",
                        "evidence": f"Content-Security-Policy: {val}",
                        "severity": "Info"
                    }
                elif meta_csp_val is not None:
                    security_headers[h] = {
                        "status": "Present (via HTML Meta)", "value": meta_csp_val,
                        "reason": "Content-Security-Policy is specified via HTML <meta http-equiv='Content-Security-Policy'> tag.",
                        "evidence": f"<meta http-equiv='Content-Security-Policy' content='{meta_csp_val}'>",
                        "severity": "Info"
                    }
                else:
                    report_only_val = lower_headers.get("content-security-policy-report-only")
                    if report_only_val is not None:
                        security_headers[h] = {
                            "status": "Report Only", "value": report_only_val,
                            "reason": "Content-Security-Policy is configured in Report-Only mode (intentional audit state).",
                            "evidence": f"Content-Security-Policy-Report-Only: {report_only_val}",
                            "severity": "Low"
                        }
                    else:
                        security_headers[h] = {
                            "status": "Missing", "value": None,
                            "reason": "Content-Security-Policy is not configured.",
                            "evidence": "Neither HTTP response header nor HTML meta tag included a Content-Security-Policy.",
                            "severity": "High"
                        }

            elif h == "Referrer-Policy":
                meta_ref_val = html_meta_headers.get("referrer-policy") or html_meta_headers.get("referrer")
                if val is not None:
                    security_headers[h] = {
                        "status": "Present", "value": val,
                        "reason": "Referrer policy controls outbound navigation information disclosure.",
                        "evidence": f"Referrer-Policy: {val}",
                        "severity": "Info"
                    }
                elif meta_ref_val is not None:
                    security_headers[h] = {
                        "status": "Present (via HTML Meta)", "value": meta_ref_val,
                        "reason": "Referrer-Policy is specified via HTML <meta name='referrer'> tag.",
                        "evidence": f"<meta name='referrer' content='{meta_ref_val}'>",
                        "severity": "Info"
                    }
                else:
                    security_headers[h] = {
                        "status": "Missing", "value": None,
                        "reason": "Missing Referrer-Policy header or meta tag.",
                        "evidence": "The HTTP response did not include a Referrer-Policy header or HTML meta tag.",
                        "severity": "Medium"
                    }

            elif h == "X-Frame-Options":
                if val is not None:
                    security_headers[h] = {"status": "Present", "value": val, "severity": "Info"}
                elif has_frame_ancestors:
                    security_headers[h] = {"status": "Present", "value": "Protected via CSP frame-ancestors", "severity": "Info"}
                else:
                    security_headers[h] = {"status": "Missing", "value": None, "severity": "Medium"}

            elif h == "X-Content-Type-Options":
                security_headers[h] = {"status": "Present" if val is not None else "Missing", "value": val, "severity": "Info" if val else "Medium"}

            elif h == "Strict-Transport-Security":
                if val is not None:
                    security_headers[h] = {
                        "status": "Present", "value": val,
                        "reason": "Strict-Transport-Security header enforces HTTPS connections.",
                        "evidence": f"Strict-Transport-Security: {val}",
                        "severity": "Info"
                    }
                else:
                    security_headers[h] = {
                        "status": "Missing", "value": None,
                        "reason": "Missing Strict-Transport-Security header on HTTPS response.",
                        "evidence": "The HTTP response did not include a Strict-Transport-Security header.",
                        "severity": "High"
                    }
            elif h in ["Report-To", "NEL"]:
                if val is not None:
                    security_headers[h] = {"status": "Present", "value": val, "severity": "Info"}
                else:
                    security_headers[h] = {
                        "status": "Missing", "value": None, "severity": "Info",
                        "reason": f"Optional browser telemetry header {h} is not present.",
                        "evidence": f"The HTTP response did not include a {h} header."
                    }
            elif h in ["Permissions-Policy", "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy", "Cross-Origin-Embedder-Policy", "Origin-Agent-Cluster"]:
                security_headers[h] = {"status": "Present" if val is not None else "Missing", "value": val, "severity": "Info" if val else "Low"}
            else:
                security_headers[h] = {"status": "Present" if val is not None else "Missing", "value": val, "severity": "Info" if val else "Low"}

        # Score calculation for Headers
        reasons = []
        for h_name, h_info in security_headers.items():
            status = h_info["status"]
            sev = h_info["severity"]
            intel = HEADER_INTEL.get(h_name, {})

            if status == "Missing":
                if sev == "High":
                    ded = 15
                elif sev == "Medium":
                    ded = 8
                elif sev == "Low":
                    ded = 1  # Modern origin-isolation cap: 1 pt max on root apex scans
                else:
                    ded = 0  # Info telemetry headers: 0 pt deduction
                
                deductions += ded
                findings.append({
                    "header": h_name, "severity": sev, "confidence": "Verified",
                    "evidence": h_info.get("evidence", f"The HTTP response did not include a {h_name} header."),
                    "message": f"{h_name} header is missing from server response.",
                    "why_it_matters": intel.get("why_it_matters", "Protects client browsers against modern web exploits."),
                    "owasp_ref": intel.get("owasp_ref", "A05:2021-Security Misconfiguration"),
                    "remediation": intel.get("example", f"Add '{h_name}' to HTTP response headers."),
                    "deduction": ded
                })
                if ded > 0:
                    reasons.append(f"[{sev}] [-{ded}] {h_name} header is missing.")

            elif status in ["Present", "Present (via HTML Meta)", "Report Only"]:
                csp_str = h_info.get("value", "")
                if h_name == "Content-Security-Policy" and csp_str:
                    # Directive Audit
                    csp_lower = csp_str.lower()
                    directives = [d.strip() for d in csp_lower.split(";") if d.strip()]
                    dir_names = [d.split()[0] for d in directives if d.split()]

                    if "'unsafe-inline'" in csp_lower:
                        ded = 2
                        deductions += ded
                        findings.append({
                            "header": h_name, "severity": "Low", "confidence": "Verified",
                            "evidence": f"CSP directive contains 'unsafe-inline' source expression in: '{csp_str[:120]}...'",
                            "message": "Content-Security-Policy contains 'unsafe-inline' directive.",
                            "why_it_matters": "Using 'unsafe-inline' relaxes script/style injection protection and increases cross-site scripting (XSS) risk.",
                            "owasp_ref": "A03:2021-Injection",
                            "remediation": "Replace 'unsafe-inline' with cryptographic nonces or hashes.",
                            "deduction": ded
                        })
                        reasons.append(f"[Low] [-{ded}] CSP contains unsafe-inline.")

                    if "'unsafe-eval'" in csp_lower:
                        ded = 1
                        deductions += ded
                        findings.append({
                            "header": h_name, "severity": "Low", "confidence": "Verified",
                            "evidence": "CSP directive includes 'unsafe-eval'.",
                            "message": "Content-Security-Policy contains 'unsafe-eval' directive.",
                            "why_it_matters": "Allows execution of string-to-code functions (eval), weakening DOM XSS protections.",
                            "owasp_ref": "A03:2021-Injection",
                            "remediation": "Remove 'unsafe-eval' and refactor dynamic code generation.",
                            "deduction": ded
                        })
                        reasons.append(f"[Low] [-{ded}] CSP contains unsafe-eval.")

                    if "object-src" not in dir_names:
                        ded = 1
                        deductions += ded
                        findings.append({
                            "header": h_name, "severity": "Low", "confidence": "Verified",
                            "evidence": "CSP does not define an 'object-src' directive.",
                            "message": "Content-Security-Policy missing 'object-src' restriction.",
                            "why_it_matters": "Unrestricted object-src allows legacy plugins (Flash, Java Applets) to execute.",
                            "owasp_ref": "A05:2021-Security Misconfiguration",
                            "remediation": "Add 'object-src \\'none\\'' to Content-Security-Policy.",
                            "deduction": ded
                        })
                        reasons.append(f"[Low] [-{ded}] CSP missing object-src directive.")

                    if "base-uri" not in dir_names:
                        ded = 1
                        deductions += ded
                        findings.append({
                            "header": h_name, "severity": "Low", "confidence": "Verified",
                            "evidence": "CSP does not define a 'base-uri' directive.",
                            "message": "Content-Security-Policy missing 'base-uri' restriction.",
                            "why_it_matters": "Missing base-uri allows malicious scripts to hijack relative URLs via <base> tag injection.",
                            "owasp_ref": "A05:2021-Security Misconfiguration",
                            "remediation": "Add 'base-uri \\'self\\'' to Content-Security-Policy.",
                            "deduction": ded
                        })
                        reasons.append(f"[Low] [-{ded}] CSP missing base-uri directive.")

        score = max(0, 100 - deductions)
        status_str = "Passed" if score >= 90 else ("Warning" if score >= 75 else "Needs Improvement")

        return {
            "security_headers": security_headers,
            "category_headers": {
                "score": score,
                "status": status_str,
                "weight": 0.25,
                "findings": findings,
                "reasons": reasons
            }
        }
