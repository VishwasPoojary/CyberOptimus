import time
from urllib.parse import urlparse
import re
import socket
from app.scanners.base_scanner import BaseScanner
from app.scanners.config import ScanConfig
from app.scanners.engine import ScannerEngine
from app.utils.network import (
    resolve_ip, fetch_url, check_ssl_certificate,
    has_ipv6, measure_network_timings, normalize_input_url,
    query_dns_records, fetch_rdap_domain_info, fetch_html_content
)
from app.utils.domain_intelligence import classify_redirect, extract_registered_domain

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
        "example": "Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted.com (Example configuration — must be adapted to the site's actual resources.)",
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
        "impact": "Ensures document environment isolation, protecting session tokens in memory."
    },
    "Cross-Origin-Resource-Policy": {
        "why_it_matters": "Permits sites to block other domains from embedding their static assets (images, fonts, scripts).",
        "risk": "Malicious actors can hotlink assets or parse sensitive binary responses using Spectre side-channels.",
        "owasp_ref": "A05:2021-Security Misconfiguration",
        "example": "Cross-Origin-Resource-Policy: same-origin",
        "impact": "Defends asset payloads from being exfiltrated or loaded in unauthorized domains."
    },
    "Cross-Origin-Embedder-Policy": {
        "why_it_matters": "Ensures the document only loads cross-origin resources that explicitly grant permission.",
        "risk": "Prerequisite for process isolation (Spectre mitigation). Without it, untrusted resources can share threads.",
        "owasp_ref": "A05:2021-Security Misconfiguration",
        "example": "Cross-Origin-Embedder-Policy: require-corp",
        "impact": "Enables opt-in resource isolation policies on modern browsers."
    },
    "Origin-Agent-Cluster": {
        "why_it_matters": "Requests that the browser run the site in its own dedicated operating system process.",
        "risk": "Failing process isolation allows sites sharing origins to sometimes inspect memory allocations.",
        "owasp_ref": "A05:2021-Security Misconfiguration",
        "example": "Origin-Agent-Cluster: ?1",
        "impact": "Locks memory mapping to a single page agent process scope."
    }
}

# Known browser preloaded HSTS domains
KNOWN_HSTS_PRELOADED = {
    "google.com", "www.google.com", "github.com", "www.github.com",
    "paypal.com", "www.paypal.com", "microsoft.com", "www.microsoft.com",
    "cloudflare.com", "www.cloudflare.com", "apple.com", "www.apple.com",
    "amazon.com", "www.amazon.com", "facebook.com", "www.facebook.com",
    "youtube.com", "www.youtube.com", "netflix.com", "www.netflix.com"
}

def split_set_cookie_header(header_value: str) -> list:
    if not header_value:
        return []
    raw_parts = header_value.split(",")
    parts = []
    days = {"mon", "tue", "wed", "thu", "fri", "sat", "sun"}
    temp = ""
    for part in raw_parts:
        if temp:
            temp += "," + part
        else:
            temp = part
        trimmed = temp.strip()
        subparts = trimmed.split(";")
        last_subpart = subparts[-1].strip().lower()
        is_split_in_expires = False
        for day in days:
            if last_subpart.endswith(day):
                is_split_in_expires = True
                break
        if not is_split_in_expires:
            parts.append(temp)
            temp = ""
    if temp:
        parts.append(temp)
    return parts

def parse_set_cookie_header(header_value: str) -> dict:
    """Parse a Set-Cookie header value into a structured dictionary.
    
    IMPORTANT: Missing attributes remain as "Not Specified" or None.
    We NEVER assume a default value for any attribute that is absent
    from the actual Set-Cookie header string. This prevents false positives
    where a missing SameSite would be misinterpreted as SameSite=None.
    """
    parts = [p.strip() for p in header_value.split(";")]
    if not parts or not parts[0]:
        return None
    first_part = parts[0]
    if "=" not in first_part:
        return None
    name, val = first_part.split("=", 1)
    cookie_info = {
        "name": name.strip(),
        "value": val.strip(),
        "raw_header": header_value,
        "secure": False,
        "http_only": False,
        "same_site": "Not Specified",
        "same_site_explicitly_set": False,
        "domain": None,
        "path": None,
        "expires": None,
        "max_age": None
    }
    for part in parts[1:]:
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            k = k.strip().lower()
            v = v.strip()
            if k == "domain":
                cookie_info["domain"] = v
            elif k == "path":
                cookie_info["path"] = v
            elif k == "expires":
                cookie_info["expires"] = v
            elif k == "max-age":
                cookie_info["max_age"] = v
            elif k == "samesite":
                cookie_info["same_site"] = v
                cookie_info["same_site_explicitly_set"] = True
        else:
            k = part.strip().lower()
            if k == "secure":
                cookie_info["secure"] = True
            elif k == "httponly":
                cookie_info["http_only"] = True
    return cookie_info

class WebsiteScanner(BaseScanner):
    def __init__(self, config: ScanConfig = None):
        self.config = config or ScanConfig()
        self.engine = ScannerEngine(self.config)

    def scan(self, target: str, config: ScanConfig = None) -> dict:
        cfg = config or self.config
        engine = ScannerEngine(cfg)
        return engine.execute(target)
            
    def _check_security_headers(self, headers: dict, domain: str, available: bool, html_meta_headers: dict = None) -> dict:
        if html_meta_headers is None:
            html_meta_headers = {}

        target_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
            "Cross-Origin-Opener-Policy",
            "Cross-Origin-Resource-Policy",
            "Cross-Origin-Embedder-Policy",
            "Origin-Agent-Cluster",
            "Report-To",
            "NEL"
        ]
        
        result = {}
        if not available:
            for h in target_headers:
                result[h] = {
                    "status": "Not Tested",
                    "value": None,
                    "reason": "Response headers could not be retrieved because the website connection could not be established.",
                    "evidence": "No HTTP response received from target.",
                    "confidence": "Verified",
                    "severity": "Info"
                }
            return result
            
        lower_headers = {k.lower(): v for k, v in headers.items()}
        csp_val = lower_headers.get("content-security-policy", "")
        if not csp_val and html_meta_headers.get("content-security-policy"):
            csp_val = html_meta_headers.get("content-security-policy")
        has_frame_ancestors = "frame-ancestors" in csp_val.lower()
        
        for h in target_headers:
            val = lower_headers.get(h.lower())
            
            if h == "Strict-Transport-Security":
                is_preloaded = any(d in domain for d in KNOWN_HSTS_PRELOADED)
                if val is not None:
                    max_age_match = re.search(r'max-age=(\d+)', val, re.IGNORECASE)
                    max_age_val = int(max_age_match.group(1)) if max_age_match else 0
                    inc_sub = "includesubdomains" in val.lower()
                    preload_attr = "preload" in val.lower()
                    
                    reasons = []
                    if max_age_val < 31536000:
                        reasons.append("max-age is less than 1 year (31,536,000s)")
                    if not inc_sub:
                        reasons.append("includeSubDomains directive is missing")
                    if not preload_attr:
                        reasons.append("preload directive is missing")
                        
                    reason_str = "HSTS header is verified and active."
                    if reasons:
                        reason_str = f"HSTS Present but not optimal: {', '.join(reasons)}."
                        
                    result[h] = {
                        "status": "Present",
                        "value": val,
                        "reason": reason_str,
                        "evidence": f"Strict-Transport-Security: {val}",
                        "confidence": "Verified",
                        "severity": "Low" if reasons else "Info",
                        "max_age": max_age_val,
                        "include_subdomains": inc_sub,
                        "preload": preload_attr,
                        "preload_eligible": (max_age_val >= 31536000 and inc_sub and preload_attr),
                        "browser_preloaded": is_preloaded
                    }
                else:
                    if is_preloaded:
                        result[h] = {
                            "status": "Present",
                            "value": "Preloaded (HSTS Active via Browser)",
                            "reason": "Domain is hardcoded in major web browser HSTS preload lists. Strict HTTPS is enforced automatically.",
                            "evidence": f"Domain '{domain}' is listed in browser HSTS preload preload database.",
                            "confidence": "Verified",
                            "severity": "Info",
                            "max_age": 31536000,
                            "include_subdomains": True,
                            "preload": True,
                            "preload_eligible": True,
                            "browser_preloaded": True
                        }
                    else:
                        result[h] = {
                            "status": "Missing",
                            "value": None,
                            "reason": "HSTS header not observed in response headers. Strict HTTPS enforcement is not guaranteed on first connect.",
                            "evidence": "The HTTP response did not include a Strict-Transport-Security header.",
                            "confidence": "Verified",
                            "severity": "High",
                            "max_age": 0,
                            "include_subdomains": False,
                            "preload": False,
                            "preload_eligible": False,
                            "browser_preloaded": False
                        }
                        
            elif h == "Content-Security-Policy":
                meta_csp_val = html_meta_headers.get("content-security-policy")
                if val is not None:
                    csp_issues = []
                    val_lower = val.lower()
                    if "'unsafe-inline'" in val_lower:
                        csp_issues.append("Allows 'unsafe-inline' script/style execution")
                    if "'unsafe-eval'" in val_lower:
                        csp_issues.append("Allows 'unsafe-eval' dynamic code evaluation")
                    if "*" in val or "'*'" in val:
                        csp_issues.append("Contains wildcard '*' source permissions")
                    if "default-src" not in val_lower:
                        csp_issues.append("Lacks default-src fallback directive")

                    reason_str = "Content-Security-Policy is active and enforcing resource loading rules."
                    sev = "Info"
                    if csp_issues:
                        reason_str = f"CSP is active but contains weak directives: {', '.join(csp_issues)}."
                        sev = "Low"

                    result[h] = {
                        "status": "Present",
                        "value": val,
                        "reason": reason_str,
                        "evidence": f"Content-Security-Policy: {val}",
                        "confidence": "Verified",
                        "severity": sev,
                        "csp_issues": csp_issues
                    }
                elif meta_csp_val is not None:
                    csp_issues = []
                    val_lower = meta_csp_val.lower()
                    if "'unsafe-inline'" in val_lower:
                        csp_issues.append("Allows 'unsafe-inline' script/style execution")
                    if "'unsafe-eval'" in val_lower:
                        csp_issues.append("Allows 'unsafe-eval' dynamic code evaluation")
                    if "*" in meta_csp_val or "'*'" in meta_csp_val:
                        csp_issues.append("Contains wildcard '*' source permissions")
                    if "default-src" not in val_lower:
                        csp_issues.append("Lacks default-src fallback directive")

                    reason_str = "Content-Security-Policy is configured via HTML <meta http-equiv='Content-Security-Policy'> tag."
                    sev = "Info"
                    if csp_issues:
                        reason_str = f"CSP specified via HTML meta tag contains weak directives: {', '.join(csp_issues)}."
                        sev = "Low"

                    result[h] = {
                        "status": "Present (via HTML Meta)",
                        "value": meta_csp_val,
                        "reason": reason_str,
                        "evidence": f"<meta http-equiv='Content-Security-Policy' content='{meta_csp_val}'>",
                        "confidence": "Verified",
                        "severity": sev,
                        "csp_issues": csp_issues
                    }
                else:
                    report_only_val = lower_headers.get("content-security-policy-report-only")
                    if report_only_val is not None:
                        result[h] = {
                            "status": "Report Only",
                            "value": report_only_val,
                            "reason": "Content-Security-Policy is configured in Report-Only mode. This represents an intentional audit/telemetry state to monitor potential policy violations before active enforcement.",
                            "evidence": f"Content-Security-Policy-Report-Only: {report_only_val}",
                            "confidence": "Verified",
                            "severity": "Low"
                        }
                    else:
                        result[h] = {
                            "status": "Missing",
                            "value": None,
                            "reason": "Content-Security-Policy is not configured in HTTP response headers or HTML meta tags. This reduces browser-side protection against certain script injection scenarios.",
                            "evidence": "Neither HTTP response header nor HTML meta tag included a Content-Security-Policy.",
                            "confidence": "Verified",
                            "severity": "High"
                        }
                        
            elif h == "X-Frame-Options":
                if val is not None:
                    result[h] = {
                        "status": "Present",
                        "value": val,
                        "reason": "Framing restrictions are active via X-Frame-Options.",
                        "evidence": f"X-Frame-Options: {val}",
                        "confidence": "Verified",
                        "severity": "Info"
                    }
                elif has_frame_ancestors:
                    result[h] = {
                        "status": "Present",
                        "value": "Protected via CSP frame-ancestors directive",
                        "reason": "Clickjacking protection is enforced via Content-Security-Policy frame-ancestors directive.",
                        "evidence": "Content-Security-Policy contains frame-ancestors directive.",
                        "confidence": "Verified",
                        "severity": "Info"
                    }
                else:
                    result[h] = {
                        "status": "Missing",
                        "value": None,
                        "reason": "Missing framing restrictions. Leaves page vulnerable to clickjacking overlay exploits.",
                        "evidence": "The HTTP response did not include an X-Frame-Options header.",
                        "confidence": "Verified",
                        "severity": "Medium"
                    }
            elif h == "X-Content-Type-Options":
                if val is not None:
                    result[h] = {
                        "status": "Present",
                        "value": val,
                        "reason": "MIME-type sniffing prevention enabled.",
                        "evidence": f"X-Content-Type-Options: {val}",
                        "confidence": "Verified",
                        "severity": "Info"
                    }
                else:
                    result[h] = {
                        "status": "Missing",
                        "value": None,
                        "reason": "MIME-type sniffing prevention is missing. Browsers may execute non-executable files as scripts.",
                        "evidence": "The HTTP response did not include an X-Content-Type-Options header.",
                        "confidence": "Verified",
                        "severity": "Medium"
                    }
            elif h == "Referrer-Policy":
                meta_ref_val = html_meta_headers.get("referrer-policy") or html_meta_headers.get("referrer")
                if val is not None:
                    result[h] = {
                        "status": "Present",
                        "value": val,
                        "reason": "Referrer policy controls outbound navigation information disclosure.",
                        "evidence": f"Referrer-Policy: {val}",
                        "confidence": "Verified",
                        "severity": "Info"
                    }
                elif meta_ref_val is not None:
                    result[h] = {
                        "status": "Present (via HTML Meta)",
                        "value": meta_ref_val,
                        "reason": "Referrer policy is specified via HTML <meta name='referrer'> tag.",
                        "evidence": f"<meta name='referrer' content='{meta_ref_val}'>",
                        "confidence": "Verified",
                        "severity": "Info"
                    }
                else:
                    result[h] = {
                        "status": "Missing",
                        "value": None,
                        "reason": "Missing Referrer-Policy header or meta tag. Sensitive tokens or URL paths may be leaked to external origins.",
                        "evidence": "The HTTP response did not include a Referrer-Policy header or HTML meta tag.",
                        "confidence": "Verified",
                        "severity": "Medium"
                    }
            else:
                intel = HEADER_INTEL.get(h, {
                    "why_it_matters": "Enhances HTTP connection security configuration.",
                    "risk": "Failing to implement increases client exposure to modern browser-based vectors.",
                    "owasp_ref": "A05:2021-Security Misconfiguration",
                    "example": "N/A",
                    "impact": "Improves overall baseline security posture."
                })
                # COEP, CORP, COOP, Permissions-Policy are Low/Info severities
                severity = "Low"
                if h in ["Report-To", "NEL", "Origin-Agent-Cluster"]:
                    severity = "Info"
                    
                if val is not None:
                    result[h] = {
                        "status": "Present",
                        "value": val,
                        "reason": f"{h} is configured on the server.",
                        "evidence": f"{h}: {val}",
                        "confidence": "Verified",
                        "severity": "Info"
                    }
                else:
                    status_label = "Missing" if severity != "Info" else "Not Observed"
                    result[h] = {
                        "status": status_label,
                        "value": None,
                        "reason": f"{h} header is missing from server response.",
                        "evidence": f"The HTTP response did not include a {h} header.",
                        "confidence": "Verified",
                        "severity": severity
                    }
        return result
        
    def _evaluate_categories(self, data: dict, dns_failed: bool, ssl_failed: bool) -> tuple[dict, int, str, str, dict, list]:
        categories = {
            "dns": {"score": 100, "status": "Passed", "reasons": [], "findings": [], "recommendations": []},
            "ssl": {"score": 100, "status": "Passed", "reasons": [], "findings": [], "recommendations": []},
            "headers": {"score": 100, "status": "Passed", "reasons": [], "findings": [], "recommendations": []},
            "redirects": {"score": 100, "status": "Passed", "reasons": [], "findings": [], "recommendations": []},
            "cookies": {"score": 100, "status": "Passed", "reasons": [], "findings": [], "recommendations": []},
            "server": {"score": 100, "status": "Passed", "reasons": [], "findings": [], "recommendations": []},
            "performance": {"score": "N/A", "status": "Observation Only", "reasons": [], "findings": [], "recommendations": []}
        }
        
        severity_summary = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Info": 0
        }
        
        # 1. DNS (15%)
        if dns_failed:
            categories["dns"]["score"] = "N/A"
            categories["dns"]["status"] = "DNS Resolution Failed (NXDOMAIN)"
            categories["dns"]["findings"].append({
                "severity": "Info",
                "message": "DNS Resolution Failed (NXDOMAIN). Target domain could not be resolved to an active IP address.",
                "evidence": f"DNS query for '{data.get('original_host', 'domain')}' returned NXDOMAIN / no A or AAAA records.",
                "confidence": "Verified",
                "why_it_matters": "Domain names must resolve to active IP addresses for client connections to succeed.",
                "owasp_ref": "N/A",
                "remediation": "Verify domain registration and configure valid A/AAAA DNS records.",
                "deduction": 0
            })
            categories["dns"]["reasons"].append("[Info] [-0] DNS resolution failed (NXDOMAIN).")
            categories["dns"]["recommendations"].append({
                "title": "Configure Valid DNS Records",
                "why_it_matters": "Domain names must point to active IP records (A/AAAA) for users to connect.",
                "risk": "Domain remains completely unreachable.",
                "owasp_ref": "N/A",
                "example": "Point A/AAAA records to your host server IP address.",
                "impact": "Restores global connectivity."
            })
        else:
            categories["dns"]["reasons"].append("[Info] [+0] DNS lookup completed successfully.")
            if data.get("ipv6_supported"):
                categories["dns"]["findings"].append({
                    "severity": "Info",
                    "message": "IPv6 configuration detected.",
                    "evidence": f"AAAA record verified for host '{data.get('original_host')}'",
                    "confidence": "Verified",
                    "why_it_matters": "Dual-stack IPv4/IPv6 support ensures compatibility with modern networks.",
                    "owasp_ref": "N/A",
                    "remediation": "N/A",
                    "deduction": 0
                })
                severity_summary["Info"] += 1
            else:
                categories["dns"]["findings"].append({
                    "severity": "Info",
                    "message": "Domain resolves to IPv4 address.",
                    "evidence": f"IP Address: {data.get('ip_address')} (IPv4 record only)",
                    "confidence": "Verified",
                    "why_it_matters": "Adding IPv6 AAAA records improves accessibility on modern networks.",
                    "owasp_ref": "N/A",
                    "remediation": "Configure AAAA records in DNS settings.",
                    "deduction": 0
                })
                severity_summary["Info"] += 1
                
        # 2. SSL/TLS (25%)
        if dns_failed:
            categories["ssl"]["status"] = "Not Tested"
            categories["ssl"]["score"] = "N/A"
            categories["ssl"]["findings"].append({
                "severity": "Info",
                "message": "SSL verification skipped because domain name failed DNS resolution (NXDOMAIN).",
                "evidence": "No network connection could be established.",
                "confidence": "Verified",
                "why_it_matters": "SSL/TLS cannot be inspected without active DNS resolution.",
                "owasp_ref": "N/A",
                "remediation": "Fix DNS resolution first.",
                "deduction": 0
            })
            categories["ssl"]["reasons"].append("[Info] [-0] SSL inspection skipped due to DNS failure.")
        else:
            if data.get("https") != "Enabled":
                categories["ssl"]["score"] = 0
                categories["ssl"]["status"] = "Failed"
                categories["ssl"]["findings"].append({
                    "severity": "Critical",
                    "message": "HTTPS is not enabled on this endpoint.",
                    "evidence": f"Target endpoint scheme is '{urlparse(data.get('final_url','')).scheme}' without TLS encryption.",
                    "confidence": "Verified",
                    "why_it_matters": "Unencrypted HTTP transmissions allow network eavesdropping and man-in-the-middle manipulation.",
                    "owasp_ref": "A02:2021-Cryptographic Failures",
                    "remediation": "Deploy TLS certificate and redirect all HTTP traffic to HTTPS.",
                    "deduction": 100
                })
                categories["ssl"]["reasons"].append("[Critical] [-100] Connection is not secured with HTTPS.")
                categories["ssl"]["recommendations"].append({
                    "title": "Deploy TLS Certificate and Enforce HTTPS",
                    "why_it_matters": "HTTPS encrypts communications between client and server, protecting parameters, session IDs, and payloads.",
                    "risk": "Attackers on shared networks can view or alter client transactions (sniffing, injection).",
                    "owasp_ref": "A02:2021-Cryptographic Failures",
                    "example": "Configure redirects from http:// to https:// and bind a TLS certificate to port 443.",
                    "impact": "Guarantees confidentiality and integrity of all client transactions."
                })
                severity_summary["Critical"] += 1
            elif ssl_failed:
                categories["ssl"]["score"] = 0
                categories["ssl"]["status"] = "Failed"
                err = data["ssl"].get("error", "Unknown validation error")
                categories["ssl"]["findings"].append({
                    "severity": "Critical",
                    "message": f"SSL/TLS configuration failed validation: {err}",
                    "evidence": f"TLS handshake validation error: {err}",
                    "confidence": "Verified",
                    "why_it_matters": "Browsers automatically block access to invalid certificates.",
                    "owasp_ref": "A02:2021-Cryptographic Failures",
                    "remediation": "Renew certificate or bind valid hostname domain matching SAN entries.",
                    "deduction": 100
                })
                categories["ssl"]["reasons"].append(f"[Critical] [-100] SSL validation failed: {err}")
                severity_summary["Critical"] += 1
            else:
                categories["ssl"]["reasons"].append("[Info] [+0] Valid SSL/TLS connection established.")
                tls_v = data["ssl"].get("tls_version", "N/A")
                if "TLSv1.3" in tls_v:
                    categories["ssl"]["findings"].append({
                        "severity": "Info",
                        "message": f"Modern TLS 1.3 protocol negotiation detected ({data['ssl'].get('cipher_suite', 'N/A')}).",
                        "evidence": f"Protocol: {tls_v} | Cipher: {data['ssl'].get('cipher_suite', 'N/A')}",
                        "confidence": "Verified",
                        "why_it_matters": "TLS 1.3 provides maximum cryptographic security and faster handshake speeds.",
                        "owasp_ref": "A02:2021-Cryptographic Failures",
                        "remediation": "Maintain current TLS configuration.",
                        "deduction": 0
                    })
                    severity_summary["Info"] += 1
                elif "TLSv1.2" in tls_v:
                    categories["ssl"]["findings"].append({
                        "severity": "Info",
                        "message": "TLS 1.2 protocol configuration verified.",
                        "evidence": f"Protocol: {tls_v} | Cipher: {data['ssl'].get('cipher_suite', 'N/A')}",
                        "confidence": "Verified",
                        "why_it_matters": "TLS 1.2 is secure when paired with strong cipher suites.",
                        "owasp_ref": "A02:2021-Cryptographic Failures",
                        "remediation": "Consider enabling TLS 1.3 for enhanced security.",
                        "deduction": 0
                    })
                    severity_summary["Info"] += 1
                else:
                    categories["ssl"]["score"] = 80
                    categories["ssl"]["status"] = "Warning"
                    categories["ssl"]["findings"].append({
                        "severity": "High",
                        "message": f"Legacy TLS protocol negotiated: {tls_v}.",
                        "evidence": f"Protocol: {tls_v}",
                        "confidence": "Verified",
                        "why_it_matters": "Legacy TLS 1.0/1.1 protocols contain known cryptographic vulnerabilities.",
                        "owasp_ref": "A02:2021-Cryptographic Failures",
                        "remediation": "Disable TLS 1.0 and TLS 1.1 in web server configuration.",
                        "deduction": 20
                    })
                    categories["ssl"]["reasons"].append(f"[High] [-20] Legacy TLS protocol: {tls_v}")
                    severity_summary["High"] += 1
                    
                if data["ssl"].get("ocsp_stapled"):
                    categories["ssl"]["findings"].append({
                        "severity": "Info",
                        "message": "OCSP Stapling verified.",
                        "evidence": "OCSP response stapled in TLS handshake.",
                        "confidence": "Verified",
                        "why_it_matters": "OCSP Stapling improves client privacy and speeds up certificate revocation checks.",
                        "owasp_ref": "N/A",
                        "remediation": "Maintain current OCSP configuration.",
                        "deduction": 0
                    })
                    severity_summary["Info"] += 1

        # 3. HTTP Security Headers (25%)
        http_failed = (data["status_code"] == "Unreachable")
        if dns_failed or ssl_failed or http_failed:
            categories["headers"]["status"] = "Not Tested"
            categories["headers"]["score"] = "N/A"
            categories["headers"]["findings"].append({
                "severity": "Info",
                "message": "HTTP Security Headers skipped due to network connectivity failures.",
                "evidence": "No HTTP response headers received.",
                "confidence": "Verified",
                "why_it_matters": "Headers cannot be inspected without an active HTTP response.",
                "owasp_ref": "N/A",
                "remediation": "N/A",
                "deduction": 0
            })
            categories["headers"]["reasons"].append("[Info] [-0] Headers audit skipped.")
        else:
            headers = data["security_headers"]
            deductions = 0
            
            for h_name, h_info in headers.items():
                status = h_info["status"]
                intel = HEADER_INTEL.get(h_name, {})
                
                if status == "Missing":
                    sev = h_info.get("severity", "Low")
                    if sev == "High":
                        ded = 15
                    elif sev == "Medium":
                        ded = 8
                    else:
                        ded = 1  # Minimal 1 pt deduction for optional hardening headers (Permissions-Policy, COOP, COEP, CORP)
                        
                    deductions += ded
                    categories["headers"]["findings"].append({
                        "header": h_name,
                        "severity": sev,
                        "confidence": "Verified",
                        "evidence": h_info.get("evidence", f"The HTTP response did not include a {h_name} header."),
                        "message": f"{h_name} header is missing from server response.",
                        "why_it_matters": intel.get("why_it_matters", "Protects client browsers against modern web exploits."),
                        "owasp_ref": intel.get("owasp_ref", "A05:2021-Security Misconfiguration"),
                        "remediation": intel.get("example", f"Add '{h_name}' to HTTP response headers."),
                        "deduction": ded
                    })
                    categories["headers"]["reasons"].append(f"[{sev}] [-{ded}] {h_name} header is missing.")
                    
                    if sev in ["High", "Medium"]:
                        categories["headers"]["recommendations"].append({
                            "title": f"Implement {h_name} Header",
                            "why_it_matters": intel.get("why_it_matters", ""),
                            "risk": intel.get("risk", ""),
                            "owasp_ref": intel.get("owasp_ref", ""),
                            "example": intel.get("example", ""),
                            "impact": intel.get("impact", "")
                        })
                    severity_summary[sev] += 1
                    
                elif status == "Report Only":
                    sev = "Low"
                    ded = 2
                    deductions += ded
                    categories["headers"]["findings"].append({
                        "header": h_name,
                        "severity": sev,
                        "confidence": "Verified",
                        "evidence": h_info.get("evidence", f"{h_name}-Report-Only: {h_info.get('value')}"),
                        "message": f"{h_name} is configured in Report-Only mode (intentional audit state).",
                        "why_it_matters": "Content-Security-Policy is configured in Report-Only mode. This represents an intentional audit/telemetry state to monitor potential policy violations before active enforcement.",
                        "owasp_ref": intel.get("owasp_ref", "A05:2021-Security Misconfiguration"),
                        "remediation": f"Audit policy reports and transition {h_name} to active enforcement when ready.",
                        "deduction": ded
                    })
                    categories["headers"]["reasons"].append(f"[{sev}] [-{ded}] {h_name} in Report-Only mode.")
                    severity_summary[sev] += 1

            categories["headers"]["score"] = max(0, 100 - deductions)
            score_h = categories["headers"]["score"]
            if score_h >= 90:
                categories["headers"]["status"] = "Passed"
            elif score_h >= 75:
                categories["headers"]["status"] = "Warning"
            elif score_h >= 50:
                categories["headers"]["status"] = "Needs Improvement"
            else:
                categories["headers"]["status"] = "Failed"

        # 4. Redirect Intelligence (20%)
        if dns_failed:
            categories["redirects"]["status"] = "Not Tested"
            categories["redirects"]["score"] = "N/A"
            categories["redirects"]["findings"].append({
                "severity": "Info",
                "confidence": "Verified",
                "evidence": "No network connection could be established.",
                "message": "Redirect analysis skipped because target domain failed DNS resolution (NXDOMAIN).",
                "why_it_matters": "Redirect inspection requires active DNS resolution.",
                "owasp_ref": "N/A",
                "remediation": "Fix DNS resolution first.",
                "deduction": 0
            })
            categories["redirects"]["reasons"].append("[Info] [-0] Redirect inspection skipped due to DNS resolution failure.")
        else:
            red_intel = data.get("redirect_intel", {})
            if red_intel:
                deduction = red_intel.get("deduction", 0)
                categories["redirects"]["score"] = max(0, 100 - deduction)
                clas = red_intel.get("classification", "Safe Canonical Redirect")
                sev = "Info"
                if clas == "Potential Typosquatting": sev = "High"
                elif clas == "External Domain Redirect": sev = "Medium"
                elif clas in ["DNS Failure", "DNS Resolution Failed (NXDOMAIN)"]: sev = "Info"
                elif "Loop" in clas: sev = "High"
                elif "Excessive" in clas: sev = "Medium"
                
                score_r = categories["redirects"]["score"]
                if score_r >= 90:
                    categories["redirects"]["status"] = "Passed"
                elif score_r >= 75:
                    categories["redirects"]["status"] = "Warning"
                elif score_r >= 50:
                    categories["redirects"]["status"] = "Needs Improvement"
                else:
                    categories["redirects"]["status"] = "Failed"
                    
                chain_urls = [h.get("url", "") for h in data.get("response_chain", [])]
                categories["redirects"]["findings"].append({
                    "title": f"Redirect Classification: {clas}",
                    "finding_type": "Redirect Intelligence",
                    "severity": sev,
                    "confidence": "Verified",
                    "evidence": f"Classification: {clas} | Chain: {' -> '.join(chain_urls)}",
                    "message": red_intel.get("rationale", ""),
                    "why_it_matters": "Redirect analysis ensures request traffic is not hijacked, spoofed, or routed to external malicious hosts.",
                    "owasp_ref": "A01:2021-Broken Access Control",
                    "remediation": "Audit domain redirects and ensure canonical URLs route strictly to authorized root origins.",
                    "deduction": deduction
                })
                severity_summary[sev] += 1

                # Check for intermediate HTTP redirect hops in response chain
                http_hops = []
                chain = data.get("response_chain", [])
                if len(chain) > 1:
                    for step in chain[:-1]:
                        u = step.get("url", "")
                        if u.lower().startswith("http://"):
                            http_hops.append(u)
                            
                if http_hops:
                    hop_deduction = 5
                    categories["redirects"]["findings"].append({
                        "title": "HTTP Redirect Hop Detected",
                        "finding_type": "Security Hardening Finding",
                        "severity": "Low",
                        "confidence": "Verified",
                        "evidence": f"Intermediate HTTP redirect hop(s): {', '.join(http_hops)}",
                        "message": "The redirect chain temporarily points to an HTTP endpoint before returning to HTTPS. Although the final destination is HTTPS and remains within the same registered domain, unnecessary HTTP redirect hops should be avoided.",
                        "why_it_matters": "Unencrypted intermediate HTTP redirect hops create a brief window where traffic could be intercepted or manipulated before upgrading to HTTPS.",
                        "owasp_ref": "A05:2021-Security Misconfiguration",
                        "remediation": "Configure web server redirects to point directly to the canonical HTTPS URL without passing through HTTP.",
                        "deduction": hop_deduction
                    })
                    categories["redirects"]["reasons"].append(f"[Low] [-{hop_deduction}] HTTP Redirect Hop Detected: Intermediate HTTP redirect hop observed.")
                    severity_summary["Low"] += 1
                    deduction += hop_deduction
                    categories["redirects"]["score"] = max(0, 100 - deduction)

        # 5. Cookie Security (10%)
        if dns_failed or ssl_failed or http_failed:
            categories["cookies"]["status"] = "Not Tested"
            categories["cookies"]["score"] = "N/A"
            categories["cookies"]["findings"].append({
                "severity": "Info",
                "confidence": "Verified",
                "evidence": "No network connection could be established.",
                "message": "Cookie analysis skipped because target domain failed DNS resolution or network connection.",
                "why_it_matters": "Cookie inspection requires an active HTTP response.",
                "owasp_ref": "N/A",
                "remediation": "Fix DNS resolution first.",
                "deduction": 0
            })
            categories["cookies"]["reasons"].append("[Info] [-0] Cookie inspection skipped due to network connectivity failure.")
        else:
            cookies = data.get("cookies", [])
            if not cookies:
                categories["cookies"]["reasons"].append("[Info] [+0] No Set-Cookie headers returned.")
                categories["cookies"]["findings"].append({
                    "severity": "Info",
                    "confidence": "Verified",
                    "evidence": "No Set-Cookie response headers observed.",
                    "message": "No cookies set by target endpoint.",
                    "why_it_matters": "Endpoint does not issue client session or tracking cookies.",
                    "owasp_ref": "A07:2021-Identification and Authentication Failures",
                    "remediation": "N/A",
                    "deduction": 0
                })
            else:
                cookie_deductions = 0
                for cookie in cookies:
                    c_name = cookie["name"]
                    is_sensitive = False
                    name_lower = c_name.lower()
                    if any(k in name_lower for k in ["session", "sid", "token", "auth", "login", "key", "pass", "csrf", "xsrf"]):
                        is_sensitive = True
                    if "id" in name_lower:
                        if any(x in name_lower for x in ["sessid", "sessionid", "userid", "memberid", "phpsessionid", "jsessionid", "aspsessionid", "secid"]):
                            is_sensitive = True
                        if name_lower in ["id", "_id", "id_"]:
                            is_sensitive = True
                            
                    if not cookie["http_only"]:
                        if is_sensitive:
                            cookie_deductions += 15
                            categories["cookies"]["findings"].append({
                                "severity": "Medium",
                                "confidence": "Verified",
                                "evidence": f"Set-Cookie: {c_name}=... (Missing HttpOnly)",
                                "message": f"Sensitive session cookie '{c_name}' lacks HttpOnly flag.",
                                "why_it_matters": "Without HttpOnly, client scripts can access cookie tokens via document.cookie, enabling XSS session theft.",
                                "owasp_ref": "A07:2021-Identification and Authentication Failures",
                                "remediation": "Append '; HttpOnly' to Set-Cookie header.",
                                "deduction": 15
                            })
                            severity_summary["Medium"] += 1
                            
                    if not cookie["secure"]:
                        if is_sensitive:
                            cookie_deductions += 15
                            categories["cookies"]["findings"].append({
                                "severity": "Medium",
                                "confidence": "Verified",
                                "evidence": f"Set-Cookie: {c_name}=... (Missing Secure)",
                                "message": f"Sensitive session cookie '{c_name}' lacks Secure flag over HTTPS.",
                                "why_it_matters": "Without Secure flag, browsers transmit cookies over unencrypted HTTP requests, enabling network sniffing.",
                                "owasp_ref": "A02:2021-Cryptographic Failures",
                                "remediation": "Append '; Secure' to Set-Cookie header.",
                                "deduction": 15
                            })
                            severity_summary["Medium"] += 1
                            
                    # SameSite attribute analysis - three distinct cases:
                    # Case 1: SameSite=None with Secure → Valid (no finding)
                    # Case 2: SameSite=None without Secure → High severity (explicit misconfiguration)
                    # Case 3: SameSite not specified → Low severity advisory (not a false "None")
                    if cookie.get("same_site_explicitly_set", False):
                        # The cookie explicitly sets SameSite
                        ss_val = cookie["same_site"].strip().lower()
                        if ss_val == "none" and not cookie["secure"]:
                            # Case 2: Explicit SameSite=None without Secure flag
                            cookie_deductions += 20
                            categories["cookies"]["findings"].append({
                                "severity": "High",
                                "confidence": "Verified",
                                "evidence": f"Set-Cookie: {c_name}=... (SameSite=None without Secure)",
                                "message": f"Cookie '{c_name}' explicitly sets SameSite=None without Secure flag.",
                                "why_it_matters": "Modern web browsers reject SameSite=None cookies unless the Secure attribute is also present.",
                                "owasp_ref": "A01:2021-Broken Access Control",
                                "remediation": "Append '; Secure' when setting SameSite=None.",
                                "deduction": 20
                            })
                            severity_summary["High"] += 1
                    else:
                        # Case 3: SameSite attribute is absent from the cookie entirely
                        cookie_deductions += 1
                        categories["cookies"]["findings"].append({
                            "severity": "Info",
                            "confidence": "Verified",
                            "evidence": f"Set-Cookie: {c_name}=... (no SameSite attribute present)",
                            "message": f"Cookie '{c_name}' does not specify a SameSite attribute.",
                            "why_it_matters": "Cookie does not specify SameSite attribute. Modern web browsers automatically default unflagged cookies to SameSite=Lax.",
                            "owasp_ref": "A01:2021-Broken Access Control",
                            "remediation": "Add 'SameSite=Lax' or 'SameSite=Strict' to the Set-Cookie header.",
                            "deduction": 1
                        })
                        severity_summary["Info"] += 1
                        
                categories["cookies"]["score"] = max(0, 100 - cookie_deductions)
                score_c = categories["cookies"]["score"]
                if score_c >= 90:
                    categories["cookies"]["status"] = "Passed"
                elif score_c >= 75:
                    categories["cookies"]["status"] = "Warning"
                elif score_c >= 50:
                    categories["cookies"]["status"] = "Needs Improvement"
                else:
                    categories["cookies"]["status"] = "Failed"

        # 6. Server Configuration (5%)
        if dns_failed or ssl_failed or http_failed:
            categories["server"]["status"] = "Not Tested"
            categories["server"]["score"] = "N/A"
            categories["server"]["findings"].append({
                "severity": "Info",
                "confidence": "Verified",
                "evidence": "No network connection could be established.",
                "message": "Server configuration inspection skipped because target domain failed DNS resolution or network connection.",
                "why_it_matters": "Server configuration inspection requires an active HTTP response.",
                "owasp_ref": "N/A",
                "remediation": "Fix DNS resolution first.",
                "deduction": 0
            })
            categories["server"]["reasons"].append("[Info] [-0] Server configuration inspection skipped due to network connectivity failure.")
        else:
            server_hdr = data.get("server", "Not disclosed")
            if server_hdr != "Not disclosed" and server_hdr != "N/A":
                if re.search(r'\d+\.\d+', server_hdr):
                    categories["server"]["score"] = 90
                    categories["server"]["status"] = "Warning"
                    categories["server"]["findings"].append({
                        "severity": "Low",
                        "confidence": "Verified",
                        "evidence": f"Server: {server_hdr}",
                        "message": f"Server signature header leaks software version information: {server_hdr}",
                        "why_it_matters": "Exposing software version numbers helps attackers identify target systems for version-specific CVE vulnerabilities.",
                        "owasp_ref": "A05:2021-Security Misconfiguration",
                        "remediation": "Hide server tokens (e.g. 'server_tokens off;' in Nginx).",
                        "deduction": 10
                    })
                    categories["server"]["reasons"].append("[Low] [-10] Server header leaks version numbers.")
                    severity_summary["Low"] += 1
                else:
                    categories["server"]["score"] = 95
                    categories["server"]["status"] = "Warning"
                    categories["server"]["findings"].append({
                        "severity": "Info",
                        "confidence": "Verified",
                        "evidence": f"Server: {server_hdr}",
                        "message": f"Server software identity revealed: {server_hdr}",
                        "why_it_matters": "Disclosing server software identity provides minor reconnaissance info to attackers.",
                        "owasp_ref": "A05:2021-Security Misconfiguration",
                        "remediation": "Remove Server header or genericize response.",
                        "deduction": 5
                    })
                    categories["server"]["reasons"].append("[Info] [-5] Server software identity exposed.")
                    severity_summary["Info"] += 1
            else:
                categories["server"]["reasons"].append("[Info] [+0] Server signature is hidden.")

        # Performance Observations (Decoupled - 0% impact on Security Score)
        performance_observations = {
            "response_time_ms": data.get("response_time_ms", 0.0),
            "dns_lookup": data.get("timings", {}).get("dns_lookup", 0.0),
            "tcp_connect": data.get("timings", {}).get("tcp_connect", 0.0),
            "tls_handshake": data.get("timings", {}).get("tls_handshake", 0.0),
            "ttfb": data.get("timings", {}).get("ttfb", 0.0),
            "download_time": data.get("timings", {}).get("download_time", 0.0),
            "total_scan_duration": data.get("timings", {}).get("total_time", data.get("response_time_ms", 0.0))
        }
        data["performance_observations"] = performance_observations

        # Scoring Aggregation (100% Security Only)
        weights = {
            "headers": 0.25,
            "ssl": 0.25,
            "redirects": 0.20,
            "dns": 0.15,
            "cookies": 0.10,
            "server": 0.05
        }
        
        evaluated_weight = 0.0
        weighted_sum = 0.0
        
        for cat_key, cat in categories.items():
            if cat_key not in weights:
                continue  # Skip non-scored categories (e.g. performance)
            if cat["score"] != "N/A":
                weighted_sum += cat["score"] * weights[cat_key]
                evaluated_weight += weights[cat_key]
                
        if dns_failed:
            overall = "N/A"
            grade = "N/A"
            threat_level = "Unreachable"
        else:
            from app.scanners.engine import calculate_authoritative_score
            overall, grade, scoring_breakdown = calculate_authoritative_score(categories, weights)
            if overall >= 95:
                threat_level = "Low"
            elif overall >= 80:
                threat_level = "Medium"
            elif overall >= 60:
                threat_level = "High"
            else:
                threat_level = "Critical"
            
        if dns_failed:
            highest_severity = "Unreachable"
        elif severity_summary.get("Critical", 0) > 0:
            highest_severity = "Critical"
        elif severity_summary.get("High", 0) > 0:
            highest_severity = "High"
        elif severity_summary.get("Medium", 0) > 0:
            highest_severity = "Medium"
        elif severity_summary.get("Low", 0) > 0:
            highest_severity = "Low"
        else:
            highest_severity = "None"

        scoring_breakdown = []
        for cat_key, cat_name in [("headers", "HTTP Security Headers"),
                                  ("ssl", "SSL/TLS Security"), 
                                  ("redirects", "Redirect Intelligence"),
                                  ("dns", "DNS Health"), 
                                  ("cookies", "Cookie Security"),
                                  ("server", "Server Configuration")]:
            score_val = categories[cat_key]["score"]
            weight_val = weights[cat_key]
            if score_val != "N/A":
                contribution = score_val * weight_val / evaluated_weight
                scoring_breakdown.append(f"{cat_name}: {score_val} ({int(weight_val*100)}% weight, contribution: {contribution:.2f})")
            else:
                scoring_breakdown.append(f"{cat_name}: Not Tested (Excluded from calculation)")
                
        return categories, overall, grade, threat_level, severity_summary, scoring_breakdown, highest_severity

    def _determine_verdict(self, highest_severity: str, overall_score, dns_failed: bool) -> dict:
        if dns_failed or overall_score == "N/A":
            return {
                "verdict": "⚪ Host Unreachable / DNS Resolution Failed",
                "highest_severity": "Unreachable",
                "badge": "secondary",
                "icon": "⚪",
                "description": "Analysis could not be completed because the domain does not resolve (NXDOMAIN). HTTP, TLS, Header, Cookie, and Server analysis were skipped."
            }
            
        if highest_severity == "Critical":
            return {
                "verdict": "🔴 Critical Security Risk",
                "highest_severity": "Critical",
                "badge": "danger",
                "icon": "🔴",
                "description": "Critical security issues were identified that may expose users or infrastructure to significant risk. Immediate remediation is recommended."
            }
        elif highest_severity == "High":
            return {
                "verdict": "🟠 High-Priority Security Improvements Recommended",
                "highest_severity": "High",
                "badge": "warning",
                "icon": "🟠",
                "description": "Important security controls are missing or misconfigured. Remediation is recommended to improve the website's security baseline."
            }
        elif highest_severity == "Medium":
            return {
                "verdict": "🟡 Security Improvements Recommended",
                "highest_severity": "Medium",
                "badge": "warning",
                "icon": "🟡",
                "description": "Multiple security weaknesses or configuration recommendations were detected that should be addressed to improve resilience against common web attacks."
            }
        elif highest_severity == "Low":
            return {
                "verdict": "🔵 Minor Security Hardening Recommended",
                "highest_severity": "Low",
                "badge": "info",
                "icon": "🔵",
                "description": "The website is securely configured overall. A few optional hardening recommendations exist to further strengthen client defenses."
            }
        else:
            return {
                "verdict": "🟢 Website Appears Well Secured",
                "highest_severity": "None",
                "badge": "success",
                "icon": "🟢",
                "description": "Security configuration appears strong based on the checks performed. No high or critical security weaknesses were identified by CyberOptimus's current checks."
            }

    def _analyze_html_content(self, html_text: str, target_url: str) -> dict:
        res = {
            "has_login_form": False,
            "has_external_form_action": False,
            "has_insecure_form_action": False,
            "has_hidden_login_form": False,
            "external_form_actions": [],
            "iframes": [],
            "external_scripts": [],
            "mixed_content_resources": [],
            "third_party_domains": [],
            "meta_title": None,
            "meta_description": None
        }
        if not html_text:
            return res

        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html_text, 'html.parser')
        except Exception:
            return res

        parsed_target = urlparse(target_url)
        target_host = parsed_target.netloc.lower()
        target_scheme = parsed_target.scheme.lower()
        third_party_domains = set()
        if soup:
            title_tag = soup.find('title')
            if title_tag and title_tag.string:
                res["meta_title"] = title_tag.string.strip()

            meta_desc = soup.find('meta', attrs={'name': re.compile(r'description', re.I)})
            if meta_desc and meta_desc.get('content'):
                res["meta_description"] = meta_desc['content'].strip()

            meta_security_headers = {}
            meta_ref = soup.find('meta', attrs={'name': re.compile(r'^(referrer|referrer-policy)$', re.I)})
            if meta_ref and meta_ref.get('content'):
                meta_security_headers["referrer-policy"] = meta_ref['content'].strip()

            meta_csp = soup.find('meta', attrs={'http-equiv': re.compile(r'^Content-Security-Policy$', re.I)})
            if meta_csp and meta_csp.get('content'):
                meta_security_headers["content-security-policy"] = meta_csp['content'].strip()

            res["meta_security_headers"] = meta_security_headers

            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '').strip()
                inputs = form.find_all('input')
                has_pwd = any(i.get('type', '').lower() == 'password' or 'pass' in i.get('name', '').lower() for i in inputs)
                
                style = form.get('style', '').lower()
                is_hidden = ('display:none' in style or 'display: none' in style or 'visibility:hidden' in style)
                
                if has_pwd:
                    res["has_login_form"] = True
                    if is_hidden:
                        res["has_hidden_login_form"] = True

                if action:
                    if action.startswith('http://') or action.startswith('https://'):
                        action_host = urlparse(action).netloc.lower()
                        action_scheme = urlparse(action).scheme.lower()
                        if action_host and extract_registered_domain(action_host) != extract_registered_domain(target_host):
                            res["has_external_form_action"] = True
                            res["external_form_actions"].append(action)
                        if action_scheme == 'http' and target_scheme == 'https':
                            res["has_insecure_form_action"] = True

            iframes = soup.find_all('iframe')
            for iframe in iframes:
                src = iframe.get('src', '')
                if src:
                    res["iframes"].append(src)
                    src_host = urlparse(src).netloc.lower()
                    if src_host and extract_registered_domain(src_host) != extract_registered_domain(target_host):
                        third_party_domains.add(src_host)

            scripts = soup.find_all('script')
            for script in scripts:
                src = script.get('src', '')
                if src:
                    src_host = urlparse(src).netloc.lower()
                    if src_host and extract_registered_domain(src_host) != extract_registered_domain(target_host):
                        res["external_scripts"].append(src)
                        third_party_domains.add(src_host)
                    if target_scheme == 'https' and src.startswith('http://'):
                        res["mixed_content_resources"].append(src)

        res["third_party_domains"] = list(third_party_domains)
        return res

    def _calculate_confidence(self, result_data: dict, dns_failed: bool, http_failed: bool) -> dict:
        total_checks = 10
        successful_checks = 0
        unavailable_checks = []
        limitations = []

        if not dns_failed:
            successful_checks += 2
        else:
            unavailable_checks.append("DNS Resolution")
            limitations.append("Target domain failed DNS resolution (NXDOMAIN). Network inspection skipped.")

        if not dns_failed and not http_failed:
            successful_checks += 2
            st = result_data.get("status_code")
            if st in [403, 406, 429]:
                limitations.append(f"Server returned HTTP status {st}. Automated crawling or responses may be rate-limited or restricted.")
            elif isinstance(st, int) and st >= 500:
                limitations.append(f"Server returned HTTP status {st} (Server Error).")
        else:
            unavailable_checks.append("HTTP Response Inspection")

        ssl_info = result_data.get("ssl", {})
        if ssl_info and ssl_info.get("tls_version") != "N/A":
            successful_checks += 2
        else:
            unavailable_checks.append("SSL/TLS Handshake")

        headers = result_data.get("security_headers", {})
        if headers and any(h.get("status") in ["Present", "Missing", "Report Only"] for h in headers.values()):
            successful_checks += 2
        else:
            unavailable_checks.append("HTTP Security Headers")

        dns_recon = result_data.get("dns_records", {})
        if dns_recon and not dns_recon.get("error"):
            successful_checks += 1
        else:
            unavailable_checks.append("DNS/DMARC Record Lookup")

        html_recon = result_data.get("html_recon", {})
        if html_recon:
            successful_checks += 1
        else:
            unavailable_checks.append("HTML Content Inspection")

        score_pct = int((successful_checks / total_checks) * 100)
        rating = "High" if score_pct >= 80 else ("Medium" if score_pct >= 50 else "Low")

        return {
            "score_percent": score_pct,
            "rating": rating,
            "successful_checks": successful_checks,
            "total_checks": total_checks,
            "unavailable_checks": unavailable_checks,
            "limitations": limitations
        }

    def _generate_score_explanation(self, overall, categories: dict, severity_summary: dict = None) -> str:
        if overall == "N/A":
            return "Analysis could not be completed because the domain does not resolve (NXDOMAIN). HTTP, TLS, Header, Cookie, and Server analysis were skipped."
            
        if severity_summary is None:
            severity_summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
            
        crit_count = severity_summary.get("Critical", 0)
        high_count = severity_summary.get("High", 0)
        med_count = severity_summary.get("Medium", 0)
        
        explanations = []
        if crit_count > 0 or (isinstance(overall, (int, float)) and overall < 50):
            explanations.append("Critical Security Issues Detected: Immediate remediation is recommended to protect users and infrastructure from severe exploitation risks.")
        elif high_count > 0:
            explanations.append("High-Priority Security Improvements Recommended: Important security controls are missing or misconfigured, requiring attention to meet baseline security standards.")
        elif med_count > 0 or (isinstance(overall, (int, float)) and overall < 80):
            explanations.append("Security Improvements Recommended: The website is operational overall, but several hardening policies should be implemented to strengthen browser and transport protections.")
        else:
            explanations.append("Website Appears Well Secured: The website demonstrates a strong enterprise security posture. No high or critical security weaknesses were identified.")
            
        critical_details = []
        high_details = []
        for cat_name, cat in categories.items():
            for f in cat.get("findings", []):
                if f.get("severity") == "Critical":
                    critical_details.append(f"{f.get('title', cat_name.upper())}: {f['message']}")
                elif f.get("severity") == "High":
                    high_details.append(f"{f.get('title', cat_name.upper())}: {f['message']}")
                    
        if critical_details:
            explanations.append(f"Critical findings: {'; '.join(critical_details)}.")
        elif high_details:
            explanations.append(f"High-priority findings: {'; '.join(high_details)}.")
            
        return " ".join(explanations)
