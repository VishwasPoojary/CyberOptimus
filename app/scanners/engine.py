import time
from urllib.parse import urlparse
from typing import Dict, Any, List
from app.scanners.config import ScanConfig
from app.scanners.base_module import BaseModule
from app.scanners.modules import (
    DNSModule, HeaderModule, SSLModule, CookieModule, TyposquattingModule
)
from app.utils.network import normalize_input_url, fetch_url, fetch_html_content, measure_network_timings, has_ipv6
from app.utils.domain_intelligence import extract_registered_domain

def calculate_authoritative_score(categories: dict, weights: dict = None) -> tuple:
    """
    Authoritative weighted score calculation function for CyberOptimus.
    Default Category Weights:
        Headers: 25% (0.25)
        SSL/TLS: 25% (0.25)
        Redirects: 20% (0.20)
        DNS: 15% (0.15)
        Cookies: 10% (0.10)
        Server: 5% (0.05)
    Returns: (final_score, grade, scoring_breakdown_list)
    """
    if weights is None:
        weights = {
            "headers": 0.25,
            "ssl": 0.25,
            "redirects": 0.20,
            "dns": 0.15,
            "cookies": 0.10,
            "server": 0.05
        }

    weighted_score = 0.0
    total_weight = 0.0
    scoring_breakdown = []

    for cat_key, w in weights.items():
        cat = categories.get(cat_key, {})
        score_val = cat.get("score") if isinstance(cat, dict) else None
        if isinstance(score_val, (int, float)):
            contrib = score_val * w
            weighted_score += contrib
            total_weight += w
            scoring_breakdown.append(f"{cat_key.upper()} (Weight {int(w*100)}%): Category Score {score_val}/100 -> +{contrib:.2f} pts")
        else:
            scoring_breakdown.append(f"{cat_key.upper()} (Weight {int(w*100)}%): Not Tested / Excluded")

    if total_weight > 0:
        raw_weighted = weighted_score / total_weight
        final_score = int(round(raw_weighted + 1e-9))
        final_score = max(0, min(100, final_score))
    else:
        final_score = 0

    if final_score >= 95:
        grade = "A+"
    elif final_score >= 90:
        grade = "A"
    elif final_score >= 80:
        grade = "B"
    elif final_score >= 70:
        grade = "C"
    elif final_score >= 60:
        grade = "D"
    else:
        grade = "F"

    scoring_breakdown.append(f"Overall Weighted Score: {final_score}/100 (Grade {grade})")
    return final_score, grade, scoring_breakdown

class ScannerEngine:
    """
    Modular execution engine for Website Security Reconnaissance.
    Dynamically constructs pipeline based on ScanConfig and orchestrates modules.
    Handles early short-circuiting for unreachable domains (NXDOMAIN).
    """

    def __init__(self, config: ScanConfig = None):
        self.config = config or ScanConfig()

    def build_pipeline(self, context: Dict[str, Any]) -> List[BaseModule]:
        pipeline: List[BaseModule] = []

        if self.config.check_dns:
            pipeline.append(DNSModule())

        # Always run TyposquattingModule so domain similarity works even when NXDOMAIN
        if self.config.check_typosquatting:
            pipeline.append(TyposquattingModule())

        # Network-dependent modules added to pipeline
        if self.config.check_headers:
            pipeline.append(HeaderModule())

        if self.config.check_ssl:
            pipeline.append(SSLModule())

        if self.config.check_cookies:
            pipeline.append(CookieModule())

        return pipeline

    def execute(self, target_url_input: str) -> Dict[str, Any]:
        start_scan_time = time.time()

        # 1. URL Normalization
        canonical_url = normalize_input_url(target_url_input)
        parsed_initial = urlparse(canonical_url)
        initial_domain = parsed_initial.netloc.split(':')[0].lower()

        context: Dict[str, Any] = {
            "target": target_url_input,
            "original_url": target_url_input,
            "canonical_url": canonical_url,
            "initial_domain": initial_domain,
            "url": canonical_url,
            "domain": initial_domain,
            "resolved_hostname": initial_domain,
            "unreachable": False,
            "dns_failed": False,
            "response": None,
            "merged_headers": {},
            "cookies_list": [],
            "response_chain": [],
            "final_url": canonical_url,
            "final_host": initial_domain,
            "categories": {}
        }

        # 2. DNS Reconnaissance First
        dns_mod = DNSModule()
        dns_res = dns_mod.run(context, self.config)
        context.update(dns_res)

        # Build execution pipeline
        pipeline = self.build_pipeline(context)

        # If DNS Succeeded, fetch network data before executing network modules
        if not context.get("unreachable"):
            start_req_time = time.time()
            response, error = fetch_url(canonical_url)
            end_req_time = time.time()
            response_time_ms = round((end_req_time - start_req_time) * 1000, 2)
            context["response"] = response
            context["response_time_ms"] = response_time_ms

            if response is not None:
                context["status_code"] = response.status_code
                context["final_url"] = response.url
                parsed_final = urlparse(response.url)
                context["final_host"] = parsed_final.netloc.split(':')[0].lower()
                context["server"] = response.headers.get("Server", "N/A")

                # Build redirect response chain and separate final response headers
                merged_headers = {}
                final_headers = {k.lower(): v for k, v in response.headers.items()}
                response_chain = []
                cookies_dict = {}

                for r in response.history:
                    r_host = urlparse(r.url).netloc.split(':')[0].lower()
                    response_chain.append({
                        "status_code": r.status_code,
                        "url": r.url,
                        "domain": r_host,
                        "headers": dict(r.headers)
                    })
                    merged_headers.update({k.lower(): v for k, v in r.headers.items()})

                response_chain.append({
                    "status_code": response.status_code,
                    "url": response.url,
                    "domain": context["final_host"],
                    "headers": dict(response.headers)
                })
                merged_headers.update({k.lower(): v for k, v in response.headers.items()})
                context["final_headers"] = final_headers
                context["raw_headers"] = dict(response.headers)
                context["merged_headers"] = merged_headers
                context["response_chain"] = response_chain

                # Cookies
                for c in response.cookies:
                    cookies_dict[c.name] = {
                        "name": c.name, "value": c.value, "domain": c.domain,
                        "path": c.path, "secure": c.secure, "http_only": c.has_nonstandard_attr('HttpOnly'),
                        "same_site": c.get_nonstandard_attr('SameSite')
                    }
                context["cookies_list"] = list(cookies_dict.values())

                # HTML Inspection if toggle enabled
                if self.config.parse_html_meta:
                    h_text, _, _ = fetch_html_content(canonical_url)
                    from app.scanners.website_scanner import WebsiteScanner
                    ws_temp = WebsiteScanner()
                    context["html_recon"] = ws_temp._analyze_html_content(h_text or "", canonical_url)

                # Performance timings
                if self.config.measure_performance:
                    timings = measure_network_timings(canonical_url)
                    if timings.get("total_time", 0) == 0:
                        timings["total_time"] = response_time_ms
                    context["performance_observations"] = timings

                context["ipv6_supported"] = has_ipv6(initial_domain)

        # 3. Execute Pipeline Modules
        categories: Dict[str, Any] = {}
        if "category_dns" in context:
            categories["dns"] = context["category_dns"]

        for module in pipeline:
            if isinstance(module, DNSModule):
                continue  # Already executed

            # Early Short-Circuiting: Skip network-dependent modules if target unreachable
            if context.get("unreachable") and isinstance(module, (HeaderModule, SSLModule, CookieModule)):
                continue

            res = module.run(context, self.config)
            context.update(res)

            if "category_headers" in res:
                categories["headers"] = res["category_headers"]
            if "category_ssl" in res:
                categories["ssl"] = res["category_ssl"]
            if "category_cookies" in res:
                categories["cookies"] = res["category_cookies"]
            if "category_redirects" in res:
                categories["redirects"] = res["category_redirects"]

        # Server Category
        if context.get("unreachable"):
            categories["server"] = {
                "score": "N/A", "status": "Not Tested", "weight": 0.05,
                "findings": [], "reasons": ["Server analysis skipped because target domain is unreachable."]
            }
        else:
            categories["server"] = {
                "score": 100, "status": "Passed", "weight": 0.05,
                "findings": [], "reasons": []
            }

        for cat_key in ["headers", "ssl", "redirects", "cookies"]:
            if cat_key not in categories:
                categories[cat_key] = {
                    "score": "N/A", "status": "Not Tested", "weight": 0.20,
                    "findings": [], "reasons": ["Category skipped via config or unreachable target."]
                }

        # 4. Overall Weighted Score Calculation
        if context.get("unreachable"):
            risk_score = 0
            grade = "F"
            threat_level = "Critical"
            highest_severity = "Critical"
            overall_verdict = "⚠️ Target Unreachable (NXDOMAIN)"
            score_explanation = "Analysis could not be completed because the domain does not resolve (NXDOMAIN)."
            scoring_breakdown = ["Target Unreachable - Category evaluation skipped."]
        else:
            severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
            for cat in categories.values():
                if isinstance(cat, dict):
                    for f in cat.get("findings", []):
                        s = f.get("severity", "Info")
                        if s in severity_counts:
                            severity_counts[s] += 1

            risk_score, grade, scoring_breakdown = calculate_authoritative_score(categories)

            if severity_counts["Critical"] > 0:
                highest_severity = "Critical"
                threat_level = "Critical"
                overall_verdict = "🛑 Critical Security Issues Detected"
                score_explanation = "Critical security vulnerabilities were identified. Immediate remediation is required."
            elif severity_counts["High"] > 0:
                highest_severity = "High"
                threat_level = "High"
                overall_verdict = "🟠 High-Priority Security Improvements Recommended"
                score_explanation = "High-severity findings exist. Remediation is recommended to strengthen posture."
            elif severity_counts["Medium"] > 0:
                highest_severity = "Medium"
                threat_level = "Medium"
                overall_verdict = "🟡 Security Improvements Recommended"
                score_explanation = "Security hardening recommendations exist to strengthen web posture."
            elif severity_counts["Low"] > 0:
                highest_severity = "Low"
                threat_level = "Low"
                overall_verdict = "🔵 Minor Security Hardening Recommended"
                score_explanation = "Security hardening recommendations remain. The website is securely configured overall."
            else:
                highest_severity = "None"
                threat_level = "None"
                overall_verdict = "🟢 Website Appears Well Secured"
                score_explanation = "🎉 No vulnerabilities or compliance findings detected. All systems operating with standard baseline settings."

        scan_duration_ms = round((time.time() - start_scan_time) * 1000, 2)
        ssl_data = context.get("ssl_info") or {
            "valid": False, "issuer": "N/A", "expiration": "N/A", "tls_version": "N/A",
            "subject": "N/A", "days_remaining": "N/A", "san": [], "cipher_suite": "N/A",
            "ocsp_stapled": False, "sct_present": False, "error": "Not checked or unreachable"
        }

        sec_headers = context.get("security_headers", {})
        header_summary = {
            "checked": len(sec_headers),
            "present": sum(1 for h in sec_headers.values() if h.get("status") in ["Present", "Present (via HTML Meta)"]),
            "report_only": sum(1 for h in sec_headers.values() if h.get("status") == "Report Only"),
            "missing": sum(1 for h_info in sec_headers.values() if h_info.get("status") == "Missing"),
            "not_tested": sum(1 for h_info in sec_headers.values() if h_info.get("status") in ["Not Tested", "Not Evaluated"])
        }

        timings_data = context.get("performance_observations") or {
            "dns_lookup": 0.0, "tcp_connect": 0.0, "tls_handshake": 0.0,
            "ttfb": 0.0, "download_time": 0.0, "total_time": 0.0
        }
        if "tcp_connect" not in timings_data:
            timings_data["tcp_connect"] = 0.0
        if "dns_lookup" not in timings_data:
            timings_data["dns_lookup"] = 0.0
        if "tls_handshake" not in timings_data:
            timings_data["tls_handshake"] = 0.0
        if "ttfb" not in timings_data:
            timings_data["ttfb"] = 0.0
        if "download_time" not in timings_data:
            timings_data["download_time"] = 0.0
        if "total_time" not in timings_data:
            timings_data["total_time"] = 0.0

        return {
            "status": "success",
            "url": canonical_url,
            "domain": initial_domain,
            "original_url": target_url_input,
            "canonical_url": canonical_url,
            "resolved_hostname": initial_domain,
            "ip_address": context.get("ip_address", "Unable to resolve IP"),
            "final_url": context.get("final_url", canonical_url),
            "final_host": context.get("final_host", initial_domain),
            "unreachable": context.get("unreachable", False),
            "dns_failed": context.get("dns_failed", False),
            "status_code": context.get("status_code", "Unreachable"),
            "server": context.get("server", "N/A"),
            "https": "Enabled" if context.get("final_url", "").startswith("https://") else "Not enabled",
            "cdn_provider": context.get("cdn_provider", "Direct / Unknown"),
            "http_protocol": context.get("http_protocol", "N/A"),
            "compression_used": context.get("compression_used", False),
            "content_encoding": context.get("content_encoding", "N/A"),
            "risk_score": risk_score,
            "overall_score": risk_score,
            "grade": grade,
            "threat_level": threat_level,
            "highest_severity": highest_severity,
            "overall_verdict": overall_verdict,
            "score_explanation": score_explanation,
            "scoring_breakdown": scoring_breakdown if not context.get("unreachable") else ["Unreachable target - Category evaluation skipped."],
            "response_time_ms": context.get("response_time_ms", scan_duration_ms),
            "scan_date": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "categories": categories,
            "dns_records": context.get("dns_records", {}),
            "rdap_info": context.get("rdap_info", {}),
            "redirect_intel": context.get("redirect_intel", {}),
            "host_redirect_warning": context.get("host_redirect_warning"),
            "security_headers": sec_headers,
            "header_summary": header_summary,
            "raw_headers": context.get("merged_headers", {}),
            "ssl": ssl_data,
            "ssl_info": ssl_data,
            "cookies": context.get("cookies_list", []),
            "cookies_list": context.get("cookies_list", []),
            "timings": timings_data,
            "performance": categories.get("performance", {}),
            "performance_observations": timings_data,
            "ipv6_supported": context.get("ipv6_supported", False)
        }
