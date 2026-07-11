import time
from urllib.parse import urlparse
import re
from app.scanners.base_scanner import BaseScanner
from app.utils.network import resolve_ip, fetch_url, check_ssl_certificate

HEADER_EXPLANATIONS = {
    "Strict-Transport-Security": "Strict-Transport-Security was not observed in this response. HSTS reduces protocol downgrade and Man-in-the-Middle (MITM) risks, but its absence in this single response does not conclusively prove the entire domain lacks HSTS enforcement.",
    "Content-Security-Policy": "Mitigates Cross-Site Scripting (XSS) and data injection vulnerabilities.",
    "X-Frame-Options": "Protects against clickjacking attacks by controlling frame embedding.",
    "X-Content-Type-Options": "Prevents MIME-type sniffing, enforcing strict content-type matching.",
    "Referrer-Policy": "Controls how much referrer info is shared when navigating away.",
    "Permissions-Policy": "Restricts browser features and APIs (e.g. camera, geolocation) that the site can use.",
    "Cross-Origin-Opener-Policy": "Isolates the document's execution context from other origin documents.",
    "Cross-Origin-Resource-Policy": "Restricts which origins can load resource files (images, scripts)."
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
        "secure": False,
        "http_only": False,
        "same_site": "None",
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
        else:
            k = part.strip().lower()
            if k == "secure":
                cookie_info["secure"] = True
            elif k == "httponly":
                cookie_info["http_only"] = True
                
    return cookie_info

class WebsiteScanner(BaseScanner):
    def scan(self, target: str) -> dict:
        # Try HTTPS if protocol is not specified
        if not target.startswith("http://") and not target.startswith("https://"):
            target = "https://" + target
            
        try:
            # Stage 1: HTTP Request & Timing (Follow Redirects)
            start_time = time.time()
            response, error = fetch_url(target)
            end_time = time.time()
            
            response_chain = []
            compression_used = False
            content_encoding = "N/A"
            cookies_list = []
            
            if response is not None:
                final_url = response.url
                status_code = response.status_code
                server = response.headers.get("Server", "Not disclosed")
                raw_headers = dict(response.headers)
                response_time = round((end_time - start_time) * 1000, 2)
                
                # Check response compression (Informational finding)
                content_encoding = raw_headers.get("content-encoding", raw_headers.get("Content-Encoding", "")).lower()
                if content_encoding and content_encoding != "none":
                    compression_used = any(c in content_encoding for c in ["gzip", "deflate", "br", "zstd"])
                
                # Parse Cookies
                raw_set_cookies = []
                if hasattr(response, 'raw') and hasattr(response.raw, 'headers'):
                    raw_set_cookies = response.raw.headers.getlist('Set-Cookie') or response.raw.headers.getlist('set-cookie')
                
                if not raw_set_cookies:
                    for k, v in response.headers.items():
                        if k.lower() == 'set-cookie':
                            raw_set_cookies.extend(split_set_cookie_header(v))
                            
                for val in raw_set_cookies:
                    parsed = parse_set_cookie_header(val)
                    if parsed:
                        cookies_list.append(parsed)
                
                # Build Response Chain
                for hist in response.history:
                    response_chain.append({
                        "url": hist.url,
                        "status_code": hist.status_code
                    })
                response_chain.append({
                    "url": response.url,
                    "status_code": response.status_code
                })
            else:
                final_url = target
                status_code = "Unreachable"
                server = "N/A"
                raw_headers = {}
                response_time = 0
                response_chain = [{"url": target, "status_code": "Unreachable"}]

            # Stage 2: URL Normalization of Final URL
            parsed_final = urlparse(final_url)
            final_domain = parsed_final.netloc
            if ':' in final_domain:
                final_domain = final_domain.split(':')[0]

            # Stage 3: DNS Resolution of Final Domain
            ip_address = resolve_ip(final_domain)
            dns_failed = (ip_address == "Unable to resolve IP")

            # Stage 4: TLS Inspection of Final Domain
            ssl_info = {"valid": False, "issuer": "N/A", "expiration": "N/A", "tls_version": "N/A", "subject": "N/A", "days_remaining": "N/A", "san": [], "error": "Not checked"}
            ssl_failed = False
            if final_url.startswith("https://"):
                ssl_info = check_ssl_certificate(final_domain)
                ssl_failed = not ssl_info.get("valid")

            # Stage 5: Security Headers Analysis (Final Response)
            headers_available = (response is not None) and (not dns_failed) and (not ssl_failed)
            security_headers = self._check_security_headers(raw_headers, available=headers_available)

            # Headers summary calculation
            h_checked = len(security_headers)
            h_present = sum(1 for h_info in security_headers.values() if h_info["status"] == "Present")
            h_report_only = sum(1 for h_info in security_headers.values() if h_info["status"] == "Report Only")
            h_missing = sum(1 for h_info in security_headers.values() if h_info["status"] == "Missing")
            h_not_tested = sum(1 for h_info in security_headers.values() if h_info["status"] in ["Not Tested", "Not Evaluated"])
            
            header_summary = {
                "checked": h_checked,
                "present": h_present,
                "report_only": h_report_only,
                "missing": h_missing,
                "not_tested": h_not_tested
            }

            result_data = {
                "url": target,
                "final_url": final_url,
                "domain": final_domain,
                "ip_address": ip_address,
                "status_code": status_code,
                "server": server,
                "response_time_ms": response_time,
                "https": "Enabled" if final_url.startswith("https://") else "Not enabled",
                "ssl": ssl_info,
                "security_headers": security_headers,
                "header_summary": header_summary,
                "raw_headers": raw_headers,
                "response_chain": response_chain,
                "compression_used": compression_used,
                "content_encoding": content_encoding,
                "cookies": cookies_list,
                "status": "success"
            }
            
            # Stage 6: Scoring
            categories, risk_score, grade, threat_level, severity_summary, scoring_breakdown = self._evaluate_categories(
                result_data, dns_failed, ssl_failed
            )
            result_data["categories"] = categories
            result_data["risk_score"] = risk_score
            result_data["grade"] = grade
            result_data["threat_level"] = threat_level
            result_data["severity_summary"] = severity_summary
            result_data["scoring_breakdown"] = scoring_breakdown
            result_data["score_explanation"] = self._generate_score_explanation(risk_score, categories)
            
            return result_data
            
        except Exception as e:
            return {
                "url": target,
                "status": "error",
                "message": str(e)
            }
            
    def _check_security_headers(self, headers: dict, available: bool) -> dict:
        target_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
            "Cross-Origin-Opener-Policy",
            "Cross-Origin-Resource-Policy"
        ]
        
        result = {}
        if not available:
            for h in target_headers:
                result[h] = {
                    "status": "Not Tested",
                    "value": None,
                    "reason": "Response headers could not be retrieved because the website connection could not be established."
                }
            return result
            
        lower_headers = {k.lower(): v for k, v in headers.items()}
        
        csp_val = lower_headers.get("content-security-policy", "")
        has_frame_ancestors = "frame-ancestors" in csp_val.lower()
        
        for h in target_headers:
            if h == "Content-Security-Policy":
                val = lower_headers.get("content-security-policy")
                if val is not None:
                    result[h] = {"status": "Present", "value": val, "reason": None}
                else:
                    report_only_val = lower_headers.get("content-security-policy-report-only")
                    if report_only_val is not None:
                        result[h] = {
                            "status": "Report Only",
                            "value": report_only_val,
                            "reason": "A CSP exists in report-only mode. Violations are reported but not enforced by the browser."
                        }
                    else:
                        result[h] = {
                            "status": "Missing",
                            "value": None,
                            "reason": "No Content Security Policy is enforced. This may increase exposure to XSS and data injection attacks."
                        }
            elif h == "Strict-Transport-Security":
                val = lower_headers.get("strict-transport-security")
                if val is not None:
                    result[h] = {"status": "Present", "value": val, "reason": None}
                else:
                    result[h] = {
                        "status": "Not Observed",
                        "value": None,
                        "reason": HEADER_EXPLANATIONS[h]
                    }
            elif h == "X-Frame-Options":
                val = lower_headers.get(h.lower())
                if val is not None:
                    result[h] = {"status": "Present", "value": val, "reason": None}
                elif has_frame_ancestors:
                    result[h] = {
                        "status": "Present",
                        "value": "Protected via CSP frame-ancestors directive",
                        "reason": "Clickjacking protection is enforced via Content-Security-Policy frame-ancestors."
                    }
                else:
                    result[h] = {"status": "Missing", "value": None, "reason": HEADER_EXPLANATIONS[h]}
            else:
                val = lower_headers.get(h.lower())
                if val is not None:
                    result[h] = {"status": "Present", "value": val, "reason": None}
                else:
                    result[h] = {"status": "Missing", "value": None, "reason": HEADER_EXPLANATIONS[h]}
        return result
        
    def _evaluate_categories(self, data: dict, dns_failed: bool, ssl_failed: bool) -> tuple[dict, int, str, str, dict, list]:
        categories = {
            "dns": {"score": 100, "status": "Passed", "reasons": [], "findings": [], "recommendations": []},
            "ssl": {"score": 100, "status": "Passed", "reasons": [], "findings": [], "recommendations": []},
            "headers": {"score": 100, "status": "Passed", "reasons": [], "findings": [], "recommendations": []},
            "server": {"score": 100, "status": "Passed", "reasons": [], "findings": [], "recommendations": []},
            "performance": {"score": 100, "status": "Passed", "reasons": [], "findings": [], "recommendations": []}
        }
        
        severity_summary = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Info": 0
        }
        
        # 1. DNS Health (Weight: 15%)
        if dns_failed:
            categories["dns"]["score"] = 0
            categories["dns"]["status"] = "Failed"
            categories["dns"]["findings"].append({
                "severity": "Critical",
                "message": "Domain does not resolve to an IP address.",
                "deduction": 100
            })
            categories["dns"]["reasons"].append("[Critical] [-100] Domain does not resolve to an IP address.")
            categories["dns"]["recommendations"].append("Verify the domain name or check DNS configurations.")
            severity_summary["Critical"] += 1
        else:
            categories["dns"]["reasons"].append("[Info] [+0] DNS lookup completed successfully.")
            categories["dns"]["recommendations"].append("Maintain current configuration.")
            
        # 2. SSL/TLS Security (Weight: 30%)
        if dns_failed:
            categories["ssl"]["status"] = "Not Tested"
            categories["ssl"]["score"] = "N/A"
            categories["ssl"]["findings"].append({
                "severity": "Info",
                "message": "Analysis could not be completed because the previous network stage failed.",
                "deduction": 0
            })
            categories["ssl"]["reasons"].append("[Info] [-0] Analysis could not be completed because the previous network stage failed.")
            categories["ssl"]["recommendations"].append("Resolve DNS configuration issues first.")
        else:
            if data["https"] != "Enabled":
                ssl_failed = True
                categories["ssl"]["score"] = 0
                categories["ssl"]["status"] = "Failed"
                categories["ssl"]["findings"].append({
                    "severity": "Critical",
                    "message": "Connection is not secured with HTTPS.",
                    "deduction": 100
                })
                categories["ssl"]["reasons"].append("[Critical] [-100] Connection is not secured with HTTPS.")
                categories["ssl"]["recommendations"].append("Enable HTTPS and enforce redirection from HTTP.")
                severity_summary["Critical"] += 1
            elif not data["ssl"].get("valid"):
                ssl_failed = True
                categories["ssl"]["score"] = 0
                categories["ssl"]["status"] = "Failed"
                error_msg = data["ssl"].get("error", "Unknown error")
                severity = "Critical"
                categories["ssl"]["findings"].append({
                    "severity": severity,
                    "message": f"SSL/TLS certificate is invalid ({error_msg}).",
                    "deduction": 100
                })
                categories["ssl"]["reasons"].append(f"[{severity}] [-100] SSL/TLS certificate is invalid ({error_msg}).")
                categories["ssl"]["recommendations"].append(f"Renew or correctly configure the SSL certificate. Issuer: {data['ssl'].get('issuer', 'Unknown')}.")
                severity_summary["Critical"] += 1
            else:
                categories["ssl"]["reasons"].append("[Info] [+0] Valid SSL/TLS connection established.")
                categories["ssl"]["recommendations"].append("Maintain current configuration.")
                
        # 3. HTTP / Connectivity check (response is available)
        http_failed = (data["status_code"] == "Unreachable")
        
        # 4. HTTP Security Headers (Weight: 25%)
        if dns_failed or ssl_failed or http_failed:
            categories["headers"]["status"] = "Not Tested"
            categories["headers"]["score"] = "N/A"
            categories["headers"]["findings"].append({
                "severity": "Info",
                "message": "Analysis could not be completed because the previous network stage failed.",
                "deduction": 0
            })
            categories["headers"]["reasons"].append("[Info] [-0] Analysis could not be completed because the previous network stage failed.")
            categories["headers"]["recommendations"].append("Resolve DNS/SSL/HTTP connectivity issues first.")
        else:
            headers = data["security_headers"]
            deductions = 0
            for header, h_info in headers.items():
                if header == "Content-Security-Policy":
                    if h_info["status"] == "Missing":
                        deduction = 25
                        severity = "High"
                        deductions += deduction
                        categories["headers"]["findings"].append({
                            "severity": severity,
                            "message": f"Content-Security-Policy header is missing. {h_info['reason']}",
                            "deduction": deduction
                        })
                        categories["headers"]["reasons"].append(f"[{severity}] [-{deduction}] Content-Security-Policy is missing.")
                        categories["headers"]["recommendations"].append("Implement Content-Security-Policy to enforce browser-side security controls.")
                        severity_summary["High"] += 1
                    elif h_info["status"] == "Report Only":
                        deduction = 10
                        severity = "Medium"
                        deductions += deduction
                        categories["headers"]["findings"].append({
                            "severity": severity,
                            "message": f"Content-Security-Policy header is in report-only mode. {h_info['reason']}",
                            "deduction": deduction
                        })
                        categories["headers"]["reasons"].append(f"[{severity}] [-{deduction}] Content-Security-Policy is in report-only mode.")
                        categories["headers"]["recommendations"].append("Enforce Content-Security-Policy to actively block violations instead of just reporting them.")
                        severity_summary["Medium"] += 1
                else:
                    if h_info["status"] != "Present":
                        if header == "Strict-Transport-Security":
                            if ssl_failed or data["https"] != "Enabled":
                                deduction = 5
                                severity = "Medium"
                            else:
                                deduction = 20
                                severity = "High"
                        elif header == "X-Frame-Options":
                            deduction = 10
                            severity = "Medium"
                        elif header == "X-Content-Type-Options":
                            deduction = 10
                            severity = "Medium"
                        elif header == "Referrer-Policy":
                            deduction = 5
                            severity = "Low"
                        elif header == "Permissions-Policy":
                            deduction = 5
                            severity = "Low"
                        elif header == "Cross-Origin-Opener-Policy":
                            deduction = 3
                            severity = "Low"
                        else: # Cross-Origin-Resource-Policy
                            deduction = 3
                            severity = "Low"
                        
                        deductions += deduction
                        severity_summary[severity] += 1
                        status_label = "was not observed" if h_info["status"] == "Not Observed" else "is missing"
                        categories["headers"]["findings"].append({
                            "severity": severity,
                            "message": f"{header} header {status_label}. {HEADER_EXPLANATIONS[header]}",
                            "deduction": deduction
                        })
                        categories["headers"]["reasons"].append(f"[{severity}] [-{deduction}] {header} {status_label}.")
                        categories["headers"]["recommendations"].append(f"Implement {header} to enforce: {HEADER_EXPLANATIONS[header]}")
            # Cookies verification
            cookies = data.get("cookies", [])
            for cookie in cookies:
                c_name = cookie["name"]
                
                # Check HttpOnly: only flag if cookie name is sensitive/session-like
                is_sensitive = False
                name_lower = c_name.lower()
                if any(k in name_lower for k in ["session", "sid", "token", "auth", "login", "key", "pass", "csrf", "xsrf"]):
                    is_sensitive = True
                if "id" in name_lower:
                    if any(x in name_lower for x in ["sessid", "sessionid", "userid", "memberid", "phpsessionid", "jsessionid", "aspsessionid", "secid"]):
                        is_sensitive = True
                    if name_lower in ["id", "_id", "id_"]:
                        is_sensitive = True
                        
                if is_sensitive and not cookie["http_only"]:
                    deduction = 2
                    severity = "Medium"
                    deductions += deduction
                    categories["headers"]["findings"].append({
                        "severity": severity,
                        "message": f"Session cookie '{c_name}' is missing the HttpOnly attribute, which exposes it to client-side scripts (XSS).",
                        "deduction": deduction
                    })
                    categories["headers"]["reasons"].append(f"[{severity}] [-{deduction}] Session cookie '{c_name}' is missing HttpOnly.")
                    categories["headers"]["recommendations"].append(f"Set the HttpOnly flag on session cookie '{c_name}'.")
                    severity_summary[severity] += 1
                    
                # Check Secure: only flag when cookie is set over HTTPS and does not contain Secure
                if data["https"] == "Enabled" and not cookie["secure"]:
                    deduction = 2
                    severity = "Medium" if is_sensitive else "Low"
                    deductions += deduction
                    categories["headers"]["findings"].append({
                        "severity": severity,
                        "message": f"Cookie '{c_name}' is missing the Secure attribute, allowing it to be transmitted over unencrypted connections.",
                        "deduction": deduction
                    })
                    categories["headers"]["reasons"].append(f"[{severity}] [-{deduction}] Cookie '{c_name}' is missing Secure.")
                    categories["headers"]["recommendations"].append(f"Set the Secure flag on cookie '{c_name}'.")
                    severity_summary[severity] += 1

            categories["headers"]["score"] = max(0, 100 - deductions)
            if categories["headers"]["score"] == 100:
                categories["headers"]["status"] = "Passed"
            elif categories["headers"]["score"] >= 70:
                categories["headers"]["status"] = "Warning"
            else:
                categories["headers"]["status"] = "Failed"
                
            if not categories["headers"]["findings"]:
                categories["headers"]["reasons"].append("[Info] [+0] All security headers verified successfully.")
                categories["headers"]["recommendations"].append("Maintain current configuration.")
        
        # 5. Server Configuration (Weight: 10%)
        if dns_failed or ssl_failed or http_failed:
            categories["server"]["status"] = "Not Tested"
            categories["server"]["score"] = "N/A"
            categories["server"]["findings"].append({
                "severity": "Info",
                "message": "Analysis could not be completed because the previous network stage failed.",
                "deduction": 0
            })
            categories["server"]["reasons"].append("[Info] [-0] Analysis could not be completed because the previous network stage failed.")
            categories["server"]["recommendations"].append("Resolve DNS/SSL/HTTP connectivity issues first.")
        else:
            server_header = data.get("server", "Not disclosed")
            if server_header != "Not disclosed" and server_header != "N/A":
                if re.search(r'\d+\.\d+', server_header):
                    categories["server"]["score"] = 90
                    categories["server"]["status"] = "Warning"
                    categories["server"]["findings"].append({
                        "severity": "Low",
                        "message": "Server header exposes exact version information.",
                        "deduction": 10
                    })
                    categories["server"]["reasons"].append("[Low] [-10] Server header exposes exact version information.")
                    categories["server"]["recommendations"].append("Configure the server to hide version information to prevent targeted exploits.")
                    severity_summary["Low"] += 1
                else:
                    categories["server"]["score"] = 95
                    categories["server"]["status"] = "Warning"
                    categories["server"]["findings"].append({
                        "severity": "Info",
                        "message": f"Server header exposes server software type ({server_header}).",
                        "deduction": 5
                    })
                    categories["server"]["reasons"].append("[Info] [-5] Server header exposes server software.")
                    categories["server"]["recommendations"].append("Consider removing the Server header entirely.")
                    severity_summary["Info"] += 1
            else:
                categories["server"]["reasons"].append("[Info] [+0] Server signature is hidden.")
                categories["server"]["recommendations"].append("Maintain current configuration.")

        # 5b. Compression checks (Info)
        if not (dns_failed or ssl_failed or http_failed):
            if data.get("compression_used"):
                categories["server"]["findings"].append({
                    "severity": "Info",
                    "message": f"Response compression is enabled ({data.get('content_encoding', 'N/A')}).",
                    "deduction": 0
                })
                categories["server"]["reasons"].append("[Info] [+0] Response compression is active.")
                severity_summary["Info"] += 1
            else:
                categories["server"]["findings"].append({
                    "severity": "Info",
                    "message": "Response compression is not enabled on the server.",
                    "deduction": 0
                })
                categories["server"]["reasons"].append("[Info] [-0] Response compression is inactive.")
                categories["server"]["recommendations"].append("Enable gzip or Brotli compression to improve performance.")
                severity_summary["Info"] += 1
                
        # 6. Performance (Weight: 20%)
        if http_failed:
            categories["performance"]["status"] = "Not Tested"
            categories["performance"]["score"] = "N/A"
            categories["performance"]["findings"].append({
                "severity": "Critical",
                "message": "HTTP connection timed out or failed.",
                "deduction": 0
            })
            categories["performance"]["reasons"].append("[Critical] [-0] HTTP connection timed out or failed.")
            categories["performance"]["recommendations"].append("Ensure the website is online and accessible.")
        else:
            rt = data["response_time_ms"]
            msg = f"Observed response time from this client was {rt} ms. Performance may vary due to network, ISP, DNS, redirects, and geography."
            if rt > 3000:
                categories["performance"]["score"] = 90
                categories["performance"]["status"] = "Warning"
                categories["performance"]["findings"].append({
                    "severity": "Low",
                    "message": msg,
                    "deduction": 10
                })
                categories["performance"]["reasons"].append(f"[Low] [-10] {msg}")
                categories["performance"]["recommendations"].append("Observe latency trends across multiple requests and network locations.")
                severity_summary["Low"] += 1
            elif rt > 1500:
                categories["performance"]["score"] = 95
                categories["performance"]["status"] = "Warning"
                categories["performance"]["findings"].append({
                    "severity": "Low",
                    "message": msg,
                    "deduction": 5
                })
                categories["performance"]["reasons"].append(f"[Low] [-5] {msg}")
                categories["performance"]["recommendations"].append("Observe latency trends across multiple requests and network locations.")
                severity_summary["Low"] += 1
            else:
                categories["performance"]["reasons"].append(f"[Info] [+0] {msg}")
                categories["performance"]["recommendations"].append("Maintain current configuration.")
                
        # Overall score
        weights = {
            "dns": 0.15,
            "ssl": 0.30,
            "headers": 0.25,
            "server": 0.10,
            "performance": 0.20
        }
        
        evaluated_weight = 0.0
        weighted_sum = 0.0
        
        for cat_key, cat in categories.items():
            if cat["score"] != "N/A":
                weighted_sum += cat["score"] * weights[cat_key]
                evaluated_weight += weights[cat_key]
                
        if evaluated_weight > 0:
            overall = int(weighted_sum / evaluated_weight)
        else:
            overall = 0
            
        overall = max(0, min(100, overall))
        
        # A valid website with DNS 100, SSL 100, no critical issues, and only optional header findings
        # should not receive below B (80).
        if not dns_failed and not ssl_failed and not http_failed:
            has_critical_or_high = (severity_summary.get("Critical", 0) > 0) or (severity_summary.get("High", 0) > 0)
            if not has_critical_or_high:
                overall = max(80, overall)
        
        if overall >= 90:
            grade = "A"
            threat_level = "Low"
        elif overall >= 80:
            grade = "B"
            threat_level = "Medium"
        elif overall >= 70:
            grade = "C"
            threat_level = "Medium"
        elif overall >= 60:
            grade = "D"
            threat_level = "High"
        else:
            grade = "F"
            threat_level = "Critical"
            
        scoring_breakdown = []
        for cat_key, cat_name in [("dns", "DNS Health"), ("ssl", "SSL/TLS Security"), 
                                  ("headers", "HTTP Security Headers"), 
                                  ("server", "Server Configuration"), 
                                  ("performance", "Performance")]:
            score_val = categories[cat_key]["score"]
            weight_val = weights[cat_key]
            if score_val != "N/A":
                contribution = score_val * weight_val / evaluated_weight
                scoring_breakdown.append(f"{cat_name}: {score_val} ({int(weight_val*100)}% weight, normalized contribution: {contribution:.2f})")
            else:
                scoring_breakdown.append(f"{cat_name}: Not Tested (Excluded from calculation)")
            
        return categories, overall, grade, threat_level, severity_summary, scoring_breakdown

    def _generate_score_explanation(self, overall: int, categories: dict) -> str:
        explanations = []
        if overall >= 90:
            explanations.append("The website has a very strong overall security profile with no critical vulnerabilities.")
        elif overall >= 80:
            explanations.append("The website has a good security profile, with minor recommended baseline settings.")
        elif overall >= 70:
            explanations.append("The website has a fair security baseline. Some medium-risk issues need to be resolved.")
        elif overall >= 60:
            explanations.append("The website has a weak security posture. Important security fixes are needed.")
        else:
            explanations.append("The website has a critical security risk profile. Immediate remediation is required.")
            
        criticals = []
        highs = []
        not_evals = []
        for cat_name, cat in categories.items():
            if cat.get("status") in ["Not Tested", "Not Evaluated"]:
                not_evals.append(cat_name.upper())
            for f in cat.get("findings", []):
                if f["severity"] == "Critical":
                    criticals.append(f"{cat_name.upper()}: {f['message']}")
                elif f["severity"] == "High":
                    highs.append(f"{cat_name.upper()}: {f['message']}")
                    
        if criticals:
            explanations.append(f"Critical issues identified: {'; '.join(criticals)}.")
        elif highs:
            explanations.append(f"High risk issues identified: {'; '.join(highs)}.")
            
        if not_evals:
            explanations.append(f"The following sections could not be evaluated due to earlier connection failures: {', '.join(not_evals)}.")
            
        return " ".join(explanations)
