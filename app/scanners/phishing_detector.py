import re
import os
import unicodedata
import requests
import dns.resolver
from urllib.parse import urlparse
import whois
from datetime import datetime, timezone
import Levenshtein
from rapidfuzz import fuzz
from app.scanners.base_scanner import BaseScanner
from app.utils.network import resolve_ip, check_ssl_certificate
from app.utils.domain_intelligence import (
    extract_registered_domain,
    compute_similarity,
    normalize_homoglyphs,
    detect_mixed_scripts,
    detect_string_edit_attacks
)

class ThreatIntelligenceManager:
    def __init__(self):
        self.vt_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.gsb_key = os.getenv("SAFE_BROWSING_API_KEY")
        self.openphish_key = os.getenv("OPENPHISH_API_KEY")
        self.phishtank_key = os.getenv("PHISHTANK_API_KEY")
        
    def check_url(self, url: str) -> dict:
        results = []
        malicious = False
        
        if not any([self.vt_key, self.gsb_key, self.openphish_key, self.phishtank_key]):
            return {"configured": False, "malicious": False, "results": ["[+0] External Threat Intelligence Not Configured"]}
            
        if self.gsb_key:
            endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.gsb_key}"
            payload = {
                "client": {"clientId": "cyberoptimus", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            try:
                resp = requests.post(endpoint, json=payload, timeout=3)
                if resp.status_code == 200:
                    data = resp.json()
                    if 'matches' in data and len(data['matches']) > 0:
                        malicious = True
                        results.append("[+50] Google Safe Browsing flagged this URL as malicious.")
                    else:
                        results.append("[+0] Google Safe Browsing found no threats.")
            except Exception:
                results.append("[+0] Google Safe Browsing check failed.")
                
        return {"configured": True, "malicious": malicious, "results": results}

class PhishingDetector(BaseScanner):
    
    KNOWN_BRANDS = {
        'paypal': ['paypal.com', 'paypal.me', 'paypalobjects.com'],
        'apple': ['apple.com', 'icloud.com'],
        'microsoft': ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'office365.com', 'azure.com', 'msn.com', 'bing.com', 'microsoftonline.com'],
        'google': ['google.com', 'youtube.com', 'gmail.com', 'blogspot.com', 'google.co.in', 'google.co.uk', 'gstatic.com'],
        'facebook': ['facebook.com', 'fb.com', 'messenger.com', 'fbcdn.net'],
        'instagram': ['instagram.com'],
        'whatsapp': ['whatsapp.com', 'wa.me'],
        'twitter': ['twitter.com', 'x.com', 't.co'],
        'linkedin': ['linkedin.com'],
        'amazon': ['amazon.com', 'aws.amazon.com', 'media-amazon.com'],
        'netflix': ['netflix.com'],
        'github': ['github.com', 'github.io', 'githubusercontent.com'],
        'discord': ['discord.com', 'discord.gg', 'discordapp.com'],
        'telegram': ['telegram.org', 't.me'],
        'steam': ['steampowered.com', 'steamcommunity.com'],
        'coinbase': ['coinbase.com'],
        'binance': ['binance.com'],
        'bankofamerica': ['bankofamerica.com', 'bofa.com'],
        'chase': ['chase.com'],
        'wellsfargo': ['wellsfargo.com'],
        'citi': ['citigroup.com', 'citi.com', 'citibank.com'],
        'hsbc': ['hsbc.com'],
        'sbi': ['onlinesbi.com', 'sbi.co.in'],
        'icici': ['icicibank.com'],
        'hdfc': ['hdfcbank.com'],
        'phonepe': ['phonepe.com'],
        'paytm': ['paytm.com'],
        'adobe': ['adobe.com'],
        'dropbox': ['dropbox.com'],
        'dhl': ['dhl.com'],
        'fedex': ['fedex.com'],
        'ebay': ['ebay.com'],
        'chatgpt': ['chatgpt.com', 'openai.com'],
        'openai': ['openai.com', 'chatgpt.com'],
        'garena': ['garena.com']
    }
    
    SUSPICIOUS_TLDS = {
        'zip', 'mov', 'top', 'xyz', 'work', 'click', 'gq', 'cf', 'tk', 'ml', 'ga', 
        'rest', 'country', 'stream', 'download', 'racing', 'cam', 'best', 'guru', 
        'icu', 'fit', 'surf', 'buzz', 'monster', 'link', 'online', 'site', 'fun'
    }
    
    URL_SHORTENERS = {
        'bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 
        'adf.ly', 'bit.do', 'cutt.ly', 'rebrand.ly', 'tiny.cc', 'shorturl.at'
    }
    
    SUSPICIOUS_KEYWORDS = [
        'login', 'verify', 'update', 'secure', 'account', 'banking', 'wallet', 
        'free', 'auth', 'confirm', 'password', 'credential', 'signin', 'support', 
        'security', 'recover', 'billing', 'validation', 'token', 'claim', 'bonus', 'prize'
    ]
    
    def __init__(self):
        super().__init__()
        self.ti_manager = ThreatIntelligenceManager()
    
    def scan(self, target: str) -> dict:
        target_url = target.strip()
        target_lower = target_url.lower()
        if target_lower.startswith("http://"):
            target = "http://" + target_url[7:]
        elif target_lower.startswith("https://"):
            target = "https://" + target_url[8:]
        else:
            target = "https://" + target_url
            
        parsed_url = urlparse(target)
        raw_host = parsed_url.netloc.lower()
        if ':' in raw_host:
            raw_host = raw_host.split(':')[0]
            
        domain = extract_registered_domain(raw_host) if raw_host else raw_host
        if not domain:
            domain = raw_host
            
        # Decode punycode if present
        try:
            decoded_domain = raw_host.encode('utf-8').decode('idna')
        except Exception:
            decoded_domain = raw_host

        # 0. Check if target domain is an OFFICIAL brand domain or subdomain
        is_official_brand_domain = False
        matched_official_brand = None
        
        for brand, legit_domains in self.KNOWN_BRANDS.items():
            for legit_dom in legit_domains:
                legit_root = extract_registered_domain(legit_dom)
                reg_root = extract_registered_domain(raw_host)
                if (reg_root and legit_root and reg_root.lower() == legit_root.lower()) or raw_host.lower() == legit_dom.lower() or raw_host.lower().endswith("." + legit_dom.lower()):
                    is_official_brand_domain = True
                    matched_official_brand = brand
                    break
            if is_official_brand_domain:
                break

        score = 0
        reasons = []
        recommendations = []
        scoring_breakdown = []
        impersonation_detected = False
        impersonation_details = None
        dns_failed = False
        
        # Track confidence components across engines
        confidence_factors = {
            "dns_checked": False,
            "whois_checked": False,
            "ssl_checked": False,
            "threat_intel_checked": False,
            "html_content_analyzed": False,
            "js_analyzed": False,
            "visual_brand_analyzed": False,
            "signal_density": 0
        }
        
        # 8 Categories of Analysis
        categories = {
            "brand_impersonation": {"score": 0, "findings": []},
            "domain_reputation": {"score": 0, "findings": []},
            "url_structure": {"score": 0, "findings": []},
            "transport_security": {"score": 0, "findings": []},
            "network_redirects": {"score": 0, "findings": []},
            "page_content": {"score": 0, "findings": []},
            "javascript_analysis": {"score": 0, "findings": []},
            "visual_brand": {"score": 0, "findings": []}
        }

        def add_risk(points: int, category_key: str, rule: str, evidence: str, severity: str = "Medium", message: str = "", why_it_matters: str = "", owasp_ref: str = "N/A"):
            nonlocal score
            score += points
            confidence_factors["signal_density"] += 1
            cat_title = category_key.replace('_', ' ').title()
            scoring_breakdown.append({
                "points": points,
                "category": cat_title,
                "rule": rule,
                "evidence": evidence
            })
            if category_key in categories:
                categories[category_key]["score"] += points
                if message:
                    categories[category_key]["findings"].append({
                        "severity": severity,
                        "confidence": "Verified",
                        "evidence": evidence,
                        "message": message,
                        "why_it_matters": why_it_matters,
                        "owasp_ref": owasp_ref
                    })

        # ---------------------------------------------------------------------
        # 1. Network Redirect Chain & Page Content Fetching
        # ---------------------------------------------------------------------
        redirect_chain = []
        final_url = target
        final_host = raw_host
        html_content = ""
        
        try:
            resp = requests.get(
                target, 
                timeout=4, 
                allow_redirects=True, 
                verify=False,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
            )
            final_url = resp.url
            final_host = urlparse(final_url).netloc.lower().split(':')[0]
            html_content = resp.text if resp.text else ""
            
            for hist in resp.history:
                redirect_chain.append({
                    "status_code": hist.status_code,
                    "url": hist.url,
                    "host": urlparse(hist.url).netloc.split(':')[0]
                })
            redirect_chain.append({
                "status_code": resp.status_code,
                "url": final_url,
                "host": final_host
            })
        except Exception:
            pass

        if len(redirect_chain) > 1:
            hop_count = len(redirect_chain) - 1
            if hop_count >= 3:
                add_risk(
                    15, "network_redirects", "Multi-hop redirect chain", f"{hop_count} hops from '{raw_host}' to '{final_host}'",
                    severity="Medium",
                    message="Multiple HTTP redirects observed.",
                    why_it_matters="Phishers use multi-stage redirect chains to obfuscate the final landing site from automated crawlers.",
                    owasp_ref="A01:2021-Broken Access Control"
                )
                reasons.append(f"[+15] Multi-hop redirect chain detected ({hop_count} redirects).")
            elif extract_registered_domain(raw_host) != extract_registered_domain(final_host):
                add_risk(
                    10, "network_redirects", "Cross-domain redirect", f"{raw_host} -> {final_host}",
                    severity="Low",
                    message="URL redirects to a different registered domain.",
                    why_it_matters="Cross-domain redirects can hide destination ownership."
                )
                reasons.append(f"[+10] Cross-domain redirect detected ('{raw_host}' -> '{final_host}').")

        # ---------------------------------------------------------------------
        # 2. Engine 1: URL Structure & Obfuscation Engine
        # ---------------------------------------------------------------------
        self._analyze_url_structure(
            target_url=target,
            raw_host=raw_host,
            domain=domain,
            is_official_brand_domain=is_official_brand_domain,
            add_risk=add_risk,
            reasons=reasons,
            recommendations=recommendations
        )

        is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", raw_host)) or bool(re.match(r"^0x[0-9a-fA-F]+$", raw_host)) or bool(re.match(r"^0[0-7]+$", raw_host)) or ":" in raw_host

        # ---------------------------------------------------------------------
        # 3. Engine 2: Domain Reputation & WHOIS Engine
        # ---------------------------------------------------------------------
        dns_failed, creation_date = self._analyze_domain_reputation(
            domain=domain,
            raw_host=raw_host,
            is_ip=is_ip,
            is_official_brand_domain=is_official_brand_domain,
            add_risk=add_risk,
            reasons=reasons,
            recommendations=recommendations,
            confidence_factors=confidence_factors
        )

        # ---------------------------------------------------------------------
        # 4. Engine 3: SSL/TLS Certificate Inspection Engine
        # ---------------------------------------------------------------------
        self._analyze_ssl_certificate(
            target_url=target,
            raw_host=raw_host,
            dns_failed=dns_failed,
            is_official_brand_domain=is_official_brand_domain,
            add_risk=add_risk,
            reasons=reasons,
            recommendations=recommendations,
            categories=categories,
            confidence_factors=confidence_factors
        )

        # ---------------------------------------------------------------------
        # 5. Engine 4: Expanded Brand Impersonation & Typosquatting Engine
        # ---------------------------------------------------------------------
        imp_detected, imp_details = self._analyze_brand_impersonation(
            domain=domain,
            raw_host=raw_host,
            target_url=target,
            decoded_domain=decoded_domain,
            is_ip=is_ip,
            is_official_brand_domain=is_official_brand_domain,
            matched_official_brand=matched_official_brand,
            add_risk=add_risk,
            reasons=reasons,
            recommendations=recommendations,
            categories=categories
        )
        if imp_detected:
            impersonation_detected = True
            impersonation_details = imp_details

        # ---------------------------------------------------------------------
        # 6. Engine 5: HTML & Page Content Inspection Engine
        # ---------------------------------------------------------------------
        if html_content and not is_official_brand_domain:
            confidence_factors["html_content_analyzed"] = True
            self._analyze_page_content(
                html_content=html_content,
                target_url=target,
                raw_host=raw_host,
                domain=domain,
                add_risk=add_risk,
                reasons=reasons,
                recommendations=recommendations
            )

        # ---------------------------------------------------------------------
        # 7. Engine 6: JavaScript Analysis Engine
        # ---------------------------------------------------------------------
        if html_content and not is_official_brand_domain:
            confidence_factors["js_analyzed"] = True
            self._analyze_javascript(
                html_content=html_content,
                target_url=target,
                add_risk=add_risk,
                reasons=reasons,
                recommendations=recommendations
            )

        # ---------------------------------------------------------------------
        # 8. Engine 7: Visual Brand & Favicon Engine
        # ---------------------------------------------------------------------
        if html_content and not is_official_brand_domain:
            confidence_factors["visual_brand_analyzed"] = True
            self._analyze_visual_brand(
                html_content=html_content,
                target_url=target,
                raw_host=raw_host,
                add_risk=add_risk,
                reasons=reasons,
                recommendations=recommendations
            )

        # ---------------------------------------------------------------------
        # 9. External Threat Intelligence Engine
        # ---------------------------------------------------------------------
        ti_result = self.ti_manager.check_url(target)
        confidence_factors["threat_intel_checked"] = True
        if not ti_result["configured"]:
            reasons.extend(ti_result["results"])
        elif ti_result["malicious"]:
            add_risk(
                50, "domain_reputation", "Flagged by Threat Intelligence API", "Google Safe Browsing / External API match",
                severity="Critical",
                message="Flagged as malicious by global threat intelligence.",
                why_it_matters="Confirmed malicious status by threat intelligence security feeds.",
                owasp_ref="A07:2021-Identification and Authentication Failures"
            )
            reasons.extend(ti_result["results"])
            recommendations.append("Immediately close the page. Site confirmed malicious by threat intelligence.")
        else:
            reasons.extend(ti_result["results"])

        # ---------------------------------------------------------------------
        # 10. Engine 8: Weighted Risk Engine & Confidence Evaluator
        # ---------------------------------------------------------------------
        if is_official_brand_domain:
            score = 0
            scoring_breakdown = [{
                "points": 0,
                "category": "Brand Whitelist",
                "rule": "Official Brand Endpoint Exemption",
                "evidence": f"Belongs to official infrastructure for {matched_official_brand.capitalize()}"
            }]

        score = min(score, 100)

        # Determine Verdict & Threat Level
        if score >= 60:
            verdict = "Phishing"
            threat_level = "Critical" if score >= 80 else "High"
        elif score >= 25:
            verdict = "Suspicious"
            threat_level = "Medium"
        else:
            verdict = "Safe"
            threat_level = "Low"

        if not recommendations and score < 25:
            recommendations.append("URL appears safe based on current multi-engine indicators, but always remain vigilant.")

        # Multi-Signal Confidence Score (0% to 100%)
        conf_base = 60
        if confidence_factors["dns_checked"]: conf_base += 5
        if confidence_factors["whois_checked"]: conf_base += 5
        if confidence_factors["ssl_checked"]: conf_base += 5
        if confidence_factors["threat_intel_checked"]: conf_base += 5
        if confidence_factors["html_content_analyzed"]: conf_base += 5
        if confidence_factors["js_analyzed"]: conf_base += 5
        if confidence_factors["visual_brand_analyzed"]: conf_base += 5
        conf_base += min(confidence_factors["signal_density"] * 2, 10)
        confidence_score = min(conf_base, 100)
        
        if is_official_brand_domain:
            confidence_score = 98

        verdict_explanation = self._generate_verdict_explanation(
            verdict=verdict,
            risk_score=score,
            confidence_score=confidence_score,
            is_official=is_official_brand_domain,
            matched_brand=matched_official_brand,
            impersonation_detected=impersonation_detected,
            impersonation_details=impersonation_details,
            reasons=reasons,
            categories=categories,
            target_url=target,
            raw_host=raw_host
        )

        return {
            "url": target,
            "domain": domain,
            "raw_host": raw_host,
            "final_url": final_url,
            "final_host": final_host,
            "redirect_chain": redirect_chain,
            "risk_score": score,
            "confidence_score": confidence_score,
            "verdict": verdict,
            "threat_level": threat_level,
            "verdict_explanation": verdict_explanation,
            "reasons": reasons,
            "scoring_breakdown": scoring_breakdown,
            "recommendations": recommendations,
            "impersonation_detected": impersonation_detected,
            "impersonation_details": impersonation_details,
            "is_official_brand_domain": is_official_brand_domain,
            "matched_official_brand": matched_official_brand.capitalize() if matched_official_brand else None,
            "creation_date": creation_date.strftime('%Y-%m-%d') if isinstance(creation_date, datetime) else "Unknown",
            "categories": categories,
            "status": "success"
        }

    # =========================================================================
    # ENGINE IMPLEMENTATIONS
    # =========================================================================

    def _analyze_url_structure(self, target_url: str, raw_host: str, domain: str, is_official_brand_domain: bool, add_risk, reasons: list, recommendations: list):
        """Engine 1: URL Structure, Obfuscation & Path Analysis."""
        is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", raw_host)) or bool(re.match(r"^0x[0-9a-fA-F]+$", raw_host)) or bool(re.match(r"^0[0-7]+$", raw_host)) or ":" in raw_host
        if is_ip:
            add_risk(
                40, "url_structure", "Raw IP address host", raw_host,
                severity="High",
                message="URL uses a raw IP address instead of a domain name.",
                why_it_matters="Attackers frequently use raw IP addresses to bypass domain reputation filters.",
                owasp_ref="A07:2021-Identification and Authentication Failures"
            )
            reasons.append("[+40] URL uses a raw IP address instead of a domain name.")
            recommendations.append("Avoid clicking links that use raw IP addresses for navigation.")

        if '@' in target_url:
            add_risk(
                25, "url_structure", "Userinfo authority '@' obfuscation", f"Target contains '@'",
                severity="High",
                message="URL userinfo '@' obfuscation detected.",
                why_it_matters="Browsers treat text before '@' as user credentials, ignoring the fake host to navigate to the real host after '@'.",
                owasp_ref="A07:2021-Identification and Authentication Failures"
            )
            reasons.append("[+25] Authority obfuscation ('@' character) detected in URL.")

        subdomain_count = raw_host.count('.')
        if domain in self.URL_SHORTENERS or raw_host in self.URL_SHORTENERS:
            add_risk(
                15, "url_structure", "URL shortener domain used", f"Domain: {raw_host}",
                severity="Low",
                message="URL shortener service used.",
                why_it_matters="Shorteners conceal destination hostnames and redirect chains."
            )
            reasons.append("[+15] URL shortener domain detected (hides true target destination).")
        elif subdomain_count > 3 and not is_official_brand_domain:
            add_risk(
                15, "url_structure", "Excessive subdomain levels", f"Subdomains: {subdomain_count}",
                severity="Low",
                message="Excessive subdomain levels observed.",
                why_it_matters="Complex subdomain chains hide true root domain ownership."
            )
            reasons.append("[+15] High number of subdomains detected (often used to obscure true host).")

        if len(target_url) > 75 and not is_official_brand_domain:
            add_risk(
                10, "url_structure", "Unusually long URL (>75 chars)", f"{len(target_url)} characters",
                severity="Low",
                message="Unusually long URL structure.",
                why_it_matters="Long URLs are designed to push malicious parameters past browser address bar view limits."
            )
            reasons.append(f"[+10] Unusually long URL length ({len(target_url)} characters).")

        if target_url.count('%') > 5:
            add_risk(
                10, "url_structure", "Excessive percent encoding", f"Count: {target_url.count('%')}",
                severity="Low",
                message="Excessive percent encoding in URL path.",
                why_it_matters="Hexadecimal percent encoding conceals payload strings from security filters."
            )
            reasons.append("[+10] High percentage encoding detected (obfuscation technique).")

        if not is_official_brand_domain:
            found_keywords = [kw for kw in self.SUSPICIOUS_KEYWORDS if kw in target_url.lower()]
            if found_keywords:
                add_risk(
                    15, "url_structure", "Credential keywords in URL path", f"Keywords: {', '.join(found_keywords)}",
                    severity="Low",
                    message="Credential harvest keywords present in URL path.",
                    why_it_matters="Phishing URLs commonly embed terms like 'login' or 'verify' to simulate authentic workflows.",
                    owasp_ref="A07:2021-Identification and Authentication Failures"
                )
                reasons.append(f"[+15] Suspicious credential keywords found in URL: {', '.join(found_keywords)}.")
                recommendations.append("Be wary of links insisting on 'login' or 'verification' from unverified sources.")

    def _analyze_domain_reputation(self, domain: str, raw_host: str, is_ip: bool, is_official_brand_domain: bool, add_risk, reasons: list, recommendations: list, confidence_factors: dict):
        """Engine 2: Domain Reputation, DNS, WHOIS & Mail Records."""
        dns_failed = False
        creation_date = None

        if not is_ip:
            ip_address = resolve_ip(domain)
            confidence_factors["dns_checked"] = True
            if ip_address == "Unable to resolve IP":
                dns_failed = True
                add_risk(
                    10, "domain_reputation", "DNS Resolution Failed (NXDOMAIN)", f"Domain '{domain}' failed DNS lookup",
                    severity="Low",
                    message="Domain failed DNS resolution (NXDOMAIN).",
                    why_it_matters="Unresolvable domains cannot host active web services in public DNS, preventing HTTP, SSL/TLS, and server response inspection."
                )
                reasons.append("[+10] Domain does not resolve to an active IP address (NXDOMAIN).")
                recommendations.append("The domain might be dead, newly registered but inactive, or a typo.")
            else:
                try:
                    txt_records = dns.resolver.resolve(domain, 'TXT', lifetime=3)
                    has_spf = any('v=spf1' in rdata.to_text() for rdata in txt_records)
                    if not has_spf and not is_official_brand_domain:
                        add_risk(
                            5, "domain_reputation", "Missing SPF email authentication record", f"No SPF record for '{domain}'",
                            severity="Low",
                            message="Domain lacks an SPF email authentication record.",
                            why_it_matters="Missing SPF records allow unauthorized senders to spoof emails from this domain.",
                            owasp_ref="A05:2021-Security Misconfiguration"
                        )
                        reasons.append("[+5] Domain lacks an SPF record (common in email phishing infrastructure).")
                except Exception:
                    pass

        tld = domain.split('.')[-1].lower() if '.' in domain else ""
        if tld in self.SUSPICIOUS_TLDS and not is_official_brand_domain:
            add_risk(
                20, "domain_reputation", f"High-abuse TLD (.{tld})", f"TLD: .{tld}",
                severity="Medium",
                message=f"Domain uses a high-abuse TLD (.{tld}).",
                why_it_matters="Certain cheap or free TLDs are statistically overrepresented in phishing and malware campaigns."
            )
            reasons.append(f"[+20] High-risk Top-Level Domain (TLD) detected (.{tld}).")

        if not is_ip and not dns_failed:
            try:
                domain_info = whois.whois(domain)
                creation_date = domain_info.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                    
                if creation_date:
                    confidence_factors["whois_checked"] = True
                    if isinstance(creation_date, datetime):
                        now = datetime.now(timezone.utc) if creation_date.tzinfo else datetime.now()
                        age_days = (now - creation_date).days
                        if age_days < 7 and not is_official_brand_domain:
                            add_risk(
                                30, "domain_reputation", "Brand new domain registration (<7 days)", f"{age_days} days old",
                                severity="High",
                                message=f"Brand new domain ({age_days} days old).",
                                why_it_matters="Phishing infrastructure is frequently registered days or hours prior to launching campaigns.",
                                owasp_ref="A07:2021-Identification and Authentication Failures"
                            )
                            reasons.append(f"[+30] Domain is extremely brand new ({age_days} days old).")
                        elif age_days < 30 and not is_official_brand_domain:
                            add_risk(
                                25, "domain_reputation", "Newly registered domain (<30 days)", f"{age_days} days old",
                                severity="Medium",
                                message=f"Newly registered domain ({age_days} days old).",
                                why_it_matters="Over 70% of malicious phishing domains are registered less than 30 days prior to attack launch.",
                                owasp_ref="A07:2021-Identification and Authentication Failures"
                            )
                            reasons.append(f"[+25] Domain is very newly registered ({age_days} days ago).")
                            recommendations.append("Exercise extreme caution with newly registered domains.")
            except Exception:
                pass

        return dns_failed, creation_date

    def _analyze_ssl_certificate(self, target_url: str, raw_host: str, dns_failed: bool, is_official_brand_domain: bool, add_risk, reasons: list, recommendations: list, categories: dict, confidence_factors: dict):
        """Engine 3: SSL/TLS Certificate Inspection Engine."""
        if dns_failed:
            confidence_factors["ssl_checked"] = True
            reasons.append("[+0] SSL evaluation skipped because domain DNS resolution failed (NXDOMAIN).")
            categories["transport_security"]["findings"].append({
                "severity": "Info",
                "confidence": "Verified",
                "evidence": f"Target hostname '{raw_host}' failed DNS lookup.",
                "message": "SSL Evaluation Unavailable (DNS Resolution Failed)",
                "why_it_matters": "SSL/TLS certificate verification requires an active network socket connection."
            })
        elif not target_url.startswith("https://"):
            add_risk(
                10, "transport_security", "Unencrypted HTTP scheme", "URL scheme is 'http://'",
                severity="Medium",
                message="Target endpoint lacks HTTPS encryption.",
                why_it_matters="Unencrypted HTTP transmissions allow network eavesdropping and credential theft.",
                owasp_ref="A02:2021-Cryptographic Failures"
            )
            confidence_factors["ssl_checked"] = True
            reasons.append("[+10] Connection is not secured with HTTPS.")
        else:
            confidence_factors["ssl_checked"] = True
            ssl_info = check_ssl_certificate(raw_host)
            if not ssl_info.get("valid"):
                err_msg = ssl_info.get("error", "Invalid certificate")
                add_risk(
                    20, "transport_security", "SSL Certificate Validation Failed", err_msg,
                    severity="High",
                    message="SSL Certificate Validation Failed (Expired/Host Mismatch).",
                    why_it_matters="Invalid or mismatched certificates allow attackers to intercept traffic or present fake portals.",
                    owasp_ref="A02:2021-Cryptographic Failures"
                )
                reasons.append(f"[+20] HTTPS is used, but SSL certificate validation failed: {err_msg}.")
                recommendations.append("An invalid certificate might indicate a man-in-the-middle attack or poorly configured phishing host.")
            else:
                issuer = ssl_info.get("issuer", "").lower()
                if ("let's encrypt" in issuer or "zerossl" in issuer) and not is_official_brand_domain:
                    categories["transport_security"]["findings"].append({
                        "severity": "Info",
                        "confidence": "Verified",
                        "evidence": f"Valid Automated DV Certificate issued by '{ssl_info.get('issuer')}'",
                        "message": "Domain Validation (DV) HTTPS Active.",
                        "why_it_matters": "Over 80% of modern phishing websites utilize free automated DV certificates. HTTPS encrypts traffic but does NOT guarantee domain trustworthiness.",
                        "owasp_ref": "A02:2021-Cryptographic Failures"
                    })
                else:
                    categories["transport_security"]["findings"].append({
                        "severity": "Info",
                        "confidence": "Verified",
                        "evidence": f"Valid SSL certificate issued for '{raw_host}'",
                        "message": "HTTPS Encryption Active (Does NOT imply site safety).",
                        "why_it_matters": "HTTPS encrypts traffic but does NOT guarantee domain trustworthiness."
                    })

    def _analyze_brand_impersonation(self, domain: str, raw_host: str, target_url: str, decoded_domain: str, is_ip: bool, is_official_brand_domain: bool, matched_official_brand: str, add_risk, reasons: list, recommendations: list, categories: dict):
        """Engine 4: Expanded Brand Impersonation & Typosquatting Engine."""
        domain_label = domain.split('.')[0] if '.' in domain else domain
        subbed_label = normalize_homoglyphs(domain_label)

        if is_official_brand_domain:
            reasons.append(f"[+0] Verified official domain/subdomain of {matched_official_brand.capitalize()}. Brand impersonation rules bypassed.")
            categories["brand_impersonation"]["findings"].append({
                "severity": "Info",
                "confidence": "Verified",
                "evidence": f"Domain '{raw_host}' belongs to official brand '{matched_official_brand}'.",
                "message": f"Verified official endpoint for {matched_official_brand.capitalize()}.",
                "why_it_matters": "Legitimate brand domains are exempt from impersonation heuristics."
            })
            return False, None

        if is_ip:
            return False, None

        for brand, legitimate_domains in self.KNOWN_BRANDS.items():
            legit_primary = legitimate_domains[0]
            legit_name = legit_primary.split('.')[0]

            # 1. Expanded Edit Attack Analysis (Transposition, Insertion, Deletion, Substitution)
            attack_check = detect_string_edit_attacks(domain_label, legit_name)
            if attack_check["is_attack"] and domain_label != legit_name:
                attack_type = attack_check["attack_type"]
                details = attack_check["details"]
                add_risk(
                    50, "brand_impersonation", f"{attack_type} targeting {brand.capitalize()}", details,
                    severity="High",
                    message=f"{attack_type} targeting {brand.capitalize()}.",
                    why_it_matters="Attackers use subtle typosquatting variations to trick users into trusting fake login portals.",
                    owasp_ref="A07:2021-Identification and Authentication Failures"
                )
                reasons.append(f"[+50] {attack_type} detected: '{domain_label}' targets '{legit_name}' ({details}).")
                recommendations.append(f"Do not enter credentials. Always navigate directly to the official {brand.capitalize()} website.")
                
                exp_details = {
                    "suspected_brand": brand.capitalize(),
                    "attack_type": f"{attack_type} / Lookalike Domain",
                    "suspicious_domain": raw_host,
                    "legitimate_domain": legit_primary,
                    "explanation": f"'{raw_host}' utilizes a {attack_type.lower()} ({details}) targeting '{legit_primary}'."
                }
                return True, exp_details

            # 2. Homoglyph / Character Substitution
            if subbed_label == legit_name and domain_label != legit_name:
                add_risk(
                    50, "brand_impersonation", f"Character substitution targeting {brand.capitalize()}", f"'{domain_label}' impersonates '{legit_name}'",
                    severity="High",
                    message=f"Character substitution impersonating {brand.capitalize()}.",
                    why_it_matters="Attackers substitute visually identical letters to trick users into trusting a phishing link.",
                    owasp_ref="A07:2021-Identification and Authentication Failures"
                )
                reasons.append(f"[+50] Character substitution detected: '{domain_label}' attempts to impersonate '{legit_name}'.")
                recommendations.append("Carefully inspect domain characters (e.g., 'I' instead of 'l', '0' instead of 'o').")
                
                exp_details = {
                    "suspected_brand": brand.capitalize(),
                    "attack_type": "Homograph / Lookalike Domain",
                    "suspicious_domain": raw_host,
                    "legitimate_domain": legit_primary,
                    "explanation": f"'{raw_host}' substitutes visually confusing characters to imitate '{legit_primary}'."
                }
                return True, exp_details

            # 3. High Edit Similarity Ratio
            dist = Levenshtein.distance(domain_label, legit_name)
            fuzz_ratio = fuzz.ratio(domain_label, legit_name)
            if (dist <= 2 or (fuzz_ratio > 82 and fuzz_ratio < 100)) and domain_label != legit_name:
                add_risk(
                    50, "brand_impersonation", f"Typosquatting domain targeting {brand.capitalize()}", f"Edit distance {dist} to '{legit_name}'",
                    severity="High",
                    message=f"Typosquatting domain targeting {brand.capitalize()}.",
                    why_it_matters="Typosquatting domains exploit common user typing mistakes to harvest login credentials.",
                    owasp_ref="A07:2021-Identification and Authentication Failures"
                )
                reasons.append(f"[+50] Lookalike domain detected: '{domain_label}' is suspiciously similar to '{legit_name}' (Similarity: {fuzz_ratio:.1f}%).")
                recommendations.append(f"Do not enter credentials. Always navigate directly to the official {brand.capitalize()} website.")
                
                exp_details = {
                    "suspected_brand": brand.capitalize(),
                    "attack_type": "Typosquatting / Lookalike Domain",
                    "suspicious_domain": raw_host,
                    "legitimate_domain": legit_primary,
                    "explanation": f"'{raw_host}' is highly similar (Levenshtein distance: {dist}) to '{legit_primary}'."
                }
                return True, exp_details

            # 4. Punycode Unicode IDN Homograph
            norm_decoded = unicodedata.normalize('NFKD', decoded_domain).encode('ASCII', 'ignore').decode('utf-8')
            norm_label = norm_decoded.split('.')[0] if '.' in norm_decoded else norm_decoded
            if raw_host.startswith('xn--') and (brand in norm_decoded or fuzz.ratio(norm_label, legit_name) > 75):
                add_risk(
                    60, "brand_impersonation", f"Unicode Homograph attack targeting {brand.capitalize()}", f"Punycode '{raw_host}' decodes to '{decoded_domain}'",
                    severity="Critical",
                    message=f"Unicode IDN homograph attack targeting {brand.capitalize()}.",
                    why_it_matters="Unicode homographs render identical-looking foreign characters to fool human eyes.",
                    owasp_ref="A07:2021-Identification and Authentication Failures"
                )
                reasons.append(f"[+60] Unicode homograph attack detected: Punycode decodes to '{decoded_domain}' impersonating '{legit_name}'.")
                
                exp_details = {
                    "suspected_brand": brand.capitalize(),
                    "attack_type": "Unicode Homograph Attack",
                    "suspicious_domain": raw_host,
                    "legitimate_domain": legit_primary,
                    "explanation": f"The Punycode domain decodes to '{decoded_domain}', which visually mimics the legitimate brand domain '{legit_primary}'."
                }
                return True, exp_details

            # 5. Keyword Impersonation
            if brand in target_url.lower() and not is_official_brand_domain:
                add_risk(
                    50, "brand_impersonation", f"Brand keyword abuse targeting {brand.capitalize()}", f"URL contains '{brand}' on host '{raw_host}'",
                    severity="High",
                    message=f"Brand keyword abuse targeting {brand.capitalize()}.",
                    why_it_matters="Attackers include brand keywords in paths or subdomains to induce false trust.",
                    owasp_ref="A07:2021-Identification and Authentication Failures"
                )
                reasons.append(f"[+50] Brand impersonation detected: URL contains '{brand}' but is hosted on an unofficial domain.")
                recommendations.append(f"Do not enter credentials. Always navigate directly to the official {brand.capitalize()} website.")
                
                exp_details = {
                    "suspected_brand": brand.capitalize(),
                    "attack_type": "Keyword Impersonation",
                    "suspicious_domain": raw_host,
                    "legitimate_domain": legit_primary,
                    "explanation": f"The URL contains the brand keyword '{brand}' but is hosted on an unofficial domain ({raw_host})."
                }
                return True, exp_details

        # 6. Mixed Unicode Script Detection
        script_info = detect_mixed_scripts(decoded_domain)
        if script_info["is_mixed"]:
            scripts_str = ", ".join(script_info["scripts"])
            add_risk(
                30, "brand_impersonation", "Mixed Unicode scripts in domain", f"Scripts: {scripts_str}",
                severity="High",
                message="Domain contains mixed Unicode scripts.",
                why_it_matters="Mixing characters from different alphabets (e.g., Latin and Cyrillic) is a classic homograph attack vector.",
                owasp_ref="A07:2021-Identification and Authentication Failures"
            )
            reasons.append(f"[+30] Mixed character scripts detected in domain ({scripts_str}).")

        return False, None

    def _analyze_page_content(self, html_content: str, target_url: str, raw_host: str, domain: str, add_risk, reasons: list, recommendations: list):
        """Engine 5: HTML, Forms & DOM Content Inspection Engine."""
        html_lower = html_content.lower()

        # 1. Login Form & Form Action Inspection
        form_matches = re.findall(r'<form[^>]*>', html_content, re.IGNORECASE)
        has_password_input = bool(re.search(r'<input[^>]*type=["\']password["\']', html_content, re.IGNORECASE))

        if form_matches and has_password_input:
            actions = re.findall(r'action=["\']([^"\']*)["\']', html_content, re.IGNORECASE)
            for action in actions:
                action_clean = action.strip()
                parsed_action = urlparse(action_clean)
                action_host = parsed_action.netloc.lower().split(':')[0] if parsed_action.netloc else ""
                action_root = extract_registered_domain(action_host) if action_host else ""

                if action_host and action_root and action_root != domain:
                    add_risk(
                        40, "page_content", "Cross-domain form submission action", f"Form posts to external host '{action_host}'",
                        severity="High",
                        message="Credential form posts to an external third-party domain.",
                        why_it_matters="Phishing pages load fake forms that submit harvested credentials directly to attacker-controlled external servers.",
                        owasp_ref="A01:2021-Broken Access Control"
                    )
                    reasons.append(f"[+40] Cross-domain credential form action detected (submits to '{action_host}').")
                    recommendations.append("Do not submit credentials. Form posts data to an external untrusted server.")

                elif action_host and (re.match(r"^\d{1,3}(\.\d{1,3}){3}$", action_host) or ":" in action_host):
                    add_risk(
                        45, "page_content", "Form action posts to raw IP address", f"Action IP: '{action_host}'",
                        severity="Critical",
                        message="Credential form submits data directly to an IP address.",
                        why_it_matters="Submitting form data directly to IP addresses bypasses domain logging and SSL host validation.",
                        owasp_ref="A07:2021-Identification and Authentication Failures"
                    )
                    reasons.append(f"[+45] Credential form action posts directly to raw IP address ({action_host}).")

                elif action_clean in ["#", "", "javascript:void(0)", "javascript:void(0);", "javascript:;"]:
                    add_risk(
                        20, "page_content", "Form action uses empty/hash target with JS submission", f"Action: '{action_clean}'",
                        severity="Medium",
                        message="Form action uses empty or JavaScript handler target.",
                        why_it_matters="Phishing pages often override form actions with JavaScript event handlers to capture credentials silently."
                    )
                    reasons.append("[+20] Form action uses empty or JavaScript handler target.")

                elif target_url.startswith("https://") and action_clean.startswith("http://"):
                    add_risk(
                        35, "page_content", "Insecure HTTP form submission target from HTTPS page", f"Action: '{action_clean}'",
                        severity="High",
                        message="HTTPS page submits credentials over unencrypted HTTP.",
                        why_it_matters="Submitting sensitive credentials from HTTPS to HTTP exposes plaintext data over the wire.",
                        owasp_ref="A02:2021-Cryptographic Failures"
                    )
                    reasons.append("[+35] Insecure HTTP form submission target from HTTPS page.")

        # 2. External Brand Asset Harvesting Ratio
        asset_urls = re.findall(r'(?:src|href)=["\'](https?://[^"\']+)["\']', html_content, re.IGNORECASE)
        if len(asset_urls) >= 3:
            official_asset_count = 0
            for asset in asset_urls:
                asset_host = urlparse(asset).netloc.lower().split(':')[0]
                asset_root = extract_registered_domain(asset_host)
                for brand, legit_doms in self.KNOWN_BRANDS.items():
                    if any(asset_root == extract_registered_domain(ld) for ld in legit_doms):
                        official_asset_count += 1
                        break
            
            ratio = official_asset_count / len(asset_urls)
            if ratio >= 0.35:
                add_risk(
                    35, "page_content", "Scraped official brand asset harvesting", f"{int(ratio*100)}% of page media loaded from official brand CDNs",
                    severity="High",
                    message="Site scrapes official brand images and assets directly from legitimate CDNs.",
                    why_it_matters="Phishing kits copy CSS/images directly from official brand sites to visually clone login portals.",
                    owasp_ref="A07:2021-Identification and Authentication Failures"
                )
                reasons.append(f"[+35] Brand asset harvesting detected ({int(ratio*100)}% of assets loaded from official brand CDNs).")

        # 3. Social Engineering Urgency Keywords
        urgency_patterns = [
            'account suspended', 'account limited', 'verify your identity', 'verify your account',
            'unusual activity detected', 'security alert', 'action required', 'confirm your password',
            'unauthorized login', 'claim your reward', 'account termination', 'update payment method',
            'suspended within 24 hours', 'immediate action required'
        ]
        matched_urgency = [p for p in urgency_patterns if p in html_lower]
        if len(matched_urgency) >= 2:
            add_risk(
                25, "page_content", "Social engineering urgency triggers", f"Keywords: {', '.join(matched_urgency[:3])}",
                severity="Medium",
                message="Social engineering high-pressure urgency text present in page body.",
                why_it_matters="Phishers rely on artificial urgency to induce panic and force users into giving credentials.",
                owasp_ref="A07:2021-Identification and Authentication Failures"
            )
            reasons.append(f"[+25] Social engineering urgency text detected: {', '.join(matched_urgency[:3])}.")

    def _analyze_javascript(self, html_content: str, target_url: str, add_risk, reasons: list, recommendations: list):
        """Engine 6: JavaScript Code Obfuscation, Anti-Analysis & Keylogging Engine."""
        # 1. Code Obfuscation & Packing
        obfuscation_patterns = [
            r'eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*r',
            r'String\.fromCharCode\s*\(',
            r'unescape\s*\(\s*["\']%[0-9a-fA-F]',
            r'\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}',
            r'atob\s*\(\s*["\'][A-Za-z0-9+/=]{20,}["\']\s*\)'
        ]
        found_obfuscations = []
        for pat in obfuscation_patterns:
            if re.search(pat, html_content):
                found_obfuscations.append(pat)

        if len(found_obfuscations) >= 1:
            add_risk(
                30, "javascript_analysis", "Obfuscated or packed JavaScript execution", "Detected packed JS / string encoding",
                severity="High",
                message="Heavily obfuscated or packed JavaScript present on page.",
                why_it_matters="Phishing kits obfuscate client-side JS scripts to hide credential exfiltration destinations from security analysts.",
                owasp_ref="A03:2021-Injection"
            )
            reasons.append("[+30] Obfuscated or packed JavaScript detected on page.")

        # 2. Anti-Analysis & Evasion Techniques
        evasion_patterns = [
            r'contextmenu', r'preventDefault\s*\(\s*\)', r'event\.keyCode\s*==\s*123',
            r'Ctrl\s*\+\s*Shift\s*\+\s*I', r'navigator\.webdriver', r'window\.callPhantom', r'_phantom'
        ]
        found_evasions = [p for p in evasion_patterns if re.search(p, html_content, re.IGNORECASE)]
        if len(found_evasions) >= 2:
            add_risk(
                30, "javascript_analysis", "JavaScript anti-debugging and crawler evasion code", f"Features: {', '.join(found_evasions[:3])}",
                severity="High",
                message="Anti-debugging and right-click/F12 inspection prevention scripts active.",
                why_it_matters="Attackers block right-click and F12 DevTools shortcuts to hinder security inspection.",
                owasp_ref="A07:2021-Identification and Authentication Failures"
            )
            reasons.append("[+30] JavaScript anti-debugging and crawler evasion code detected.")

        # 3. Keyloggers & Dynamic Redirections
        keylogger_found = bool(re.search(r'addEventListener\s*\(\s*["\']key(?:down|press|up)["\']', html_content, re.IGNORECASE))
        timer_redirect_found = bool(re.search(r'setTimeout\s*\([^)]*location\.(?:href|replace)', html_content, re.IGNORECASE))

        if keylogger_found:
            add_risk(
                35, "javascript_analysis", "JavaScript input keylogging listener", "Event listener for keypress/keydown attached to input fields",
                severity="High",
                message="Client-side JavaScript input keylogger listener active.",
                why_it_matters="Keylogging scripts stream keystrokes in real-time to remote servers as the user types.",
                owasp_ref="A07:2021-Identification and Authentication Failures"
            )
            reasons.append("[+35] Client-side JavaScript input keylogger listener active.")

        if timer_redirect_found:
            add_risk(
                25, "javascript_analysis", "Automated timer-based script redirection", "setTimeout redirection script present",
                severity="Medium",
                message="Automated timer redirection script present.",
                why_it_matters="Delayed redirects redirect users away after stealing credentials to disguise the attack."
            )
            reasons.append("[+25] Automated timer-based script redirection present.")

    def _analyze_visual_brand(self, html_content: str, target_url: str, raw_host: str, add_risk, reasons: list, recommendations: list):
        """Engine 7: Visual Brand, Favicon & Page Title Alignment Engine."""
        # 1. Favicon Inspection & Hijacking
        fav_links = re.findall(r'<link[^>]*rel=["\'](?:shortcut )?icon["\'][^>]*href=["\']([^"\']+)["\']', html_content, re.IGNORECASE)
        for fav in fav_links:
            parsed_fav = urlparse(fav)
            fav_host = parsed_fav.netloc.lower().split(':')[0] if parsed_fav.netloc else ""
            fav_root = extract_registered_domain(fav_host) if fav_host else ""
            
            if fav_host and fav_root and fav_root != extract_registered_domain(raw_host):
                for brand, legit_doms in self.KNOWN_BRANDS.items():
                    if any(fav_root == extract_registered_domain(ld) for ld in legit_doms):
                        add_risk(
                            35, "visual_brand", f"Official {brand.capitalize()} favicon hijacking", f"Favicon loaded from '{fav_host}'",
                            severity="High",
                            message=f"Official {brand.capitalize()} favicon loaded from official CDN on unofficial domain.",
                            why_it_matters="Loading official brand favicons tricks browser tabs into displaying legitimate brand icons.",
                            owasp_ref="A07:2021-Identification and Authentication Failures"
                        )
                        reasons.append(f"[+35] Cross-domain official {brand.capitalize()} favicon hijacking detected.")
                        break

        # 2. Official Brand Logo Image Embedded
        img_tags = re.findall(r'<img[^>]+>', html_content, re.IGNORECASE)
        for img in img_tags:
            alt_match = re.search(r'alt=["\']([^"\']+)["\']', img, re.IGNORECASE)
            src_match = re.search(r'src=["\']([^"\']+)["\']', img, re.IGNORECASE)
            alt_text = alt_match.group(1).lower() if alt_match else ""
            src_text = src_match.group(1).lower() if src_match else ""

            for brand in self.KNOWN_BRANDS.keys():
                if (f"{brand} logo" in alt_text or f"{brand}-logo" in src_text or f"{brand}_logo" in src_text) and not extract_registered_domain(raw_host) in self.KNOWN_BRANDS[brand]:
                    add_risk(
                        30, "visual_brand", f"Embedded official {brand.capitalize()} logo image", f"Image tag: {img[:60]}...",
                        severity="High",
                        message=f"Official {brand.capitalize()} logo image present on unofficial domain.",
                        why_it_matters="Attackers display official logos to create a visual clone of legitimate portals."
                    )
                    reasons.append(f"[+30] Official {brand.capitalize()} logo image embedded on unofficial domain.")
                    break

        # 3. Visual Title / Header Alignment
        title_match = re.search(r'<title[^>]*>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
        h1_matches = re.findall(r'<h[12][^>]*>(.*?)</h[12]>', html_content, re.IGNORECASE | re.DOTALL)
        combined_headers = (title_match.group(1) if title_match else "") + " " + " ".join(h1_matches)
        combined_headers = combined_headers.lower()

        brand_login_prompts = {
            'microsoft': ['sign in to your microsoft account', 'microsoft online login', 'sign in to office 365'],
            'paypal': ['log in to your paypal account', 'paypal checkout', 'pay with paypal'],
            'google': ['sign in - google accounts', 'google sign-in', 'log in with google'],
            'netflix': ['netflix sign in', 'watch netflix'],
            'apple': ['sign in to icloud', 'apple id sign in'],
            'coinbase': ['sign in to coinbase', 'coinbase pro login']
        }

        for brand, prompts in brand_login_prompts.items():
            if any(prompt in combined_headers for prompt in prompts) and extract_registered_domain(raw_host) not in self.KNOWN_BRANDS[brand]:
                add_risk(
                    40, "visual_brand", f"Visual {brand.capitalize()} login title header on unofficial host", f"Header matches '{brand}' login prompt",
                    severity="High",
                    message=f"Visual {brand.capitalize()} login page header present on unofficial host.",
                    why_it_matters="The page title and headings claim to be an official sign-in portal for a brand on an unrelated domain.",
                    owasp_ref="A07:2021-Identification and Authentication Failures"
                )
                reasons.append(f"[+40] Visual {brand.capitalize()} login title header detected on unofficial host.")
                break

    def _generate_verdict_explanation(
        self, 
        verdict: str, 
        risk_score: int, 
        confidence_score: int, 
        is_official: bool, 
        matched_brand: str, 
        impersonation_detected: bool, 
        impersonation_details: dict, 
        reasons: list, 
        categories: dict,
        target_url: str,
        raw_host: str
    ) -> str:
        """Generates a detailed plain-English narrative synthesis explaining the verdict decision."""
        if is_official:
            brand_name = matched_brand.capitalize() if matched_brand else "the target brand"
            return (
                f"This URL was classified as **Safe** (Risk Score: {risk_score}/100, Confidence: {confidence_score}%) "
                f"because the target domain `{raw_host}` was verified as part of the official registered infrastructure "
                f"for **{brand_name}**. Brand impersonation and typosquatting heuristics were automatically bypassed, "
                f"and no risk penalties were applied."
            )
            
        key_signals = []
        for cat_key, cat_val in categories.items():
            for f in cat_val.get("findings", []):
                if f.get("severity") in ["Critical", "High", "Medium"]:
                    key_signals.append(f["message"])
                    
        signal_str = f" Output based on {len(key_signals)} significant risk signal(s): {'; '.join(key_signals[:3])}." if key_signals else ""
        
        if verdict == "Phishing":
            if impersonation_detected and impersonation_details:
                brand = impersonation_details.get("suspected_brand", "a known brand")
                attack_type = impersonation_details.get("attack_type", "Brand Impersonation")
                exp = impersonation_details.get("explanation", "")
                return (
                    f"This URL was classified as **Phishing** (Risk Score: {risk_score}/100, Confidence: {confidence_score}%) "
                    f"due to active **{attack_type}** targeting **{brand}**. {exp}{signal_str} "
                    f"Note: HTTPS encryption alone does NOT guarantee that a website is trustworthy or safe."
                )
            else:
                return (
                    f"This URL was classified as **Phishing** (Risk Score: {risk_score}/100, Confidence: {confidence_score}%) "
                    f"because multiple high-risk indicators aligned across URL structure, domain reputation, HTML form targets, or JavaScript code analysis.{signal_str} "
                    f"Users are advised not to interact with or submit credentials on this page."
                )
        elif verdict == "Suspicious":
            return (
                f"This URL was classified as **Suspicious** (Risk Score: {risk_score}/100, Confidence: {confidence_score}%) "
                f"due to multiple warning indicators that depart from established security baselines.{signal_str} "
                f"Exercise caution before entering any sensitive information."
            )
        else:
            return (
                f"This URL was classified as **Safe** (Risk Score: {risk_score}/100, Confidence: {confidence_score}%) "
                f"because no brand impersonation, typosquatting, or high-risk structural anomalies were detected. "
                f"Always verify the destination domain in your browser address bar before authenticating."
            )
