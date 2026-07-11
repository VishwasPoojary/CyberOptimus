import re
import os
import requests
import dns.resolver
from urllib.parse import urlparse
import whois
from datetime import datetime, timezone
import difflib
import Levenshtein
from rapidfuzz import fuzz
from app.scanners.base_scanner import BaseScanner
from app.utils.network import resolve_ip, check_ssl_certificate

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
            
        # Example GSB Check
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
                
        # (Other APIs would follow a similar pattern here)
        
        return {"configured": True, "malicious": malicious, "results": results}

class PhishingDetector(BaseScanner):
    
    KNOWN_BRANDS = {
        'paypal': ['paypal.com'],
        'apple': ['apple.com'],
        'microsoft': ['microsoft.com'],
        'google': ['google.com'],
        'facebook': ['facebook.com', 'fb.com'],
        'amazon': ['amazon.com'],
        'netflix': ['netflix.com'],
        'bankofamerica': ['bankofamerica.com'],
        'chase': ['chase.com'],
        'wellsfargo': ['wellsfargo.com']
    }
    
    SUSPICIOUS_KEYWORDS = ['login', 'verify', 'update', 'secure', 'account', 'banking', 'auth', 'confirm']
    
    def __init__(self):
        super().__init__()
        self.ti_manager = ThreatIntelligenceManager()
    
    def scan(self, target: str) -> dict:
        if not target.startswith("http"):
            target = "https://" + target
            
        parsed_url = urlparse(target)
        domain = parsed_url.netloc.lower()
        if ':' in domain:
            domain = domain.split(':')[0]
            
        base_domain = domain[4:] if domain.startswith('www.') else domain
        
        # Decode punycode if present
        try:
            decoded_domain = base_domain.encode('utf-8').decode('idna')
        except Exception:
            decoded_domain = base_domain
            
        score = 0
        reasons = []
        recommendations = []
        
        # 1. Use of IP Address
        is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain))
        if is_ip:
            score += 40
            reasons.append("[+40] URL uses an IP address instead of a domain name.")
            recommendations.append("Avoid clicking links that use raw IP addresses for navigation.")
            
        # 2. DNS Analysis
        if not is_ip:
            ip_address = resolve_ip(base_domain)
            if ip_address == "Unable to resolve IP":
                score += 10
                reasons.append("[+10] Domain does not resolve to an IP address.")
                recommendations.append("The domain might be dead, newly registered but inactive, or a typo.")
            else:
                try:
                    txt_records = dns.resolver.resolve(base_domain, 'TXT', lifetime=3)
                    has_spf = any('v=spf1' in rdata.to_text() for rdata in txt_records)
                    if not has_spf:
                        score += 5
                        reasons.append("[+5] Domain lacks an SPF record (common in phishing domains).")
                except Exception:
                    pass
            
        # 3. Advanced Brand Impersonation & Lookalikes
        impersonation_detected = False
        impersonation_details = None
        domain_name = decoded_domain.split('.')[0]
        
        # Normalization for substitution detection
        subbed_domain = domain_name.replace('0', 'o').replace('1', 'l').replace('i', 'l').replace('rn', 'm').replace('vv', 'w')
        
        # Check against known brands
        for brand, legitimate_domains in self.KNOWN_BRANDS.items():
            if is_ip:
                break
                
            # Is it the exact legitimate domain?
            is_legit = False
            for legit_domain in legitimate_domains:
                if base_domain == legit_domain or base_domain.endswith('.' + legit_domain):
                    is_legit = True
                    break
                    
            if is_legit:
                continue # 0 penalty for legit domains
                
            legit_name = brand
            legit_domain = legitimate_domains[0]
            
            # Check for keyword impersonation
            if brand in target.lower():
                score += 50
                reasons.append(f"[+50] Brand impersonation detected: URL contains '{brand}' but is not the legitimate domain.")
                recommendations.append(f"Do not enter credentials. Always navigate directly to the official {brand.capitalize()} website.")
                impersonation_detected = True
                impersonation_details = {
                    "suspected_brand": brand.capitalize(),
                    "attack_type": "Keyword Impersonation",
                    "suspicious_domain": base_domain,
                    "legitimate_domain": legit_domain,
                    "explanation": f"The domain contains the brand keyword '{brand}' but is hosted on an unofficial host."
                }
                break
                
            # Check for character substitution
            if subbed_domain == legit_name and domain_name != legit_name:
                score += 50
                reasons.append(f"[+50] Character substitution detected: '{domain_name}' attempts to impersonate '{legit_name}'.")
                recommendations.append(f"Carefully inspect the domain name for substituted characters (e.g., 'I' instead of 'l', '0' instead of 'o').")
                impersonation_detected = True
                
                subs = []
                # Simple substitution logic explanation
                if 'i' in domain_name or 'I' in domain_name:
                    subs.append("capital I or similar lookalike instead of lowercase l")
                if '0' in domain_name:
                    subs.append("number 0 instead of lowercase o")
                if 'rn' in domain_name:
                    subs.append("'rn' instead of 'm'")
                if 'vv' in domain_name:
                    subs.append("'vv' instead of 'w'")
                    
                explanation = f"'{base_domain}' uses {', '.join(subs)} to imitate '{legit_domain}'." if subs else f"'{base_domain}' uses character substitutions to imitate '{legit_domain}'."
                
                impersonation_details = {
                    "suspected_brand": brand.capitalize(),
                    "attack_type": "Homograph / Lookalike Domain",
                    "suspicious_domain": base_domain,
                    "legitimate_domain": legit_domain,
                    "explanation": explanation
                }
                break
                
            # Check for Levenshtein and RapidFuzz similarity
            dist = Levenshtein.distance(domain_name, legit_name)
            fuzz_ratio = fuzz.ratio(domain_name, legit_name)
            
            if dist == 1 or (fuzz_ratio > 80 and fuzz_ratio < 100):
                score += 50
                reasons.append(f"[+50] Lookalike domain detected: '{domain_name}' is suspiciously similar to '{legit_name}' (Levenshtein dist: {dist}, RapidFuzz: {fuzz_ratio:.1f}%).")
                recommendations.append("This is likely a typosquatting or homograph attack.")
                impersonation_detected = True
                impersonation_details = {
                    "suspected_brand": brand.capitalize(),
                    "attack_type": "Homograph / Lookalike Domain",
                    "suspicious_domain": base_domain,
                    "legitimate_domain": legit_domain,
                    "explanation": f"'{base_domain}' is highly similar (Levenshtein distance: {dist}) to '{legit_domain}'."
                }
                break
                
            # Unicode homograph (punycode)
            if base_domain.startswith('xn--') and (brand in decoded_domain or fuzz.ratio(decoded_domain, legit_name) > 80):
                score += 60
                reasons.append(f"[+60] Unicode homograph attack detected: Punycode domain decodes to '{decoded_domain}' impersonating '{legit_name}'.")
                impersonation_detected = True
                impersonation_details = {
                    "suspected_brand": brand.capitalize(),
                    "attack_type": "Unicode Homograph Attack",
                    "suspicious_domain": base_domain,
                    "legitimate_domain": legit_domain,
                    "explanation": f"The Punycode domain decodes to '{decoded_domain}', which visually mimics the legitimate brand domain '{legit_domain}'."
                }
                break

        # 4. Domain Age Check (WHOIS)
        if not is_ip:
            try:
                domain_info = whois.whois(base_domain)
                creation_date = domain_info.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                    
                if creation_date:
                    if isinstance(creation_date, datetime):
                        now = datetime.now(timezone.utc) if creation_date.tzinfo else datetime.now()
                        age_days = (now - creation_date).days
                        if age_days < 30:
                            score += 25
                            reasons.append(f"[+25] Domain is very new (registered {age_days} days ago).")
                            recommendations.append("Exercise extreme caution with newly registered domains.")
            except Exception:
                pass 
            
        # 5. Suspicious Keywords
        found_keywords = [kw for kw in self.SUSPICIOUS_KEYWORDS if kw in target.lower()]
        if found_keywords:
            score += 20
            reasons.append(f"[+20] Suspicious keywords found in URL: {', '.join(found_keywords)}.")
            recommendations.append("Be wary of URLs insisting on 'login' or 'verification' from unverified sources.")
            
        # 6. Subdomains
        if domain.count('.') > 3:
            score += 15
            reasons.append("[+15] High number of subdomains detected (often used to obscure the true domain).")
            recommendations.append("Check the root domain to verify the actual destination.")
            
        # 7. URL Length
        if len(target) > 75:
            score += 10
            reasons.append("[+10] Unusually long URL (can be used to hide malicious parameters).")
            
        # 8. URL Encoding/Obfuscation
        if target.count('%') > 5:
            score += 10
            reasons.append("[+10] High amount of URL encoding detected (often used to obfuscate payloads).")
            
        # 9. HTTPS and SSL Certificate Check
        if not target.startswith("https://"):
            score += 10
            reasons.append("[+10] Connection is not secured with HTTPS.")
        else:
            ssl_info = check_ssl_certificate(domain)
            if not ssl_info.get("valid"):
                score += 20
                reasons.append("[+20] HTTPS is used, but the SSL certificate is invalid or untrusted.")
                recommendations.append("An invalid certificate might indicate an active man-in-the-middle attack or poorly configured phishing site.")

        # 10. Threat Intelligence API Architecture
        ti_result = self.ti_manager.check_url(target)
        if not ti_result["configured"]:
            reasons.extend(ti_result["results"])
        elif ti_result["malicious"]:
            score += 50
            reasons.extend(ti_result["results"])
            recommendations.append("Immediately close the page. The site has been confirmed as malicious by external intelligence.")
        else:
            reasons.extend(ti_result["results"])

        # Cap score at 100
        score = min(score, 100)
        
        # Determine Threat Level
        if score >= 75:
            threat_level = "Critical"
        elif score >= 50:
            threat_level = "High"
        elif score >= 25:
            threat_level = "Medium"
        else:
            threat_level = "Low"
            
        if not recommendations and score < 25:
            recommendations.append("URL appears safe based on current heuristics, but always remain vigilant.")

        return {
            "url": target,
            "domain": domain,
            "risk_score": score,
            "threat_level": threat_level,
            "reasons": reasons,
            "recommendations": recommendations,
            "impersonation_detected": impersonation_detected,
            "impersonation_details": impersonation_details,
            "status": "success"
        }
