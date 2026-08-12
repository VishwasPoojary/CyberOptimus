from typing import Dict, Any
from app.scanners.base_module import BaseModule
from app.scanners.config import ScanConfig
from app.utils.network import resolve_ip, query_dns_records, fetch_rdap_domain_info

class DNSModule(BaseModule):
    name = "DNSModule"

    def run(self, context: Dict[str, Any], config: ScanConfig) -> Dict[str, Any]:
        initial_domain = context.get("initial_domain", "")
        
        ip_address = resolve_ip(initial_domain)
        dns_failed = (ip_address == "Unable to resolve IP")
        
        dns_records = query_dns_records(initial_domain) if not dns_failed else {
            "A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "CNAME": [],
            "spf": {"present": False, "record": None, "valid": False},
            "dmarc": {"present": False, "policy": "none", "record": None},
            "dnssec": False, "error": "NXDOMAIN - Domain does not resolve"
        }
        
        rdap_info = fetch_rdap_domain_info(initial_domain) if not dns_failed else {
            "rdap_available": False, "creation_date": None, "expiration_date": None,
            "registrar": "Unknown", "domain_age_days": None, "error": "Domain unreachable"
        }

        # Build DNS category evaluation
        findings = []
        deductions = 0
        if dns_failed:
            findings.append({
                "severity": "Critical",
                "confidence": "Verified",
                "evidence": f"DNS query for '{initial_domain}' returned NXDOMAIN / Host Unreachable.",
                "message": f"Domain '{initial_domain}' does not resolve to an active IP address.",
                "why_it_matters": "Unresolvable domains cannot host web services and may indicate abandoned, malformed, or typosquatted infrastructure.",
                "owasp_ref": "A05:2021-Security Misconfiguration",
                "remediation": "Verify domain registration status and DNS A/AAAA record configuration in your authoritative DNS provider.",
                "deduction": 100
            })
            deductions = 100
            dns_status = "Failed"
            score = 0
        else:
            spf_info = dns_records.get("spf", {})
            if spf_info.get("status") == "missing":
                findings.append({
                    "severity": "Low",
                    "confidence": "Verified",
                    "evidence": f"DNS TXT query for apex domain '{initial_domain}' returned {len(dns_records.get('TXT', []))} TXT record(s), but none contained 'v=spf1'.",
                    "message": "SPF (Sender Policy Framework) record is missing.",
                    "why_it_matters": "Missing SPF allows unauthorized mail servers to spoof emails sent from this domain.",
                    "owasp_ref": "A05:2021-Security Misconfiguration",
                    "remediation": "Publish an SPF record in DNS TXT records (e.g., 'v=spf1 mx ~all' or domain-appropriate mail server ip4/include directives).",
                    "deduction": 5
                })
                deductions += 5
            elif spf_info.get("status") == "error":
                findings.append({
                    "severity": "Info",
                    "confidence": "Inconclusive",
                    "evidence": f"SPF DNS query encountered a network/DNS error: {spf_info.get('error')}",
                    "message": "SPF record check inconclusive due to DNS query failure.",
                    "why_it_matters": "DNS lookup failed during evaluation. Verification was skipped to avoid false positive penalties.",
                    "owasp_ref": "A05:2021-Security Misconfiguration",
                    "remediation": "Ensure authoritative DNS servers respond reliably to TXT queries.",
                    "deduction": 0
                })

            dmarc_info = dns_records.get("dmarc", {})
            if dmarc_info.get("status") == "missing":
                findings.append({
                    "severity": "Low",
                    "confidence": "Verified",
                    "evidence": f"DNS TXT query for host '_dmarc.{initial_domain}' returned no 'v=DMARC1' TXT records.",
                    "message": "DMARC policy record is missing.",
                    "why_it_matters": "DMARC instructs receiving mail servers how to handle emails failing SPF or DKIM checks.",
                    "owasp_ref": "A05:2021-Security Misconfiguration",
                    "remediation": "Consider publishing DMARC with p=none initially, monitor authentication reports, and gradually strengthen the policy as appropriate.",
                    "deduction": 5
                })
                deductions += 5
            elif dmarc_info.get("status") == "error":
                findings.append({
                    "severity": "Info",
                    "confidence": "Inconclusive",
                    "evidence": f"DMARC DNS query encountered a network/DNS error: {dmarc_info.get('error')}",
                    "message": "DMARC record check inconclusive due to DNS query failure.",
                    "why_it_matters": "DNS lookup for _dmarc record failed during evaluation. Verification was skipped to avoid false positive penalties.",
                    "owasp_ref": "A05:2021-Security Misconfiguration",
                    "remediation": "Ensure authoritative DNS servers respond reliably to TXT queries for _dmarc subdomain.",
                    "deduction": 0
                })
                
            score = max(0, 100 - deductions)
            dns_status = "Passed" if score >= 90 else ("Warning" if score >= 75 else "Needs Improvement")

        return {
            "ip_address": ip_address,
            "dns_failed": dns_failed,
            "unreachable": dns_failed,
            "dns_records": dns_records,
            "rdap_info": rdap_info,
            "category_dns": {
                "score": score,
                "status": dns_status,
                "weight": 0.15,
                "findings": findings,
                "reasons": [f"[{f['severity']}] [-{f['deduction']}] {f['message']}" for f in findings]
            }
        }
