from typing import Dict, Any
from app.scanners.base_module import BaseModule
from app.scanners.config import ScanConfig
from app.utils.domain_intelligence import classify_redirect, extract_registered_domain

class TyposquattingModule(BaseModule):
    name = "TyposquattingModule"

    def run(self, context: Dict[str, Any], config: ScanConfig) -> Dict[str, Any]:
        initial_domain = context.get("initial_domain", "")
        final_domain = context.get("final_host", initial_domain)
        response_chain = context.get("response_chain", [])
        unreachable = context.get("unreachable", False)

        redirect_intel = classify_redirect(
            orig_url=context.get("original_url", initial_domain),
            orig_host=initial_domain,
            orig_ip=context.get("ip_address", "Unable to resolve IP"),
            final_url=context.get("final_url", initial_domain),
            final_host=final_domain,
            final_ip=context.get("final_ip", "Unable to resolve IP"),
            redirect_chain=response_chain,
            dns_failed=unreachable
        )
        similarity = redirect_intel.get("similarity_score", 0.0)

        findings = []
        deductions = 0

        # Check for host redirect warning or high similarity typosquatting target
        host_redirect_warning = None
        if redirect_intel.get("badge_class") == "danger":
            host_redirect_warning = redirect_intel.get("rationale")
            deductions += 25
            findings.append({
                "severity": "High",
                "confidence": "Verified",
                "evidence": f"{initial_domain} -> {final_domain}",
                "message": "Host Redirection Alert: Redirect chain transitions to an external registered domain.",
                "why_it_matters": "External domain redirects can lead users to unexpected third-party destinations.",
                "owasp_ref": "A01:2021-Broken Access Control",
                "remediation": "Audit redirect configurations to ensure users are not directed to untrusted external sites.",
                "deduction": 25
            })

        # Typosquatting Brand-Protection Analysis (Runs independently of DNS resolution!)
        # e.g., paypai.com normalized to paypai.com has high visual similarity to paypal.com (~0.90+)
        if similarity >= 0.85 and extract_registered_domain(initial_domain) != extract_registered_domain(final_domain):
            if unreachable:
                # Dynamic Brand-Protection Remediation Advice for unreachable domains
                remediation_advice = (
                    f"Brand Protection Alert: The domain '{initial_domain}' is visually similar to '{extract_registered_domain(final_domain)}' "
                    f"(Typosquatting Risk: {round(similarity * 100)}% match). Although currently unreachable (NXDOMAIN), brand protection monitoring "
                    f"and defensive registration are recommended to prevent typosquatting or phishing infrastructure staging."
                )
            else:
                remediation_advice = (
                    f"Audit domain ownership and verify that '{initial_domain}' is officially authorized by "
                    f"the legitimate brand owner of '{extract_registered_domain(final_domain)}'."
                )
            
            findings.append({
                "severity": "Medium" if unreachable else "High",
                "confidence": "High",
                "evidence": f"Domain similarity match: {round(similarity * 100)}%",
                "message": f"Typosquatting / Visual Similarity Risk Detected ({round(similarity * 100)}% match).",
                "why_it_matters": "Visually similar domains (combining homoglyphs or missing dots) are frequently registered for phishing campaigns.",
                "owasp_ref": "A01:2021-Broken Access Control",
                "remediation": remediation_advice,
                "deduction": 0 if unreachable else 15
            })

        score = max(0, 100 - deductions) if not unreachable else "N/A"
        status_str = "Passed" if score != "N/A" and score >= 90 else ("Warning" if score != "N/A" and score >= 75 else ("Not Tested" if unreachable else "Needs Improvement"))

        return {
            "redirect_intel": redirect_intel,
            "host_redirect_warning": host_redirect_warning,
            "category_redirects": {
                "score": score,
                "status": status_str,
                "weight": 0.20,
                "findings": findings,
                "reasons": [f"[{f['severity']}] [-{f['deduction']}] {f['message']}" for f in findings]
            }
        }
