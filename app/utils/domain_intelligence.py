import re
import unicodedata
from typing import Dict, Any, List

# Common 2-level TLDs for root domain extraction
TWO_LEVEL_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk",
    "co.in", "net.in", "org.in", "gen.in", "ind.in", "firm.in",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp",
    "com.br", "net.br", "org.br", "gov.br",
    "co.za", "org.za", "web.za", "net.za",
    "com.sg", "net.sg", "org.sg", "edu.sg",
    "com.mx", "org.mx", "gob.mx", "edu.mx",
    "co.nz", "net.nz", "org.nz", "govt.nz"
}

def extract_registered_domain(hostname: str) -> str:
    """Extracts the registered root domain from a hostname (e.g. www.google.com -> google.com)."""
    if not hostname:
        return ""
    
    # Strip port if present and convert to lowercase
    host = hostname.split(":")[0].lower().strip(".")
    parts = host.split(".")
    
    if len(parts) <= 2:
        return host
        
    # Check if last 2 parts match a known two-level TLD
    possible_two_level = f"{parts[-2]}.{parts[-1]}"
    if possible_two_level in TWO_LEVEL_TLDS and len(parts) >= 3:
        return f"{parts[-3]}.{possible_two_level}"
        
    return f"{parts[-2]}.{parts[-1]}"

def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes the Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
        
    return previous_row[-1]

def compute_similarity(domain1: str, domain2: str) -> float:
    """Computes a normalized similarity score (0.0 to 1.0) between two domain roots."""
    d1 = domain1.split(".")[0].lower()
    d2 = domain2.split(".")[0].lower()
    
    max_len = max(len(d1), len(d2))
    if max_len == 0:
        return 1.0
        
    dist = levenshtein_distance(d1, d2)
    similarity = round(1.0 - (dist / max_len), 3)
    return max(0.0, min(1.0, similarity))

def normalize_homoglyphs(domain: str) -> str:
    """Normalizes common visual character substitutions (homoglyphs) across ASCII, Cyrillic, and Greek."""
    substitutions = {
        '0': 'o',
        '1': 'l',
        '3': 'e',
        '4': 'a',
        '5': 's',
        '8': 'b',
        'rn': 'm',
        'vv': 'w',
        'cl': 'd',
        # Cyrillic homoglyphs
        'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y', 'і': 'i', 'ѕ': 's', 'ԁ': 'd',
        # Greek homoglyphs
        'α': 'a', 'ο': 'o', 'ρ': 'p', 'υ': 'u', 'ν': 'v', 'κ': 'k'
    }
    normalized = domain.lower()
    for sub, target in substitutions.items():
        normalized = normalized.replace(sub, target)
    return normalized

def detect_mixed_scripts(text: str) -> dict:
    """Detects whether a domain or text contains characters from multiple Unicode scripts (e.g. Latin + Cyrillic)."""
    if not text:
        return {"is_mixed": False, "scripts": []}
    
    scripts = set()
    for char in text:
        if not char.isalpha():
            continue
        try:
            script_name = unicodedata.name(char).split()[0]
            # Map script names (CYRILLIC, LATIN, GREEK, ARABIC, CJK, etc.)
            scripts.add(script_name)
        except ValueError:
            pass
            
    is_mixed = len(scripts) > 1
    return {
        "is_mixed": is_mixed,
        "scripts": list(scripts)
    }

def detect_string_edit_attacks(domain_label: str, brand_name: str) -> dict:
    """Analyzes exact edit attack types between a domain label and a legitimate brand name.
    
    Attack types detected:
    - Transposition (adjacent swapped characters, e.g. micorsoft vs microsoft, payapl vs paypal)
    - Insertion (extra character added, e.g. paypaal vs paypal)
    - Deletion (character omitted, e.g. paypl vs paypal)
    - Substitution (character replaced, e.g. paypaI vs paypal, m1crosoft vs microsoft)
    """
    d = domain_label.lower()
    b = brand_name.lower()
    
    if d == b:
        return {"is_attack": False, "attack_type": None, "details": ""}
        
    dist = levenshtein_distance(d, b)
    if dist > 2:
        return {"is_attack": False, "attack_type": None, "details": ""}
        
    len_diff = len(d) - len(b)
    
    # 1. Transposition check (Swapped adjacent characters, same length)
    if len_diff == 0 and dist <= 2:
        diff_indices = [i for i in range(len(d)) if d[i] != b[i]]
        if len(diff_indices) == 2 and diff_indices[1] == diff_indices[0] + 1:
            if d[diff_indices[0]] == b[diff_indices[1]] and d[diff_indices[1]] == b[diff_indices[0]]:
                return {
                    "is_attack": True,
                    "attack_type": "Transposition Attack",
                    "details": f"Adjacent characters swapped: '{d[diff_indices[0]]}{d[diff_indices[1]]}' instead of '{b[diff_indices[0]]}{b[diff_indices[1]]}' in '{b}'"
                }

    # 2. Insertion check (Extra character added to brand name)
    if len_diff == 1 and dist == 1:
        for i in range(len(d)):
            if d[:i] + d[i+1:] == b:
                return {
                    "is_attack": True,
                    "attack_type": "Insertion Attack",
                    "details": f"Extra character '{d[i]}' inserted into brand name '{b}'"
                }

    # 3. Deletion check (Character omitted from brand name)
    if len_diff == -1 and dist == 1:
        for i in range(len(b)):
            if b[:i] + b[i+1:] == d:
                return {
                    "is_attack": True,
                    "attack_type": "Deletion Attack",
                    "details": f"Character '{b[i]}' omitted from brand name '{b}'"
                }

    # 4. Substitution check (Character replaced)
    if len_diff == 0 and dist == 1:
        diff_idx = next((i for i in range(len(d)) if d[i] != b[i]), None)
        if diff_idx is not None:
            return {
                "is_attack": True,
                "attack_type": "Substitution Attack",
                "details": f"Character '{d[diff_idx]}' substituted for '{b[diff_idx]}' in brand name '{b}'"
            }

    if dist <= 2:
        return {
            "is_attack": True,
            "attack_type": "Typosquatting Attack",
            "details": f"Edit distance {dist} to legitimate brand '{b}'"
        }
        
    return {"is_attack": False, "attack_type": None, "details": ""}

def detect_typosquatting(orig_host: str, final_host: str) -> dict:
    """Analyzes domain similarity between original and final hosts.
    
    Returns evidence-based indicators without concluding impersonation
    unless supported by concrete homoglyph or TLD shift evidence.
    """
    orig_root = extract_registered_domain(orig_host)
    final_root = extract_registered_domain(final_host)
    
    if orig_root == final_root:
        return {"has_homoglyph_evidence": False, "has_tld_shift": False, "reason": "Same registered domain", "similarity": 1.0}

    orig_name = orig_root.split(".")[0]
    final_name = final_root.split(".")[0]
    
    orig_tld = orig_root.split(".", 1)[1] if "." in orig_root else ""
    final_tld = final_root.split(".", 1)[1] if "." in final_root else ""
    
    similarity = compute_similarity(orig_root, final_root)
    norm_orig = normalize_homoglyphs(orig_name)
    norm_final = normalize_homoglyphs(final_name)
    
    reasons = []
    has_homoglyph_evidence = False
    has_tld_shift = False
    
    if norm_orig == norm_final and orig_name != final_name:
        has_homoglyph_evidence = True
        reasons.append("Character homoglyph substitution detected (e.g. 0/O, 1/l, rn/m)")
        
    if orig_name == final_name and orig_tld != final_tld:
        has_tld_shift = True
        reasons.append(f"TLD shift detected (.{orig_tld} -> .{final_tld})")
        
    if similarity >= 0.5 and orig_name != final_name and not has_homoglyph_evidence:
        reasons.append(f"High edit similarity ({int(similarity * 100)}%) between domain labels")
        
    reason_str = " | ".join(reasons) if reasons else "Different registered root domain"
    
    return {
        "has_homoglyph_evidence": has_homoglyph_evidence,
        "has_tld_shift": has_tld_shift,
        "reason": reason_str,
        "similarity": similarity
    }

POPULAR_BRAND_TARGETS = [
    "paypal.com", "google.com", "microsoft.com", "apple.com",
    "amazon.com", "facebook.com", "instagram.com", "whatsapp.com",
    "twitter.com", "linkedin.com", "github.com", "discord.com",
    "telegram.org", "netflix.com", "spotify.com", "coinbase.com",
    "binance.com", "bankofamerica.com", "chase.com", "wellsfargo.com",
    "citi.com", "hsbc.com", "sbi.co.in", "icicibank.com", "hdfcbank.com",
    "phonepe.com", "paytm.com", "adobe.com", "cloudflare.com",
    "chatgpt.com", "openai.com", "x.com", "youtube.com", "tiktok.com",
    "garena.com", "reddit.com", "wikipedia.org", "yahoo.com"
]

COMMON_TLDS = ["com", "org", "net", "io", "in", "co.uk", "gov", "edu", "ai", "dev", "me", "co", "app", "biz", "info", "xyz", "online"]

def analyze_domain_similarity(orig_host: str, final_host: str = None) -> dict:
    """Calculates domain similarity and typosquatting indicators independently of DNS resolution.
    
    If final_host is provided and differs from orig_host, compares orig_host vs final_host.
    Otherwise, compares orig_host against known popular brand targets.
    """
    orig_root = extract_registered_domain(orig_host)
    if not orig_root:
        orig_root = orig_host
        
    if final_host and extract_registered_domain(final_host) != orig_root:
        return detect_typosquatting(orig_host, final_host)
        
    orig_name = orig_root.split(".")[0].lower()
    norm_orig = normalize_homoglyphs(orig_name)
    
    best_match = None
    best_sim = 0.0
    has_homoglyph = False
    attack_details = None
    
    # 1. Check for missing dot before TLD (e.g. githubcom -> github.com)
    reconstructed_domain = None
    if "." not in orig_host.strip("."):
        clean_h = orig_host.lower().strip(".")
        for tld in COMMON_TLDS:
            if clean_h.endswith(tld) and len(clean_h) > len(tld):
                label = clean_h[:-len(tld)]
                reconstructed_domain = f"{label}.{tld}"
                break
                
    for brand_dom in POPULAR_BRAND_TARGETS:
        brand_root = extract_registered_domain(brand_dom)
        brand_name = brand_root.split(".")[0].lower()
        
        if orig_root.lower() == brand_root.lower():
            return {
                "has_homoglyph_evidence": False,
                "has_tld_shift": False,
                "has_missing_dot": False,
                "reason": f"Exact match for brand domain '{brand_root}'",
                "similarity": 1.0,
                "target_brand": brand_root
            }
            
        if reconstructed_domain and reconstructed_domain.lower() == brand_root.lower():
            return {
                "has_homoglyph_evidence": False,
                "has_tld_shift": False,
                "has_missing_dot": True,
                "reason": f"Malformed domain (missing dot before TLD) targeting {brand_root}",
                "similarity": 0.90,
                "target_brand": brand_root
            }
            
        sim = compute_similarity(orig_root, brand_root)
        norm_brand = normalize_homoglyphs(brand_name)
        
        is_homoglyph = (norm_orig == norm_brand and orig_name != brand_name)
        edit_attack = detect_string_edit_attacks(orig_name, brand_name)
        
        if edit_attack.get("is_attack"):
            best_sim = max(sim, 0.85)
            best_match = brand_root
            attack_details = f"{edit_attack['attack_type']}: {edit_attack['details']}"
            break
        elif is_homoglyph or sim > best_sim:
            best_sim = sim
            best_match = brand_root
            if is_homoglyph:
                has_homoglyph = True
                best_sim = max(best_sim, 0.833)
                break
                
    if best_match and (attack_details or has_homoglyph or best_sim >= 0.6):
        if attack_details:
            reason = f"Potential typosquatting targeting {best_match} ({attack_details})"
        elif has_homoglyph:
            reason = f"Character homoglyph substitution targeting {best_match}"
        else:
            reason = f"High visual similarity ({int(best_sim * 100)}%) targeting {best_match}"
            
        return {
            "has_homoglyph_evidence": has_homoglyph,
            "has_tld_shift": False,
            "has_missing_dot": False,
            "reason": reason,
            "similarity": best_sim,
            "target_brand": best_match
        }
        
    return {
        "has_homoglyph_evidence": False,
        "has_tld_shift": False,
        "has_missing_dot": False,
        "reason": "Standard registered domain",
        "similarity": 1.0,
        "target_brand": None
    }

def classify_redirect(
    orig_url: str,
    orig_host: str,
    orig_ip: str,
    final_url: str,
    final_host: str,
    final_ip: str,
    redirect_chain: List[dict],
    dns_failed: bool
) -> dict:
    """Classifies redirect behavior into Safe Canonical, Suspicious Host Change, Critical Redirect, or DNS Failure."""
    sim_analysis = analyze_domain_similarity(orig_host, final_host if not dns_failed else None)
    sim_score = sim_analysis["similarity"]
    
    if dns_failed or orig_ip in ["Unable to resolve IP", "Unknown"]:
        target_brand = sim_analysis.get("target_brand")
        if sim_analysis.get("has_missing_dot") and target_brand:
            rationale = (
                f"Analysis could not be completed because the domain does not resolve (NXDOMAIN). "
                f"Domain similarity analysis identified a malformed domain targeting {target_brand} (missing dot before TLD). "
                f"HTTP, TLS, Header, Cookie, and Server analysis were skipped."
            )
        elif sim_analysis.get("has_homoglyph_evidence") and target_brand:
            rationale = (
                f"Analysis could not be completed because the domain does not resolve (NXDOMAIN). "
                f"Domain similarity analysis identified a potential typosquatting/homoglyph target: {target_brand} ({int(sim_score * 100)}% similarity). "
                f"HTTP, TLS, Header, Cookie, and Server analysis were skipped."
            )
        elif target_brand and sim_score >= 0.6:
            rationale = (
                f"Analysis could not be completed because the domain does not resolve (NXDOMAIN). "
                f"Domain similarity analysis identified a potential typosquatting/lookalike target: {target_brand} ({int(sim_score * 100)}% similarity). "
                f"HTTP, TLS, Header, Cookie, and Server analysis were skipped."
            )
        else:
            rationale = (
                f"Analysis could not be completed because the domain does not resolve (NXDOMAIN). "
                f"HTTP, TLS, Header, Cookie, and Server analysis were skipped."
            )
            
        return {
            "classification": "DNS Resolution Failed (NXDOMAIN)",
            "status": "Unreachable",
            "severity": "Info",
            "deduction": 0,
            "rationale": rationale,
            "similarity_score": sim_score,
            "badge_class": "warning"
        }
        
    hop_count = len(redirect_chain)
    has_loop = False
    seen_urls = set()
    for hop in redirect_chain:
        u = hop.get("url")
        if u:
            if u in seen_urls:
                has_loop = True
                break
            seen_urls.add(u)
            
    if has_loop:
        return {
            "classification": "Redirect Loop Detected",
            "status": "High",
            "severity": "High",
            "deduction": 30,
            "rationale": f"Circular redirect loop detected during request execution. The server repeatedly redirected back to a previously visited URL.",
            "similarity_score": 1.0,
            "badge_class": "danger"
        }
        
    if hop_count > 5:
        return {
            "classification": "Excessive Redirects",
            "status": "Medium",
            "severity": "Medium",
            "deduction": 15,
            "rationale": f"Excessive redirect chain detected ({hop_count} hops). Standard security baselines advise limiting redirects to under 5 steps.",
            "similarity_score": 1.0,
            "badge_class": "warning"
        }

    orig_root = extract_registered_domain(orig_host)
    final_root = extract_registered_domain(final_host)
    
    if hop_count == 0:
        return {
            "classification": "No Redirect Detected",
            "status": "Safe",
            "severity": "Info",
            "deduction": 0,
            "rationale": "No redirect detected. Target URL responded directly with HTTP status 200.",
            "similarity_score": 1.0,
            "badge_class": "success"
        }
    
    if orig_root.lower() == final_root.lower():
        transition_desc = "Standard canonical host/protocol transition."
        class_title = "Safe Canonical Redirect"
        if orig_url.lower().startswith("http://") and final_url.lower().startswith("https://"):
            transition_desc = "HTTP -> HTTPS secure protocol upgrade."
        elif "www." in orig_host.lower() and "www." not in final_host.lower():
            transition_desc = "www -> non-www canonical redirect."
        elif "www." not in orig_host.lower() and "www." in final_host.lower():
            transition_desc = "non-www -> www canonical redirect."
        elif orig_host.lower() != final_host.lower():
            transition_desc = f"Subdomain transition from {orig_host} to {final_host}."
            class_title = "Safe Same-Domain Redirect"
            
        return {
            "classification": class_title,
            "status": "Safe",
            "severity": "Info",
            "deduction": 0,
            "rationale": f"The redirect stays strictly within the registered domain ({orig_root}). {transition_desc}",
            "similarity_score": 1.0,
            "badge_class": "success"
        }
        
    typo_check = detect_typosquatting(orig_host, final_host)
    sim_score = typo_check["similarity"]
    
    if typo_check.get("has_homoglyph_evidence") or typo_check.get("has_tld_shift"):
        return {
            "classification": "Potential Typosquatting",
            "status": "Suspicious",
            "severity": "High",
            "deduction": 35,
            "rationale": f"Final hostname registered domain ({final_root}) differs from original target domain ({orig_root}). Evidence: {typo_check['reason']}. Manual verification recommended.",
            "similarity_score": sim_score,
            "badge_class": "danger"
        }

    return {
        "classification": "External Domain Redirect",
        "status": "Review Recommended",
        "severity": "Info",
        "deduction": 0,
        "rationale": f"External domain redirect detected ({orig_host} -> {final_host}). This may be intentional, such as a brand migration or domain transition. Manual verification recommended.",
        "similarity_score": sim_score,
        "badge_class": "warning"
    }
