import re
import math
import hashlib
import requests
from app.scanners.base_scanner import BaseScanner

# Keyboard sequences (lowercase for case-insensitive matching)
KEYBOARD_WALKS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
]

# Common dictionary words / names / terms (lowercase)
COMMON_WORDS = {
    "password", "admin", "administrator", "welcome", "login", "root",
    "cyber", "optimus", "security", "shadow", "master", "secret",
    "system", "matrix", "dragon", "soccer", "football", "monkey",
    "summer", "winter", "spring", "autumn", "hunter", "google",
    "microsoft", "facebook", "youtube", "netflix", "apple", "amazon",
    "vishwas", "poojary"
}

# Top common passwords list
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "123456789", "12345", "1234567",
    "qwerty", "1234567890", "1234", "admin", "welcome", "letmein",
    "password123", "pass123", "iloveyou", "sunshine", "princess",
    "charlie", "1234567890", "000000", "aaaaaa"
}

def format_time_duration(seconds: float) -> str:
    """Formats raw seconds into human-readable duration strings."""
    if seconds < 0.001:
        return "Instantly"
    elif seconds < 1:
        return f"{round(seconds * 1000, 1)} ms"
    elif seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        return f"{int(seconds // 60)} minutes"
    elif seconds < 86400:
        return f"{int(seconds // 3600)} hours"
    elif seconds < 31536000:
        return f"{int(seconds // 86400)} days"
    elif seconds < 31536000 * 100:
        years = int(seconds // 31536000)
        return f"{years} year{'s' if years > 1 else ''}"
    elif seconds < 31536000 * 1000000:
        return "Centuries"
    else:
        return "Millions of years"

class PasswordChecker(BaseScanner):
    
    def check_pwned_passwords(self, password: str) -> dict:
        """Queries HaveIBeenPwned API using k-Anonymity (SHA-1 prefix).
        
        Only the first 5 characters of the SHA-1 hash are transmitted.
        The raw password and full hash NEVER leave the local server.
        """
        if not password:
            return {"is_breached": False, "count": 0, "source": "None"}
            
        try:
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]
            
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            resp = requests.get(
                url, 
                headers={"User-Agent": "CyberOptimus-SecurityScanner/1.0"}, 
                timeout=2.5
            )
            
            if resp.status_code == 200:
                lines = resp.text.splitlines()
                for line in lines:
                    parts = line.split(':')
                    if len(parts) == 2 and parts[0].strip() == suffix:
                        count = int(parts[1].strip())
                        return {
                            "is_breached": True,
                            "count": count,
                            "source": "Have I Been Pwned API (k-Anonymity)"
                        }
                return {
                    "is_breached": False,
                    "count": 0,
                    "source": "Have I Been Pwned API (k-Anonymity)"
                }
        except Exception:
            pass
            
        # Fallback to local common breach dataset
        pwd_lower = password.lower()
        if pwd_lower in COMMON_PASSWORDS:
            return {
                "is_breached": True,
                "count": 10000,
                "source": "Local Breached Password Database"
            }
            
        return {
            "is_breached": False,
            "count": 0,
            "source": "Local Breached Password Database"
        }

    def scan(self, target: str) -> dict:
        if not target:
            return {
                "status": "success",
                "score": 0,
                "strength": "Very Weak",
                "entropy": 0.0,
                "crack_time_slow": "Instantly",
                "crack_time_fast": "Instantly",
                "length": 0,
                "composition": {
                    "length": 0,
                    "lowercase_count": 0,
                    "uppercase_count": 0,
                    "digits_count": 0,
                    "symbols_count": 0,
                    "space_count": 0,
                    "unicode_count": 0,
                    "unique_count": 0,
                    "unique_ratio": 0.0,
                    "pool_size": 0
                },
                "checks": {
                    "has_uppercase": False,
                    "has_lowercase": False,
                    "has_digit": False,
                    "has_symbol": False,
                    "min_length": False,
                    "unique_ratio": True
                },
                "breach_analysis": {
                    "is_breached": False,
                    "count": 0,
                    "source": "None"
                },
                "crack_time_matrix": {
                    "online_throttled": "Instantly",
                    "online_unthrottled": "Instantly",
                    "offline_slow_hash": "Instantly",
                    "offline_fast_hash": "Instantly"
                },
                "risk_factors": [{"severity": "Critical", "message": "Password cannot be empty"}],
                "suggestions": ["Please enter a password to analyze."],
                "attack_analysis": {
                    "most_likely_attack": "Brute Force",
                    "estimated_time": "Instantly",
                    "confidence": "Very High",
                    "reason": "An empty password offers no defense space."
                }
            }

        length = len(target)
        
        # 1. Character Composition Analysis
        lowercase_count = sum(1 for c in target if c.islower())
        uppercase_count = sum(1 for c in target if c.isupper())
        digits_count = sum(1 for c in target if c.isdigit())
        symbols_count = sum(1 for c in target if not c.isalnum() and not c.isspace() and c.isprintable())
        space_count = sum(1 for c in target if c.isspace())
        unicode_count = sum(1 for c in target if ord(c) > 127)
        
        has_lowercase = lowercase_count > 0
        has_uppercase = uppercase_count > 0
        has_digit = digits_count > 0
        has_symbol = symbols_count > 0
        
        unique_chars = len(set(target))
        unique_ratio = round(unique_chars / length, 2) if length > 0 else 0.0
        
        # Calculate character set pool size
        pool_size = 0
        if has_lowercase: pool_size += 26
        if has_uppercase: pool_size += 26
        if has_digit: pool_size += 10
        if has_symbol: pool_size += 33
        if space_count > 0: pool_size += 1
        if unicode_count > 0: pool_size += 100
        
        # Shannon Entropy calculation
        entropy = length * math.log2(pool_size) if pool_size > 0 else 0.0
        
        # 2. Multi-Tier Crack Time Scenarios
        guesses = 2 ** entropy
        
        # Scenario rates:
        # online_throttled: 100 guesses/sec
        # online_unthrottled: 10,000 guesses/sec
        # offline_slow_hash: 10,000 guesses/sec (bcrypt / Argon2id)
        # offline_fast_hash: 100,000,000,000 guesses/sec (100 Billion/sec MD5/NTLM GPU cluster)
        
        time_online_throttled_sec = guesses / 100
        time_online_unthrottled_sec = guesses / 10000
        time_offline_slow_sec = guesses / 10000
        time_offline_fast_sec = guesses / 1e11
        
        crack_time_matrix = {
            "online_throttled": format_time_duration(time_online_throttled_sec),
            "online_unthrottled": format_time_duration(time_online_unthrottled_sec),
            "offline_slow_hash": format_time_duration(time_offline_slow_sec),
            "offline_fast_hash": format_time_duration(time_offline_fast_sec)
        }
        
        crack_time_slow_display = crack_time_matrix["offline_slow_hash"]
        crack_time_fast_display = crack_time_matrix["offline_fast_hash"]
        
        # 3. HaveIBeenPwned Data Breach Exposure Check
        breach_analysis = self.check_pwned_passwords(target)
        
        # 4. Pattern Recognition & Attack Classification
        risk_factors = []
        suggestions = []
        target_lower = target.lower()
        
        has_repeats = bool(re.search(r"(.)\1\1", target))
        
        # Keyboard pattern walk
        has_kb_walk = False
        if length >= 3:
            for walk in KEYBOARD_WALKS:
                for i in range(len(walk) - 2):
                    pattern = walk[i:i+3]
                    if pattern in target_lower or pattern[::-1] in target_lower:
                        has_kb_walk = True
                        break
                if has_kb_walk:
                    break
                    
        # Sequential character pattern
        has_sequences = False
        if length >= 3:
            for i in range(length - 2):
                c1, c2, c3 = ord(target_lower[i]), ord(target_lower[i+1]), ord(target_lower[i+2])
                if (c2 == c1 + 1 and c3 == c2 + 1) or (c2 == c1 - 1 and c3 == c2 - 1):
                    if target_lower[i:i+3].isalnum():
                        has_sequences = True
                        break

        # Years/dates check
        has_year = bool(re.search(r"(19|20)\d{2}", target))
        has_date = False
        date_matches = re.findall(r"\d{8}", target)
        for dm in date_matches:
            part1 = int(dm[:4])
            part2 = int(dm[4:])
            if (1900 <= part1 <= 2030) or (1900 <= part2 <= 2030):
                has_date = True
                break

        # Dictionary words check
        has_dict_word = False
        matched_words = []
        for word in COMMON_WORDS:
            if len(word) >= 4 and word in target_lower:
                has_dict_word = True
                matched_words.append(word)

        is_common = target_lower in COMMON_PASSWORDS or (target_lower.isdigit() and length <= 8)

        # Classify Primary Attack Vector
        if breach_analysis["is_breached"]:
            most_likely_attack = "Credential Stuffing / Breached Database Attack"
            estimated_time = "Instantly"
            confidence = "Very High"
            reason = f"Password found in Have I Been Pwned data breach records ({breach_analysis['count']:,} exposures). Automated botnets test leaked credentials across thousands of services."
            risk_factors.append({
                "severity": "Critical",
                "message": f"Password exposed in {breach_analysis['count']:,} known public data breaches!"
            })
            suggestions.append("CRITICAL: Do not use this password! It has appeared in actual data breaches and is actively targeted in credential stuffing attacks.")
            
        elif is_common:
            most_likely_attack = "Common Password / Dictionary Attack"
            estimated_time = "Less than 1 second"
            confidence = "Very High"
            reason = "The password appears in standard password wordlists. Attackers check common wordlists first in automated scans."
            risk_factors.append({
                "severity": "Critical",
                "message": "Common password found in standard credential databases"
            })
            suggestions.append("Avoid common wordlist passwords. Attackers check these databases immediately in automated scans.")
            suggestions.append("Ensure you use unique passwords for every account to avoid Credential Stuffing.")
            
        elif has_dict_word and (has_digit or has_symbol):
            most_likely_attack = "Hybrid Attack"
            confidence = "High"
            reason = "Combines dictionary words with common leading/trailing numbers or symbols, which attackers target using rule-based dictionary generators."
            estimated_time = "Less than 1 minute" if length < 10 else ("Few minutes" if length < 15 else "Few hours")
            risk_factors.append({
                "severity": "High",
                "message": f"Contains dictionary word '{matched_words[0]}' combined with symbols/numbers"
            })
            suggestions.append("Avoid simple modifications to dictionary words. Attackers use rule-based hybrid attacks to crack variations like 'Word123' instantly.")
            suggestions.append("Remove dictionary words completely, even if you append numbers or special characters.")
            
        elif target_lower in COMMON_WORDS or (has_dict_word and len(target) == len(matched_words[0])):
            most_likely_attack = "Dictionary Attack"
            estimated_time = "Less than 1 second"
            confidence = "High"
            reason = "The password consists entirely of a dictionary word. Dictionary wordlists are tested exhaustively in seconds."
            risk_factors.append({
                "severity": "High",
                "message": "Password is a single dictionary word"
            })
            suggestions.append("Avoid single dictionary words. Combine multiple random, unrelated words into a passphrase instead.")
            
        elif has_kb_walk:
            most_likely_attack = "Keyboard Pattern Attack"
            estimated_time = "Less than 1 minute"
            confidence = "High"
            reason = "Matches a keyboard path layout (e.g. qwerty, asdf), which automated scripts check early in custom sequence generators."
            risk_factors.append({
                "severity": "Medium",
                "message": "Predictable keyboard walk pattern detected"
            })
            suggestions.append("Avoid predictable keyboard walk sequences. Use randomly distributed keys or distinct word sequences.")
            
        elif re.match(r"^[A-Z][a-z]+[!@#\$%\^&\*\(\)_\+\-=\[\]\{\};':\",\./<>\?]*[0-9]+[!@#\$%\^&\*\(\)_\+\-=\[\]\{\};':\",\./<>\?]*$", target):
            most_likely_attack = "Mask Attack"
            confidence = "High"
            reason = "Matches a standard uppercase-lowercase-symbol-digit complexity pattern template (mask), which optimizes attacker scan paths."
            estimated_time = "Few minutes" if length < 10 else ("Few hours" if length < 13 else "Few days")
            risk_factors.append({
                "severity": "Medium",
                "message": "Conforms to standard structural password mask pattern"
            })
            suggestions.append("Avoid standard capitalization structures (e.g. capitalized first letter and trailing digits). Use randomized structures.")
            
        else:
            most_likely_attack = "Brute Force"
            estimated_time = crack_time_fast_display
            confidence = "Medium"
            reason = "No predictable keyboard walks, dictionary words, dates, or structural masks detected. Attackers must search the entire character set."
            suggestions.append("Keep using high-entropy random characters or long passphrases.")

        # Additional secondary risk checks
        if has_repeats:
            risk_factors.append({
                "severity": "Medium",
                "message": "Consecutive repeated characters detected (e.g. aaa, 111)"
            })
            suggestions.append("Avoid repeating the same character consecutively.")
        if has_sequences and most_likely_attack not in ["Common Password / Dictionary Attack", "Credential Stuffing / Breached Database Attack"]:
            risk_factors.append({
                "severity": "Medium",
                "message": "Sequential alphabetic/numeric pattern detected (e.g. 1234, abcd)"
            })
            suggestions.append("Avoid ascending or descending sequences of numbers or letters.")
        if has_date:
            risk_factors.append({
                "severity": "High",
                "message": "Significant calendar date pattern detected (e.g. 17082006)"
            })
            suggestions.append("Avoid using dates of significance (birthdays, anniversaries) in passwords.")
        elif has_year and most_likely_attack != "Hybrid Attack":
            risk_factors.append({
                "severity": "Medium",
                "message": "4-digit year pattern detected (e.g. 2026)"
            })
            suggestions.append("Remove calendar years from your password, as they are targeted by simple list adjustments.")

        # 5. Enterprise Scoring Calculation (0-100)
        score = 0
        if length < 8:
            score = min(25, length * 3)
            risk_factors.append({
                "severity": "High",
                "message": "Password is shorter than the recommended minimum of 8 characters"
            })
            suggestions.append("Ensure your password is at least 8 characters long, ideally 12 or more.")
        else:
            score = 40
            length_bonus = min(30, (length - 8) * 3)
            score += length_bonus
            
            if has_lowercase: score += 10
            if has_uppercase: score += 10
            if has_digit: score += 10
            if has_symbol: score += 10
                
            # Apply deductions
            if breach_analysis["is_breached"]: score -= 60
            if is_common: score -= 50
            if has_repeats: score -= 15
            if has_sequences: score -= 15
            if has_kb_walk: score -= 15
            if has_date: score -= 15
            elif has_year: score -= 10
            if has_dict_word: score -= 10
            if unique_ratio < 0.5: score -= 10
                
        final_score = max(0, min(100, score))
        
        # Strength Labels
        if final_score <= 20:
            strength_label = "Very Weak"
        elif final_score <= 40:
            strength_label = "Weak"
        elif final_score <= 60:
            strength_label = "Medium"
        elif final_score <= 80:
            strength_label = "Strong"
        else:
            strength_label = "Very Strong"
            
        # Deduplicate suggestions
        seen = set()
        unique_suggestions = []
        for s in suggestions:
            if s not in seen:
                seen.add(s)
                unique_suggestions.append(s)
                
        if final_score >= 80 and not unique_suggestions:
            unique_suggestions.append("Your password meets all modern security and entropy recommendations.")
            
        return {
            "status": "success",
            "score": final_score,
            "strength": strength_label,
            "entropy": round(entropy, 2),
            "crack_time_slow": crack_time_slow_display,
            "crack_time_fast": crack_time_fast_display,
            "length": length,
            "composition": {
                "length": length,
                "lowercase_count": lowercase_count,
                "uppercase_count": uppercase_count,
                "digits_count": digits_count,
                "symbols_count": symbols_count,
                "space_count": space_count,
                "unicode_count": unicode_count,
                "unique_count": unique_chars,
                "unique_ratio": unique_ratio,
                "pool_size": pool_size
            },
            "checks": {
                "has_uppercase": has_uppercase,
                "has_lowercase": has_lowercase,
                "has_digit": has_digit,
                "has_symbol": has_symbol,
                "min_length": length >= 8,
                "unique_ratio": unique_ratio >= 0.5
            },
            "breach_analysis": breach_analysis,
            "crack_time_matrix": crack_time_matrix,
            "risk_factors": risk_factors,
            "suggestions": unique_suggestions,
            "attack_analysis": {
                "most_likely_attack": most_likely_attack,
                "estimated_time": estimated_time,
                "confidence": confidence,
                "reason": reason
            }
        }
