#%%

#!/usr/bin/env python3
"""
Password Strength Checker - Jupyter/Interactive Version
Enhanced with entropy calculation, breach detection, and advanced pattern analysis.

Features:
- Shannon entropy calculation (bits)
- Estimated crack time based on hashing algorithm
- Breached password detection (local dictionary + patterns)
- Advanced pattern recognition (keyboard, leet speak, dates, repeats)
- NIST 800-63B compliance guidelines
- Detailed security recommendations
- Works in Jupyter notebooks and terminal

Usage:
    # In Jupyter:
    %run project1_password_checker.py
    
    # Or import and use:
    from project1_password_checker import check_password, check_password_strength
    
    # In terminal:
    python project1_password_checker.py
"""

import re
import sys
import math
from typing import Tuple, List, Dict, Any


# ============================================================================
# CONFIGURATION
# ============================================================================

# Character set sizes for entropy calculation
CHARSET_SIZES = {
    'lowercase': 26,
    'uppercase': 26,
    'digits': 10,
    'symbols': 33,
    'extended': 95,
}

# Crack time assumptions (guesses per second)
CRACK_RATES = {
    'online_throttled': 10,
    'online_unthrottled': 100,
    'offline_slow': 10_000,
    'offline_fast': 100_000_000_000,
}

# Common passwords (expanded list)
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "monkey", "1234567",
    "letmein", "trustno1", "dragon", "baseball", "iloveyou", "master", "sunshine",
    "ashley", "bailey", "shadow", "123123", "654321", "superman", "qazwsx",
    "michael", "football", "password1", "password123", "welcome", "jesus",
    "ninja", "mustang", "password1234", "admin", "admin123", "root", "toor",
    "pass", "test", "guest", "changeme", "123456789", "1234567890",
    "0987654321", "111111", "000000", "121212", "123321", "666666", "696969",
    "7777777", "888888", "abcdef", "abcd1234", "qwerty123", "1q2w3e4r",
    "1q2w3e", "1qaz2wsx", "123qwe", "1234qwer", "qwer1234", "zaq12wsx",
    "password!", "p@ssword", "p@ssw0rd", "passw0rd", "passwd", "pass123",
    "welcome1", "welcome123", "summer", "winter", "spring", "autumn",
    "lover", "princess", "pokemon", "maggie", "corvette", "harley", "liverpool",
    "jennifer", "jordan", "hunter", "ranger", "buster", "soccer", "batman",
    "starwars", "george", "pepper", "carlos", "joshua", "matthew", "andrew",
    "charlie", "thomas", "jessica", "daniel", "david", "joseph", "richard",
    "computer", "internet", "microsoft", "windows", "apple", "google", "facebook",
}

# Keyboard patterns
KEYBOARD_PATTERNS = [
    "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbn", "zxcvbnm",
    "1234567890", "0987654321", "qazwsx", "wsxedc", "edcrfv", "rfvtgb",
    "tgbyhn", "yhnujm", "ujmik", "1qaz", "2wsx", "3edc", "4rfv", "5tgb",
    "6yhn", "7ujm", "8ik", "9ol", "0p", "qweasdzxc", "asdzxcqwe",
]

# Leet speak mappings
LEET_MAP = {
    '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b',
    '@': 'a', '$': 's', '!': 'i', '+': 't',
}

# Sequential patterns
SEQUENTIAL_PATTERNS = [
    "0123456789", "9876543210", "abcdefghijklmnopqrstuvwxyz",
    "zyxwvutsrqponmlkjihgfedcba", "qwertyuiop", "asdfghjkl", "zxcvbnm",
]


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def unleet(text: str) -> str:
    """Convert leet speak to normal text."""
    result = text.lower()
    for leet_char, normal_char in LEET_MAP.items():
        result = result.replace(leet_char, normal_char)
    return result


def calculate_entropy(password: str) -> float:
    """Calculate Shannon entropy in bits."""
    if not password:
        return 0.0
    
    pool_size = 0
    if re.search(r"[a-z]", password):
        pool_size += CHARSET_SIZES['lowercase']
    if re.search(r"[A-Z]", password):
        pool_size += CHARSET_SIZES['uppercase']
    if re.search(r"\d", password):
        pool_size += CHARSET_SIZES['digits']
    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?`~]", password):
        pool_size += CHARSET_SIZES['symbols']
    
    if pool_size == 0:
        pool_size = CHARSET_SIZES['lowercase']
    
    entropy = len(password) * math.log2(pool_size)
    
    patterns = detect_patterns(password)
    if patterns:
        penalty = min(0.5, len(patterns) * 0.1)
        entropy *= (1 - penalty)
    
    return round(entropy, 2)


def detect_patterns(password: str) -> List[Dict[str, Any]]:
    """Detect various weak patterns in password."""
    patterns_found = []
    password_lower = password.lower()
    unleeted = unleet(password)
    
    # Keyboard patterns
    for pattern in KEYBOARD_PATTERNS:
        if len(pattern) >= 4 and pattern in password_lower:
            patterns_found.append({
                'type': 'keyboard',
                'pattern': pattern,
                'severity': 'high',
                'message': f"Keyboard pattern '{pattern}'"
            })
    
    # Sequential characters
    for seq in SEQUENTIAL_PATTERNS:
        for i in range(len(seq) - 2):
            substr = seq[i:i+3]
            if substr in password_lower:
                patterns_found.append({
                    'type': 'sequential',
                    'pattern': substr,
                    'severity': 'medium',
                    'message': f"Sequential characters '{substr}'"
                })
                break
    
    # Repeated characters (3+ same char)
    repeats = re.findall(r"(.)\1{2,}", password)
    if repeats:
        patterns_found.append({
            'type': 'repeated',
            'pattern': ', '.join(repeats),
            'severity': 'medium',
            'message': f"Repeated characters: {', '.join(repeats)}"
        })
    
    # Repeated sequences
    for length in range(2, len(password) // 2 + 1):
        for i in range(len(password) - length * 2 + 1):
            substr = password[i:i+length]
            if substr == password[i+length:i+length*2] and len(substr) >= 2:
                patterns_found.append({
                    'type': 'repeated_sequence',
                    'pattern': substr,
                    'severity': 'high',
                    'message': f"Repeated sequence '{substr}'"
                })
                break
    
    # Date patterns
    date_patterns = [
        (r"(19|20)\d{2}", "4-digit year"),
        (r"(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])", "MMDD format"),
        (r"([1-9]|1[0-2])([1-9]|[12]\d|3[01])", "M/D format"),
    ]
    
    for pattern, desc in date_patterns:
        if re.search(pattern, password):
            patterns_found.append({
                'type': 'date',
                'pattern': desc,
                'severity': 'medium',
                'message': f"Date pattern ({desc})"
            })
    
    # Leet speak detection
    if unleeted != password_lower:
        common_words = ["password", "admin", "user", "login", "welcome", "hello"]
        for word in common_words:
            if word in unleeted:
                patterns_found.append({
                    'type': 'leet_speak',
                    'pattern': word,
                    'severity': 'high',
                    'message': f"Leet speak substitution of '{word}'"
                })
    
    # Common suffixes
    common_suffixes = ["123", "1234", "12345", "1!", "12!", "123!"]
    for suffix in common_suffixes:
        if password.endswith(suffix) and len(password) > len(suffix) + 3:
            patterns_found.append({
                'type': 'common_suffix',
                'pattern': suffix,
                'severity': 'low',
                'message': f"Common suffix '{suffix}'"
            })
            break
    
    return patterns_found


def estimate_crack_time(entropy: float) -> Dict[str, str]:
    """Estimate time to crack password with brute force."""
    if entropy <= 0:
        return {key: 'instant' for key in CRACK_RATES.keys()}
    
    combinations = 2 ** entropy
    crack_times = {}
    
    for attack_type, rate in CRACK_RATES.items():
        seconds = combinations / (rate * 2)
        
        if seconds < 1:
            crack_times[attack_type] = 'instant'
        elif seconds < 60:
            crack_times[attack_type] = f'{seconds:.1f} seconds'
        elif seconds < 3600:
            crack_times[attack_type] = f'{seconds/60:.1f} minutes'
        elif seconds < 86400:
            crack_times[attack_type] = f'{seconds/3600:.1f} hours'
        elif seconds < 31536000:
            crack_times[attack_type] = f'{seconds/86400:.1f} days'
        elif seconds < 31536000 * 100:
            crack_times[attack_type] = f'{seconds/31536000:.1f} years'
        elif seconds < 31536000 * 1000000:
            crack_times[attack_type] = f'{seconds/31536000:.0f} years'
        else:
            crack_times[attack_type] = 'centuries'
    
    return crack_times


def is_breached(password: str) -> Tuple[bool, str]:
    """Check if password appears in common breached passwords."""
    password_lower = password.lower()
    unleeted = unleet(password)
    
    if password_lower in COMMON_PASSWORDS:
        return True, "Found in common password database"
    
    if unleeted in COMMON_PASSWORDS and unleeted != password_lower:
        return True, f"Leet speak version of '{unleeted}' (commonly breached)"
    
    for common in COMMON_PASSWORDS:
        if len(common) >= 6 and common in password_lower:
            return True, f"Contains common password '{common}'"
    
    return False, ""


def check_nist_compliance(password: str) -> Dict[str, Any]:
    """Check password against NIST 800-63B guidelines."""
    compliance = {
        'meets_minimum': True,
        'recommendations': [],
        'violations': []
    }
    
    if len(password) < 8:
        compliance['meets_minimum'] = False
        compliance['violations'].append("Below NIST minimum (8 characters)")
    elif len(password) < 12:
        compliance['recommendations'].append("Consider 12+ characters for better security")
    elif len(password) >= 16:
        compliance['recommendations'].append("Excellent length for high-security applications")
    
    breached, reason = is_breached(password)
    if breached:
        compliance['violations'].append(f"BREACHED: {reason}")
        compliance['meets_minimum'] = False
    
    char_types = sum([
        1 if re.search(r"[a-z]", password) else 0,
        1 if re.search(r"[A-Z]", password) else 0,
        1 if re.search(r"\d", password) else 0,
        1 if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?`~]", password) else 0,
    ])
    
    if char_types >= 3:
        compliance['recommendations'].append("Good character variety")
    
    if ' ' in password:
        compliance['recommendations'].append("Spaces detected - good for passphrases")
    
    return compliance


# ============================================================================
# MAIN PASSWORD ANALYSIS
# ============================================================================

def check_password_strength(password: str) -> Dict[str, Any]:
    """Comprehensive password strength analysis."""
    result = {
        'password_length': len(password),
        'score': 0,
        'entropy': 0.0,
        'strength_label': '',
        'crack_times': {},
        'patterns': [],
        'breached': False,
        'breach_reason': '',
        'nist_compliance': {},
        'feedback': [],
        'recommendations': []
    }
    
    result['entropy'] = calculate_entropy(password)
    result['patterns'] = detect_patterns(password)
    result['breached'], result['breach_reason'] = is_breached(password)
    result['nist_compliance'] = check_nist_compliance(password)
    result['crack_times'] = estimate_crack_time(result['entropy'])
    
    score = 0
    feedback = []
    
    # Length scoring (0-30 points)
    if len(password) >= 20:
        score += 30
        feedback.append("✓ Excellent length (20+ characters)")
    elif len(password) >= 16:
        score += 25
        feedback.append("✓ Very good length (16+ characters)")
    elif len(password) >= 12:
        score += 20
        feedback.append("✓ Good length (12+ characters)")
    elif len(password) >= 8:
        score += 10
        feedback.append("✓ Meets minimum length")
    else:
        feedback.append("✗ Too short - use at least 12 characters")
    
    # Entropy scoring (0-30 points)
    if result['entropy'] >= 100:
        score += 30
        feedback.append(f"✓ Excellent entropy ({result['entropy']} bits)")
    elif result['entropy'] >= 80:
        score += 25
        feedback.append(f"✓ Strong entropy ({result['entropy']} bits)")
    elif result['entropy'] >= 60:
        score += 20
        feedback.append(f"✓ Good entropy ({result['entropy']} bits)")
    elif result['entropy'] >= 40:
        score += 10
        feedback.append(f"⚠ Moderate entropy ({result['entropy']} bits)")
    else:
        feedback.append(f"✗ Low entropy ({result['entropy']} bits) - too predictable")
    
    # Character variety (0-15 points)
    char_score = 0
    if re.search(r"[A-Z]", password):
        char_score += 4
    else:
        feedback.append("✗ Add uppercase letters (A-Z)")
    
    if re.search(r"[a-z]", password):
        char_score += 4
    else:
        feedback.append("✗ Add lowercase letters (a-z)")
    
    if re.search(r"\d", password):
        char_score += 3
    else:
        feedback.append("✗ Add numbers (0-9)")
    
    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?`~]", password):
        char_score += 4
    else:
        feedback.append("✗ Add symbols (!@#$%^&*)")
    
    score += char_score
    
    # Pattern penalties
    if result['patterns']:
        pattern_penalty = 0
        for pattern in result['patterns']:
            if pattern['severity'] == 'high':
                pattern_penalty += 10
                feedback.append(f"✗ {pattern['message']}")
            elif pattern['severity'] == 'medium':
                pattern_penalty += 5
                feedback.append(f"⚠ {pattern['message']}")
            else:
                pattern_penalty += 2
                feedback.append(f"ℹ {pattern['message']}")
        
        score -= min(30, pattern_penalty)
    
    # Breach penalty
    if result['breached']:
        score -= 40
        feedback.append(f"✗✗✗ BREACHED PASSWORD: {result['breach_reason']}")
    
    # NIST compliance bonus
    if result['nist_compliance']['meets_minimum']:
        score += 5
        feedback.append("✓ Meets NIST 800-63B minimum requirements")
    
    score = max(0, min(100, score))
    result['score'] = score
    result['feedback'] = feedback
    
    # Strength label
    if score >= 90:
        result['strength_label'] = 'Excellent'
    elif score >= 80:
        result['strength_label'] = 'Very Strong'
    elif score >= 70:
        result['strength_label'] = 'Strong'
    elif score >= 60:
        result['strength_label'] = 'Good'
    elif score >= 50:
        result['strength_label'] = 'Fair'
    elif score >= 40:
        result['strength_label'] = 'Weak'
    else:
        result['strength_label'] = 'Very Weak'
    
    # Recommendations
    recommendations = []
    if len(password) < 16:
        recommendations.append("Use a longer password (16+ characters recommended)")
    if result['entropy'] < 60:
        recommendations.append("Increase randomness - avoid predictable patterns")
    if result['breached']:
        recommendations.append("CRITICAL: Choose a completely different password")
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?`~]", password):
        recommendations.append("Add special characters for better security")
    if result['patterns']:
        recommendations.append("Avoid keyboard patterns, sequences, and repeated characters")
    if len(password) < 20 and result['score'] < 80:
        recommendations.append("Consider using a passphrase (e.g., 'correct-horse-battery-staple')")
    recommendations.append("Use a password manager to generate and store unique passwords")
    recommendations.append("Enable two-factor authentication (2FA) wherever possible")
    
    result['recommendations'] = recommendations
    
    return result


# ============================================================================
# DISPLAY FUNCTIONS
# ============================================================================

def display_results(result: Dict[str, Any], password: str) -> None:
    """Display comprehensive password analysis results."""
    
    print("\n" + "=" * 70)
    print("PASSWORD STRENGTH ANALYSIS REPORT")
    print("=" * 70)
    
    print(f"\nPassword: {'*' * len(password)} ({len(password)} characters)")
    print(f"Strength: {result['strength_label']}")
    print(f"Score: {result['score']}/100")
    print(f"Entropy: {result['entropy']} bits")
    
    # Visual strength bar
    bar_length = 40
    filled = int((result['score'] / 100) * bar_length)
    bar = "█" * filled + "░" * (bar_length - filled)
    
    if result['score'] >= 80:
        color = "\033[92m"
        status = "[EXCELLENT] ✓✓"
    elif result['score'] >= 60:
        color = "\033[93m"
        status = "[GOOD] ✓"
    elif result['score'] >= 40:
        color = "\033[93m"
        status = "[FAIR] ⚠"
    else:
        color = "\033[91m"
        status = "[WEAK] ✗"
    
    reset = "\033[0m"
    print(f"\n[{bar}] {color}{status}{reset}")
    
    if result['breached']:
        print(f"\n{'!' * 70}")
        print(f"⚠️  WARNING: This password has been BREACHED!")
        print(f"   Reason: {result['breach_reason']}")
        print(f"{'!' * 70}")
    
    print("\n" + "-" * 70)
    print("ESTIMATED CRACK TIME")
    print("-" * 70)
    print(f"  Online (rate-limited):     {result['crack_times'].get('online_throttled', 'N/A')}")
    print(f"  Online (no rate limit):    {result['crack_times'].get('online_unthrottled', 'N/A')}")
    print(f"  Offline (slow hash):       {result['crack_times'].get('offline_slow', 'N/A')}")
    print(f"  Offline (fast hash/GPU):   {result['crack_times'].get('offline_fast', 'N/A')}")
    
    if result['patterns']:
        print("\n" + "-" * 70)
        print("PATTERNS DETECTED")
        print("-" * 70)
        for pattern in result['patterns']:
            severity_icon = {"high": "✗", "medium": "⚠", "low": "ℹ"}.get(pattern['severity'], "•")
            print(f"  {severity_icon} {pattern['message']}")
    
    print("\n" + "-" * 70)
    print("NIST 800-63B COMPLIANCE")
    print("-" * 70)
    nist = result['nist_compliance']
    if nist['meets_minimum']:
        print("  ✓ Meets minimum requirements")
    else:
        print("  ✗ Does NOT meet minimum requirements")
    
    if nist['violations']:
        print("\n  Violations:")
        for violation in nist['violations']:
            print(f"    • {violation}")
    
    if nist['recommendations']:
        print("\n  Notes:")
        for rec in nist['recommendations']:
            print(f"    • {rec}")
    
    print("\n" + "-" * 70)
    print("DETAILED FEEDBACK")
    print("-" * 70)
    for item in result['feedback']:
        print(f"  {item}")
    
    print("\n" + "-" * 70)
    print("SECURITY RECOMMENDATIONS")
    print("-" * 70)
    for i, rec in enumerate(result['recommendations'], 1):
        print(f"  {i}. {rec}")
    
    print("\n" + "-" * 70)
    print("ENTROPY GUIDE")
    print("-" * 70)
    print("  0-40 bits:   Very weak - easily cracked")
    print("  40-60 bits:  Moderate - acceptable for low-value accounts")
    print("  60-80 bits:  Good - suitable for most accounts")
    print("  80-100 bits: Strong - recommended for important accounts")
    print("  100+ bits:   Excellent - suitable for master passwords")
    
    print("\n" + "=" * 70)


# ============================================================================
# USER-FRIENDLY WRAPPER FUNCTIONS
# ============================================================================

def check_password(password: str = None, verbose: bool = True) -> Dict[str, Any]:
    """
    Check a password's strength.
    
    Args:
        password: Password to check (if None, prompts user)
        verbose: If True, displays full report
    
    Returns:
        Dictionary with analysis results
    """
    if password is None:
        password = input("\nEnter password to check: ")
    
    if not password:
        print("Error: Password cannot be empty")
        return {}
    
    result = check_password_strength(password)
    
    if verbose:
        display_results(result, password)
    
    return result


def generate_password(length: int = 16) -> str:
    """Generate a cryptographically secure random password."""
    import secrets
    import string
    
    if length < 8:
        print("Error: Minimum password length is 8 characters")
        return ""
    
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()_+-="
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    
    print(f"\nGenerated password ({length} characters): {password}")
    print("⚠️  Save this password securely - it cannot be recovered!")
    
    return password


# ============================================================================
# MAIN ENTRY POINT (works in both Jupyter and terminal)
# ============================================================================

def main():
    """Main function - runs interactive password checker."""
    print("=" * 70)
    print("PASSWORD STRENGTH CHECKER - PROFESSIONAL EDITION")
    print("=" * 70)
    print("\nThis tool analyzes password strength using:")
    print("  • Shannon entropy calculation")
    print("  • Pattern detection (keyboard, sequences, repeats)")
    print("  • Breached password database")
    print("  • NIST 800-63B compliance checking")
    print("  • Crack time estimation")
    print("\n" + "-" * 70)
    
    while True:
        print("\nOptions:")
        print("  1. Check a password")
        print("  2. Generate a strong password")
        print("  3. Exit")
        
        choice = input("\nSelect option (1/2/3): ").strip()
        
        if choice == '1':
            password = input("\nEnter password to check: ")
            if password:
                result = check_password_strength(password)
                display_results(result, password)
            else:
                print("Error: Password cannot be empty")
        
        elif choice == '2':
            try:
                length = int(input("Enter password length (8-64, default 16): ").strip() or "16")
                if 8 <= length <= 64:
                    pwd = generate_password(length)
                    if pwd:
                        print("\nAnalyzing generated password...")
                        result = check_password_strength(pwd)
                        display_results(result, pwd)
                else:
                    print("Error: Length must be between 8 and 64")
            except ValueError:
                print("Error: Please enter a valid number")
        
        elif choice == '3':
            print("\nGoodbye! Stay secure! 🔒")
            break
        
        else:
            print("Invalid option. Please choose 1, 2, or 3.")
        
        # Ask if user wants to continue
        if choice in ['1', '2']:
            again = input("\nCheck another password? (y/n): ").strip().lower()
            if again != 'y':
                print("\nGoodbye! Stay secure! 🔒")
                break
    
    return 0


# Run main() when executed directly or via %run in Jupyter
if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nInterrupted. Goodbye! 🔒")
        sys.exit(0)
    except EOFError:
        # Handles Jupyter %run without stdin
        print("\n\nUse: check_password() to check a password interactively")
        print("Or: result = check_password_strength('YourPassword')")
# %%
