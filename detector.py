import re
from urllib.parse import urlparse

# ── Check 1: HTTPS ──

def check_https(url):
    if not url.startswith("https://"):
        return {
            "check": "HTTPS Missing",
            "result": "FAIL",
            "score": 20,
            "reason": "URL does not use HTTPS - connection is not secure"
        }
    return {
        "check": "HTTPS Missing",
        "result": "PASS",
        "score": 0,
        "reason": "URL uses HTTPS"
    }

# ── Check 2: IP instead of domain? ──

def check_ip_address(url):
    ip_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
    if ip_pattern.search(url):
        return {
            "check": "IP Address in URL",
            "result": "FAIL",
            "score": 25,
            "reason": "URL uses a raw IP address instead of a domain name"
        }
    return {
        "check": "IP Address in URL",
        "result": "PASS",
        "score": 0,
        "reason": "No raw IP address found"
    }

# ── Check 3: URL suspiciously long? ──

def check_url_length(url):
    length = len(url)
    if length > 60:
        return {
            "check": "URL Length",
            "result": "FAIL",
            "score": 25,
            "reason": f"URL is very long ({length} characters) - often used to hide fake domains"
        }
    elif length > 40:
        return {
            "check": "URL Length",
            "result": "WARNING",
            "score": 10,
            "reason": f"URL is moderately long ({length} characters)"
        }
    return {
        "check": "URL Length",
        "result": "PASS",
        "score": 0,
        "reason": f"URL length looks normal ({length} characters)"
    }

# ── Check 4: Suspicious keywords? ──

def check_suspicious_keywords(url):
    keywords = [
        "login", "verify", "bank", "secure", "account", "update",
        "confirm", "password", "signin", "paypal", "support", "urgent",
        "suspend", "alert", "expire", "unlock", "wallet", "billing",
        "notification", "security", "restricted", "invoice", "authenticate",
        "recover", "restore", "validate", "credential"
    ]
    url_lower = url.lower()
    found = [word for word in keywords if word in url_lower]

    if found:
        return {
            "check": "Suspicious Keywords",
            "result": "FAIL",
            "score": 20,
            "reason": f"Found suspicious keywords: {', '.join(found)}"
        }
    return {
        "check": "Suspicious Keywords",
        "result": "PASS",
        "score": 0,
        "reason": "No suspicious keywords found"
    }

# ── Check 5: Suspicious domain extension? ──

def check_domain_extension(url):
    suspicious_extensions = [
        ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
        ".click", ".loan", ".buzz", ".work", ".icu", ".info",
        ".site", ".online", ".live", ".rest", ".fit",".ru",".cc",".pw"
    ]

    try:
        parsed = urlparse(url)
        domain = parsed.hostname or ""
    except Exception:
        domain = url.lower()

    for ext in suspicious_extensions:
        if domain.endswith(ext):
            return {
                "check": "Suspicious Domain Extension",
                "result": "FAIL",
                "score": 20,
                "reason": f"URL uses a suspicious domain extension: {ext}"
            }

    return {
        "check": "Suspicious Domain Extension",
        "result": "PASS",
        "score": 0,
        "reason": "Domain extension looks normal"
    }


# ── Check 6: @ Symbol in URL ──

def check_at_symbol(url):
    """
    Catches: https://google.com@evil.com/login
    The browser ignores everything before @ and goes to evil.com
    """
    parsed = urlparse(url)
    url_without_scheme = url.split("://", 1)[-1]

    if "@" in url_without_scheme:
        return {
            "check": "@ Symbol Redirect",
            "result": "FAIL",
            "score": 25,
            "reason": "URL contains '@' — browser may redirect to a different domain"
        }
    return {
        "check": "@ Symbol Redirect",
        "result": "PASS",
        "score": 0,
        "reason": "No '@' symbol redirect trick found"
    }


# ── Check 7: Excessive Subdomains ──

def check_subdomain_depth(url):
    """
    Catches: https://paypal.com.login.security.evil.com
    Phishers stack fake brand names as subdomains
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
    except Exception:
        hostname = ""

    parts = hostname.split(".")
    # Remove TLD and main domain, count subdomains
    subdomain_count = len(parts) - 2  # e.g., a.b.c.evil.com → 3 subdomains

    if subdomain_count >= 4:
        return {
            "check": "Subdomain Depth",
            "result": "FAIL",
            "score": 15,
            "reason": f"URL has {subdomain_count} subdomains — often used to impersonate brands"
        }
    elif subdomain_count == 3:
        return {
            "check": "Subdomain Depth",
            "result": "WARNING",
            "score": 10,
            "reason": f"URL has {subdomain_count} subdomains — moderately suspicious"
        }
    return {
        "check": "Subdomain Depth",
        "result": "PASS",
        "score": 0,
        "reason": f"Subdomain depth looks normal ({subdomain_count} subdomains)"
    }


# ── Check 8: Hyphen Abuse in Domain ──

def check_hyphen_abuse(url):
    """
    Catches: https://paypal-secure-login-verify-account.com
    Legitimate domains rarely have 3+ hyphens
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
    except Exception:
        hostname = ""

    hyphen_count = hostname.count("-")

    if hyphen_count >= 4:
        return {
            "check": "Hyphen Abuse",
            "result": "FAIL",
            "score": 15,
            "reason": f"Domain has {hyphen_count} hyphens — highly suspicious"
        }
    elif hyphen_count == 3:
        return {
            "check": "Hyphen Abuse",
            "result": "WARNING",
            "score": 10,
            "reason": f"Domain has {hyphen_count} hyphens — moderately suspicious"
        }
    return {
        "check": "Hyphen Abuse",
        "result": "PASS",
        "score": 0,
        "reason": f"Hyphen count looks normal ({hyphen_count})"
    }


# ── Check 9: Punycode / IDN Homograph Attack ──

def check_punycode(url):
    """
    Catches: https://xn--pypal-4ve.com (looks like paypal.com in browser)
    Attackers use international characters that look identical to ASCII
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
    except Exception:
        hostname = ""

    if "xn--" in hostname:
        return {
            "check": "Punycode / Homograph Attack",
            "result": "FAIL",
            "score": 20,
            "reason": "Domain uses Punycode (xn--) — may be impersonating another site with lookalike characters"
        }
    return {
        "check": "Punycode / Homograph Attack",
        "result": "PASS",
        "score": 0,
        "reason": "No Punycode detected"
    }


# ── Check 10: URL Shortener ──

def check_url_shortener(url):
    """
    Catches: https://bit.ly/3xPhish, https://tinyurl.com/abc
    Shorteners hide the real destination URL
    """
    shorteners = [
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
        "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
        "tiny.cc", "lnkd.in", "rb.gy", "v.gd", "qr.ae"
    ]

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
    except Exception:
        hostname = ""

    for shortener in shorteners:
        if hostname == shortener or hostname.endswith("." + shortener):
            return {
                "check": "URL Shortener",
                "result": "FAIL",
                "score": 15,
                "reason": f"URL uses a link shortener ({shortener}) — real destination is hidden"
            }
    return {
        "check": "URL Shortener",
        "result": "PASS",
        "score": 0,
        "reason": "No URL shortener detected"
    }


# ── Check 11: Unusual Port ──

def check_unusual_port(url):
    """
    Catches: https://google.com:8443/login
    Legitimate sites use standard ports (80/443)
    """
    try:
        parsed = urlparse(url)
        port = parsed.port
    except Exception:
        port = None

    standard_ports = [None, 80, 443]

    if port not in standard_ports:
        return {
            "check": "Unusual Port",
            "result": "FAIL",
            "score": 15,
            "reason": f"URL uses non-standard port :{port} — legitimate sites use port 80 or 443"
        }
    return {
        "check": "Unusual Port",
        "result": "PASS",
        "score": 0,
        "reason": "Port is standard"
    }


# ── Check 12: Brand Impersonation ──

def check_brand_impersonation(url):
    """
    Catches: https://g00gle-support.com, https://app1e-id.com
    Checks if URL contains a well-known brand name but is NOT the official domain
    """
    brands = {
        "google": ["google.com", "google.co.in", "google.co.uk", "googleapis.com"],
        "apple": ["apple.com", "icloud.com"],
        "microsoft": ["microsoft.com", "live.com", "outlook.com", "office.com"],
        "amazon": ["amazon.com", "amazon.in", "amazon.co.uk", "aws.amazon.com"],
        "paypal": ["paypal.com"],
        "facebook": ["facebook.com", "fb.com"],
        "instagram": ["instagram.com"],
        "netflix": ["netflix.com"],
        "twitter": ["twitter.com", "x.com"],
        "linkedin": ["linkedin.com"],
        "whatsapp": ["whatsapp.com"],
        "dropbox": ["dropbox.com"],
        "chase": ["chase.com"],
        "wellsfargo": ["wellsfargo.com"],
        "bankofamerica": ["bankofamerica.com"],
    }

    # Common character substitutions attackers use
    leet_map = {
        "0": "o", "1": "l", "3": "e", "4": "a",
        "5": "s", "7": "t", "8": "b", "@": "a"
    }

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
    except Exception:
        hostname = ""

    hostname_lower = hostname.lower()

    # Decode leet speak in hostname for comparison
    decoded_hostname = hostname_lower
    for leet_char, real_char in leet_map.items():
        decoded_hostname = decoded_hostname.replace(leet_char, real_char)

    for brand, legit_domains in brands.items():
        # Check if brand name (or leet-speak version) appears in the hostname
        if brand in hostname_lower or brand in decoded_hostname:
            # But it's NOT actually the official domain
            is_legit = any(
                hostname_lower == d or hostname_lower.endswith("." + d)
                for d in legit_domains
            )
            if not is_legit:
                return {
                    "check": "Brand Impersonation",
                    "result": "FAIL",
                    "score": 25,
                    "reason": f"Domain appears to impersonate '{brand}' but is NOT the official site"
                }

    return {
        "check": "Brand Impersonation",
        "result": "PASS",
        "score": 0,
        "reason": "No brand impersonation detected"
    }


# ══════════════════════════════════════════════
# Scoring Engine
# ══════════════════════════════════════════════

def analyze_url(url):
    checks = [
        check_https(url),
        check_ip_address(url),
        check_url_length(url),
        check_suspicious_keywords(url),
        check_domain_extension(url),
        check_at_symbol(url),
        check_subdomain_depth(url),
        check_hyphen_abuse(url),
        check_punycode(url),
        check_url_shortener(url),
        check_unusual_port(url),
        check_brand_impersonation(url),
    ]
    total_score = sum(check["score"] for check in checks)

    max_score = 200
    percentage = (total_score / max_score) * 100

    if percentage <= 5:
        verdict = "Safe"
        verdict_color = "green"
        message = "This URL appears to be safe"

    elif percentage <= 25:
        verdict = "Suspicious"
        verdict_color = "orange"
        message = "This URL has suspicious characteristics. Proceed with caution."

    else:
        verdict = "Dangerous"
        verdict_color = "red"
        message = "This URL is likely a phishing attempt. Do NOT visit it."

        message = "This URL is likely a phishing attempt. Do NOT visit it."

    return {
        "url": url,
        "checks": checks,
        "total_score": total_score,
        "max_score": 200,
        "verdict": verdict,
        "verdict_color": verdict_color,
        "message": message
    }


# ══════════════════════════════════════════════
# Test Block
# ══════════════════════════════════════════════

if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",                          # Safe
        "http://paypal-secure-login.verify.tk/update/account",  # Dangerous (original)
        "https://google.com@evil.com/login",               # @ symbol redirect
        "https://paypal.com.login.security.evil.com",      # Subdomain impersonation
        "https://paypal-secure-login-verify-account.com",  # Hyphen abuse
        "https://bit.ly/3xPhish",                          # URL shortener
        "https://xn--pypal-4ve.com",                       # Punycode
        "https://google.com:8443/login",                   # Unusual port
        "https://g00gle-support.com/verify",               # Brand impersonation
    ]

    for url in test_urls:
        print(f"\n{'=' * 60}")

        result = analyze_url(url)

        print(f"URL      : {result['url']}")
        print(f"Score    : {result['total_score']} / {result['max_score']}")
        print(f"Verdict  : {result['verdict']}")
        print(f"Message  : {result['message']}")

        print("\nCheck Breakdown:")

        # This loop MUST be inside the URL loop

        for check in result['checks']:
            icon = (
                "✅" if check["result"] == "PASS"
                else "⚠️" if check["result"] == "WARNING"
                else "❌"
            )

            print(
                f"  {icon} {check['check']:<30} | "
                f"Score: {check['score']} | {check['reason']}"
            )

# DONE!!
