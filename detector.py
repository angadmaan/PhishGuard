import re

# Check 1: HTTPS

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

# Check 2: IP instead of domain?

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
        "reason": "No raw IP adress found"
    }

# Check 3: If URL is suspiciously long?

def check_url_length(url):
    length = len(url)
    if length > 100:
        return {
            "check": "URL Length",
            "result": "FAIL",
            "score": 15,
            "reason": f"URL is very long ({length}) characters) - often used to hide fake domains "
        }
    elif length > 75:
        return {
            "check": "URL Length",
            "result": "WARNING",
            "score": 10,
            "reason": f"URL is moderately long ({length} characters)"

        }
    return {
        "check": "URL Lenght",
        "result": "PASS",
        "score": 0,
        "reason": f"URL length looks normal ({length} characters)"
    }

# Check 4: Does the URL contain suspicious keywords?

def check_suspicious_keywords(url):
    keywords = [
        "login", "verify", "bank", "secure", "account", "update", "confirm", "password", "signin", "paypal", "support", "urgent", "suspend"
    ]
    url_lower = url.lower()
    found = [word for word in keywords if word in url_lower]

    if found:
        return {
            "check": "Suspicious Keywords",
            "result": "FAIl",
            "score": 20,
            "reason": f"Found Suspicious keywords: {','.join(found)}"
        }
    return {
        "check": "Suspicious Keywords",
        "result": "PASS",
        "score": 0,
        "reason": "No Suspicious keywords found"
    }

# Check 5: Suspicious Domain extension?

def check_domain_extension(url):
    suspicious_extensions = [
        ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".loan"
    ]
    url_lower = url.lower()

    for ext in suspicious_extensions:
        if ext in url_lower:
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


# Scoring Engine:

def analyze_url(url):
    checks = [
        check_https(url),
        check_ip_address(url),
        check_url_length(url),
        check_suspicious_keywords(url),
        check_domain_extension(url)
    ]
    total_score = sum(check["score"] for check in checks)

    if total_score <= 20:
        verdict = "Safe"
        verdict_color = "green"
        message = "This URL appears to be safe"

    elif total_score <= 50:
        verdict = "Suspicious"
        verdict_color = "orange"
        message = "This URL has suspicious characteristics. Proceed with caution."

    else:
        verdict = "Dangerous"
        verdict_color = "red"
        message = "This URL is likely phishing attempt. Do NOT visit it."

    return {
        "url": url,
        "checks": checks,
        "total_score": total_score,
        "max_score": 100,
        "verdict": verdict,
        "verdict_color": verdict_color,
        "message": message
    }


# Test BLOCK:

if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "http://paypal-secure-login.verify.tk/update/account"
    ]

    for url in test_urls:
        print(f"\n{'=' * 60}")

        result = analyze_url(url)

        print(f"URL      : {result['url']}")
        print(f"Score    : {result['total_score']}")
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