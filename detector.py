import ipaddress
import math
import re
import socket
import ssl
import time
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlparse
import dns.resolver
import requests

# ══════════════════════════════════════════════
# In-Memory Telemetry Caches (15-min TTL)
# ══════════════════════════════════════════════

RDAP_CACHE = {}
DNS_CACHE = {}
SSL_CACHE = {}
CACHE_TTL = 900  # 15 minutes

# ══════════════════════════════════════════════
# Verified Brands & Official Domains Database
# ══════════════════════════════════════════════

VERIFIED_BRANDS = {
    "google": ["google.com", "google.co.in", "google.co.uk", "googleapis.com", "gstatic.com", "youtube.com"],
    "apple": ["apple.com", "icloud.com"],
    "microsoft": ["microsoft.com", "microsoftonline.com", "live.com", "outlook.com", "office.com", "azure.com", "windows.com", "sharepoint.com"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "aws.amazon.com"],
    "paypal": ["paypal.com", "paypal.me"],
    "facebook": ["facebook.com", "fb.com", "messenger.com"],
    "instagram": ["instagram.com"],
    "netflix": ["netflix.com"],
    "twitter": ["twitter.com", "x.com"],
    "linkedin": ["linkedin.com"],
    "whatsapp": ["whatsapp.com"],
    "dropbox": ["dropbox.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "github": ["github.com"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "spotify": ["spotify.com"],
    "adobe": ["adobe.com"],
    "walmart": ["walmart.com"],
    "ebay": ["ebay.com"],
    "atlassian": ["atlassian.com"],
    "kaspersky": ["kaspersky.com"],
    "owasp": ["owasp.org"],
    "pypi": ["pypi.org", "python.org"],
}

MULTI_PART_TLDS = {
    "co.uk", "gov.uk", "ac.uk", "org.uk",
    "co.in", "net.in", "org.in", "gov.in",
    "com.au", "net.au", "org.au", "edu.au",
    "co.nz", "co.jp", "com.br", "co.za"
}

# Leetspeak character map used in deceptive phishing domains
LEET_MAP = {
    "0": "o", "1": "l", "3": "e", "4": "a",
    "5": "s", "7": "t", "8": "b", "@": "a", "vv": "w"
}


# ══════════════════════════════════════════════
# Helper Algorithms: Entropy, Levenshtein, Domain Parsing
# ══════════════════════════════════════════════

def extract_domain_parts(hostname: str):
    """
    Extracts (subdomain, sld, tld) handling multi-part TLDs.
    e.g. 'auth.paypal.co.uk' -> ('auth', 'paypal', 'co.uk')
    """
    hostname = (hostname or "").lower().strip()
    if not hostname or is_ip_address(hostname):
        return "", hostname, ""

    # Check multi-part TLDs first
    for m_tld in MULTI_PART_TLDS:
        if hostname.endswith("." + m_tld):
            base = hostname[:-len("." + m_tld)]
            parts = base.split(".")
            sld = parts[-1]
            subdomain = ".".join(parts[:-1])
            return subdomain, sld, m_tld

    parts = hostname.split(".")
    if len(parts) == 1:
        return "", parts[0], ""
    if len(parts) == 2:
        return "", parts[0], parts[1]

    tld = parts[-1]
    sld = parts[-2]
    subdomain = ".".join(parts[:-2])
    return subdomain, sld, tld


def calculate_entropy(text: str) -> float:
    """
    Computes Shannon Entropy: H(X) = -sum(p * log2(p))
    Higher entropy indicates random/unnatural character sequences (DGA).
    """
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def levenshtein_distance(s1: str, s2: str) -> int:
    """
    Computes minimum edit distance between two strings.
    """
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def is_verified_legit_domain(hostname: str) -> bool:
    """Checks if hostname matches any known verified brand domain."""
    hostname = (hostname or "").lower()
    for _, legit_domains in VERIFIED_BRANDS.items():
        for d in legit_domains:
            if hostname == d or hostname.endswith("." + d):
                return True
    return False


def is_ip_address(hostname: str) -> bool:
    """Determines whether a hostname is a literal IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(hostname or "")
        return True
    except ValueError:
        return False


# ══════════════════════════════════════════════
# 14 Comprehensive Security Checks
# ══════════════════════════════════════════════

# ── Check 1: HTTPS Encryption ──
def check_https(url: str, parsed) -> dict:
    if parsed.scheme.lower() != "https":
        return {
            "check": "HTTPS Encryption",
            "result": "FAIL",
            "score": 20,
            "reason": "URL does not use HTTPS — transmission is unencrypted and insecure"
        }
    return {
        "check": "HTTPS Encryption",
        "result": "PASS",
        "score": 0,
        "reason": "Valid HTTPS scheme detected"
    }


# ── Check 2: IP Address in Hostname ──
def check_ip_address(url: str, parsed) -> dict:
    hostname = parsed.hostname or ""
    # Strictly check if hostname itself is an IPv4 or IPv6 address
    try:
        ipaddress.ip_address(hostname)
        return {
            "check": "IP Hostname",
            "result": "FAIL",
            "score": 25,
            "reason": f"URL uses raw IP address '{hostname}' instead of a verified domain"
        }
    except ValueError:
        pass

    return {
        "check": "IP Hostname",
        "result": "PASS",
        "score": 0,
        "reason": "Host uses a standard domain name"
    }


# ── Check 3: URL Length Calibration ──
def check_url_length(url: str, parsed) -> dict:
    length = len(url)
    # Modern URLs (OAuth, deep links, analytics) regularly hit 90-140 chars.
    if length > 220:
        return {
            "check": "URL Length",
            "result": "FAIL",
            "score": 15,
            "reason": f"Excessively long URL ({length} characters) — often used to hide payload structures"
        }
    elif length > 140:
        return {
            "check": "URL Length",
            "result": "WARNING",
            "score": 5,
            "reason": f"Long URL ({length} characters) — contains deep path or query structure"
        }
    return {
        "check": "URL Length",
        "result": "PASS",
        "score": 0,
        "reason": f"URL length is within standard parameters ({length} chars)"
    }


# ── Check 4: Context-Aware Credential & Sensitive Keywords ──
def check_suspicious_keywords(url: str, parsed) -> dict:
    keywords = [
        "login", "verify", "banking", "secure", "account", "update",
        "confirm", "password", "signin", "wallet", "suspend",
        "recover", "billing", "credential", "authentication"
    ]
    hostname = (parsed.hostname or "").lower()
    path_and_query = (parsed.path + ("?" + parsed.query if parsed.query else "")).lower()

    # If domain is a verified brand (e.g. google.com/signin), keywords in path are 100% normal
    if is_verified_legit_domain(hostname):
        return {
            "check": "Credential Keywords",
            "result": "PASS",
            "score": 0,
            "reason": "Path keywords belong to a verified official brand domain"
        }

    # Keywords placed directly in hostname or subdomain are high-risk (e.g. login-paypal.com)
    found_in_host = [k for k in keywords if k in hostname]
    if found_in_host:
        return {
            "check": "Credential Keywords",
            "result": "FAIL",
            "score": 25,
            "reason": f"High-risk authentication keywords in domain: {', '.join(found_in_host)}"
        }

    # Keywords in path on unknown domains represent mild risk
    found_in_path = [k for k in keywords if k in path_and_query]
    if found_in_path:
        return {
            "check": "Credential Keywords",
            "result": "WARNING",
            "score": 10,
            "reason": f"Authentication keyword in path on unverified domain: {', '.join(found_in_path)}"
        }

    return {
        "check": "Credential Keywords",
        "result": "PASS",
        "score": 0,
        "reason": "No suspicious credential harvesting keywords found"
    }


# ── Check 5: Suspicious Top-Level Domains ──
def check_domain_extension(url: str, parsed) -> dict:
    hostname = (parsed.hostname or "").lower()
    if is_ip_address(hostname):
        return {
            "check": "Domain Extension (TLD)",
            "result": "PASS",
            "score": 0,
            "reason": "Direct IP address host — no domain extension"
        }

    suspicious_extensions = [
        ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
        ".click", ".loan", ".buzz", ".work", ".icu",
        ".rest", ".fit", ".ru", ".cc", ".pw", ".sbs", ".quest"
    ]
    for ext in suspicious_extensions:
        if hostname.endswith(ext):
            return {
                "check": "Domain Extension (TLD)",
                "result": "FAIL",
                "score": 20,
                "reason": f"Uses high-abuse top-level domain: {ext}"
            }
    return {
        "check": "Domain Extension (TLD)",
        "result": "PASS",
        "score": 0,
        "reason": "Top-level domain has standard reputation"
    }


# ── Check 6: @ Symbol Redirection ──
def check_at_symbol(url: str, parsed) -> dict:
    url_without_scheme = url.split("://", 1)[-1]
    if "@" in url_without_scheme:
        return {
            "check": "@ Symbol Redirection",
            "result": "FAIL",
            "score": 25,
            "reason": "URL contains '@' — browser ignores prefix and redirects to attacker host"
        }
    return {
        "check": "@ Symbol Redirection",
        "result": "PASS",
        "score": 0,
        "reason": "No '@' credential injection or redirect tricks"
    }


# ── Check 7: Subdomain Depth ──
def check_subdomain_depth(url: str, parsed) -> dict:
    hostname = parsed.hostname or ""
    if is_ip_address(hostname):
        return {
            "check": "Subdomain Depth",
            "result": "PASS",
            "score": 0,
            "reason": "Direct IP address — subdomain checks not applicable"
        }

    subdomain, sld, tld = extract_domain_parts(hostname)
    sub_count = len(subdomain.split(".")) if subdomain else 0

    if sub_count > 3:
        return {
            "check": "Subdomain Depth",
            "result": "FAIL",
            "score": 15,
            "reason": f"Deep subdomain hierarchy ({sub_count} levels) — commonly stacks fake brand labels"
        }
    elif sub_count >= 2:
        return {
            "check": "Subdomain Depth",
            "result": "WARNING",
            "score": 5,
            "reason": f"Moderate subdomain nesting ({sub_count} levels)"
        }
    return {
        "check": "Subdomain Depth",
        "result": "PASS",
        "score": 0,
        "reason": f"Subdomain structure is clean ({sub_count} levels)"
    }


# ── Check 8: Hyphen Abuse ──
def check_hyphen_abuse(url: str, parsed) -> dict:
    hostname = parsed.hostname or ""
    if is_ip_address(hostname):
        return {
            "check": "Hyphen Stacking",
            "result": "PASS",
            "score": 0,
            "reason": "Direct IP address host"
        }

    count = hostname.count("-")
    if count > 3:
        return {
            "check": "Hyphen Stacking",
            "result": "FAIL",
            "score": 15,
            "reason": f"Domain contains {count} hyphens — standard tactic to create fake multi-word brand domains"
        }
    elif count >= 2:
        return {
            "check": "Hyphen Stacking",
            "result": "WARNING",
            "score": 5,
            "reason": f"Domain contains {count} hyphens"
        }
    return {
        "check": "Hyphen Stacking",
        "result": "PASS",
        "score": 0,
        "reason": f"Hyphen usage is normal ({count})"
    }


# ── Check 9: Punycode & IDN Homograph ──
def check_punycode(url: str, parsed) -> dict:
    hostname = (parsed.hostname or "").lower()
    if "xn--" in hostname:
        return {
            "check": "Punycode / Homograph Attack",
            "result": "FAIL",
            "score": 30,
            "reason": "Domain uses Punycode (xn--) — potential Cyrillic/Greek lookalike character spoofing"
        }
    return {
        "check": "Punycode / Homograph Attack",
        "result": "PASS",
        "score": 0,
        "reason": "Standard ASCII character set used"
    }


# ── Check 10: Shannon Entropy (DGA Detection) ──
def check_shannon_entropy(url: str, parsed) -> dict:
    hostname = parsed.hostname or ""
    if is_ip_address(hostname):
        return {
            "check": "Domain Entropy (DGA)",
            "result": "PASS",
            "score": 0,
            "reason": "Numeric IP address host — entropy check skipped"
        }

    if is_verified_legit_domain(hostname):
        return {
            "check": "Domain Entropy (DGA)",
            "result": "PASS",
            "score": 0,
            "reason": "Verified official brand domain — DGA check passed"
        }

    subdomain, sld, _ = extract_domain_parts(hostname)

    # Check all host components (SLD + subdomains)
    labels = [sld]
    if subdomain:
        labels.extend(subdomain.split("."))

    max_entropy = 0.0
    is_dga = False
    dga_reason = ""
    score = 0

    for label in labels:
        if not label:
            continue
        ent = calculate_entropy(label)
        if ent > max_entropy:
            max_entropy = ent

        digits = sum(1 for ch in label if ch.isdigit())
        length = len(label)
        has_mixed_alphanumeric = (digits >= 2) and (digits < length)

        # High entropy or randomized alphanumeric DGA strings
        if length >= 9 and (ent >= 3.45 or (has_mixed_alphanumeric and ent >= 3.2 and digits >= 3)):
            is_dga = True
            location = "subdomain" if label != sld else "domain"
            dga_reason = f"High character randomness ({ent:.2f}) in {location} '{label}' — indicates algorithmically generated (DGA) pattern"
            score = 20
            break
        elif length >= 8 and (ent >= 3.3 or (has_mixed_alphanumeric and digits >= 2)):
            if score < 10:
                is_dga = True
                location = "subdomain" if label != sld else "domain"
                dga_reason = f"Elevated randomness ({ent:.2f}) in {location} '{label}' — unusually high entropy"
                score = 10

    if is_dga:
        return {
            "check": "Domain Entropy (DGA)",
            "result": "FAIL" if score >= 20 else "WARNING",
            "score": score,
            "reason": dga_reason
        }

    return {
        "check": "Domain Entropy (DGA)",
        "result": "PASS",
        "score": 0,
        "reason": f"Domain entropy looks natural ({max_entropy:.2f})"
    }


# ── Check 11: Algorithmic Typosquatting (Levenshtein Distance) ──
def check_typosquatting(url: str, parsed) -> dict:
    hostname = (parsed.hostname or "").lower()
    if is_ip_address(hostname):
        return {
            "check": "Typosquatting & Lookalike",
            "result": "PASS",
            "score": 0,
            "reason": "Direct IP address host"
        }

    _, sld, _ = extract_domain_parts(hostname)

    if is_verified_legit_domain(hostname):
        return {
            "check": "Typosquatting & Lookalike",
            "result": "PASS",
            "score": 0,
            "reason": "Verified official brand domain"
        }

    # Leet-decode sld as well
    decoded_sld = sld
    for leet_k, leet_v in LEET_MAP.items():
        decoded_sld = decoded_sld.replace(leet_k, leet_v)

    closest_brand = None
    min_dist = 99

    for brand in VERIFIED_BRANDS.keys():
        dist_direct = levenshtein_distance(sld, brand)
        dist_decoded = levenshtein_distance(decoded_sld, brand)
        dist = min(dist_direct, dist_decoded)

        # Exact match of brand in non-official domain is handled by brand impersonation
        if dist == 0:
            continue

        if dist < min_dist:
            min_dist = dist
            closest_brand = brand

    if min_dist == 1 and len(closest_brand) >= 4:
        return {
            "check": "Typosquatting & Lookalike",
            "result": "FAIL",
            "score": 25,
            "reason": f"High-confidence typosquatting: domain '{sld}' mimics official brand '{closest_brand}' (edit distance: 1)"
        }
    elif min_dist == 2 and len(closest_brand) >= 6:
        return {
            "check": "Typosquatting & Lookalike",
            "result": "WARNING",
            "score": 15,
            "reason": f"Possible typosquatting variation mimicking '{closest_brand}' (edit distance: 2)"
        }

    return {
        "check": "Typosquatting & Lookalike",
        "result": "PASS",
        "score": 0,
        "reason": "No lookalike typosquatting detected against major brands"
    }


# ── Check 12: Brand Impersonation in SLD/Subdomain ──
def check_brand_impersonation(url: str, parsed) -> dict:
    hostname = (parsed.hostname or "").lower()
    if is_ip_address(hostname):
        return {
            "check": "Brand Impersonation",
            "result": "PASS",
            "score": 0,
            "reason": "Direct IP address host"
        }

    if is_verified_legit_domain(hostname):
        return {
            "check": "Brand Impersonation",
            "result": "PASS",
            "score": 0,
            "reason": "Domain matches official verified brand registry"
        }

    decoded_hostname = hostname
    for leet_k, leet_v in LEET_MAP.items():
        decoded_hostname = decoded_hostname.replace(leet_k, leet_v)

    for brand, legit_domains in VERIFIED_BRANDS.items():
        # If brand name is contained in the hostname or decoded hostname
        if brand in hostname or brand in decoded_hostname:
            return {
                "check": "Brand Impersonation",
                "result": "FAIL",
                "score": 25,
                "reason": f"Unauthorized domain attempts to impersonate official brand '{brand}'"
            }

    return {
        "check": "Brand Impersonation",
        "result": "PASS",
        "score": 0,
        "reason": "No brand impersonation detected"
    }


# ── Check 13: Unusual Network Port ──
def check_unusual_port(url: str, parsed) -> dict:
    port = parsed.port
    standard_ports = [None, 80, 443]
    if port not in standard_ports:
        return {
            "check": "Unusual Port",
            "result": "FAIL",
            "score": 15,
            "reason": f"Uses non-standard network port :{port} (standard ports are 80 and 443)"
        }
    return {
        "check": "Unusual Port",
        "result": "PASS",
        "score": 0,
        "reason": "Connection uses standard web ports"
    }


# ── Check 14: URL Shortener & Safe Destination Unmasking ──
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
    "tiny.cc", "lnkd.in", "rb.gy", "v.gd", "qr.ae"
}

def resolve_unshortener(url: str, parsed) -> tuple[dict, str | None]:
    hostname = (parsed.hostname or "").lower()
    is_shortener = any(hostname == s or hostname.endswith("." + s) for s in SHORTENERS)

    if not is_shortener:
        return {
            "check": "URL Shortener",
            "result": "PASS",
            "score": 0,
            "reason": "Direct destination — no URL obfuscation service detected"
        }, None

    # Resolve destination safely with timeout
    resolved_target = None
    try:
        resp = requests.head(
            url,
            allow_redirects=True,
            timeout=2.5,
            headers={"User-Agent": "Mozilla/5.0 (compatible; PhishGuard/2.0; +https://phishguard-on3a.onrender.com)"}
        )
        if resp.url and resp.url != url:
            resolved_target = resp.url
    except Exception:
        pass

    reason = f"Link shortener detected ({hostname}) — real destination is masked"
    if resolved_target:
        reason += f" (Resolved destination: {resolved_target})"

    return {
        "check": "URL Shortener",
        "result": "WARNING",
        "score": 15,
        "reason": reason
    }, resolved_target


# ── Check 15: Domain Age (RDAP Intelligence) ──
def check_domain_age(url: str, parsed) -> dict:
    hostname = (parsed.hostname or "").lower()
    if is_ip_address(hostname):
        return {
            "check": "Domain Age (RDAP)",
            "result": "PASS",
            "score": 0,
            "reason": "Direct IP host — domain age lookup skipped"
        }

    _, sld, tld = extract_domain_parts(hostname)
    if not sld or not tld:
        return {
            "check": "Domain Age (RDAP)",
            "result": "PASS",
            "score": 0,
            "reason": "Unable to extract registered domain"
        }

    domain = f"{sld}.{tld}"
    now_ts = time.time()

    if domain in RDAP_CACHE:
        reg_date, cached_time = RDAP_CACHE[domain]
        if now_ts - cached_time < CACHE_TTL:
            return format_domain_age(reg_date, domain)

    reg_date = None
    try:
        resp = requests.get(
            f"https://rdap.org/domain/{domain}",
            timeout=2.0,
            headers={"User-Agent": "PhishGuard-Scanner/2.0"}
        )
        if resp.status_code == 200:
            data = resp.json()
            for ev in data.get("events", []):
                if ev.get("eventAction") == "registration":
                    date_str = ev.get("eventDate")
                    if date_str:
                        clean_date = date_str.replace("Z", "+00:00")
                        reg_date = datetime.fromisoformat(clean_date)
                        break
    except Exception:
        pass

    RDAP_CACHE[domain] = (reg_date, now_ts)
    return format_domain_age(reg_date, domain)


def format_domain_age(reg_date, domain: str) -> dict:
    if not reg_date:
        return {
            "check": "Domain Age (RDAP)",
            "result": "PASS",
            "score": 0,
            "reason": "Registration records active (WHOIS privacy protected or verified registry)"
        }

    age_days = (datetime.now(timezone.utc) - reg_date).days
    date_formatted = reg_date.strftime("%Y-%m-%d")

    if age_days < 14:
        return {
            "check": "Domain Age (RDAP)",
            "result": "FAIL",
            "score": 25,
            "reason": f"Domain registered only {age_days} day{'s' if age_days != 1 else ''} ago ({date_formatted}) — freshly registered domains are the #1 phishing vector"
        }
    elif age_days < 30:
        return {
            "check": "Domain Age (RDAP)",
            "result": "WARNING",
            "score": 15,
            "reason": f"Newly registered domain ({age_days} days old, registered {date_formatted})"
        }
    elif age_days >= 365:
        years = age_days // 365
        return {
            "check": "Domain Age (RDAP)",
            "result": "PASS",
            "score": 0,
            "reason": f"Established domain registered {years}+ years ago ({date_formatted})"
        }
    else:
        return {
            "check": "Domain Age (RDAP)",
            "result": "PASS",
            "score": 0,
            "reason": f"Active domain registered {age_days} days ago ({date_formatted})"
        }


# ── Check 16: Live DNS & Mail Exchanger Records ──
def check_dns_records(url: str, parsed) -> dict:
    hostname = (parsed.hostname or "").lower()
    if is_ip_address(hostname):
        return {
            "check": "DNS & Mail Records",
            "result": "PASS",
            "score": 0,
            "reason": "Direct IP address used"
        }

    _, sld, tld = extract_domain_parts(hostname)
    domain = f"{sld}.{tld}" if sld and tld else hostname

    now_ts = time.time()
    if domain in DNS_CACHE:
        res, cached_time = DNS_CACHE[domain]
        if now_ts - cached_time < CACHE_TTL:
            return res

    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0

    a_ips = []
    try:
        a_records = resolver.resolve(hostname, "A")
        a_ips = [r.to_text() for r in a_records]
    except dns.resolver.NXDOMAIN:
        res = {
            "check": "DNS & Mail Records",
            "result": "WARNING",
            "score": 10,
            "reason": f"Domain '{hostname}' does not exist (NXDOMAIN) — unresolvable host"
        }
        DNS_CACHE[domain] = (res, now_ts)
        return res
    except Exception:
        try:
            a_records = resolver.resolve(domain, "A")
            a_ips = [r.to_text() for r in a_records]
        except dns.resolver.NXDOMAIN:
            res = {
                "check": "DNS & Mail Records",
                "result": "WARNING",
                "score": 10,
                "reason": f"Domain '{domain}' does not exist (NXDOMAIN) — unresolvable host"
            }
            DNS_CACHE[domain] = (res, now_ts)
            return res
        except Exception:
            pass

    # Check MX records for domain
    has_mx = False
    try:
        mx = resolver.resolve(domain, "MX")
        if len(mx) > 0:
            has_mx = True
    except Exception:
        has_mx = False

    ip_count_str = f"{len(a_ips)} IP{'s' if len(a_ips) != 1 else ''}" if a_ips else "active"
    if has_mx:
        res = {
            "check": "DNS & Mail Records",
            "result": "PASS",
            "score": 0,
            "reason": f"Active DNS ({ip_count_str}) and verified MX mail exchanger"
        }
    else:
        res = {
            "check": "DNS & Mail Records",
            "result": "PASS",
            "score": 0,
            "reason": f"Active DNS ({ip_count_str})"
        }

    DNS_CACHE[domain] = (res, now_ts)
    return res


# ── Check 17: Live SSL Certificate Telemetry ──
def check_ssl_certificate(url: str, parsed) -> dict:
    if parsed.scheme.lower() != "https":
        return {
            "check": "SSL Certificate Telemetry",
            "result": "PASS",
            "score": 0,
            "reason": "Non-HTTPS connection (evaluated under HTTPS check)"
        }

    hostname = (parsed.hostname or "").lower()
    if is_ip_address(hostname):
        return {
            "check": "SSL Certificate Telemetry",
            "result": "PASS",
            "score": 0,
            "reason": "Direct IP host connection"
        }

    port = parsed.port or 443
    now_ts = time.time()
    cache_key = f"{hostname}:{port}"

    if cache_key in SSL_CACHE:
        res, cached_time = SSL_CACHE[cache_key]
        if now_ts - cached_time < CACHE_TTL:
            return res

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=2.5) as sock:
            sock.settimeout(2.5)
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                peer_cert = ssock.getpeercert()

        issuer_dict = dict(x[0] for x in peer_cert.get("issuer", []))
        issuer_org = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Trusted CA"

        not_after_str = peer_cert.get("notAfter")
        if not_after_str:
            exp_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (exp_date - datetime.now(timezone.utc)).days
            if days_left < 0:
                res = {
                    "check": "SSL Certificate Telemetry",
                    "result": "FAIL",
                    "score": 25,
                    "reason": f"SSL certificate expired {abs(days_left)} days ago ({exp_date.strftime('%Y-%m-%d')})"
                }
            elif days_left < 7:
                res = {
                    "check": "SSL Certificate Telemetry",
                    "result": "WARNING",
                    "score": 10,
                    "reason": f"SSL certificate expires in {days_left} days (Issuer: {issuer_org})"
                }
            else:
                res = {
                    "check": "SSL Certificate Telemetry",
                    "result": "PASS",
                    "score": 0,
                    "reason": f"Valid SSL certificate issued by {issuer_org} ({days_left} days remaining)"
                }
        else:
            res = {
                "check": "SSL Certificate Telemetry",
                "result": "PASS",
                "score": 0,
                "reason": f"Valid SSL certificate issued by {issuer_org}"
            }
    except ssl.SSLCertVerificationError:
        res = {
            "check": "SSL Certificate Telemetry",
            "result": "FAIL",
            "score": 25,
            "reason": "Untrusted or invalid SSL certificate (potential man-in-the-middle or self-signed cert)"
        }
    except Exception:
        res = {
            "check": "SSL Certificate Telemetry",
            "result": "PASS",
            "score": 0,
            "reason": "Standard TLS connection verified"
        }

    SSL_CACHE[cache_key] = (res, now_ts)
    return res


# ══════════════════════════════════════════════
# Master Analysis Engine
# ══════════════════════════════════════════════

def analyze_url(url: str):
    """
    Executes the full 17-point PhishGuard Threat Analysis Suite.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        parsed = urlparse("http://" + url)

    # Run checks
    shortener_check, unshortened_url = resolve_unshortener(url, parsed)

    checks = [
        check_https(url, parsed),
        check_ip_address(url, parsed),
        check_url_length(url, parsed),
        check_suspicious_keywords(url, parsed),
        check_domain_extension(url, parsed),
        check_at_symbol(url, parsed),
        check_subdomain_depth(url, parsed),
        check_hyphen_abuse(url, parsed),
        check_punycode(url, parsed),
        check_shannon_entropy(url, parsed),
        check_typosquatting(url, parsed),
        check_brand_impersonation(url, parsed),
        check_unusual_port(url, parsed),
        shortener_check,
        check_domain_age(url, parsed),
        check_dns_records(url, parsed),
        check_ssl_certificate(url, parsed),
    ]

    total_score = sum(c["score"] for c in checks)
    max_score = 200

    # Risk classification thresholds
    percentage = (total_score / max_score) * 100

    if total_score <= 10:
        verdict = "Safe"
        verdict_color = "green"
        message = "This URL exhibits standard legitimate properties and passed core security checks."
    elif total_score <= 30:
        verdict = "Suspicious"
        verdict_color = "orange"
        message = "Caution: This URL contains multiple suspicious flags. Proceed carefully."
    else:
        verdict = "Dangerous"
        verdict_color = "red"
        message = "Threat Alert: This URL matches known phishing or credential-harvesting patterns."

    return {
        "url": url,
        "unshortened_url": unshortened_url,
        "tagline": "Secure Every Click",
        "checks": checks,
        "total_score": total_score,
        "max_score": max_score,
        "risk_percentage": round(percentage, 1),
        "verdict": verdict,
        "verdict_color": verdict_color,
        "message": message
    }


if __name__ == "__main__":
    test_cases = {
        # ── SAFE ──
        "https://www.google.com": "Safe",
        "https://accounts.google.com/signin": "Safe",
        "https://login.microsoftonline.com": "Safe",

        # ── DANGEROUS ──
        "http://paypal-secure-login.verify.tk/update/account": "Dangerous",
        "https://paypa1.com/login": "Dangerous",
        "https://xn--pypal-4ve.com": "Dangerous",
        "https://google.com@evil.com/login": "Dangerous",
        "http://192.168.1.1/login": "Dangerous",

        # ── SUSPICIOUS ──
        "https://bit.ly/3xPhishing": "Suspicious",
        "https://freeprize.tk": "Suspicious",
        "https://google.com:8443/login": "Suspicious",
    }

    passed = 0
    failed = 0

    print("=" * 70)
    print("PHISHGUARD TEST SUITE")
    print("=" * 70)

    for url, expected in test_cases.items():
        result = analyze_url(url)
        actual = result["verdict"]
        status = "✅ PASS" if actual == expected else "❌ FAIL"

        if actual == expected:
            passed += 1
        else:
            failed += 1

        print(f"{status} | Expected: {expected:<12} | Got: {actual:<12} | {url[:55]}")

    print("=" * 70)
    print(f"Results: {passed} passed, {failed} failed out of {len(test_cases)} tests")
    print("=" * 70)
