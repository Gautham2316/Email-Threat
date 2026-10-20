"""
src/url_analyzer.py
===================
Module 3: URL Threat Analysis Engine
SIH 2026 — AI-Powered Email Threat Detection Platform

Analyzes URLs extracted from suspicious emails using static, heuristic,
lexical, and structural feature extraction.

CRITICAL SECURITY GUARANTEES:
1. Zero Network Access: Never opens, fetches, crawls, or resolves DNS for
   any submitted URL.
2. Non-Destructive: Preserves the original raw URL as forensic evidence.
3. Safe Defanging: Converts active links to safe representations
   (e.g., hxxps://example[.]com) to prevent accidental clicking.
4. Bounded & Explainable Scoring: Heuristic risk scores are strictly bounded
   in [0, 100] with detailed evidence for every triggered indicator.
5. No False Claims: Threat intelligence reputation status is explicitly
   reported as 'not_checked' rather than falsely declaring URLs 'safe'.

AUTHOR: SIH 2026 Team
VERSION: 1.0.0
"""

from __future__ import annotations

import html
import ipaddress
import re
import unicodedata
import urllib.parse
from datetime import datetime, timezone
from typing import Any

import tldextract as _tldextract

ANALYZER_VERSION: str = "1.0.0"

# ---------------------------------------------------------------------------
# Offline PSL extractor using bundled snapshot (zero network, no caching)
# ---------------------------------------------------------------------------
_TLD_EXTRACT = _tldextract.TLDExtract(
    cache_dir=None, suffix_list_urls=(), fallback_to_snapshot=True
)

# ---------------------------------------------------------------------------
# Known URL shortener services (local documented list)
# ---------------------------------------------------------------------------
SHORTENER_DOMAINS: frozenset[str] = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "mcaf.ee", "rebrand.ly", "tiny.cc", "clck.ru",
    "cutt.ly", "shorturl.at", "qr.ae", "rb.gy", "v.gd", "soo.gd",
    "trib.al", "s.id", "t.ly", "lnkd.in", "bc.vc", "linktr.ee"
})

# ---------------------------------------------------------------------------
# High-profile brands targeted in email phishing campaigns
# Maps brand keyword -> legitimate primary organizational domain
# ---------------------------------------------------------------------------
TARGETED_BRANDS: dict[str, str] = {
    "paypal": "paypal.com",
    "microsoft": "microsoft.com",
    "office365": "office.com",
    "outlook": "live.com",
    "google": "google.com",
    "gmail": "google.com",
    "apple": "apple.com",
    "icloud": "apple.com",
    "amazon": "amazon.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "whatsapp": "whatsapp.com",
    "chase": "chase.com",
    "bankofamerica": "bankofamerica.com",
    "wellsfargo": "wellsfargo.com",
    "citibank": "citi.com",
    "dhl": "dhl.com",
    "fedex": "fedex.com",
    "usps": "usps.com",
    "adobe": "adobe.com",
    "dropbox": "dropbox.com",
    "docusign": "docusign.com",
    "sbi": "onlinesbi.sbi",
    "hdfc": "hdfcbank.com",
    "icici": "icicibank.com",
}

# ---------------------------------------------------------------------------
# Phishing action keywords frequently observed in malicious URLs
# ---------------------------------------------------------------------------
PHISHING_KEYWORDS: frozenset[str] = frozenset({
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "authenticate", "authentication", "security", "secure", "account",
    "update", "banking", "confirm", "confirmation", "password", "credential",
    "wallet", "restore", "unlock", "suspended", "re-activate", "alert",
    "notice", "validate", "invoice", "payment", "billing"
})

# ---------------------------------------------------------------------------
# Dangerous/suspicious payload file extensions in URL paths
# ---------------------------------------------------------------------------
SUSPICIOUS_PAYLOAD_EXTENSIONS: frozenset[str] = frozenset({
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".jse", ".hta",
    ".ps1", ".apk", ".iso", ".img", ".vhd", ".zip", ".rar", ".7z",
    ".tar", ".gz", ".msi", ".dll", ".jar", ".wsf", ".cpl"
})

# ---------------------------------------------------------------------------
# High-abuse Top-Level Domains (TLDs) commonly seen in disposable phishing
# ---------------------------------------------------------------------------
HIGH_RISK_TLDS: frozenset[str] = frozenset({
    "xyz", "top", "click", "buzz", "club", "work", "icu", "tk",
    "ml", "ga", "cf", "gq", "loan", "men", "stream", "download",
    "racing", "win", "bid", "vip", "kim", "party"
})

# ---------------------------------------------------------------------------
# Dangerous executable or local URI schemes
# ---------------------------------------------------------------------------
DANGEROUS_SCHEMES: frozenset[str] = frozenset({
    "javascript", "data", "file", "vbscript", "about", "blob"
})


# ===========================================================================
# SECTION B — HELPER FUNCTIONS (DEFANGING, IP PARSING, DOMAIN DECOMPOSITION)
# ===========================================================================

def defang_url(raw_url: str) -> str:
    """
    Convert a live URL into a defanged representation safe for terminal
    reports, logs, and user interfaces (e.g., hxxps://example[.]com).

    Parameters
    ----------
    raw_url : str
        The URL to defang.

    Returns
    -------
    str
        Defanged string. Original evidence is unchanged elsewhere.
    """
    if not isinstance(raw_url, str) or not raw_url.strip():
        return ""

    s = raw_url.strip()
    # Defang common schemes
    s = re.sub(r"^https://", "hxxps://", s, flags=re.IGNORECASE)
    s = re.sub(r"^http://", "hxxp://", s, flags=re.IGNORECASE)
    s = re.sub(r"^ftp://", "fxp://", s, flags=re.IGNORECASE)

    try:
        parts = urllib.parse.urlsplit(s)
        if parts.netloc:
            # Defang authority (dots, @, colons in IP)
            defanged_netloc = parts.netloc.replace(".", "[.]").replace("@", "[@]")
            return urllib.parse.urlunsplit(
                (parts.scheme, defanged_netloc, parts.path, parts.query, parts.fragment)
            )
        # If no netloc (e.g. malformed or path-only), defang dots safely
        return s.replace(".", "[.]").replace("@", "[@]")
    except Exception:
        return s.replace(".", "[.]").replace("@", "[@]")


def _extract_ip_info(hostname: str | None) -> tuple[bool, dict[str, Any] | None]:
    """
    Determine if a hostname is an IPv4 or IPv6 address literal and extract
    its classification (public/private/loopback/reserved).
    """
    if not hostname:
        return False, None

    clean_host = hostname.strip().strip("[]").strip()

    # Standard IPv4 / IPv6 parsing
    try:
        ip_obj = ipaddress.ip_address(clean_host)
        return True, {
            "ip": str(ip_obj),
            "version": ip_obj.version,
            "is_private": ip_obj.is_private,
            "is_loopback": ip_obj.is_loopback,
            "is_reserved": ip_obj.is_reserved,
            "is_multicast": ip_obj.is_multicast,
            "is_link_local": ip_obj.is_link_local,
            "is_global": ip_obj.is_global,
        }
    except ValueError:
        pass

    # Check for integer/dword or hex IP representations (e.g., 2130706433 or 0x7f000001)
    if clean_host.isdigit():
        try:
            val = int(clean_host)
            if 0 <= val <= 0xFFFFFFFF:
                ip_obj = ipaddress.IPv4Address(val)
                return True, {
                    "ip": str(ip_obj),
                    "version": 4,
                    "is_private": ip_obj.is_private,
                    "is_loopback": ip_obj.is_loopback,
                    "is_reserved": ip_obj.is_reserved,
                    "is_multicast": ip_obj.is_multicast,
                    "is_link_local": ip_obj.is_link_local,
                    "is_global": ip_obj.is_global,
                    "obfuscated_integer": val,
                }
        except Exception:
            pass

    return False, None


def _check_punycode_and_homograph(
    hostname: str | None,
) -> tuple[bool, bool, str | None, str | None]:
    """
    Check if a hostname uses Punycode (IDN) or contains homograph characters.

    Returns
    -------
    tuple of (is_punycode, is_homograph, decoded_idna, details)
    """
    if not hostname:
        return False, False, None, None

    h = hostname.lower().strip()
    is_punycode = "xn--" in h
    decoded: str | None = None
    is_homograph = False
    details: str | None = None

    if is_punycode:
        try:
            decoded = h.encode("ascii").decode("idna")
            # Check if decoded contains non-Latin characters mixed with Latin
            scripts = set()
            for ch in decoded:
                if ch in ".-_":
                    continue
                try:
                    name = unicodedata.name(ch, "")
                    script = name.split()[0] if name else "UNKNOWN"
                    scripts.add(script)
                except Exception:
                    pass
            # If characters from Cyrillic, Greek, Hebrew, Arabic, etc., are present
            suspicious_scripts = {"CYRILLIC", "GREEK", "HEBREW", "ARABIC"}
            if any(s in scripts for s in suspicious_scripts):
                is_homograph = True
                details = f"Decoded IDNA domain '{decoded}' contains mixed {scripts} characters"
        except Exception as exc:
            details = f"Punycode decode error: {exc}"
    else:
        # Check raw non-ASCII unicode in hostname
        non_ascii = [ch for ch in h if ord(ch) > 127]
        if non_ascii:
            is_homograph = True
            details = f"Hostname contains non-ASCII characters: {''.join(set(non_ascii))}"

    return is_punycode, is_homograph, decoded, details


def _extract_domain_parts(
    hostname: str | None,
) -> tuple[str, str, str, str]:
    """
    Extract (subdomain, domain, suffix, org_domain) using PSL-aware rules.
    """
    if not hostname:
        return "", "", "", ""

    h = hostname.lower().strip()
    ext = _TLD_EXTRACT(h)
    org_domain = f"{ext.domain}.{ext.suffix}" if (ext.domain and ext.suffix) else h
    return ext.subdomain, ext.domain, ext.suffix, org_domain


def _normalize_leetspeak(s: str) -> str:
    """
    Normalize common leetspeak substitutions (e.g. paypa1 -> paypal, micr0s0ft -> microsoft).
    """
    table = str.maketrans({"1": "l", "0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a"})
    return s.translate(table)



# ===========================================================================
# SECTION C — SINGLE URL FEATURE EXTRACTION AND HEURISTIC SCORING
# ===========================================================================

def _sanitize_normalized_url(scheme: str, netloc: str, path: str, query: str, fragment: str) -> str:
    """
    Build normalized URL with password/credentials redacted for safe logging.
    """
    if "@" in netloc:
        userinfo, _, hostpart = netloc.rpartition("@")
        if ":" in userinfo:
            user, _, _ = userinfo.partition(":")
            netloc = f"{user}:***@{hostpart}"
        else:
            netloc = f"{userinfo}@{hostpart}"
    return urllib.parse.urlunsplit((scheme, netloc, path, query, fragment))


def _analyze_single_url(
    raw_url: Any,
    source_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Perform deep static feature extraction and heuristic threat analysis
    on a single URL. Makes ZERO network requests.
    """
    # 1. Base validation of input type
    if not isinstance(raw_url, str):
        return {
            "original_url": str(raw_url) if raw_url is not None else "",
            "normalized_url": None,
            "defanged_url": "",
            "scheme": None,
            "hostname": None,
            "port": None,
            "path": None,
            "query": None,
            "fragment": None,
            "is_ip_literal": False,
            "ip_literal": None,
            "is_shortener": False,
            "is_punycode": False,
            "has_credentials": False,
            "indicators": [],
            "warnings": [f"Invalid input type: expected str, got {type(raw_url).__name__}"],
            "heuristic_risk_score": 0,
            "risk_level": "none",
            "analysis_status": "error",
            "threat_intel": {
                "reputation_checked": False,
                "verdict": "not_checked",
                "reason": "External reputation lookup is not performed in local heuristic mode.",
            },
        }

    original_url = raw_url.strip()
    if not original_url:
        return {
            "original_url": "",
            "normalized_url": None,
            "defanged_url": "",
            "scheme": None,
            "hostname": None,
            "port": None,
            "path": None,
            "query": None,
            "fragment": None,
            "is_ip_literal": False,
            "ip_literal": None,
            "is_shortener": False,
            "is_punycode": False,
            "has_credentials": False,
            "indicators": [],
            "warnings": ["Empty URL string provided"],
            "heuristic_risk_score": 0,
            "risk_level": "none",
            "analysis_status": "malformed",
            "threat_intel": {
                "reputation_checked": False,
                "verdict": "not_checked",
                "reason": "External reputation lookup is not performed in local heuristic mode.",
            },
        }

    defanged = defang_url(original_url)
    indicators: list[dict[str, Any]] = []
    warnings: list[str] = []
    analysis_status = "analyzed"

    # 2. Syntax parsing via urllib.parse.urlsplit
    try:
        parsed = urllib.parse.urlsplit(original_url)
    except Exception as exc:
        indicators.append({
            "id": "MALFORMED_URL_SYNTAX",
            "title": "Malformed URL Syntax",
            "description": f"URL failed standard RFC 3986 parsing: {exc}",
            "severity": "medium",
            "score_contribution": 25,
            "evidence": original_url[:100],
        })
        return {
            "original_url": original_url,
            "normalized_url": None,
            "defanged_url": defanged,
            "scheme": None,
            "hostname": None,
            "port": None,
            "path": None,
            "query": None,
            "fragment": None,
            "is_ip_literal": False,
            "ip_literal": None,
            "is_shortener": False,
            "is_punycode": False,
            "has_credentials": False,
            "indicators": indicators,
            "warnings": [f"Parsing error: {exc}"],
            "heuristic_risk_score": 25,
            "risk_level": "low",
            "analysis_status": "malformed",
            "threat_intel": {
                "reputation_checked": False,
                "verdict": "not_checked",
                "reason": "External reputation lookup is not performed in local heuristic mode.",
            },
        }

    raw_scheme = parsed.scheme.lower() if parsed.scheme else ""
    raw_netloc = parsed.netloc
    raw_path = parsed.path or ""
    raw_query = parsed.query or ""
    raw_fragment = parsed.fragment or ""

    # Port extraction (safe against malformed port numbers)
    port: int | None = None
    try:
        port = parsed.port
    except ValueError:
        warnings.append(f"Invalid non-numeric port in URL netloc: {raw_netloc!r}")
        indicators.append({
            "id": "INVALID_PORT_SPECIFICATION",
            "title": "Invalid Port Specification",
            "description": "URL contains an invalid or non-numeric port value in authority.",
            "severity": "low",
            "score_contribution": 10,
            "evidence": raw_netloc,
        })

    # Hostname extraction
    hostname: str | None = None
    try:
        hostname = parsed.hostname.lower() if parsed.hostname else None
    except Exception:
        hostname = None

    # Check for missing scheme / missing host
    if not raw_scheme:
        warnings.append("URL is missing a scheme (e.g., http:// or https://)")
        analysis_status = "malformed"
        indicators.append({
            "id": "MISSING_URL_SCHEME",
            "title": "Missing URL Scheme",
            "description": "URL does not specify an explicit protocol scheme.",
            "severity": "low",
            "score_contribution": 5,
            "evidence": original_url[:50],
        })

    # Dangerous URI schemes (javascript:, data:, file:, etc.)
    if raw_scheme in DANGEROUS_SCHEMES:
        analysis_status = "unsupported_scheme"
        indicators.append({
            "id": "DANGEROUS_URI_SCHEME",
            "title": "Dangerous Executable URI Scheme",
            "description": f"URL uses dangerous or executable scheme '{raw_scheme}:' capable of payload execution.",
            "severity": "critical",
            "score_contribution": 50,
            "evidence": f"{raw_scheme}:...",
        })

    # Insecure plain HTTP scheme
    if raw_scheme == "http":
        indicators.append({
            "id": "INSECURE_HTTP_SCHEME",
            "title": "Insecure Plaintext HTTP Scheme",
            "description": "URL uses unencrypted HTTP instead of HTTPS. (HTTP alone is not proof of malice).",
            "severity": "low",
            "score_contribution": 5,
            "evidence": "http://",
        })

    # Check embedded credentials (username/password in URL authority)
    has_credentials = bool(parsed.username or parsed.password or ("@" in raw_netloc))
    if has_credentials:
        indicators.append({
            "id": "EMBEDDED_CREDENTIALS",
            "title": "Embedded Authority Credentials",
            "description": "URL contains embedded username or credentials before '@' in authority, a common phishing spoofing trick.",
            "severity": "high",
            "score_contribution": 30,
            "evidence": raw_netloc.split("@")[0] if "@" in raw_netloc else "userinfo",
        })

    # Normalized URL (with credentials masked)
    normalized_url = _sanitize_normalized_url(raw_scheme, raw_netloc, raw_path, raw_query, raw_fragment)

    # 3. IP address literal detection & classification
    is_ip_literal, ip_info = _extract_ip_info(hostname)
    if is_ip_literal and ip_info:
        if ip_info.get("is_global"):
            indicators.append({
                "id": "IP_HOST_GLOBAL",
                "title": "Global IP Address Hostname",
                "description": "Hostname is a raw public IPv4/IPv6 literal rather than a registered domain name.",
                "severity": "high",
                "score_contribution": 35,
                "evidence": ip_info.get("ip", ""),
            })
        elif ip_info.get("is_private") or ip_info.get("is_loopback") or ip_info.get("is_reserved"):
            indicators.append({
                "id": "IP_HOST_LOCAL_PRIVATE",
                "title": "Private or Loopback IP Address Hostname",
                "description": "Hostname points to a private, loopback, or reserved IP address (e.g., 127.0.0.1, 10.x, 192.168.x).",
                "severity": "medium",
                "score_contribution": 25,
                "evidence": ip_info.get("ip", ""),
            })
        if "obfuscated_integer" in ip_info:
            indicators.append({
                "id": "OBFUSCATED_INTEGER_IP",
                "title": "Obfuscated Integer/Dword IP Address",
                "description": "IP address is encoded as a decimal integer to evade simple IP string filters.",
                "severity": "high",
                "score_contribution": 30,
                "evidence": str(ip_info["obfuscated_integer"]),
            })

    # 4. Punycode & IDN Homograph detection
    is_punycode, is_homograph, decoded_idna, idn_details = _check_punycode_and_homograph(hostname)
    if is_punycode:
        indicators.append({
            "id": "PUNYCODE_IDN_DOMAIN",
            "title": "Punycode (IDN) Encoded Domain",
            "description": "Domain uses Punycode internationalized encoding (xn--).",
            "severity": "medium",
            "score_contribution": 25,
            "evidence": f"Punycode: {hostname} -> Decoded: {decoded_idna}",
        })
    if is_homograph:
        indicators.append({
            "id": "HOMOGRAPH_ATTACK_SUSPECTED",
            "title": "Suspected Homograph or Mixed-Script Characters",
            "description": idn_details or "Domain contains mixed non-Latin or confusable character scripts.",
            "severity": "high",
            "score_contribution": 35,
            "evidence": idn_details or str(hostname),
        })

    # 5. Domain decomposition & Subdomain hierarchy analysis
    subdomain, domain_name, tld_suffix, org_domain = _extract_domain_parts(hostname)

    if hostname:
        # Check known URL shorteners
        is_shortener = (org_domain in SHORTENER_DOMAINS) or (hostname in SHORTENER_DOMAINS)
        if is_shortener:
            indicators.append({
                "id": "URL_SHORTENER_DETECTED",
                "title": "Known URL Shortener Service",
                "description": f"URL uses shortening service '{org_domain}', masking destination and preventing pre-click inspection.",
                "severity": "medium",
                "score_contribution": 20,
                "evidence": org_domain,
            })
    else:
        is_shortener = False

    # Subdomain depth analysis
    if subdomain:
        sub_labels = [lbl for lbl in subdomain.split(".") if lbl]
        sub_depth = len(sub_labels)
        if sub_depth >= 4:
            indicators.append({
                "id": "EXCESSIVE_SUBDOMAIN_DEPTH",
                "title": "Excessive Subdomain Depth",
                "description": f"Hostname contains {sub_depth} subdomain levels, common in automated phishing kit infrastructure.",
                "severity": "medium",
                "score_contribution": 15,
                "evidence": f"{subdomain} ({sub_depth} levels)",
            })

        # Deceptive / Misleading subdomains: check for brand name or pseudo-TLD inside subdomain
        sub_lower = subdomain.lower()
        sub_norm = _normalize_leetspeak(sub_lower)
        for brand, legitimate_org in TARGETED_BRANDS.items():
            if (brand in sub_lower or brand in sub_norm) and org_domain != legitimate_org:
                indicators.append({
                    "id": "BRAND_SPOOFING_IN_SUBDOMAIN",
                    "title": f"Targeted Brand Name in Subdomain ({brand.title()})",
                    "description": (
                        f"Subdomain contains brand '{brand}' while organizational domain is '{org_domain}' "
                        f"(expected legitimate domain: '{legitimate_org}')."
                    ),
                    "severity": "high",
                    "score_contribution": 35,
                    "evidence": f"Subdomain: {subdomain} | Org domain: {org_domain}",
                })
                break

        # Check for fake TLD strings in subdomain (e.g. paypal.com.attacker.com)
        pseudo_tld_match = re.search(r"\b(com|net|org|gov|edu|co)\b", subdomain.lower())
        if pseudo_tld_match and not any(i["id"] == "BRAND_SPOOFING_IN_SUBDOMAIN" for i in indicators):
            indicators.append({
                "id": "PSEUDO_TLD_IN_SUBDOMAIN",
                "title": "Deceptive TLD Sequence in Subdomain",
                "description": f"Subdomain contains pseudo-TLD component '{pseudo_tld_match.group(0)}' mimicking a top-level domain.",
                "severity": "medium",
                "score_contribution": 20,
                "evidence": subdomain,
            })

    # Brand name mismatch in registered domain (e.g. login-paypal-security.com or paypa1-restore.com)
    if domain_name:
        dom_lower = domain_name.lower()
        dom_norm = _normalize_leetspeak(dom_lower)
        for brand, legitimate_org in TARGETED_BRANDS.items():
            if (brand in dom_lower or brand in dom_norm) and org_domain != legitimate_org:
                # Make sure we don't duplicate if already flagged in subdomain
                if not any(i["id"] == "BRAND_SPOOFING_IN_SUBDOMAIN" and brand in i["evidence"].lower() for i in indicators):
                    indicators.append({
                        "id": "BRAND_NAME_MISMATCH",
                        "title": f"Brand Squatting or Keyword Typo ({brand.title()})",
                        "description": (
                            f"Domain name '{domain_name}' incorporates brand keyword '{brand}' "
                            f"on an unrelated organizational domain '{org_domain}'."
                        ),
                        "severity": "high",
                        "score_contribution": 30,
                        "evidence": f"Domain: {domain_name} | Legitimate: {legitimate_org}",
                    })
                    break

    # High-abuse TLDs
    if tld_suffix and tld_suffix.lower() in HIGH_RISK_TLDS:
        indicators.append({
            "id": "HIGH_RISK_TLD",
            "title": f"High-Abuse Top-Level Domain (.{tld_suffix})",
            "description": f"URL uses TLD '.{tld_suffix}', which is historically associated with low-cost disposable spam campaigns.",
            "severity": "low",
            "score_contribution": 10,
            "evidence": f".{tld_suffix}",
        })

    # 6. Path and Payload analysis
    full_path_query = (raw_path + "?" + raw_query).lower()

    # Check for direct executable / archive payload download
    for ext in SUSPICIOUS_PAYLOAD_EXTENSIONS:
        if raw_path.lower().endswith(ext) or f"{ext}?" in full_path_query:
            indicators.append({
                "id": "SUSPICIOUS_PAYLOAD_DOWNLOAD",
                "title": f"Executable / Payload File Extension ({ext})",
                "description": f"URL path points directly to an executable, script, or payload archive file ({ext}).",
                "severity": "high",
                "score_contribution": 40,
                "evidence": raw_path,
            })
            break

    # Path traversal detection
    if "../" in original_url or "..%2f" in original_url.lower() or "..\\" in original_url:
        indicators.append({
            "id": "PATH_TRAVERSAL_DETECTED",
            "title": "Path Traversal Sequence in URL",
            "description": "URL contains path traversal sequences ('../' or '..%2f') attempting directory traversal.",
            "severity": "medium",
            "score_contribution": 25,
            "evidence": original_url,
        })

    # Phishing action keywords count
    combined_text = f"{hostname or ''} {raw_path} {raw_query}".lower()
    matched_phish_words = [kw for kw in PHISHING_KEYWORDS if kw in combined_text]
    if len(matched_phish_words) >= 2:
        indicators.append({
            "id": "MULTIPLE_PHISHING_KEYWORDS",
            "title": "Multiple Phishing Action Keywords",
            "description": f"URL contains multiple credential/security action keywords: {', '.join(sorted(matched_phish_words)[:5])}.",
            "severity": "medium",
            "score_contribution": 15,
            "evidence": ", ".join(sorted(matched_phish_words)[:5]),
        })
    elif len(matched_phish_words) == 1:
        indicators.append({
            "id": "PHISHING_KEYWORD_PRESENT",
            "title": "Phishing Keyword Present",
            "description": f"URL contains security/credential keyword '{matched_phish_words[0]}'.",
            "severity": "low",
            "score_contribution": 5,
            "evidence": matched_phish_words[0],
        })

    # 7. Obfuscation & character encoding analysis
    if "%00" in original_url.lower():
        indicators.append({
            "id": "NULL_BYTE_INJECTION",
            "title": "Null Byte (%00) in URL",
            "description": "URL contains a URL-encoded null byte (%00) used in filter bypass attacks.",
            "severity": "high",
            "score_contribution": 30,
            "evidence": "%00",
        })
    if "%25" in original_url.lower():
        indicators.append({
            "id": "DOUBLE_PERCENT_ENCODING",
            "title": "Double Percent-Encoding Detected",
            "description": "URL contains '%25' indicating double-encoded characters to evade inspection engines.",
            "severity": "medium",
            "score_contribution": 15,
            "evidence": "%25",
        })

    # 8. Excessive URL length analysis
    url_len = len(original_url)
    if url_len > 250:
        indicators.append({
            "id": "EXCESSIVE_URL_LENGTH",
            "title": f"Excessively Long URL ({url_len} characters)",
            "description": f"URL exceeds 250 characters ({url_len} chars), a technique used to conceal parameters or overflow buffers.",
            "severity": "medium",
            "score_contribution": 15,
            "evidence": f"Length: {url_len}",
        })
    elif url_len > 120:
        indicators.append({
            "id": "LONG_URL",
            "title": f"Unusually Long URL ({url_len} characters)",
            "description": f"URL is longer than 120 characters ({url_len} chars).",
            "severity": "low",
            "score_contribution": 5,
            "evidence": f"Length: {url_len}",
        })

    # 9. Bounded Risk Score Calculation
    total_score = sum(ind.get("score_contribution", 0) for ind in indicators)
    bounded_score = max(0, min(100, total_score))

    # Determine risk level
    if bounded_score == 0:
        risk_level = "none"
    elif bounded_score < 30:
        risk_level = "low"
    elif bounded_score < 70:
        risk_level = "medium"
    elif bounded_score < 90:
        risk_level = "high"
    else:
        risk_level = "critical"

    # Assemble result dictionary
    result: dict[str, Any] = {
        "original_url": original_url,
        "normalized_url": normalized_url,
        "defanged_url": defanged,
        "scheme": raw_scheme or None,
        "hostname": hostname,
        "port": port,
        "path": raw_path or None,
        "query": raw_query or None,
        "fragment": raw_fragment or None,
        "is_ip_literal": is_ip_literal,
        "ip_literal": ip_info,
        "is_shortener": is_shortener,
        "is_punycode": is_punycode,
        "has_credentials": has_credentials,
        "indicators": indicators,
        "warnings": warnings,
        "heuristic_risk_score": bounded_score,
        "risk_level": risk_level,
        "analysis_status": analysis_status,
        "threat_intel": {
            "reputation_checked": False,
            "verdict": "not_checked",
            "reason": "External reputation lookup is not performed in local heuristic mode.",
        },
    }

    if source_metadata:
        result["source_metadata"] = source_metadata

    return result


# ===========================================================================
# SECTION D — BATCH URL ANALYSIS AND SUMMARY GENERATION (PUBLIC API)
# ===========================================================================

def _build_batch_summary(
    total: int,
    max_score: int,
    risk_level: str,
    high_risk_count: int,
    unique_domains_count: int,
) -> str:
    """
    Produce a concise, human-readable summary of the URL analysis results.
    """
    if total == 0:
        return "No URLs extracted or analyzed."

    parts: list[str] = [
        f"Analyzed {total} URL(s) across {unique_domains_count} unique domain(s).",
        f"Maximum heuristic risk score: {max_score}/100 (Risk level: {risk_level.upper()}).",
    ]
    if high_risk_count > 0:
        parts.append(f"FLAGGED: {high_risk_count} URL(s) exhibit high or critical threat indicators.")
    else:
        parts.append("No critical or high-risk URL threats detected in heuristic analysis.")
    parts.append("Note: External reputation intelligence is not_checked.")
    return " ".join(parts)


def analyze_urls(urls_input: Any) -> dict[str, Any]:
    """
    Analyze suspicious URLs extracted from an email message.

    This is the primary public entry point for Module 3.

    Parameters
    ----------
    urls_input : Any
        Flexible input accepting:
        - Output dict from Module 1 (containing 'urls' key)
        - List of dicts as returned by Module 1 (e.g., [{'url': '...', 'found_in': ...}])
        - List of string URLs (e.g., ['https://example.com', 'http://phish.com'])
        - A single string URL

    Returns
    -------
    dict
        Structured analysis report with keys:
        - total_urls_analyzed   : int
        - unique_domains        : list[str]
        - max_risk_score        : int (0 to 100)
        - overall_url_risk_level: 'none' | 'low' | 'medium' | 'high' | 'critical'
        - risk_distribution     : dict with counts for each risk level
        - high_risk_url_count   : int
        - results               : list of individual URL analysis dictionaries
        - threat_intel_status   : always 'not_checked' (no external API calls)
        - summary               : human-readable summary string
        - warnings              : list of any top-level warnings encountered
        - analyzed_at           : ISO 8601 UTC timestamp
        - analyzer_version      : version string

    Security Invariants
    -------------------
    - Makes ZERO network requests (no DNS, no HTTP, no socket).
    - Preserves all original URL evidence without modification.
    - Provides defanged representations for safe display.
    """
    warnings: list[str] = []
    normalized_items: list[tuple[str, dict[str, Any] | None]] = []

    # 1. Flexible input normalization
    if urls_input is None:
        warnings.append("No URL input provided (urls_input was None)")
    elif isinstance(urls_input, dict):
        # Case A: Full Module 1 output passed directly
        if "urls" in urls_input and isinstance(urls_input["urls"], list):
            for item in urls_input["urls"]:
                if isinstance(item, dict) and "url" in item:
                    meta = {k: v for k, v in item.items() if k != "url"}
                    normalized_items.append((str(item["url"]), meta))
                elif isinstance(item, str):
                    normalized_items.append((item, None))
        else:
            warnings.append("Dictionary provided does not contain a 'urls' list")
    elif isinstance(urls_input, list):
        # Case B: List of items (dicts or strings)
        for item in urls_input:
            if isinstance(item, dict) and "url" in item:
                meta = {k: v for k, v in item.items() if k != "url"}
                normalized_items.append((str(item["url"]), meta))
            elif isinstance(item, str):
                normalized_items.append((item, None))
            else:
                normalized_items.append((item, None))
    elif isinstance(urls_input, str):
        # Case C: Single URL string
        if urls_input.strip():
            normalized_items.append((urls_input.strip(), None))
        else:
            warnings.append("Empty URL string provided")
    else:
        warnings.append(f"Unexpected input type: {type(urls_input).__name__}")

    # 2. Analyze each URL
    results: list[dict[str, Any]] = []
    unique_domains_set: set[str] = set()
    risk_distribution = {"none": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}

    for raw_url, meta in normalized_items:
        res = _analyze_single_url(raw_url, source_metadata=meta)
        results.append(res)

        host = res.get("hostname")
        if host:
            unique_domains_set.add(host)

        level = res.get("risk_level", "none")
        if level in risk_distribution:
            risk_distribution[level] += 1
        else:
            risk_distribution["low"] += 1

    total = len(results)
    max_score = max((r.get("heuristic_risk_score", 0) for r in results), default=0)

    # Determine overall risk level
    if max_score == 0:
        overall_level = "none"
    elif max_score < 30:
        overall_level = "low"
    elif max_score < 70:
        overall_level = "medium"
    elif max_score < 90:
        overall_level = "high"
    else:
        overall_level = "critical"

    high_risk_count = risk_distribution.get("high", 0) + risk_distribution.get("critical", 0)
    unique_domains = sorted(unique_domains_set)

    summary = _build_batch_summary(
        total=total,
        max_score=max_score,
        risk_level=overall_level,
        high_risk_count=high_risk_count,
        unique_domains_count=len(unique_domains),
    )

    return {
        "total_urls_analyzed": total,
        "unique_domains": unique_domains,
        "max_risk_score": max_score,
        "overall_url_risk_level": overall_level,
        "risk_distribution": risk_distribution,
        "high_risk_url_count": high_risk_count,
        "results": results,
        "threat_intel_status": "not_checked",
        "summary": summary,
        "warnings": warnings,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "analyzer_version": ANALYZER_VERSION,
    }
