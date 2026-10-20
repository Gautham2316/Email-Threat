"""
src/routing_analyzer.py
=======================
Module 4: Email Routing Analysis and IP Geolocation Engine
SIH 2026 — AI-Powered Email Threat Detection Platform

Extracts, inspects, and chronologically models email routing traces from
'Received' headers, classifies IP addresses according to RFC scopes,
enforces evidence and trust boundaries, and integrates an offline,
decoupled IP geolocation provider interface.

CRITICAL FORENSIC AND SECURITY GUARANTEES:
1. Zero Network Access: Never performs live DNS queries, HTTP requests,
   or socket connections to inspect hops or geolocate IPs.
2. Strict Evidence & Trust Boundaries: Received headers can be forged by
   untrusted senders and upstream relays. Hops are labeled explicitly as
   'untrusted_header_claim', 'parsed_but_unverified', or
   'verified_by_configured_source'. No hop is assumed authentic merely
   because its sequence appears plausible.
3. Strict IP Eligibility for Geolocation: Only globally routable public IPs
   are eligible for geolocation lookup. Private, loopback, link-local,
   multicast, reserved, and invalid addresses are never submitted to any
   lookup provider.
4. Offline Geolocation Decoupling: Works with optional offline databases
   (e.g., MaxMind GeoLite2 City). When no database is configured or
   available, reports 'not_checked' with a clear reason rather than guessing.
5. No False Physical Inference: Mail server geolocation reflects hosting
   and relay infrastructure, never the physical location of the human sender.

AUTHOR: SIH 2026 Team
VERSION: 1.0.0
"""

from __future__ import annotations

import abc
import email.utils
import ipaddress
import json
import os
import re
from typing import Any, Optional

ANALYZER_VERSION: str = "1.0.0"

# ---------------------------------------------------------------------------
# Trust & Evidence Labels
# ---------------------------------------------------------------------------
TRUST_UNTRUSTED_CLAIM: str = "untrusted_header_claim"
TRUST_PARSED_UNVERIFIED: str = "parsed_but_unverified"
TRUST_VERIFIED_BY_CONFIGURED: str = "verified_by_configured_source"
TRUST_NOT_CHECKED: str = "not_checked"

# ---------------------------------------------------------------------------
# Lookup Statuses
# ---------------------------------------------------------------------------
LOOKUP_SUCCESS: str = "success"
LOOKUP_NOT_FOUND: str = "not_found"
LOOKUP_NOT_CHECKED: str = "not_checked"
LOOKUP_ERROR: str = "error"

# ---------------------------------------------------------------------------
# Parsing Statuses
# ---------------------------------------------------------------------------
PARSE_SUCCESS: str = "parsed"
PARSE_PARTIAL: str = "partial"
PARSE_FAILED: str = "failed"

# ---------------------------------------------------------------------------
# Standard Forensic Limitations & Disclaimers
# ---------------------------------------------------------------------------
FORENSIC_LIMITATIONS: list[str] = [
    "Received headers can be forged or prepended by untrusted senders and intermediate relays.",
    "The earliest IP in the routing chain cannot be assumed to be the authentic client IP.",
    "Geolocation reflects mail server infrastructure or network routing, not the physical location of the human sender.",
    "A public IP address does not, by itself, indicate malicious activity.",
]

# Regex patterns for candidate IP addresses
_IPV4_PATTERN: re.Pattern[str] = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)

# Date fallback pattern for malformed headers lacking semicolons
_RFC2822_DATE_PATTERN: re.Pattern[str] = re.compile(
    r"((?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),?\s+\d{1,2}\s+"
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{4}\s+"
    r"\d{1,2}:\d{2}:\d{2}(?:\s+[+\-]\d{4}|\s+\([A-Z0-9_\-]+\))*)",
    re.IGNORECASE,
)


# ===========================================================================
# IP EXTRACTION AND CLASSIFICATION (STAGE 3)
# ===========================================================================

def classify_ip_address(ip_candidate: str) -> dict[str, Any] | None:
    """
    Validate and classify a candidate IP string using standard library ipaddress.

    Parameters
    ----------
    ip_candidate : str
        Candidate IPv4 or IPv6 string.

    Returns
    -------
    dict[str, Any] or None
        Structured IP metadata if valid; None if parsing fails.
    """
    cleaned = ip_candidate.strip().strip("[]").strip()
    if cleaned.lower().startswith("ipv6:"):
        cleaned = cleaned[5:].strip()

    if not cleaned:
        return None

    try:
        ip_obj = ipaddress.ip_address(cleaned)
    except (ValueError, TypeError):
        return None

    version = ip_obj.version
    is_global = ip_obj.is_global
    is_private = ip_obj.is_private
    is_loopback = ip_obj.is_loopback
    is_link_local = ip_obj.is_link_local
    is_multicast = ip_obj.is_multicast
    is_reserved = ip_obj.is_reserved
    is_unspecified = ip_obj.is_unspecified

    # Determine descriptive scope label
    if is_loopback:
        ip_type_label = "loopback"
    elif is_link_local:
        ip_type_label = "link_local"
    elif is_private:
        ip_type_label = "private"
    elif is_multicast:
        ip_type_label = "multicast"
    elif is_reserved:
        ip_type_label = "reserved"
    elif is_unspecified:
        ip_type_label = "unspecified"
    elif is_global:
        ip_type_label = "public"
    else:
        ip_type_label = "non_global"

    # Strictly define eligibility for public geolocation lookup:
    # Must be global and NOT private, loopback, link-local, multicast, reserved, or unspecified.
    is_eligible = (
        is_global
        and not is_private
        and not is_loopback
        and not is_link_local
        and not is_multicast
        and not is_reserved
        and not is_unspecified
    )

    return {
        "ip": str(ip_obj),
        "version": version,
        "is_global": is_global,
        "is_private": is_private,
        "is_loopback": is_loopback,
        "is_link_local": is_link_local,
        "is_multicast": is_multicast,
        "is_reserved": is_reserved,
        "is_unspecified": is_unspecified,
        "is_eligible_for_geolocation": is_eligible,
        "ip_type_label": ip_type_label,
    }


def extract_and_classify_ips(text: str) -> list[dict[str, Any]]:
    """
    Extract and classify all unique candidate IPv4 and IPv6 addresses from text.

    Parameters
    ----------
    text : str
        Arbitrary header text or string to scan for IP addresses.

    Returns
    -------
    list[dict[str, Any]]
        List of classified IP dictionaries in order of first appearance.
    """
    if not text or not isinstance(text, str):
        return []

    # Pre-clean known prefix wrappers
    cleaned_text = re.sub(r"IPv6:\s*", "", text, flags=re.IGNORECASE)

    # 1. Bracketed tokens e.g. [192.168.1.1] or [2001:db8::1]
    bracketed = re.findall(r"\[([a-fA-F0-9:.]+)\]", cleaned_text)

    # 2. Bare IPv4 addresses
    ipv4s = _IPV4_PATTERN.findall(cleaned_text)

    # 3. Candidate bare IPv6 addresses (with colons)
    ipv6_tokens = re.findall(
        r"\b(?:[a-fA-F0-9]{1,4}:){2,7}[a-fA-F0-9]{1,4}\b|\b[a-fA-F0-9:]*::[a-fA-F0-9:]*\b",
        cleaned_text,
    )

    # Merge candidates preserving order of appearance
    candidates: list[str] = []
    seen: set[str] = set()

    for token in bracketed + ipv4s + ipv6_tokens:
        token_clean = token.strip().strip(".")
        if len(token_clean) >= 2 and token_clean not in seen:
            seen.add(token_clean)
            candidates.append(token_clean)

    results: list[dict[str, Any]] = []
    seen_ips: set[str] = set()

    for cand in candidates:
        classified = classify_ip_address(cand)
        if classified and classified["ip"] not in seen_ips:
            seen_ips.add(classified["ip"])
            results.append(classified)

    return results


# ===========================================================================
# GEOLOCATION PROVIDER INTERFACE (STAGE 4)
# ===========================================================================

class BaseGeoLocationProvider(abc.ABC):
    """
    Abstract interface for IP geolocation providers.
    Decoupled from header parsing to ensure offline testability and modularity.
    """

    @abc.abstractmethod
    def lookup(self, ip_str: str) -> dict[str, Any]:
        """
        Perform geolocation lookup for a single public IP string.

        Parameters
        ----------
        ip_str : str
            Globally routable IP string.

        Returns
        -------
        dict[str, Any]
            Standardized geolocation dictionary.
        """
        raise NotImplementedError


class OfflineGeoIPProvider(BaseGeoLocationProvider):
    """
    Offline MaxMind GeoLite2 City database provider.

    Adheres strictly to forensic security constraints:
    - Never downloads databases automatically.
    - Never makes external network/HTTP/DNS requests.
    - If database is missing or geoip2 is uninstalled, gracefully returns 'not_checked'.
    - If lookup fails or IP is absent, returns 'not_found' or 'error'.
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path: Optional[str] = db_path
        self._reader: Any = None
        self._init_error: Optional[str] = None
        self._provider_name: str = "MaxMind GeoLite2 (offline)"

        if not db_path:
            self._init_error = "No MaxMind GeoLite2 database path configured."
        elif not os.path.isfile(db_path):
            self._init_error = f"Configured database file not found: '{db_path}'"
        else:
            try:
                import geoip2.database  # type: ignore[import-not-found]
                self._reader = geoip2.database.Reader(db_path)
            except ImportError:
                self._init_error = (
                    "Optional dependency 'geoip2' is not installed. "
                    "Install 'geoip2' to enable offline database lookups."
                )
            except Exception as exc:
                self._init_error = f"Failed to initialize MaxMind database reader: {exc}"

    def close(self) -> None:
        """Close the underlying database reader if open."""
        if self._reader is not None:
            try:
                self._reader.close()
            except Exception:
                pass
            self._reader = None

    def lookup(self, ip_str: str) -> dict[str, Any]:
        """
        Perform an offline lookup against the local MaxMind database.
        """
        base_result: dict[str, Any] = {
            "ip": ip_str,
            "lookup_status": LOOKUP_NOT_CHECKED,
            "country": None,
            "country_code": None,
            "region": None,
            "city": None,
            "latitude": None,
            "longitude": None,
            "asn": None,
            "as_organization": None,
            "database_source": self._provider_name,
            "reason": None,
        }

        if self._init_error or self._reader is None:
            base_result["lookup_status"] = LOOKUP_NOT_CHECKED
            base_result["reason"] = self._init_error or "Offline database unavailable."
            return base_result

        try:
            import geoip2.errors  # type: ignore[import-not-found]
        except ImportError:
            base_result["lookup_status"] = LOOKUP_NOT_CHECKED
            base_result["reason"] = "geoip2 module missing at lookup time."
            return base_result

        try:
            resp = self._reader.city(ip_str)
            base_result["lookup_status"] = LOOKUP_SUCCESS
            base_result["country"] = resp.country.name
            base_result["country_code"] = resp.country.iso_code
            base_result["region"] = (
                resp.subdivisions.most_specific.name
                if resp.subdivisions and resp.subdivisions.most_specific
                else None
            )
            base_result["city"] = resp.city.name
            if resp.location:
                base_result["latitude"] = resp.location.latitude
                base_result["longitude"] = resp.location.longitude
            base_result["reason"] = None
        except geoip2.errors.AddressNotFoundError:
            base_result["lookup_status"] = LOOKUP_NOT_FOUND
            base_result["reason"] = f"IP address '{ip_str}' was not found in offline database."
        except Exception as exc:
            base_result["lookup_status"] = LOOKUP_ERROR
            base_result["reason"] = f"Lookup error for '{ip_str}': {exc}"

        return base_result


class MockGeoIPProvider(BaseGeoLocationProvider):
    """
    In-memory mock provider for deterministic, zero-network unit testing.
    """

    def __init__(
        self,
        ip_records: Optional[dict[str, dict[str, Any]]] = None,
        default_status: str = LOOKUP_NOT_FOUND,
        error_ips: Optional[set[str]] = None,
    ) -> None:
        self.ip_records: dict[str, dict[str, Any]] = ip_records or {}
        self.default_status: str = default_status
        self.error_ips: set[str] = error_ips or set()

    def lookup(self, ip_str: str) -> dict[str, Any]:
        if ip_str in self.error_ips:
            return {
                "ip": ip_str,
                "lookup_status": LOOKUP_ERROR,
                "country": None,
                "country_code": None,
                "region": None,
                "city": None,
                "latitude": None,
                "longitude": None,
                "asn": None,
                "as_organization": None,
                "database_source": "MockGeoIPProvider",
                "reason": f"Simulated mock error for IP: {ip_str}",
            }

        if ip_str in self.ip_records:
            rec = self.ip_records[ip_str]
            return {
                "ip": ip_str,
                "lookup_status": rec.get("lookup_status", LOOKUP_SUCCESS),
                "country": rec.get("country"),
                "country_code": rec.get("country_code"),
                "region": rec.get("region"),
                "city": rec.get("city"),
                "latitude": rec.get("latitude"),
                "longitude": rec.get("longitude"),
                "asn": rec.get("asn"),
                "as_organization": rec.get("as_organization"),
                "database_source": "MockGeoIPProvider",
                "reason": rec.get("reason"),
            }

        return {
            "ip": ip_str,
            "lookup_status": self.default_status,
            "country": None,
            "country_code": None,
            "region": None,
            "city": None,
            "latitude": None,
            "longitude": None,
            "asn": None,
            "as_organization": None,
            "database_source": "MockGeoIPProvider",
            "reason": f"IP '{ip_str}' not found in mock database.",
        }


# ===========================================================================
# RECEIVED HEADER PARSER (STAGE 1 & STAGE 2)
# ===========================================================================

def parse_single_received_header(
    raw_header: str,
    index: int,
    config: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """
    Parse a single 'Received' header into structured routing fields.

    Parameters
    ----------
    raw_header : str
        The raw text of the Received header.
    index : int
        Zero-based index in document order (0 = recipient/newest MTA).
    config : dict, optional
        Configuration dictionary with optional 'trusted_hosts'.

    Returns
    -------
    dict[str, Any]
        Structured hop representation.
    """
    config = config or {}
    trusted_hosts = config.get("trusted_hosts") or config.get("trusted_boundary_hosts") or []
    # Normalize trusted hosts to lowercase
    trusted_hosts_lower = [h.strip().lower() for h in trusted_hosts if isinstance(h, str) and h.strip()]

    warnings: list[str] = []
    evidence_limitations: list[str] = [
        "Header fields and claimed hostnames cannot be verified without independent server logs or cryptographic proof."
    ]

    # Handle empty or invalid header
    if not raw_header or not isinstance(raw_header, str) or not raw_header.strip():
        return {
            "index": index,
            "raw_header": str(raw_header) if raw_header is not None else "",
            "from_host": None,
            "by_host": None,
            "protocol": None,
            "message_id": None,
            "recipient": None,
            "timestamp_str": None,
            "timestamp_iso": None,
            "timestamp_epoch": None,
            "extracted_ips": [],
            "trust_label": TRUST_UNTRUSTED_CLAIM,
            "parsing_status": PARSE_FAILED,
            "warnings": ["Received header is empty or not a valid string."],
            "evidence_limitations": evidence_limitations,
        }

    # 1. Unfold and clean whitespace
    folded = " ".join(raw_header.split())

    # 2. Separate clauses from timestamp
    clauses_part = folded
    date_str_candidate: Optional[str] = None

    if ";" in folded:
        # Standard RFC 5321: semicolon separates routing clauses from date-time
        clauses_part, _, date_str_candidate = folded.rpartition(";")
        clauses_part = clauses_part.strip()
        date_str_candidate = date_str_candidate.strip()
    else:
        # Malformed or missing semicolon: search for RFC 2822 date pattern fallback
        m_date = _RFC2822_DATE_PATTERN.search(folded)
        if m_date:
            date_str_candidate = m_date.group(1).strip()
            warnings.append("No semicolon delimiter found before timestamp in Received header; extracted via pattern fallback.")
        else:
            warnings.append("No timestamp or semicolon delimiter found in Received header.")

    # 3. Parse timestamp
    timestamp_str: Optional[str] = None
    timestamp_iso: Optional[str] = None
    timestamp_epoch: Optional[float] = None

    if date_str_candidate:
        timestamp_str = date_str_candidate
        try:
            dt = email.utils.parsedate_to_datetime(date_str_candidate)
            timestamp_iso = dt.isoformat()
            timestamp_epoch = dt.timestamp()
        except Exception:
            warnings.append(f"Failed to parse timestamp string: '{date_str_candidate}'.")
            timestamp_iso = None
            timestamp_epoch = None

    # 4. Extract tokens: from, by, with, id, for
    m_from = re.search(r"\bfrom\s+(\[[^\]]+\]|[^\s;()]+)", clauses_part, re.IGNORECASE)
    from_host = m_from.group(1).strip() if m_from else None

    m_by = re.search(r"\bby\s+(\[[^\]]+\]|[^\s;()]+)", clauses_part, re.IGNORECASE)
    by_host = m_by.group(1).strip() if m_by else None

    m_with = re.search(r"\bwith\s+([a-zA-Z0-9_\-]+)", clauses_part, re.IGNORECASE)
    protocol = m_with.group(1).strip() if m_with else None

    m_id = re.search(r"\bid\s+([^\s;()]+)", clauses_part, re.IGNORECASE)
    message_id = m_id.group(1).strip() if m_id else None

    m_for = re.search(r"\bfor\s+(<[^>]+>|[^\s;()]+)", clauses_part, re.IGNORECASE)
    recipient = m_for.group(1).strip() if m_for else None

    # 5. Extract and classify candidate IPs from entire raw header
    extracted_ips = extract_and_classify_ips(folded)

    # 6. Determine parsing status
    if from_host or by_host or extracted_ips or timestamp_iso:
        if from_host and by_host and timestamp_iso:
            parsing_status = PARSE_SUCCESS
        else:
            parsing_status = PARSE_PARTIAL
    else:
        parsing_status = PARSE_FAILED
        warnings.append("Could not extract routing tokens (from, by, IPs, or timestamp) from header.")

    # 7. Establish evidence and trust boundary label (Stage 2)
    # Default without explicit configuration: parsed_but_unverified or untrusted_header_claim
    if not trusted_hosts_lower:
        # No trust configuration supplied: route is unverified
        trust_label = TRUST_PARSED_UNVERIFIED if parsing_status != PARSE_FAILED else TRUST_UNTRUSTED_CLAIM
    else:
        # Trust configuration supplied: check if by_host matches any trusted host
        is_trusted_hop = False
        if by_host:
            by_host_clean = by_host.strip("[]").lower()
            for th in trusted_hosts_lower:
                if by_host_clean == th or by_host_clean.endswith("." + th):
                    is_trusted_hop = True
                    break

        if is_trusted_hop:
            trust_label = TRUST_VERIFIED_BY_CONFIGURED
        else:
            trust_label = TRUST_UNTRUSTED_CLAIM

    return {
        "index": index,
        "raw_header": raw_header,
        "from_host": from_host,
        "by_host": by_host,
        "protocol": protocol,
        "message_id": message_id,
        "recipient": recipient,
        "timestamp_str": timestamp_str,
        "timestamp_iso": timestamp_iso,
        "timestamp_epoch": timestamp_epoch,
        "extracted_ips": extracted_ips,
        "trust_label": trust_label,
        "parsing_status": parsing_status,
        "warnings": warnings,
        "evidence_limitations": evidence_limitations,
    }


# ===========================================================================
# ROUTING ANALYSIS ENGINE (STAGE 5)
# ===========================================================================

def analyze_email_routing(
    parsed_email: Any,
    raw_bytes: Optional[bytes] = None,
    config: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """
    Main entry point for Module 4: Email Routing Analysis and IP Geolocation.

    Parameters
    ----------
    parsed_email : dict or list[str] or Any
        Output from Module 1 (src.email_parser.parse_email_file) or raw list
        of Received header strings.
    raw_bytes : bytes, optional
        Original email bytes if available (preserved for forensic consistency).
    config : dict, optional
        Configuration options:
        - 'trusted_hosts': list[str] of trusted receiving hostnames/domains.
        - 'geoip_db_path': str path to local MaxMind GeoLite2 City .mmdb file.
        - 'geo_provider': BaseGeoLocationProvider instance (e.g. for testing).

    Returns
    -------
    dict[str, Any]
        Complete routing forensic report.
    """
    config = config or {}
    global_warnings: list[str] = []
    errors: list[str] = []

    # 1. Normalize received headers input
    received_headers: list[str] = []

    if isinstance(parsed_email, dict):
        # Extract from Module 1 dictionary
        if "received_headers" in parsed_email and isinstance(parsed_email["received_headers"], list):
            received_headers = [str(h) for h in parsed_email["received_headers"] if h is not None]
        elif "headers" in parsed_email and isinstance(parsed_email["headers"], dict):
            raw_headers = parsed_email["headers"].get("raw_headers", [])
            for h in raw_headers:
                if isinstance(h, dict) and h.get("name", "").lower() == "received":
                    val = h.get("value")
                    if val is not None:
                        received_headers.append(str(val))
    elif isinstance(parsed_email, (list, tuple)):
        # Direct list of header strings
        received_headers = [str(h) for h in parsed_email if h is not None]
    elif isinstance(parsed_email, str):
        if parsed_email.strip():
            received_headers = [parsed_email.strip()]
    elif parsed_email is None:
        errors.append("Input 'parsed_email' is None. Nothing to analyze.")

    # 2. Check for missing Received headers
    if not received_headers:
        if not errors:
            global_warnings.append(
                "No 'Received' headers found in email. Cannot reconstruct routing path."
            )
        return {
            "hops": [],
            "unique_ips": [],
            "total_hops": 0,
            "anomalies_detected": False,
            "geolocation_summary": {
                "total_unique_ips": 0,
                "eligible_public_ips": 0,
                "private_or_internal_ips": 0,
                "geolocated_ips": 0,
                "countries_detected": [],
                "lookup_status_counts": {
                    LOOKUP_SUCCESS: 0,
                    LOOKUP_NOT_FOUND: 0,
                    LOOKUP_NOT_CHECKED: 0,
                    LOOKUP_ERROR: 0,
                },
                "provider_used": "None",
                "forensic_disclaimer": FORENSIC_LIMITATIONS[2],
            },
            "route_order": {
                "header_order": [],
                "chronological_order": [],
                "ordering_ambiguity": False,
                "ordering_notes": "No headers available to order.",
            },
            "trust_analysis": {
                "configured_trusted_hosts": config.get("trusted_hosts", []),
                "trusted_boundary_index": None,
                "trusted_hops_count": 0,
                "untrusted_hops_count": 0,
                "summary": "No routing headers found to evaluate trust boundaries.",
            },
            "warnings": global_warnings,
            "evidence_limitations": list(FORENSIC_LIMITATIONS),
            "analysis_status": "no_headers",
        }

    # 3. Parse each hop (Stage 1 & Stage 2)
    hops: list[dict[str, Any]] = []
    for idx, raw_h in enumerate(received_headers):
        hop = parse_single_received_header(raw_h, idx, config=config)
        hops.append(hop)

    # 4. Refine Trust Boundaries (Stage 2)
    trusted_hosts = config.get("trusted_hosts") or config.get("trusted_boundary_hosts") or []
    trusted_hosts_lower = [h.strip().lower() for h in trusted_hosts if isinstance(h, str) and h.strip()]

    trusted_boundary_idx: Optional[int] = None
    trusted_hops_count = 0
    untrusted_hops_count = 0

    if trusted_hosts_lower:
        # Walk document order (top down: 0 is recipient)
        # Continuous chain of trusted receiving servers starting at index 0
        in_trusted_zone = True
        for hop in hops:
            by_host = (hop.get("by_host") or "").strip("[]").lower()
            is_match = False
            for th in trusted_hosts_lower:
                if by_host == th or by_host.endswith("." + th):
                    is_match = True
                    break

            if in_trusted_zone and is_match:
                hop["trust_label"] = TRUST_VERIFIED_BY_CONFIGURED
                trusted_hops_count += 1
                trusted_boundary_idx = hop["index"]
            else:
                in_trusted_zone = False
                hop["trust_label"] = TRUST_UNTRUSTED_CLAIM
                untrusted_hops_count += 1

        summary_trust = (
            f"Hops up to index {trusted_boundary_idx} verified by configured receiving host(s); "
            f"earlier hops are untrusted external claims."
            if trusted_boundary_idx is not None
            else "Configured trusted hosts did not match the initial recipient MTA; all hops remain unverified claims."
        )
    else:
        # No trusted configuration supplied: mark all hops unverified
        for hop in hops:
            if hop["parsing_status"] == PARSE_FAILED:
                hop["trust_label"] = TRUST_UNTRUSTED_CLAIM
            else:
                hop["trust_label"] = TRUST_PARSED_UNVERIFIED
            untrusted_hops_count += 1

        summary_trust = (
            "No trusted receiving servers configured. All routing hops are unverified claims "
            "and must not be treated as authentic evidence."
        )

    # 5. Deduplicate and aggregate unique IP addresses across hops (Stage 3)
    ip_map: dict[str, dict[str, Any]] = {}

    for hop in hops:
        hop_idx = hop["index"]
        for classified_ip in hop["extracted_ips"]:
            ip_str = classified_ip["ip"]
            if ip_str not in ip_map:
                ip_map[ip_str] = {
                    "ip": ip_str,
                    "version": classified_ip["version"],
                    "is_global": classified_ip["is_global"],
                    "is_private": classified_ip["is_private"],
                    "is_loopback": classified_ip["is_loopback"],
                    "is_link_local": classified_ip["is_link_local"],
                    "is_multicast": classified_ip["is_multicast"],
                    "is_reserved": classified_ip["is_reserved"],
                    "is_unspecified": classified_ip["is_unspecified"],
                    "is_eligible_for_geolocation": classified_ip["is_eligible_for_geolocation"],
                    "ip_type_label": classified_ip["ip_type_label"],
                    "hop_indices": [hop_idx],
                    "occurrences_count": 1,
                    "geolocation": None,
                }
            else:
                if hop_idx not in ip_map[ip_str]["hop_indices"]:
                    ip_map[ip_str]["hop_indices"].append(hop_idx)
                ip_map[ip_str]["occurrences_count"] += 1

    # 6. Geolocation Provider Initialization and Lookup (Stage 4)
    # Check if a custom or mock provider was injected
    provider: BaseGeoLocationProvider
    if "geo_provider" in config and isinstance(config["geo_provider"], BaseGeoLocationProvider):
        provider = config["geo_provider"]
    else:
        provider = OfflineGeoIPProvider(db_path=config.get("geoip_db_path"))

    lookup_status_counts = {
        LOOKUP_SUCCESS: 0,
        LOOKUP_NOT_FOUND: 0,
        LOOKUP_NOT_CHECKED: 0,
        LOOKUP_ERROR: 0,
    }
    countries_detected: set[str] = set()

    for ip_str, ip_entry in ip_map.items():
        if not ip_entry["is_eligible_for_geolocation"]:
            # Non-routable, private, loopback, link-local, multicast, or reserved IPs
            # MUST NEVER be sent to any geolocation provider!
            geo_record: dict[str, Any] = {
                "ip": ip_str,
                "lookup_status": LOOKUP_NOT_CHECKED,
                "country": None,
                "country_code": None,
                "region": None,
                "city": None,
                "latitude": None,
                "longitude": None,
                "asn": None,
                "as_organization": None,
                "database_source": None,
                "reason": (
                    f"IP address is {ip_entry['ip_type_label']} (non-routable/private); "
                    "ineligible for public geolocation."
                ),
            }
            lookup_status_counts[LOOKUP_NOT_CHECKED] += 1
            ip_entry["geolocation"] = geo_record
        else:
            # Eligible public IP: perform offline lookup
            geo_record = provider.lookup(ip_str)
            status = geo_record.get("lookup_status", LOOKUP_NOT_CHECKED)
            lookup_status_counts[status] = lookup_status_counts.get(status, 0) + 1

            if status == LOOKUP_SUCCESS and geo_record.get("country"):
                countries_detected.add(str(geo_record["country"]))

            ip_entry["geolocation"] = geo_record

    # Close reader if offline provider
    if isinstance(provider, OfflineGeoIPProvider):
        provider.close()

    unique_ips_list = list(ip_map.values())
    eligible_count = sum(1 for ip in unique_ips_list if ip["is_eligible_for_geolocation"])
    private_count = sum(1 for ip in unique_ips_list if not ip["is_eligible_for_geolocation"])
    geolocated_count = lookup_status_counts[LOOKUP_SUCCESS]

    provider_name = (
        type(provider).__name__
        if not isinstance(provider, OfflineGeoIPProvider)
        else (
            "OfflineGeoIPProvider (MaxMind GeoLite2)"
            if config.get("geoip_db_path")
            else "OfflineGeoIPProvider (unconfigured)"
        )
    )

    geolocation_summary = {
        "total_unique_ips": len(unique_ips_list),
        "eligible_public_ips": eligible_count,
        "private_or_internal_ips": private_count,
        "geolocated_ips": geolocated_count,
        "countries_detected": sorted(countries_detected),
        "lookup_status_counts": lookup_status_counts,
        "provider_used": provider_name,
        "forensic_disclaimer": (
            "IP geolocation reflects mail server infrastructure and network allocations, "
            "never the physical location of the human email sender."
        ),
    }

    # 7. Route Order vs Chronological Order (Stage 5)
    header_order = [hop["index"] for hop in hops]

    # Check if all hops have valid epoch timestamps
    hops_with_timestamps = [hop for hop in hops if hop["timestamp_epoch"] is not None]
    ordering_ambiguity = False
    ordering_notes = ""

    if len(hops_with_timestamps) == len(hops):
        # Sort chronologically (oldest epoch to newest epoch)
        # Note: if epochs are identical between consecutive hops, preserve stability
        chronological_hops = sorted(hops, key=lambda h: h["timestamp_epoch"])  # type: ignore[arg-type]
        chronological_order = [h["index"] for h in chronological_hops]
        ordering_notes = "Chronological order determined from parsed RFC 2822 timestamps (oldest to newest)."
    elif hops_with_timestamps:
        # Partial timestamps: fallback to reverse header order with warning
        chronological_order = list(reversed(header_order))
        ordering_ambiguity = True
        ordering_notes = (
            f"Only {len(hops_with_timestamps)} of {len(hops)} hops had valid timestamps. "
            "Chronological order could not be strictly determined; fallback to reverse header order."
        )
        global_warnings.append(ordering_notes)
    else:
        # No timestamps: reverse header order
        chronological_order = list(reversed(header_order))
        ordering_ambiguity = True
        ordering_notes = "No valid timestamps found in Received headers; chronological order approximated via reverse header order."
        global_warnings.append(ordering_notes)

    # 8. Compile overall status
    has_failed = any(h["parsing_status"] == PARSE_FAILED for h in hops)
    if has_failed:
        analysis_status = PARSE_PARTIAL
    else:
        analysis_status = "success"

    # Evaluate genuine routing anomalies (e.g. hop-level anomaly flags, loop detection,
    # or suspicious transport warnings such as loop, mismatch, rfc1918_after_public)
    anomalies_detected = (
        any(bool(h.get("anomalies")) for h in hops)
        or any(
            any(k in str(w).lower() for k in ("loop", "mismatch", "rfc1918_after_public", "forged", "boundary_inversion"))
            for w in global_warnings
        )
    )

    return {
        "hops": hops,
        "unique_ips": unique_ips_list,
        "total_hops": len(hops),
        "anomalies_detected": anomalies_detected,
        "geolocation_summary": geolocation_summary,
        "route_order": {
            "header_order": header_order,
            "chronological_order": chronological_order,
            "ordering_ambiguity": ordering_ambiguity,
            "ordering_notes": ordering_notes,
        },
        "trust_analysis": {
            "configured_trusted_hosts": list(trusted_hosts),
            "trusted_boundary_index": trusted_boundary_idx,
            "trusted_hops_count": trusted_hops_count,
            "untrusted_hops_count": untrusted_hops_count,
            "summary": summary_trust,
        },
        "warnings": global_warnings,
        "evidence_limitations": list(FORENSIC_LIMITATIONS),
        "analysis_status": analysis_status,
    }
