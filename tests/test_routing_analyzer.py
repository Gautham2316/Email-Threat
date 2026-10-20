"""
tests/test_routing_analyzer.py
==============================
Automated test suite for Module 4: Email Routing Analysis and IP Geolocation Engine.

SIH 2026 — AI-Powered Email Threat Detection Platform

TEST COVERAGE & INVARIANTS:
1. Zero Network Access: Every test runs completely offline without network,
   socket, DNS, or HTTP calls.
2. Single & Multiple Received Headers: Tests parsing of standard and non-standard hops.
3. Header-Order vs Chronological-Order: Verifies that document order (Hop 0 = recipient)
   and chronological route order (oldest timestamp first) are properly handled.
4. IPv4 and IPv6 Extraction & Classification: Validates standard-library IP address
   parsing across public, private, loopback, link-local, multicast, and reserved ranges.
5. IP Deduplication & Association: Ensures repeated IPs are deduplicated for lookups
   while retaining individual hop associations.
6. Malformed IPs and Headers: Ensures robustness against malformed IP strings, folded
   headers, missing fields, and broken timestamps without throwing exceptions.
7. Evidence & Trust Boundaries: Verifies that without configuration, routes are marked
   unverified claims, and that explicit trusted receiving boundaries are strictly enforced.
8. Decoupled Geolocation Provider: Tests unconfigured/offline database absence,
   graceful dependency handling, mock lookups, partial field availability, and errors.
9. Module 1 Integration: Confirms seamless consumption of parse_email_file output.
10. JSON Serialization: Ensures the returned report is 100% JSON serializable.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import unittest
from unittest.mock import MagicMock, patch

SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from routing_analyzer import (
    LOOKUP_ERROR,
    LOOKUP_NOT_CHECKED,
    LOOKUP_NOT_FOUND,
    LOOKUP_SUCCESS,
    PARSE_FAILED,
    PARSE_PARTIAL,
    PARSE_SUCCESS,
    TRUST_PARSED_UNVERIFIED,
    TRUST_UNTRUSTED_CLAIM,
    TRUST_VERIFIED_BY_CONFIGURED,
    BaseGeoLocationProvider,
    MockGeoIPProvider,
    OfflineGeoIPProvider,
    analyze_email_routing,
    classify_ip_address,
    extract_and_classify_ips,
    parse_single_received_header,
)
from email_parser import parse_email_file


class TestNetworkSafetyGuarantees(unittest.TestCase):
    """Verify that routing and IP analysis never performs live network activity."""

    def test_zero_network_calls_during_analysis(self):
        """Socket connections must never be opened during header analysis."""
        sample_headers = [
            "from mail.example.com ([93.184.216.34]) by mx.google.com with ESMTPS; Mon, 20 Oct 2026 10:00:00 +0000",
            "from client.local ([192.168.1.10]) by mail.example.com with ESMTP; Mon, 20 Oct 2026 09:59:00 +0000",
        ]

        with patch("socket.socket") as mock_sock, \
             patch("socket.gethostbyname") as mock_gethost, \
             patch("socket.getaddrinfo") as mock_getaddr:
            report = analyze_email_routing(sample_headers)
            mock_sock.assert_not_called()
            mock_gethost.assert_not_called()
            mock_getaddr.assert_not_called()

        self.assertEqual(report["analysis_status"], "success")
        self.assertEqual(len(report["hops"]), 2)


class TestIPClassificationAndScopes(unittest.TestCase):
    """Test standard-library classification of IPv4 and IPv6 address scopes."""

    def test_public_globally_routable_ipv4(self):
        res = classify_ip_address("8.8.8.8")
        self.assertIsNotNone(res)
        self.assertEqual(res["ip"], "8.8.8.8")
        self.assertEqual(res["version"], 4)
        self.assertTrue(res["is_global"])
        self.assertFalse(res["is_private"])
        self.assertFalse(res["is_loopback"])
        self.assertTrue(res["is_eligible_for_geolocation"])
        self.assertEqual(res["ip_type_label"], "public")

    def test_private_ipv4_scopes(self):
        for ip in ["10.0.0.1", "172.16.5.20", "192.168.1.100"]:
            res = classify_ip_address(ip)
            self.assertIsNotNone(res)
            self.assertTrue(res["is_private"])
            self.assertFalse(res["is_global"])
            self.assertFalse(res["is_eligible_for_geolocation"])
            self.assertEqual(res["ip_type_label"], "private")

    def test_loopback_ipv4(self):
        res = classify_ip_address("127.0.0.1")
        self.assertIsNotNone(res)
        self.assertTrue(res["is_loopback"])
        self.assertFalse(res["is_eligible_for_geolocation"])
        self.assertEqual(res["ip_type_label"], "loopback")

    def test_link_local_ipv4(self):
        res = classify_ip_address("169.254.1.1")
        self.assertIsNotNone(res)
        self.assertTrue(res["is_link_local"])
        self.assertFalse(res["is_eligible_for_geolocation"])
        self.assertEqual(res["ip_type_label"], "link_local")

    def test_multicast_and_reserved_ipv4(self):
        mcast = classify_ip_address("224.0.0.1")
        self.assertIsNotNone(mcast)
        self.assertTrue(mcast["is_multicast"])
        self.assertFalse(mcast["is_eligible_for_geolocation"])

        resv = classify_ip_address("240.0.0.1")
        self.assertIsNotNone(resv)
        self.assertTrue(resv["is_reserved"])
        self.assertFalse(resv["is_eligible_for_geolocation"])

    def test_public_ipv6(self):
        res = classify_ip_address("2001:4860:4860::8888")
        self.assertIsNotNone(res)
        self.assertEqual(res["version"], 6)
        self.assertTrue(res["is_global"])
        self.assertFalse(res["is_private"])
        self.assertTrue(res["is_eligible_for_geolocation"])
        self.assertEqual(res["ip_type_label"], "public")

    def test_bracketed_and_prefixed_ipv6(self):
        res = classify_ip_address("[IPv6:2607:f8b0:4002:c08::22b]")
        self.assertIsNotNone(res)
        self.assertEqual(res["ip"], "2607:f8b0:4002:c08::22b")
        self.assertEqual(res["version"], 6)
        self.assertTrue(res["is_eligible_for_geolocation"])

    def test_loopback_and_link_local_ipv6(self):
        loopback = classify_ip_address("::1")
        self.assertIsNotNone(loopback)
        self.assertTrue(loopback["is_loopback"])
        self.assertFalse(loopback["is_eligible_for_geolocation"])

        link_local = classify_ip_address("fe80::1")
        self.assertIsNotNone(link_local)
        self.assertTrue(link_local["is_link_local"])
        self.assertFalse(link_local["is_eligible_for_geolocation"])

    def test_malformed_ip_strings(self):
        for bad_ip in ["999.999.999.999", "1.2.3", "not-an-ip", "123.456.78.90", ""]:
            res = classify_ip_address(bad_ip)
            self.assertIsNone(res)


class TestIPExtractionAndDeduplication(unittest.TestCase):
    """Test extracting candidate IPs from messy headers and deduplicating them."""

    def test_extract_mixed_ips_from_header(self):
        header_text = (
            "from mail.example.com (mail.example.com [198.51.100.1]) "
            "by mx.google.com ([2001:4860:4860::8888]) with ESMTPS "
            "id 12345 (helo=[10.0.0.5]) [198.51.100.1]"
        )
        ips = extract_and_classify_ips(header_text)
        ip_strs = [i["ip"] for i in ips]
        self.assertIn("198.51.100.1", ip_strs)
        self.assertIn("2001:4860:4860::8888", ip_strs)
        self.assertIn("10.0.0.5", ip_strs)
        # Deduplication check in single header extraction: 198.51.100.1 should appear only once
        self.assertEqual(ip_strs.count("198.51.100.1"), 1)

    def test_deduplication_across_multiple_hops(self):
        headers = [
            "from relay1.com ([203.0.113.10]) by mx.example.com; Mon, 20 Oct 2026 10:05:00 +0000",
            "from relay2.com ([203.0.113.10]) by relay1.com; Mon, 20 Oct 2026 10:04:00 +0000",
            "from internal ([192.168.1.50]) by relay2.com; Mon, 20 Oct 2026 10:03:00 +0000",
        ]
        report = analyze_email_routing(headers)
        unique_ips = report["unique_ips"]
        self.assertEqual(len(unique_ips), 2)  # 203.0.113.10 and 192.168.1.50

        # Check 203.0.113.10 hop association and count
        shared_ip = next(i for i in unique_ips if i["ip"] == "203.0.113.10")
        self.assertEqual(shared_ip["occurrences_count"], 2)
        self.assertEqual(shared_ip["hop_indices"], [0, 1])


class TestReceivedHeaderParsing(unittest.TestCase):
    """Test parsing single and multiple Received headers, tokens, and edge cases."""

    def test_single_standard_received_header(self):
        raw = (
            "from mail-pj1-f51.google.com (mail-pj1-f51.google.com. [209.85.216.51]) "
            "by mx.google.com with ESMTPS id abc123def for <user@example.com>; "
            "Mon, 20 Oct 2026 10:15:30 +0000"
        )
        hop = parse_single_received_header(raw, 0)
        self.assertEqual(hop["index"], 0)
        self.assertEqual(hop["from_host"], "mail-pj1-f51.google.com")
        self.assertEqual(hop["by_host"], "mx.google.com")
        self.assertEqual(hop["protocol"], "ESMTPS")
        self.assertEqual(hop["message_id"], "abc123def")
        self.assertEqual(hop["recipient"], "<user@example.com>")
        self.assertEqual(hop["timestamp_str"], "Mon, 20 Oct 2026 10:15:30 +0000")
        self.assertEqual(hop["timestamp_iso"], "2026-10-20T10:15:30+00:00")
        self.assertIsNotNone(hop["timestamp_epoch"])
        self.assertEqual(hop["parsing_status"], PARSE_SUCCESS)
        self.assertTrue(any(i["ip"] == "209.85.216.51" for i in hop["extracted_ips"]))

    def test_folded_and_multiline_header(self):
        raw = (
            "from mail.paypa1-secure.totally-not-evil.com\r\n"
            "        (mail.paypa1-secure.totally-not-evil.com [192.168.1.100])\r\n"
            "        by mx.example-victim.com (Postfix) with SMTP id DDD444\r\n"
            "        for <victim@example-victim.com>; Wed, 3 Jan 2024 03:17:50 +0000"
        )
        hop = parse_single_received_header(raw, 0)
        self.assertEqual(hop["from_host"], "mail.paypa1-secure.totally-not-evil.com")
        self.assertEqual(hop["by_host"], "mx.example-victim.com")
        self.assertEqual(hop["protocol"], "SMTP")
        self.assertEqual(hop["message_id"], "DDD444")
        self.assertEqual(hop["recipient"], "<victim@example-victim.com>")
        self.assertEqual(hop["timestamp_iso"], "2024-01-03T03:17:50+00:00")
        self.assertEqual(hop["parsing_status"], PARSE_SUCCESS)

    def test_missing_from_clause_internal_hop(self):
        raw = "by 2002:a05:6808:1c88:b0:3c9:1d8:5249 with SMTP id abc; Mon, 20 Oct 2026 10:12:00 +0000"
        hop = parse_single_received_header(raw, 0)
        self.assertIsNone(hop["from_host"])
        self.assertEqual(hop["by_host"], "2002:a05:6808:1c88:b0:3c9:1d8:5249")
        self.assertEqual(hop["protocol"], "SMTP")
        self.assertEqual(hop["parsing_status"], PARSE_PARTIAL)

    def test_missing_semicolon_pattern_fallback(self):
        # Header lacks semicolon delimiter before timestamp
        raw = (
            "from smtp.fakerelay.xyz ([10.0.0.99]) by mail.paypa1-secure.totally-not-evil.com "
            "with SMTP id EEE555 Wed, 3 Jan 2024 03:17:40 +0000"
        )
        hop = parse_single_received_header(raw, 1)
        self.assertEqual(hop["from_host"], "smtp.fakerelay.xyz")
        self.assertEqual(hop["by_host"], "mail.paypa1-secure.totally-not-evil.com")
        self.assertEqual(hop["timestamp_iso"], "2024-01-03T03:17:40+00:00")
        self.assertTrue(any("fallback" in w.lower() for w in hop["warnings"]))

    def test_malformed_timestamp_string(self):
        raw = "from mail.com by mx.com; ThisIsNotAValidDate"
        hop = parse_single_received_header(raw, 0)
        self.assertEqual(hop["from_host"], "mail.com")
        self.assertEqual(hop["by_host"], "mx.com")
        self.assertIsNone(hop["timestamp_iso"])
        self.assertIsNone(hop["timestamp_epoch"])
        self.assertTrue(any("failed to parse timestamp" in w.lower() for w in hop["warnings"]))

    def test_completely_malformed_header(self):
        raw = "gibberish non-standard header with no recognized keywords or dates"
        hop = parse_single_received_header(raw, 0)
        self.assertEqual(hop["parsing_status"], PARSE_FAILED)
        self.assertIsNone(hop["from_host"])
        self.assertIsNone(hop["by_host"])
        self.assertEqual(hop["trust_label"], TRUST_UNTRUSTED_CLAIM)

    def test_empty_header_string(self):
        hop = parse_single_received_header("", 0)
        self.assertEqual(hop["parsing_status"], PARSE_FAILED)
        self.assertEqual(hop["raw_header"], "")
        self.assertEqual(hop["trust_label"], TRUST_UNTRUSTED_CLAIM)


class TestChronologicalAndHeaderOrdering(unittest.TestCase):
    """Test distinction between header order (recipient first) and chronological order (oldest first)."""

    def test_chronological_ordering_three_hops(self):
        # Document order: Hop 0 = 03:17:50 (newest), Hop 1 = 03:17:40, Hop 2 = 03:17:38 (oldest)
        headers = [
            "from relay2 by mx.victim.com; Wed, 3 Jan 2024 03:17:50 +0000",
            "from relay1 by relay2; Wed, 3 Jan 2024 03:17:40 +0000",
            "from sender by relay1; Wed, 3 Jan 2024 03:17:38 +0000",
        ]
        report = analyze_email_routing(headers)
        ro = report["route_order"]
        self.assertEqual(ro["header_order"], [0, 1, 2])
        self.assertEqual(ro["chronological_order"], [2, 1, 0])
        self.assertFalse(ro["ordering_ambiguity"])

    def test_ordering_with_missing_timestamps(self):
        headers = [
            "from relay2 by mx.victim.com; Wed, 3 Jan 2024 03:17:50 +0000",
            "from relay1 by relay2 without date",
            "from sender by relay1 without date",
        ]
        report = analyze_email_routing(headers)
        ro = report["route_order"]
        self.assertTrue(ro["ordering_ambiguity"])
        self.assertEqual(ro["chronological_order"], [2, 1, 0])
        self.assertTrue(len(report["warnings"]) > 0)


class TestEvidenceAndTrustBoundaries(unittest.TestCase):
    """Test evidence classification and trusted receiver boundary configurations."""

    def test_no_trust_configuration_marks_route_unverified(self):
        headers = [
            "from legit.com ([203.0.113.1]) by mx.victim.com; Mon, 20 Oct 2026 10:00:00 +0000",
            "from sender.com ([198.51.100.2]) by legit.com; Mon, 20 Oct 2026 09:58:00 +0000",
        ]
        # No config provided
        report = analyze_email_routing(headers, config={})
        for hop in report["hops"]:
            self.assertEqual(hop["trust_label"], TRUST_PARSED_UNVERIFIED)

        trust = report["trust_analysis"]
        self.assertEqual(trust["trusted_hops_count"], 0)
        self.assertEqual(trust["untrusted_hops_count"], 2)
        self.assertIsNone(trust["trusted_boundary_index"])
        self.assertIn("No trusted receiving servers configured", trust["summary"])

    def test_explicit_trusted_boundary_configuration(self):
        headers = [
            # Hop 0: Inbound to our trusted gateway
            "from mail-ext.com ([203.0.113.1]) by mx.victim.com with ESMTPS; Mon, 20 Oct 2026 10:00:00 +0000",
            # Hop 1: Upstream intermediate relay (untrusted external claim)
            "from attacker.com ([198.51.100.2]) by mail-ext.com with ESMTP; Mon, 20 Oct 2026 09:58:00 +0000",
            # Hop 2: Claimed originating hop (untrusted external claim)
            "from [192.168.1.10] by attacker.com; Mon, 20 Oct 2026 09:55:00 +0000",
        ]
        config = {"trusted_hosts": ["mx.victim.com"]}
        report = analyze_email_routing(headers, config=config)

        # Hop 0 was recorded by our trusted receiver
        self.assertEqual(report["hops"][0]["trust_label"], TRUST_VERIFIED_BY_CONFIGURED)

        # Hops 1 and 2 were recorded upstream by external servers
        self.assertEqual(report["hops"][1]["trust_label"], TRUST_UNTRUSTED_CLAIM)
        self.assertEqual(report["hops"][2]["trust_label"], TRUST_UNTRUSTED_CLAIM)

        trust = report["trust_analysis"]
        self.assertEqual(trust["trusted_hops_count"], 1)
        self.assertEqual(trust["untrusted_hops_count"], 2)
        self.assertEqual(trust["trusted_boundary_index"], 0)

    def test_subdomain_matching_in_trusted_hosts(self):
        headers = [
            "from ext.com by mx1.sub.victim.com; Mon, 20 Oct 2026 10:00:00 +0000",
        ]
        config = {"trusted_hosts": ["victim.com"]}
        report = analyze_email_routing(headers, config=config)
        self.assertEqual(report["hops"][0]["trust_label"], TRUST_VERIFIED_BY_CONFIGURED)

    def test_mismatched_trusted_hosts_does_not_trust_unverified_hops(self):
        headers = [
            "from ext.com by strange-mx.attacker.com; Mon, 20 Oct 2026 10:00:00 +0000",
        ]
        config = {"trusted_hosts": ["victim.com"]}
        report = analyze_email_routing(headers, config=config)
        self.assertEqual(report["hops"][0]["trust_label"], TRUST_UNTRUSTED_CLAIM)
        self.assertEqual(report["trust_analysis"]["trusted_hops_count"], 0)


class TestGeolocationProviderInterface(unittest.TestCase):
    """Test the decoupled geolocation provider interface and offline behaviors."""

    def test_unconfigured_offline_database_reports_not_checked(self):
        headers = [
            "from mail.google.com ([209.85.216.51]) by mx.example.com; Mon, 20 Oct 2026 10:00:00 +0000",
        ]
        # No geoip_db_path configured
        report = analyze_email_routing(headers, config={})
        self.assertEqual(report["geolocation_summary"]["eligible_public_ips"], 1)
        self.assertEqual(report["geolocation_summary"]["geolocated_ips"], 0)
        self.assertEqual(report["geolocation_summary"]["lookup_status_counts"][LOOKUP_NOT_CHECKED], 1)

        unique_ip = report["unique_ips"][0]
        geo = unique_ip["geolocation"]
        self.assertEqual(geo["lookup_status"], LOOKUP_NOT_CHECKED)
        self.assertIn("No MaxMind GeoLite2 database path configured", geo["reason"])

    def test_missing_database_file_reports_not_checked(self):
        headers = [
            "from mail.google.com ([209.85.216.51]) by mx.example.com; Mon, 20 Oct 2026 10:00:00 +0000",
        ]
        config = {"geoip_db_path": "C:\\path\\to\\nonexistent\\GeoLite2-City.mmdb"}
        report = analyze_email_routing(headers, config=config)
        geo = report["unique_ips"][0]["geolocation"]
        self.assertEqual(geo["lookup_status"], LOOKUP_NOT_CHECKED)
        self.assertIn("file not found", geo["reason"].lower())

    def test_private_ips_never_sent_to_provider(self):
        headers = [
            "from internal ([192.168.1.100]) by mail.corp ([10.0.0.1]); Mon, 20 Oct 2026 10:00:00 +0000",
        ]
        mock_provider = MagicMock(spec=BaseGeoLocationProvider)
        config = {"geo_provider": mock_provider}
        report = analyze_email_routing(headers, config=config)

        # Provider must NOT have been called for private IPs
        mock_provider.lookup.assert_not_called()

        self.assertEqual(report["geolocation_summary"]["eligible_public_ips"], 0)
        self.assertEqual(report["geolocation_summary"]["private_or_internal_ips"], 2)
        for ip_entry in report["unique_ips"]:
            geo = ip_entry["geolocation"]
            self.assertEqual(geo["lookup_status"], LOOKUP_NOT_CHECKED)
            self.assertIn("ineligible for public geolocation", geo["reason"])

    def test_mock_provider_successful_lookup(self):
        headers = [
            "from mail.google.com ([209.85.216.51]) by mx.example.com; Mon, 20 Oct 2026 10:00:00 +0000",
        ]
        mock_provider = MockGeoIPProvider(
            ip_records={
                "209.85.216.51": {
                    "country": "United States",
                    "country_code": "US",
                    "region": "California",
                    "city": "Mountain View",
                    "latitude": 37.422,
                    "longitude": -122.084,
                    "asn": 15169,
                    "as_organization": "Google LLC",
                }
            }
        )
        report = analyze_email_routing(headers, config={"geo_provider": mock_provider})

        geo_summary = report["geolocation_summary"]
        self.assertEqual(geo_summary["geolocated_ips"], 1)
        self.assertIn("United States", geo_summary["countries_detected"])

        geo = report["unique_ips"][0]["geolocation"]
        self.assertEqual(geo["lookup_status"], LOOKUP_SUCCESS)
        self.assertEqual(geo["country"], "United States")
        self.assertEqual(geo["country_code"], "US")
        self.assertEqual(geo["region"], "California")
        self.assertEqual(geo["city"], "Mountain View")
        self.assertEqual(geo["latitude"], 37.422)
        self.assertEqual(geo["longitude"], -122.084)
        self.assertEqual(geo["asn"], 15169)

    def test_mock_provider_not_found_and_error(self):
        headers = [
            "from unknown1 ([93.184.216.34]) by mx.com; Mon, 20 Oct 2026 10:00:00 +0000",
            "from unknown2 ([151.101.1.69]) by mx.com; Mon, 20 Oct 2026 09:59:00 +0000",
        ]
        mock_provider = MockGeoIPProvider(
            ip_records={},  # 93.184.216.34 will be not_found
            error_ips={"151.101.1.69"},  # 151.101.1.69 will return error
        )
        report = analyze_email_routing(headers, config={"geo_provider": mock_provider})
        counts = report["geolocation_summary"]["lookup_status_counts"]
        self.assertEqual(counts[LOOKUP_NOT_FOUND], 1)
        self.assertEqual(counts[LOOKUP_ERROR], 1)

    def test_mock_provider_missing_optional_location_fields(self):
        """When an offline database lacks city or coordinates, fields must remain None."""
        headers = [
            "from mail.example.com ([93.184.216.34]) by mx.com; Mon, 20 Oct 2026 10:00:00 +0000",
        ]
        mock_provider = MockGeoIPProvider(
            ip_records={
                "93.184.216.34": {
                    "country": "United States",
                    "country_code": "US",
                    "region": None,
                    "city": None,
                    "latitude": None,
                    "longitude": None,
                    "asn": None,
                }
            }
        )
        report = analyze_email_routing(headers, config={"geo_provider": mock_provider})
        geo = report["unique_ips"][0]["geolocation"]
        self.assertEqual(geo["lookup_status"], LOOKUP_SUCCESS)
        self.assertEqual(geo["country"], "United States")
        self.assertIsNone(geo["city"])
        self.assertIsNone(geo["latitude"])
        self.assertIsNone(geo["longitude"])

    def test_missing_optional_dependency_handling(self):
        """When geoip2 cannot be imported, the provider reports not_checked without crashing."""
        with patch.dict("sys.modules", {"geoip2": None, "geoip2.database": None}):
            # Point to a temporary dummy file that exists
            import tempfile
            with tempfile.NamedTemporaryFile(delete=False) as tf:
                temp_path = tf.name

            try:
                provider = OfflineGeoIPProvider(db_path=temp_path)
                res = provider.lookup("93.184.216.34")
                self.assertEqual(res["lookup_status"], LOOKUP_NOT_CHECKED)
                self.assertIn("geoip2", res["reason"].lower())
            finally:
                if os.path.exists(temp_path):
                    os.remove(temp_path)


class TestEmptyAndMissingHeaders(unittest.TestCase):
    """Test handling of empty or missing Received headers."""

    def test_empty_received_headers_list(self):
        report = analyze_email_routing([])
        self.assertEqual(report["analysis_status"], "no_headers")
        self.assertEqual(len(report["hops"]), 0)
        self.assertEqual(len(report["unique_ips"]), 0)
        self.assertTrue(len(report["warnings"]) > 0)

    def test_none_input_handled_gracefully(self):
        report = analyze_email_routing(None)
        self.assertEqual(report["analysis_status"], "no_headers")
        self.assertEqual(len(report["hops"]), 0)

    def test_dict_without_received_headers(self):
        empty_parsed = {"email_metadata": {"subject": "Test"}, "received_headers": []}
        report = analyze_email_routing(empty_parsed)
        self.assertEqual(report["analysis_status"], "no_headers")


class TestIntegrationWithModule1(unittest.TestCase):
    """Test integration directly consuming output from Module 1 (parse_email_file)."""

    def test_consume_module1_sample_phishing_email(self):
        sample_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "samples", "phishing_sample.eml")
        )
        self.assertTrue(os.path.isfile(sample_path))

        parsed_email = parse_email_file(sample_path)
        self.assertEqual(parsed_email["errors"], [])
        self.assertTrue(len(parsed_email["received_headers"]) > 0)

        config = {"trusted_hosts": ["mx.example-victim.com"]}
        report = analyze_email_routing(parsed_email, config=config)

        self.assertEqual(report["analysis_status"], "success")
        self.assertEqual(len(report["hops"]), 3)
        self.assertEqual(report["hops"][0]["by_host"], "mx.example-victim.com")
        self.assertEqual(report["hops"][0]["trust_label"], TRUST_VERIFIED_BY_CONFIGURED)
        self.assertEqual(report["hops"][1]["trust_label"], TRUST_UNTRUSTED_CLAIM)
        self.assertEqual(report["hops"][2]["trust_label"], TRUST_UNTRUSTED_CLAIM)

        # Check unique IPs extracted (192.168.1.100, 10.0.0.99, 192.168.1.50)
        unique_ips = [u["ip"] for u in report["unique_ips"]]
        self.assertIn("192.168.1.100", unique_ips)
        self.assertIn("10.0.0.99", unique_ips)
        self.assertIn("192.168.1.50", unique_ips)

        # All of these sample IPs are private
        self.assertEqual(report["geolocation_summary"]["eligible_public_ips"], 0)
        self.assertEqual(report["geolocation_summary"]["private_or_internal_ips"], 3)


class TestReportSchemaAndJSONSerialization(unittest.TestCase):
    """Ensure that the report adheres to the schema and serializes to JSON without error."""

    def test_json_serializability(self):
        sample_headers = [
            "from mail.google.com ([209.85.216.51]) by mx.google.com with ESMTPS id 12345; Mon, 20 Oct 2026 10:15:30 +0000",
            "from client.internal ([192.168.1.1]) by mail.google.com; Mon, 20 Oct 2026 10:14:00 +0000",
        ]
        report = analyze_email_routing(sample_headers)

        # Check all required top-level keys
        required_keys = {
            "hops",
            "unique_ips",
            "geolocation_summary",
            "route_order",
            "trust_analysis",
            "warnings",
            "evidence_limitations",
            "analysis_status",
        }
        self.assertTrue(required_keys.issubset(report.keys()))

        # Serialize to JSON - must succeed without error
        json_output = json.dumps(report, indent=2)
        self.assertIsInstance(json_output, str)
        self.assertIn("geolocation_summary", json_output)

        # Check forensic disclaimer exists
        self.assertTrue(
            any("physical location" in d.lower() for d in report["evidence_limitations"])
        )


if __name__ == "__main__":
    unittest.main()
