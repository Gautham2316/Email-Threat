"""
tests/test_url_analyzer.py
==========================
Automated test suite for Module 3: URL Threat Analysis Engine.

RULES & INVARIANTS:
1. Zero Network Access: Every test verifies local heuristic analysis without
   outbound socket, DNS, or HTTP calls.
2. Safe Handling: URLs are analyzed as untrusted strings, never visited or crawled.
3. Original Evidence Preservation: Original URLs are strictly preserved intact.
4. Bounded Scoring: Heuristic risk scores remain strictly within [0, 100].
5. Non-Destructive Integration: Seamlessly consumes Module 1 output schemas.
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from url_analyzer import (
    analyze_urls,
    defang_url,
    SHORTENER_DOMAINS,
    TARGETED_BRANDS,
    PHISHING_KEYWORDS,
    SUSPICIOUS_PAYLOAD_EXTENSIONS,
    HIGH_RISK_TLDS,
    DANGEROUS_SCHEMES,
)
from email_parser import parse_email_file


class TestURLSyntaxAndParsing(unittest.TestCase):
    """Test standard URL syntax parsing, component extraction, and error handling."""

    def test_normal_https_url(self):
        report = analyze_urls("https://www.example.com/path/index.html?param=value#section")
        self.assertEqual(report["total_urls_analyzed"], 1)
        res = report["results"][0]
        self.assertEqual(res["scheme"], "https")
        self.assertEqual(res["hostname"], "www.example.com")
        self.assertEqual(res["path"], "/path/index.html")
        self.assertEqual(res["query"], "param=value")
        self.assertEqual(res["fragment"], "section")
        self.assertEqual(res["heuristic_risk_score"], 0)
        self.assertEqual(res["risk_level"], "none")
        self.assertEqual(res["analysis_status"], "analyzed")

    def test_normal_http_url_has_low_risk(self):
        # HTTP is flagged as insecure transport, but HTTP alone is not proof of malice
        report = analyze_urls("http://www.example.org/")
        res = report["results"][0]
        self.assertEqual(res["scheme"], "http")
        self.assertEqual(res["heuristic_risk_score"], 5)
        self.assertEqual(res["risk_level"], "low")
        self.assertTrue(any(i["id"] == "INSECURE_HTTP_SCHEME" for i in res["indicators"]))

    def test_missing_scheme(self):
        report = analyze_urls("www.example.com/login")
        res = report["results"][0]
        self.assertIn("MISSING_URL_SCHEME", [i["id"] for i in res["indicators"]])
        self.assertTrue(len(res["warnings"]) > 0)

    def test_malformed_url_syntax(self):
        # An invalid port like :abc generates an indicator without crashing
        report = analyze_urls("http://example.com:invalidport/test")
        res = report["results"][0]
        self.assertTrue(any(i["id"] == "INVALID_PORT_SPECIFICATION" for i in res["indicators"]))
        self.assertIsNone(res["port"])


class TestIPAddressAnalysis(unittest.TestCase):
    """Test IPv4, IPv6, localhost, and private/reserved IP literal detection."""

    def test_ipv4_global_literal(self):
        report = analyze_urls("http://93.184.216.34/index.html")
        res = report["results"][0]
        self.assertTrue(res["is_ip_literal"])
        self.assertIsNotNone(res["ip_literal"])
        self.assertEqual(res["ip_literal"]["version"], 4)
        self.assertTrue(res["ip_literal"]["is_global"])
        self.assertTrue(any(i["id"] == "IP_HOST_GLOBAL" for i in res["indicators"]))
        self.assertGreaterEqual(res["heuristic_risk_score"], 35)

    def test_ipv4_private_literal(self):
        report = analyze_urls("http://192.168.1.50/admin")
        res = report["results"][0]
        self.assertTrue(res["is_ip_literal"])
        self.assertTrue(res["ip_literal"]["is_private"])
        self.assertTrue(any(i["id"] == "IP_HOST_LOCAL_PRIVATE" for i in res["indicators"]))

    def test_ipv4_loopback_literal(self):
        report = analyze_urls("http://127.0.0.1:8000/api")
        res = report["results"][0]
        self.assertTrue(res["is_ip_literal"])
        self.assertTrue(res["ip_literal"]["is_loopback"])
        self.assertTrue(any(i["id"] == "IP_HOST_LOCAL_PRIVATE" for i in res["indicators"]))

    def test_ipv6_bracketed_literal(self):
        report = analyze_urls("http://[2001:db8::1]:8080/path")
        res = report["results"][0]
        self.assertTrue(res["is_ip_literal"])
        self.assertEqual(res["ip_literal"]["version"], 6)
        self.assertEqual(res["port"], 8080)

    def test_ipv6_loopback_literal(self):
        report = analyze_urls("http://[::1]/test")
        res = report["results"][0]
        self.assertTrue(res["is_ip_literal"])
        self.assertTrue(res["ip_literal"]["is_loopback"])

    def test_obfuscated_integer_ip(self):
        # 2130706433 is 127.0.0.1 as a 32-bit integer
        report = analyze_urls("http://2130706433/payload")
        res = report["results"][0]
        self.assertTrue(res["is_ip_literal"])
        self.assertEqual(res["ip_literal"]["ip"], "127.0.0.1")
        self.assertTrue(any(i["id"] == "OBFUSCATED_INTEGER_IP" for i in res["indicators"]))

    def test_standard_domain_is_not_ip(self):
        report = analyze_urls("https://example.com/test")
        res = report["results"][0]
        self.assertFalse(res["is_ip_literal"])
        self.assertIsNone(res["ip_literal"])


class TestCredentialsAndAuthority(unittest.TestCase):
    """Test embedded username/password detection and credential sanitization."""

    def test_embedded_credentials_detected(self):
        report = analyze_urls("https://admin:supersecret@attacker-controlled.com/dashboard")
        res = report["results"][0]
        self.assertTrue(res["has_credentials"])
        self.assertTrue(any(i["id"] == "EMBEDDED_CREDENTIALS" for i in res["indicators"]))
        # Password must be redacted in normalized representation
        self.assertNotIn("supersecret", res["normalized_url"])
        self.assertIn("***", res["normalized_url"])

    def test_embedded_username_only(self):
        report = analyze_urls("https://paypal.com@evil-destination.com/")
        res = report["results"][0]
        self.assertTrue(res["has_credentials"])
        self.assertEqual(res["hostname"], "evil-destination.com")
        self.assertTrue(any(i["id"] == "EMBEDDED_CREDENTIALS" for i in res["indicators"]))


class TestPunycodeAndHomograph(unittest.TestCase):
    """Test Punycode and internationalized domain homograph detection."""

    def test_punycode_domain_detected(self):
        # xn--e1afmkfd.xn--p1ai is an example IDN domain
        report = analyze_urls("http://xn--e1afmkfd.xn--p1ai/test")
        res = report["results"][0]
        self.assertTrue(res["is_punycode"])
        self.assertTrue(any(i["id"] == "PUNYCODE_IDN_DOMAIN" for i in res["indicators"]))

    def test_homograph_cyrillic_detected(self):
        # xn--pple-43d.com is Cyrillic 'a' + 'pple.com' (homograph of apple.com)
        report = analyze_urls("https://xn--pple-43d.com/login")
        res = report["results"][0]
        self.assertTrue(res["is_punycode"])
        self.assertTrue(any("HOMOGRAPH" in i["id"] or "PUNYCODE" in i["id"] for i in res["indicators"]))

    def test_standard_ascii_is_not_homograph(self):
        report = analyze_urls("https://www.apple.com/iphone")
        res = report["results"][0]
        self.assertFalse(res["is_punycode"])
        self.assertFalse(any(i["id"] == "HOMOGRAPH_ATTACK_SUSPECTED" for i in res["indicators"]))


class TestDomainAndSubdomainHeuristics(unittest.TestCase):
    """Test brand spoofing, excessive depth, and high-risk TLD heuristics."""

    def test_brand_spoofing_in_subdomain(self):
        report = analyze_urls("http://paypal-account-verify.totally-not-evil.com/login")
        res = report["results"][0]
        self.assertTrue(any(i["id"] == "BRAND_SPOOFING_IN_SUBDOMAIN" for i in res["indicators"]))
        self.assertGreaterEqual(res["heuristic_risk_score"], 35)

    def test_brand_name_mismatch_in_registered_domain(self):
        report = analyze_urls("https://verify-microsoft-security.com/auth")
        res = report["results"][0]
        self.assertTrue(any(i["id"] == "BRAND_NAME_MISMATCH" for i in res["indicators"]))

    def test_typosquatting_leetspeak_detected(self):
        report = analyze_urls("https://secure.paypa1-restore.totally-not-evil.com/restore")
        res = report["results"][0]
        self.assertTrue(any(i["id"] == "BRAND_SPOOFING_IN_SUBDOMAIN" for i in res["indicators"]))

    def test_excessive_subdomain_depth(self):
        report = analyze_urls("https://a.b.c.d.example.com/page")
        res = report["results"][0]
        self.assertTrue(any(i["id"] == "EXCESSIVE_SUBDOMAIN_DEPTH" for i in res["indicators"]))

    def test_pseudo_tld_in_subdomain(self):
        report = analyze_urls("https://secure.login.com.free-host.org/verify")
        res = report["results"][0]
        self.assertTrue(any(i["id"] == "PSEUDO_TLD_IN_SUBDOMAIN" for i in res["indicators"]))

    def test_high_risk_tld_detected(self):
        report = analyze_urls("https://cheap-invoices.xyz/document")
        res = report["results"][0]
        self.assertTrue(any(i["id"] == "HIGH_RISK_TLD" for i in res["indicators"]))

    def test_legitimate_brand_domain_not_flagged_for_spoofing(self):
        # paypal.com is the genuine brand owner, so it should not flag brand spoofing
        report = analyze_urls("https://www.paypal.com/signin")
        res = report["results"][0]
        self.assertFalse(any("BRAND" in i["id"] for i in res["indicators"]))


class TestPathAndPayloadHeuristics(unittest.TestCase):
    """Test payload file extensions, traversal sequences, and character obfuscation."""

    def test_suspicious_payload_download_exe(self):
        report = analyze_urls("https://updates.example.com/files/setup.exe")
        res = report["results"][0]
        self.assertTrue(any(i["id"] == "SUSPICIOUS_PAYLOAD_DOWNLOAD" for i in res["indicators"]))
        self.assertGreaterEqual(res["heuristic_risk_score"], 40)

    def test_suspicious_payload_download_scr_and_bat(self):
        report1 = analyze_urls("http://download.site.com/invoice.scr")
        self.assertTrue(any(i["id"] == "SUSPICIOUS_PAYLOAD_DOWNLOAD" for i in report1["results"][0]["indicators"]))

        report2 = analyze_urls("http://download.site.com/run.bat")
        self.assertTrue(any(i["id"] == "SUSPICIOUS_PAYLOAD_DOWNLOAD" for i in report2["results"][0]["indicators"]))

    def test_path_traversal_sequence(self):
        report = analyze_urls("https://example.com/../../etc/passwd")
        res = report["results"][0]
        self.assertTrue(any(i["id"] == "PATH_TRAVERSAL_DETECTED" for i in res["indicators"]))

    def test_phishing_keywords_in_path_and_host(self):
        report = analyze_urls("https://secure-portal.com/login/verify/account/update")
        res = report["results"][0]
        self.assertTrue(any("PHISHING_KEYWORD" in i["id"] for i in res["indicators"]))

    def test_null_byte_obfuscation(self):
        report = analyze_urls("https://example.com/image.jpg%00.exe")
        res = report["results"][0]
        self.assertTrue(any(i["id"] == "NULL_BYTE_INJECTION" for i in res["indicators"]))

    def test_double_percent_encoding(self):
        report = analyze_urls("https://example.com/%252f%252e%252e/test")
        res = report["results"][0]
        self.assertTrue(any(i["id"] == "DOUBLE_PERCENT_ENCODING" for i in res["indicators"]))

    def test_excessive_url_length(self):
        long_url = "https://example.com/" + "a" * 260
        report = analyze_urls(long_url)
        res = report["results"][0]
        self.assertTrue(any(i["id"] == "EXCESSIVE_URL_LENGTH" for i in res["indicators"]))


class TestShortenerAndSchemes(unittest.TestCase):
    """Test known shorteners and dangerous executable schemes."""

    def test_known_url_shortener_detected(self):
        report = analyze_urls("https://bit.ly/3phish")
        res = report["results"][0]
        self.assertTrue(res["is_shortener"])
        self.assertTrue(any(i["id"] == "URL_SHORTENER_DETECTED" for i in res["indicators"]))

    def test_tinyurl_shortener_detected(self):
        report = analyze_urls("https://tinyurl.com/invoice-doc")
        res = report["results"][0]
        self.assertTrue(res["is_shortener"])

    def test_dangerous_scheme_javascript(self):
        report = analyze_urls("javascript:alert(document.cookie)")
        res = report["results"][0]
        self.assertEqual(res["analysis_status"], "unsupported_scheme")
        self.assertTrue(any(i["id"] == "DANGEROUS_URI_SCHEME" for i in res["indicators"]))
        self.assertGreaterEqual(res["heuristic_risk_score"], 50)

    def test_dangerous_scheme_data(self):
        report = analyze_urls("data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==")
        res = report["results"][0]
        self.assertEqual(res["analysis_status"], "unsupported_scheme")
        self.assertTrue(any(i["id"] == "DANGEROUS_URI_SCHEME" for i in res["indicators"]))

    def test_dangerous_scheme_file(self):
        report = analyze_urls("file:///C:/Windows/System32/calc.exe")
        res = report["results"][0]
        self.assertEqual(res["analysis_status"], "unsupported_scheme")
        self.assertTrue(any(i["id"] == "DANGEROUS_URI_SCHEME" for i in res["indicators"]))


class TestDefangingAndPreservation(unittest.TestCase):
    """Test URL defanging transformations and original evidence immutability."""

    def test_defang_http_and_https(self):
        self.assertTrue(defang_url("http://example.com").startswith("hxxp://"))
        self.assertTrue(defang_url("https://example.com").startswith("hxxps://"))

    def test_defang_netloc_dots_and_at(self):
        defanged = defang_url("https://user:pass@sub.evil.com/path")
        self.assertIn("[.]", defanged)
        self.assertIn("[@]", defanged)
        self.assertNotIn("https://", defanged)

    def test_defang_ip_literal(self):
        defanged = defang_url("http://192.168.1.1:8080/path")
        self.assertEqual(defanged, "hxxp://192[.]168[.]1[.]1:8080/path")

    def test_original_url_preserved_strictly(self):
        original = "http://user:pass@192.168.1.1:8080/login?token=abc#section"
        report = analyze_urls(original)
        res = report["results"][0]
        self.assertEqual(res["original_url"], original)


class TestScoringAndBatchAggregation(unittest.TestCase):
    """Test bounded risk scores, deterministic levels, and batch statistics."""

    def test_scoring_bounds_zero_to_hundred(self):
        # A URL triggering many high-severity indicators must not exceed 100
        extreme_url = "http://user:pass@203.0.113.199:8080/login/verify/update/download.exe?token=1%00#test"
        report = analyze_urls(extreme_url)
        res = report["results"][0]
        self.assertGreaterEqual(res["heuristic_risk_score"], 0)
        self.assertLessEqual(res["heuristic_risk_score"], 100)
        self.assertEqual(res["risk_level"], "critical")

    def test_risk_level_thresholds(self):
        clean_report = analyze_urls("https://www.example.com")
        self.assertEqual(clean_report["results"][0]["risk_level"], "none")

        http_report = analyze_urls("http://www.example.com")
        self.assertEqual(http_report["results"][0]["risk_level"], "low")

    def test_threat_intel_status_is_not_checked(self):
        report = analyze_urls("https://example.com")
        self.assertEqual(report["threat_intel_status"], "not_checked")
        res = report["results"][0]
        self.assertEqual(res["threat_intel"]["verdict"], "not_checked")
        self.assertFalse(res["threat_intel"]["reputation_checked"])

    def test_empty_input_handled_gracefully(self):
        report = analyze_urls([])
        self.assertEqual(report["total_urls_analyzed"], 0)
        self.assertEqual(report["max_risk_score"], 0)
        self.assertEqual(report["overall_url_risk_level"], "none")

    def test_none_input_handled_gracefully(self):
        report = analyze_urls(None)
        self.assertEqual(report["total_urls_analyzed"], 0)
        self.assertTrue(len(report["warnings"]) > 0)

    def test_unexpected_types_handled_gracefully(self):
        report = analyze_urls([12345, None, ""])
        self.assertEqual(report["total_urls_analyzed"], 3)
        self.assertIn(report["results"][0]["analysis_status"], ("error", "malformed"))

    def test_batch_summary_statistics(self):
        urls = [
            "https://www.python.org",
            "http://192.168.1.1/admin",
            "https://bit.ly/invoice"
        ]
        report = analyze_urls(urls)
        self.assertEqual(report["total_urls_analyzed"], 3)
        self.assertEqual(len(report["unique_domains"]), 3)
        self.assertIn("Analyzed 3 URL(s)", report["summary"])
        self.assertGreater(report["max_risk_score"], 0)


class TestIntegrationWithModule1(unittest.TestCase):
    """Test seamless integration with Module 1 parse_email_file output schemas."""

    def test_consume_module1_full_dict_output(self):
        sample_path = os.path.join(os.path.dirname(__file__), "..", "samples", "phishing_sample.eml")
        parsed = parse_email_file(sample_path)
        # Pass the full parsed email dict directly into analyze_urls
        report = analyze_urls(parsed)
        self.assertEqual(report["total_urls_analyzed"], 4)
        self.assertGreater(report["max_risk_score"], 0)
        self.assertIn(report["overall_url_risk_level"], ("medium", "high", "critical"))
        self.assertTrue(report["high_risk_url_count"] >= 0)

    def test_consume_module1_urls_list_directly(self):
        sample_path = os.path.join(os.path.dirname(__file__), "..", "samples", "multipart.eml")
        parsed = parse_email_file(sample_path)
        # Pass the parsed['urls'] list of dicts directly
        report = analyze_urls(parsed["urls"])
        self.assertEqual(report["total_urls_analyzed"], 5)
        # Verify source metadata was preserved
        for res in report["results"]:
            self.assertIn("source_metadata", res)
            self.assertIn("found_in", res["source_metadata"])


class TestNetworkSafetyGuarantees(unittest.TestCase):
    """Verify that URL analysis makes zero socket, HTTP, or DNS calls."""

    @patch("socket.socket")
    @patch("urllib.request.urlopen")
    def test_zero_network_calls_during_analysis(self, mock_urlopen, mock_socket):
        urls = [
            "https://www.google.com",
            "http://paypal-account-verify.totally-not-evil.com/login",
            "https://bit.ly/test",
            "http://192.168.1.1/payload.exe",
            "javascript:alert(1)"
        ]
        report = analyze_urls(urls)
        # Neither socket nor urllib.request.urlopen should have ever been touched
        self.assertFalse(mock_socket.called)
        self.assertFalse(mock_urlopen.called)
        self.assertEqual(report["total_urls_analyzed"], 5)


if __name__ == "__main__":
    unittest.main()
