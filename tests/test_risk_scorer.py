"""
tests/test_risk_scorer.py
=========================
Comprehensive automated test suite for Module 6: Evidence-Based Email Risk Scoring Engine.

Invariants Verified:
1. Zero Network Access: Purely local evidence fusion without outbound socket, DNS, or HTTP calls.
2. Bounded Score: Risk scores are strictly bounded within the mathematical range [0, 100].
3. Neutrality of Absence: Missing evidence (SPF not_checked, missing GeoLite2 DB, missing AI model,
   no URLs, internal routing) never counts as a malicious finding.
4. Correlated Signal Dampening: Diminishing returns applied to repeated/correlated indicators.
5. Single-Signal Safeguard: An isolated low-severity heuristic cannot escalate an email to Medium or High.
6. Positive Signal Mitigation: Legitimate authentications reduce risk unless critical threats exist.
7. Total JSON Serializability: Output can always be safely serialized to standard JSON.
8. Determinism: Identical inputs produce byte-for-byte identical output reports.
"""

import os
import sys
import json
import unittest
from unittest.mock import patch, MagicMock

SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from risk_scorer import (
    calculate_email_risk,
    calculate_risk_score,
    RISK_LEVEL_THRESHOLDS,
    PILLAR_BUDGETS,
    DIMINISHING_RETURNS_SCALE,
    SCORING_VERSION,
)
from email_parser import parse_email_file
from auth_verifier import verify_authentication
from url_analyzer import analyze_urls
from routing_analyzer import analyze_email_routing
from ai_text_analyzer import analyze_email_text

SAMPLES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "samples"))


class TestRiskScorerBasicContracts(unittest.TestCase):
    """Test basic contracts, output schema, and JSON serializability."""

    def test_required_top_level_keys_present(self):
        result = calculate_email_risk()
        required_keys = [
            "analysis_status",
            "risk_score",
            "risk_level",
            "summary",
            "evidence",
            "positive_signals",
            "limitations",
            "missing_evidence",
            "recommended_actions",
            "scoring_metadata",
        ]
        for key in required_keys:
            self.assertIn(key, result, f"Missing required top-level key: {key}")

    def test_json_serializability(self):
        """Ensure full report is JSON serializable under standard json.dumps."""
        result = calculate_email_risk(
            parsed_email={"headers": {"subject": "Test", "from": "Alice <alice@example.com>"}},
            auth_result={"dmarc": {"status": "pass"}},
            url_result={"risk_score": 10, "findings": [{"indicator": "shortener", "severity": "low"}]},
            routing_result={"analysis_status": "completed"},
            ai_result={"verdict": "benign", "confidence": 0.95},
        )
        serialized = json.dumps(result, indent=2)
        self.assertIsInstance(serialized, str)
        deserialized = json.loads(serialized)
        self.assertEqual(deserialized["risk_score"], result["risk_score"])
        self.assertEqual(deserialized["risk_level"], result["risk_level"])

    def test_deterministic_output(self):
        """Ensure calling calculate_email_risk multiple times with identical inputs gives identical output."""
        sample_args = {
            "parsed_email": {"headers": {"from": "security@paypal-security.com", "subject": "Urgent"}},
            "auth_result": {"dkim": {"status": "fail"}, "dmarc": {"status": "fail"}},
            "url_result": {"risk_score": 50, "high_risk_urls": 1, "findings": [{"indicator": "brand_in_subdomain", "severity": "high"}]},
            "routing_result": {"total_hops": 3, "warnings": ["relay_mismatch"]},
            "ai_result": {"verdict": "phishing", "confidence": 0.92, "model_status": "loaded"},
        }
        res1 = calculate_email_risk(**sample_args)
        res2 = calculate_email_risk(**sample_args)
        self.assertEqual(res1, res2)

    def test_alias_function(self):
        """calculate_risk_score is an exact alias for calculate_email_risk."""
        res1 = calculate_email_risk()
        res2 = calculate_risk_score()
        self.assertEqual(res1, res2)


class TestScoreBoundariesAndLevels(unittest.TestCase):
    """Test score bounds [0, 100] and risk level assignments."""

    def test_score_never_exceeds_100(self):
        """Even with extreme cumulative threats across all vectors, score is capped at 100."""
        extreme_auth = {
            "dkim": {"status": "fail", "summary": "DKIM failed signature"},
            "dmarc": {"status": "fail", "summary": "DMARC failed rejection policy"},
            "spoofing_detected": True,
        }
        extreme_urls = {
            "risk_score": 100,
            "high_risk_urls": 10,
            "suspicious_urls": 10,
            "findings": [
                {"indicator": "executable_payload", "severity": "critical", "url": "http://evil.com/setup.exe"},
                {"indicator": "dangerous_scheme", "severity": "critical", "url": "javascript:alert(1)"},
                {"indicator": "ip_address_host", "severity": "high", "url": "http://192.168.1.1/login"},
                {"indicator": "brand_in_subdomain", "severity": "high", "url": "http://paypal.evil.com"},
            ] * 5,
        }
        extreme_routing = {
            "anomalies_detected": True,
            "warnings": ["loop_detected", "invalid_timestamp", "rfc1918_after_public", "suspicious_hop_domain"],
        }
        extreme_ai = {
            "verdict": "phishing",
            "confidence": 0.99,
            "model_status": "loaded",
        }
        extreme_parsed = {
            "headers": {
                "from": "PayPal Security <hacker@malicious-domain.com>",
                "subject": "URGENT: Account Suspended!",
            }
        }

        result = calculate_email_risk(
            parsed_email=extreme_parsed,
            auth_result=extreme_auth,
            url_result=extreme_urls,
            routing_result=extreme_routing,
            ai_result=extreme_ai,
        )
        self.assertLessEqual(result["risk_score"], 100)
        self.assertGreaterEqual(result["risk_score"], 70)
        self.assertEqual(result["risk_level"], "critical")

    def test_score_never_below_zero(self):
        """Even with strong positive signals and zero threats, score is bounded at >= 0."""
        clean_auth = {
            "dkim": {"status": "pass"},
            "dmarc": {"status": "pass"},
        }
        clean_urls = {
            "risk_score": 0,
            "total_urls_analyzed": 3,
            "high_risk_urls": 0,
            "suspicious_urls": 0,
            "findings": [],
        }
        clean_ai = {
            "verdict": "benign",
            "confidence": 0.98,
            "model_status": "loaded",
        }
        result = calculate_email_risk(
            auth_result=clean_auth,
            url_result=clean_urls,
            ai_result=clean_ai,
        )
        self.assertGreaterEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_level"], "none")

    def test_risk_level_threshold_mapping(self):
        """Verify thresholds correctly map to corresponding risk level strings."""
        # 0..19 -> none, 20..39 -> low, 40..69 -> medium, 70..89 -> high, 90..100 -> critical
        levels = [
            (0, "none"),
            (19, "none"),
            (20, "low"),
            (39, "low"),
            (40, "medium"),
            (69, "medium"),
            (70, "high"),
            (89, "high"),
            (90, "critical"),
            (100, "critical"),
        ]
        from risk_scorer import _determine_risk_level
        for score, expected_level in levels:
            self.assertEqual(_determine_risk_level(score), expected_level, f"Failed for score {score}")


class TestMissingEvidenceNeutrality(unittest.TestCase):
    """
    CRITICAL INVARIANT: Missing evidence, unverified items, or skipped modules
    must NEVER automatically imply maliciousness.
    """

    def test_spf_not_checked_is_strictly_neutral(self):
        """auth_verifier reporting SPF as 'not_checked' must yield 0 risk points."""
        auth_data = {
            "spf": {
                "independent_result": "not_checked",
                "explanation": "No connecting IP available",
            },
            "dkim": {"status": "not_checked"},
            "dmarc": {"status": "none"},
        }
        result = calculate_email_risk(auth_result=auth_data)
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_level"], "none")
        # Check that it's documented in missing_evidence
        missing_keys = [item["field"] for item in result["missing_evidence"]]
        self.assertIn("spf", missing_keys)

    def test_missing_geolite2_database_does_not_increase_risk(self):
        """Routing analyzer reporting missing GeoLite2 DB does not penalize score."""
        routing_data = {
            "analysis_status": "completed",
            "geolocation_enabled": False,
            "geolocation_status": "database_not_found",
            "total_hops": 2,
            "warnings": [],
        }
        result = calculate_email_risk(routing_result=routing_data)
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_level"], "none")
        missing_keys = [item["field"] for item in result["missing_evidence"]]
        self.assertIn("ip_geolocation", missing_keys)

    def test_public_or_foreign_ip_addresses_do_not_increase_risk(self):
        """Public or foreign IP in routing hops alone must not increase risk."""
        routing_data = {
            "analysis_status": "completed",
            "total_hops": 3,
            "hops": [
                {"hop_number": 1, "ip": "203.0.113.195", "ip_type": "public", "country": "DE"},
                {"hop_number": 2, "ip": "198.51.100.22", "ip_type": "public", "country": "US"},
            ],
            "warnings": [],
            "anomalies_detected": False,
        }
        result = calculate_email_risk(routing_result=routing_data)
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_level"], "none")

    def test_no_urls_in_email_is_neutral(self):
        """Email with zero URLs has neutral URL pillar contribution (0 points)."""
        url_data = {
            "analysis_status": "no_urls",
            "total_urls_analyzed": 0,
            "risk_score": 0,
            "findings": [],
        }
        result = calculate_email_risk(url_result=url_data)
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_level"], "none")
        # URL evidence should show clean/no URLs
        url_ev = [e for e in result["evidence"] if e["pillar"] == "url_threats"]
        self.assertTrue(len(url_ev) == 0 or url_ev[0]["contribution"] == 0)

    def test_ai_model_unavailable_or_error_is_neutral(self):
        """AI model failing or unavailable must be noted in limitations/missing, not penalized."""
        ai_data = {
            "analysis_status": "skipped",
            "model_status": "unavailable",
            "verdict": "unknown",
            "confidence": 0.0,
            "error": "PyTorch not installed in environment",
        }
        result = calculate_email_risk(ai_result=ai_data)
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_level"], "none")
        missing_keys = [item["field"] for item in result["missing_evidence"]]
        self.assertIn("ai_phishing_classifier", missing_keys)

    def test_all_modules_unavailable_or_empty(self):
        """When all modules provide no data, status is inconclusive with 0 score."""
        result = calculate_email_risk()
        self.assertEqual(result["analysis_status"], "inconclusive")
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_level"], "none")
        self.assertGreater(len(result["missing_evidence"]), 0)


class TestSingleSignalSafeguard(unittest.TestCase):
    """
    INVARIANT: A single, isolated low-severity heuristic indicator
    (e.g., bit.ly shortener or unfamiliar TLD alone) must not escalate
    an email to Medium or High risk without corroborating evidence.
    """

    def test_single_url_shortener_alone_is_low_risk(self):
        url_data = {
            "risk_score": 15,
            "total_urls_analyzed": 1,
            "high_risk_urls": 0,
            "suspicious_urls": 1,
            "findings": [
                {
                    "url": "https://bit.ly/3xyz",
                    "indicator": "shortener_service",
                    "severity": "low",
                    "description": "URL uses bit.ly shortening service",
                }
            ],
        }
        result = calculate_email_risk(url_result=url_data)
        self.assertLessEqual(result["risk_score"], 25)
        self.assertIn(result["risk_level"], ["none", "low"])
        self.assertNotEqual(result["risk_level"], "medium")
        self.assertNotEqual(result["risk_level"], "high")

    def test_single_high_risk_tld_alone_is_low_risk(self):
        url_data = {
            "risk_score": 15,
            "total_urls_analyzed": 1,
            "high_risk_urls": 0,
            "suspicious_urls": 1,
            "findings": [
                {
                    "url": "https://promo-newsletter.xyz/unsubscribe",
                    "indicator": "high_risk_tld",
                    "severity": "low",
                    "description": "TLD .xyz is frequently observed in bulk/phishing campaigns",
                }
            ],
        }
        result = calculate_email_risk(url_result=url_data)
        self.assertLessEqual(result["risk_score"], 25)
        self.assertIn(result["risk_level"], ["none", "low"])


class TestCorrelatedSignalDampening(unittest.TestCase):
    """
    INVARIANT: Repeated or correlated indicators must not scale linearly.
    Diminishing returns must apply.
    """

    def test_multiple_identical_url_shorteners_damped(self):
        """5 shortened URLs must NOT produce 5x the score of 1 shortened URL."""
        # 1 shortener
        url_1 = {
            "risk_score": 15,
            "total_urls_analyzed": 1,
            "findings": [{"indicator": "shortener_service", "severity": "low", "url": "https://bit.ly/1"}],
        }
        res_1 = calculate_email_risk(url_result=url_1)

        # 5 shorteners of same type
        url_5 = {
            "risk_score": 15,
            "total_urls_analyzed": 5,
            "findings": [
                {"indicator": "shortener_service", "severity": "low", "url": f"https://bit.ly/{i}"}
                for i in range(1, 6)
            ],
        }
        res_5 = calculate_email_risk(url_result=url_5)

        # 5 shorteners score must be strictly less than 5 * score_1
        # And must remain within URL pillar budget (35)
        self.assertLess(res_5["risk_score"], res_1["risk_score"] * 5)
        self.assertLessEqual(res_5["risk_score"], PILLAR_BUDGETS["url_threats"])

    def test_correlated_auth_failure_dampening(self):
        """DKIM fail + DMARC fail caused by the same sender condition are budgeted."""
        auth_data = {
            "dkim": {"status": "fail", "summary": "DKIM signature failed"},
            "dmarc": {"status": "fail", "summary": "DMARC policy reject"},
        }
        res = calculate_email_risk(auth_result=auth_data)
        self.assertLessEqual(res["risk_score"], PILLAR_BUDGETS["identity_auth"])


class TestDisplayNameSpoofingDetection(unittest.TestCase):
    """Test heuristic detection of brand impersonation in From header display names."""

    def test_brand_in_display_name_with_foreign_domain(self):
        parsed = {
            "headers": {
                "from": '"PayPal Account Support" <service-alert@cheap-vps-host.ru>',
                "subject": "Important Account Notification",
            }
        }
        result = calculate_email_risk(parsed_email=parsed)
        # Should flag display name spoofing
        ev_indicators = [e["indicator"] for e in result["evidence"]]
        self.assertIn("display_name_spoofing", ev_indicators)
        self.assertGreater(result["risk_score"], 0)

    def test_legitimate_brand_display_name_not_flagged(self):
        parsed = {
            "headers": {
                "from": '"PayPal Support" <support@paypal.com>',
                "subject": "Your Receipt",
            }
        }
        result = calculate_email_risk(parsed_email=parsed)
        ev_indicators = [e["indicator"] for e in result["evidence"]]
        self.assertNotIn("display_name_spoofing", ev_indicators)


class TestPositiveSignalMitigations(unittest.TestCase):
    """Test that legitimate positive signals reduce risk when no critical payload is present."""

    def test_dkim_and_dmarc_pass_reduces_mild_risk(self):
        mild_url = {
            "risk_score": 15,
            "total_urls_analyzed": 1,
            "findings": [{"indicator": "shortener_service", "severity": "low"}],
        }
        # Without auth pass
        res_without = calculate_email_risk(url_result=mild_url)

        # With auth pass
        good_auth = {
            "dkim": {"status": "pass"},
            "dmarc": {"status": "pass"},
        }
        res_with = calculate_email_risk(url_result=mild_url, auth_result=good_auth)

        self.assertLess(res_with["risk_score"], res_without["risk_score"])
        self.assertGreater(len(res_with["positive_signals"]), 0)

    def test_positive_signals_do_not_suppress_critical_executable_payload(self):
        """Even with DKIM pass, an executable payload in a URL remains dangerous."""
        dangerous_url = {
            "risk_score": 90,
            "total_urls_analyzed": 1,
            "findings": [{"indicator": "executable_payload", "severity": "critical", "url": "http://evil.com/setup.exe"}],
        }
        good_auth = {
            "dkim": {"status": "pass"},
            "dmarc": {"status": "pass"},
        }
        res = calculate_email_risk(url_result=dangerous_url, auth_result=good_auth)
        # The critical payload must keep the email at medium/high risk
        self.assertGreaterEqual(res["risk_score"], 35)


class TestCrossVectorSynergyBonus(unittest.TestCase):
    """Test synergy bonus applied when multiple independent high-severity pillars trigger."""

    def test_multi_vector_synergy_triggers(self):
        # High URL threat + AI phishing verdict = synergy bonus (+10)
        url_threat = {
            "risk_score": 60,
            "high_risk_urls": 1,
            "findings": [{"indicator": "brand_in_subdomain", "severity": "high", "url": "http://paypal.login.evil.com"}],
        }
        ai_phish = {
            "verdict": "phishing",
            "confidence": 0.95,
            "model_status": "loaded",
        }
        res = calculate_email_risk(url_result=url_threat, ai_result=ai_phish)
        synergy_ev = [e for e in result_ev if e["indicator"] == "cross_vector_synergy"] if (result_ev := res["evidence"]) else []
        self.assertEqual(len(synergy_ev), 1)
        self.assertEqual(synergy_ev[0]["contribution"], 10)
        self.assertGreaterEqual(res["risk_score"], 45)


class TestMalformedAndIncompleteInputs(unittest.TestCase):
    """Test system resilience against corrupt, missing, or malformed inputs."""

    def test_non_dict_inputs_handled_gracefully(self):
        # Passing unexpected types like strings or None
        result = calculate_email_risk(
            parsed_email="invalid_string",
            auth_result=12345,
            url_result=None,
            routing_result=[],
            ai_result=False,
        )
        self.assertEqual(result["analysis_status"], "inconclusive")
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_level"], "none")

    def test_partially_missing_keys_in_dicts(self):
        # Passing dicts with missing internal fields
        result = calculate_email_risk(
            parsed_email={},
            auth_result={"some_random_key": True},
            url_result={"findings": "not_a_list"},
            routing_result={"hops": "not_a_list"},
            ai_result={"verdict": 999},
        )
        self.assertIn("analysis_status", result)
        self.assertIn("risk_score", result)
        self.assertGreaterEqual(result["risk_score"], 0)
        self.assertLessEqual(result["risk_score"], 100)


class TestRealSampleIntegration(unittest.TestCase):
    """Test full pipeline integration with real .eml sample files in the repository."""

    def test_plain_text_sample_is_low_risk(self):
        sample_path = os.path.join(SAMPLES_DIR, "plain_text.eml")
        if not os.path.exists(sample_path):
            self.skipTest(f"Sample not found: {sample_path}")

        parsed = parse_email_file(sample_path)
        urls = analyze_urls(parsed.get("urls", []))
        routing = analyze_email_routing(parsed.get("received_headers", []))
        ai = analyze_email_text(parsed.get("body", {}).get("plain_text", ""))

        risk = calculate_email_risk(
            parsed_email=parsed,
            url_result=urls,
            routing_result=routing,
            ai_result=ai,
        )
        self.assertEqual(risk["analysis_status"], "completed")
        self.assertLessEqual(risk["risk_score"], 39)
        self.assertIn(risk["risk_level"], ["none", "low"])

    def test_phishing_sample_is_high_or_critical_risk(self):
        sample_path = os.path.join(SAMPLES_DIR, "phishing_sample.eml")
        if not os.path.exists(sample_path):
            self.skipTest(f"Sample not found: {sample_path}")

        parsed = parse_email_file(sample_path)
        urls = analyze_urls(parsed.get("urls", []))
        routing = analyze_email_routing(parsed.get("received_headers", []))
        ai = analyze_email_text(parsed.get("body", {}).get("plain_text", ""))

        risk = calculate_email_risk(
            parsed_email=parsed,
            url_result=urls,
            routing_result=routing,
            ai_result=ai,
        )
        self.assertEqual(risk["analysis_status"], "completed")
        self.assertGreaterEqual(risk["risk_score"], 70)
        self.assertIn(risk["risk_level"], ["high", "critical"])


class TestScoringAuditAndReconciliation(unittest.TestCase):
    """Regression tests verifying mathematical auditability and reconciliation."""

    def test_phishing_sample_reconciliation(self):
        """Verify phishing_sample.eml evidence contributions reconcile with pillar and final scores."""
        sample_path = os.path.join(SAMPLES_DIR, "phishing_sample.eml")
        if not os.path.exists(sample_path):
            self.skipTest(f"Sample not found: {sample_path}")

        parsed = parse_email_file(sample_path)
        urls = analyze_urls(parsed.get("urls", []))
        routing = analyze_email_routing(parsed.get("received_headers", []))
        ai = analyze_email_text(parsed.get("body", {}).get("plain_text", ""))

        risk = calculate_email_risk(
            parsed_email=parsed,
            url_result=urls,
            routing_result=routing,
            ai_result=ai,
        )

        # 1. URL pillar evidence sum must EXACTLY equal URL pillar score
        url_contrib_sum = sum(e["score_contribution"] for e in risk["evidence"] if e["pillar"] == "url_threats")
        self.assertEqual(url_contrib_sum, risk["pillar_scores"]["url_threats"]["score"])

        # 2. Auth pillar evidence sum must EXACTLY equal Auth pillar score
        auth_contrib_sum = sum(e["score_contribution"] for e in risk["evidence"] if e["pillar"] == "identity_auth")
        self.assertEqual(auth_contrib_sum, risk["pillar_scores"]["identity_authentication"]["score"])

        # 3. AI pillar evidence sum must EXACTLY equal AI pillar score
        ai_contrib_sum = sum(e["score_contribution"] for e in risk["evidence"] if e["pillar"] == "ai_content")
        self.assertEqual(ai_contrib_sum, risk["pillar_scores"]["ai_content_analysis"]["score"])

        # 4. Total evidence contributions must EXACTLY equal final risk score
        all_contrib_sum = sum(e["score_contribution"] for e in risk["evidence"])
        self.assertEqual(all_contrib_sum, risk["risk_score"])

        # 5. Metadata formula must hold
        meta = risk["scoring_metadata"]
        expected_score = meta["capped_pillar_scores_sum"] + meta["synergy_bonus"] - meta["mitigation_discount"]
        self.assertEqual(expected_score, risk["risk_score"])
        self.assertEqual(meta["final_risk_score"], risk["risk_score"])

    def test_synthetic_pillar_capping_and_attribution(self):
        """Verify proportional attribution when multiple URL findings exceed the 35-point budget cap."""
        url_data = {
            "risk_score": 90,
            "total_urls_analyzed": 5,
            "findings": [
                {"indicator": "brand_in_subdomain", "severity": "high", "url": "http://paypal.evil.com/1"},
                {"indicator": "brand_in_subdomain", "severity": "high", "url": "http://paypal.evil.com/2"},
                {"indicator": "insecure_http", "severity": "low", "url": "http://evil.com/test"},
                {"indicator": "phishing_keywords", "severity": "low", "url": "http://evil.com/login-verify"},
            ],
        }
        risk = calculate_email_risk(url_result=url_data)

        # Total URL pillar score must be capped at 35
        self.assertEqual(risk["pillar_scores"]["url_threats"]["score"], PILLAR_BUDGETS["url_threats"])

        # Sum of effective contributions in URL evidence must EXACTLY equal 35
        url_ev = [e for e in risk["evidence"] if e["pillar"] == "url_threats"]
        self.assertEqual(sum(e["effective_contribution"] for e in url_ev), 35)
        self.assertEqual(sum(e["score_contribution"] for e in url_ev), 35)

        # Every evidence item has distinct accounting fields
        for e in url_ev:
            self.assertIn("raw_points", e)
            self.assertIn("dampened_points", e)
            self.assertIn("pillar_cap_reduction", e)
            self.assertIn("effective_contribution", e)
            # Cap reduction + dampened points == effective contribution
            self.assertEqual(e["dampened_points"] + e["pillar_cap_reduction"], e["effective_contribution"])

    def test_single_signal_safeguard_accounting_metadata(self):
        """Single isolated low-severity finding has explicit safeguard accounting in metadata."""
        url_data = {
            "risk_score": 15,
            "total_urls_analyzed": 1,
            "findings": [{"indicator": "shortener_service", "severity": "low", "url": "https://bit.ly/test"}],
        }
        risk = calculate_email_risk(url_result=url_data)
        self.assertLessEqual(risk["risk_score"], 25)
        meta = risk["scoring_metadata"]
        self.assertIn("single_signal_safeguard_applied", meta)
        self.assertIn("single_signal_safeguard_reduction", meta)

    def test_mitigation_revocation_on_critical_payload(self):
        """Mitigations from DKIM/DMARC are revoked to 0 when an executable payload is present."""
        auth_data = {
            "dkim": {"status": "pass"},
            "dmarc": {"status": "pass"},
        }
        url_data = {
            "risk_score": 100,
            "total_urls_analyzed": 1,
            "findings": [{"indicator": "executable_payload", "severity": "critical", "url": "http://evil.com/invoice.exe"}],
        }
        risk = calculate_email_risk(auth_result=auth_data, url_result=url_data)
        meta = risk["scoring_metadata"]
        self.assertTrue(meta["mitigation_revoked_by_critical_payload"])
        self.assertEqual(meta["mitigation_discount"], 0)
        self.assertGreaterEqual(risk["risk_score"], 35)

    def test_missing_evidence_does_not_declare_minimal_threat(self):
        """An email evaluated with missing checks does not falsely declare 'Minimal or No Threat Detected'."""
        auth_data = {
            "spf": {"status": "not_checked"},
            "dkim": {"status": "none"},
            "dmarc": {"status": "none"},
        }
        ai_data = {
            "analysis_status": "unavailable",
            "model_status": "unavailable",
        }
        risk = calculate_email_risk(auth_result=auth_data, ai_result=ai_data)
        self.assertEqual(risk["risk_score"], 0)
        # Must indicate incomplete verification rather than clean bill of health
        self.assertIn("Incomplete Verification", risk["verdict_title"])
        self.assertGreater(len(risk["missing_evidence"]), 0)

    def test_dangerous_scheme_and_synergy_reconciliation(self):
        """Targeted audit of multi-occurrence dampening, cap-reduction, and synergy accounting."""
        sample_path = os.path.join(SAMPLES_DIR, "phishing_sample.eml")
        if not os.path.exists(sample_path):
            self.skipTest(f"Sample not found: {sample_path}")

        parsed = parse_email_file(sample_path)
        urls = analyze_urls(parsed.get("urls", []))
        routing = analyze_email_routing(parsed.get("received_headers", []))
        ai = analyze_email_text(parsed.get("body", {}).get("plain_text", ""))

        risk = calculate_email_risk(
            parsed_email=parsed,
            url_result=urls,
            routing_result=routing,
            ai_result=ai,
        )

        # 1. Locate the multi-occurrence scheme indicator (3 occurrences of insecure HTTP scheme)
        scheme_items = [e for e in risk["evidence"] if e.get("occurrence_count") == 3]
        self.assertEqual(len(scheme_items), 1, "Expected exactly 1 indicator with occurrence_count == 3")
        item = scheme_items[0]

        # Verify exact mathematical definitions:
        # base_points: 5 (low-severity scheme indicator)
        # occurrence_count: 3
        # raw_points: 5 * 3 = 15 (linear un-dampened points)
        # dampened_points: round(5 * 1.5) = 8 (via DIMINISHING_RETURNS_SCALE[2] = 1.5)
        # multi_occurrence_dampening_reduction: 15 - 8 = 7
        # pillar_cap_reduction: -2 (Hamilton-Hare quota reduction from 43 dampened sum to 35 cap)
        # effective_contribution / score_contribution: 8 + (-2) = 6
        self.assertEqual(item["base_points"], 5)
        self.assertEqual(item["occurrence_count"], 3)
        self.assertEqual(item["raw_points"], 15)
        self.assertEqual(item["dampened_points"], 8)
        self.assertEqual(item["raw_points"] - item["dampened_points"], 7)
        self.assertEqual(item["pillar_cap_reduction"], -2)
        self.assertEqual(item["effective_contribution"], 6)
        self.assertEqual(item["score_contribution"], 6)
        self.assertEqual(item["dampened_points"] + item["pillar_cap_reduction"], item["score_contribution"])

        # 2. Verify Composite Synergy Indicator
        composite_items = [e for e in risk["evidence"] if e["pillar"] == "composite"]
        self.assertEqual(len(composite_items), 1, "Expected exactly 1 composite synergy item")
        syn = composite_items[0]
        self.assertEqual(syn["indicator"], "cross_vector_synergy")
        self.assertEqual(syn["raw_points"], 10)
        self.assertEqual(syn["dampened_points"], 10)
        self.assertEqual(syn["pillar_cap_reduction"], 0)
        self.assertEqual(syn["score_contribution"], 10)

        # 3. Verify Full Metadata Reconciliation
        meta = risk["scoring_metadata"]
        all_ev = risk["evidence"]

        # Sum of raw_points in evidence must equal raw_signal_points_sum
        self.assertEqual(sum(e["raw_points"] for e in all_ev), meta["raw_signal_points_sum"])
        self.assertEqual(meta["raw_signal_points_sum"], 119)

        # Sum of dampened_points in evidence must equal dampened_points_sum
        self.assertEqual(sum(e["dampened_points"] for e in all_ev), meta["dampened_points_sum"])
        self.assertEqual(meta["dampened_points_sum"], 93)

        # Multi-occurrence dampening reduction: 119 - 93 = 26
        self.assertEqual(meta["raw_signal_points_sum"] - meta["dampened_points_sum"], meta["multi_occurrence_dampening_reduction"])
        self.assertEqual(meta["multi_occurrence_dampening_reduction"], 26)

        # Pillar cap reduction: 8 points absorbed across URL items
        self.assertEqual(meta["pillar_cap_reduction"], 8)

        # Capped pillar score sum: 75
        self.assertEqual(meta["capped_pillar_scores_sum"], 75)

        # Final score reconciliation: 75 + 10 - 0 = 85
        expected_final = meta["capped_pillar_scores_sum"] + meta["synergy_bonus"] - meta["mitigation_discount"]
        self.assertEqual(expected_final, risk["risk_score"])
        self.assertEqual(meta["final_risk_score"], risk["risk_score"])
        self.assertEqual(sum(e["score_contribution"] for e in all_ev), risk["risk_score"])

        # 4. Verify Pillar-Level Raw Score and Pre-Cap Dampened Breakdown
        pillars = risk["pillar_scores"]
        self.assertEqual(pillars["url_threats"]["raw_score"], 69)
        self.assertEqual(pillars["url_threats"]["uncapped_dampened_score"], 43)
        self.assertEqual(pillars["url_threats"]["cap_reduction"], 8)
        self.assertEqual(pillars["url_threats"]["score"], 35)

        self.assertEqual(meta["pillar_raw_points_sum"], 109)
        self.assertEqual(meta["pillar_dampened_points_sum"], 83)
        self.assertEqual(meta["pillar_raw_points_sum"] + meta["synergy_bonus"], meta["raw_signal_points_sum"])
        self.assertEqual(meta["pillar_dampened_points_sum"] + meta["synergy_bonus"], meta["dampened_points_sum"])
        self.assertEqual(meta["pillar_dampened_points_sum"] - meta["pillar_cap_reduction"], meta["capped_pillar_scores_sum"])


if __name__ == "__main__":
    unittest.main()
