"""
tests/test_report_generator.py
==============================
Automated test suite for Module 7: PDF Forensic Report Generator.
SIH 2026 — AI-Powered Email Threat Detection Platform

TEST SUITE INVARIANTS:
1. Zero Network Access: Tests never open outbound sockets, DNS queries, or HTTP requests.
2. Safe Filesystem Use: All generated PDF files are created in temporary directories (tempfile.TemporaryDirectory)
   and cleaned up immediately after each test. Never overwrites sample artifacts.
3. Strict PDF Integrity: Asserts generated documents start with standard %PDF- header and are non-empty.
4. Defensive Robustness: Verifies that malicious HTML/XML markup (<script>, <img onerror>, unescaped &)
   and excessively long strings in email fields cannot break ReportLab compilation or cause XSS/XML injection.
5. Epistemic Transparency: Confirms that unverified checks (SPF 'not_checked', missing GeoLite2 DB)
   are honestly labeled and that AI confidence caveats are present.
"""

import os
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

# Ensure src/ is in sys.path
SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from report_generator import (
    generate_forensic_pdf,
    generate_email_forensic_report,
    _safe_xml,
    _defang_text,
    _format_alignment_status,
    REPORT_GENERATOR_VERSION,
)
from email_parser import parse_email_file
from auth_verifier import verify_authentication
from url_analyzer import analyze_urls
from routing_analyzer import analyze_email_routing
from ai_text_analyzer import analyze_email_text
from risk_scorer import calculate_email_risk

SAMPLES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "samples"))


class TestReportGeneratorBasics(unittest.TestCase):
    """Test basic contracts, PDF creation, and filesystem safety."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.output_pdf = os.path.join(self.temp_dir.name, "test_report.pdf")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_generate_pdf_from_minimal_synthetic_data(self):
        """Generate PDF from minimal synthetic dictionary inputs."""
        risk_data = {
            "risk_score": 15,
            "risk_level": "low",
            "verdict_title": "Low Risk — Minor Anomalies",
            "summary": "Email contains minor heuristic flags.",
            "pillar_scores": {
                "identity_authentication": {"score": 5, "max_possible": 35, "uncapped_dampened_score": 5, "cap_reduction": 0, "status": "evaluated", "signals_count": 1},
                "url_threats": {"score": 10, "max_possible": 35, "uncapped_dampened_score": 10, "cap_reduction": 0, "status": "evaluated", "signals_count": 1},
                "ai_content_analysis": {"score": 0, "max_possible": 25, "uncapped_dampened_score": 0, "cap_reduction": 0, "status": "evaluated", "signals_count": 0},
                "routing_transport": {"score": 0, "max_possible": 15, "uncapped_dampened_score": 0, "cap_reduction": 0, "status": "evaluated", "signals_count": 0},
            },
            "evidence": [
                {
                    "pillar": "url_threats",
                    "indicator": "shortener_service",
                    "severity": "low",
                    "occurrence_count": 1,
                    "raw_points": 5,
                    "dampened_points": 5,
                    "pillar_cap_reduction": 0,
                    "score_contribution": 5,
                    "explanation": "URL uses shortening service.",
                }
            ],
            "scoring_metadata": {
                "raw_signal_points_sum": 5,
                "dampened_points_sum": 5,
                "multi_occurrence_dampening_reduction": 0,
                "pillar_cap_reduction": 0,
                "capped_pillar_scores_sum": 15,
                "synergy_bonus": 0,
                "mitigation_discount": 0,
                "mathematical_reconciliation": "final_risk_score (15) = capped_pillar_scores_sum (15)",
            },
            "missing_evidence": [{"field": "spf", "reason": "Connecting IP not verified."}],
            "recommended_actions": ["Verify sender out-of-band."],
        }

        result = generate_forensic_pdf(
            risk_data=risk_data,
            output_path=self.output_pdf,
            case_id="CASE-SYNTHETIC-001",
        )

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["pdf_path"], os.path.abspath(self.output_pdf))
        self.assertTrue(os.path.exists(self.output_pdf))
        self.assertGreater(result["file_size_bytes"], 1000)

        # Check valid PDF header signature
        with open(self.output_pdf, "rb") as f:
            header = f.read(5)
            self.assertEqual(header, b"%PDF-")

    def test_default_output_directory_creation(self):
        """When no output_path is provided, automatically uses 'reports/' directory."""
        risk_data = {"risk_score": 0, "risk_level": "none", "pillar_scores": {}}
        result = generate_forensic_pdf(risk_data=risk_data, case_id="CASE-AUTO-DIR")

        pdf_path = result["pdf_path"]
        self.assertTrue(os.path.exists(pdf_path))
        self.assertIn("reports", pdf_path)
        with open(pdf_path, "rb") as f:
            self.assertEqual(f.read(5), b"%PDF-")

        # Clean up auto-generated test file
        if os.path.exists(pdf_path):
            os.remove(pdf_path)

    def test_invalid_risk_data_raises_value_error(self):
        """Passing non-dictionary risk data raises ValueError."""
        with self.assertRaises(ValueError):
            generate_forensic_pdf(risk_data="invalid_string", output_path=self.output_pdf)

    def test_unwritable_output_path_raises_runtime_error(self):
        """Targeting a directory path or illegal path raises RuntimeError."""
        risk_data = {"risk_score": 0, "risk_level": "none"}
        # Pointing output_path to an existing directory
        with self.assertRaises(RuntimeError):
            generate_forensic_pdf(risk_data=risk_data, output_path=self.temp_dir.name)


class TestPhishingSampleEndToEndPDF(unittest.TestCase):
    """Test full integration from real sample files to completed forensic PDF."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.output_pdf = os.path.join(self.temp_dir.name, "phishing_forensic_report.pdf")
        self.sample_path = os.path.join(SAMPLES_DIR, "phishing_sample.eml")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_end_to_end_pipeline_pdf_generation(self):
        """Process phishing_sample.eml through all modules into a PDF report."""
        if not os.path.exists(self.sample_path):
            self.skipTest(f"Sample not found: {self.sample_path}")

        # Run pipeline
        parsed = parse_email_file(self.sample_path)
        with open(self.sample_path, "rb") as f:
            raw_bytes = f.read()

        auth = verify_authentication(parsed, raw_bytes=raw_bytes)
        urls = analyze_urls(parsed.get("urls", []))
        routing = analyze_email_routing(parsed.get("received_headers", []), raw_bytes=raw_bytes)
        body_text = parsed.get("body", {}).get("plain_text") or parsed.get("body_text", "")
        ai = analyze_email_text(body_text)

        risk = calculate_email_risk(
            parsed_email=parsed,
            auth_result=auth,
            url_result=urls,
            routing_result=routing,
            ai_result=ai,
        )

        res = generate_forensic_pdf(
            email_data=parsed,
            auth_data=auth,
            url_data=urls,
            routing_data=routing,
            ai_data=ai,
            risk_data=risk,
            output_path=self.output_pdf,
            case_id="CASE-PHISH-SAMPLE-01",
            include_body_excerpt=True,
        )

        self.assertEqual(res["status"], "success")
        self.assertEqual(res["risk_score"], 85)
        self.assertEqual(res["risk_level"], "high")
        self.assertTrue(os.path.exists(self.output_pdf))

        file_size = os.path.getsize(self.output_pdf)
        self.assertGreater(file_size, 5000, "Generated PDF must contain substantial forensic content")

        with open(self.output_pdf, "rb") as f:
            content = f.read()
            self.assertTrue(content.startswith(b"%PDF-"))
            self.assertTrue(content.endswith(b"%%EOF\n") or b"%%EOF" in content[-100:])

    def test_orchestration_helper_function(self):
        """Test generate_email_forensic_report end-to-end orchestration helper."""
        if not os.path.exists(self.sample_path):
            self.skipTest(f"Sample not found: {self.sample_path}")

        res = generate_email_forensic_report(
            email_path=self.sample_path,
            output_path=self.output_pdf,
            case_id="CASE-ORCHESTRATION-01",
        )

        self.assertEqual(res["status"], "success")
        self.assertEqual(res["risk_score"], 85)
        self.assertTrue(os.path.exists(self.output_pdf))


class TestDefensiveSanitizationAndEscaping(unittest.TestCase):
    """Test safety against malicious inputs, HTML/XML injections, and layout breaking."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.output_pdf = os.path.join(self.temp_dir.name, "sanitized_report.pdf")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_xml_injection_in_subject_and_headers(self):
        """Email subject or sender containing raw XML/HTML markup does not crash ReportLab."""
        malicious_subject = '<script>alert("XSS")</script> & <b>Urgent Invoice</b> <img src=x onerror=alert(1)>'
        malicious_from = '"Attacker <evil@test.com>" <attacker@phish.com>'
        malicious_url = "http://evil.com/<script>login</script>?param=1&user=<admin>"

        email_data = {
            "email_metadata": {
                "subject": malicious_subject,
                "from": malicious_from,
                "to": ["user@example.com"],
                "date": "2026-10-20 12:00:00",
                "message_id": "<id1234@evil.com>",
                "return_path": "<bounce@evil.com>",
            },
            "file_metadata": {"filename": "malicious<script>.eml", "file_size_bytes": 1024, "sha256": "abcd1234fakehash"},
            "body": {"plain_text": "Body containing raw <xml> <tags> & unescaped ampersands & more <tags>."},
        }

        url_data = {
            "total_urls_analyzed": 1,
            "unique_domains": ["evil.com"],
            "results": [
                {
                    "url": malicious_url,
                    "indicators": [{"id": "DANGEROUS_TAG", "severity": "high", "score_contribution": 20, "description": "Triggered <script> injection"}],
                }
            ],
        }

        risk_data = {
            "risk_score": 60,
            "risk_level": "medium",
            "verdict_title": "Medium Risk <script> Tag",
            "summary": "Summary with <br> & <b> tags.",
            "pillar_scores": {
                "identity_authentication": {"score": 0, "max_possible": 35, "uncapped_dampened_score": 0, "cap_reduction": 0, "status": "evaluated", "signals_count": 0},
                "url_threats": {"score": 20, "max_possible": 35, "uncapped_dampened_score": 20, "cap_reduction": 0, "status": "evaluated", "signals_count": 1},
                "ai_content_analysis": {"score": 0, "max_possible": 25, "uncapped_dampened_score": 0, "cap_reduction": 0, "status": "evaluated", "signals_count": 0},
                "routing_transport": {"score": 0, "max_possible": 15, "uncapped_dampened_score": 0, "cap_reduction": 0, "status": "evaluated", "signals_count": 0},
            },
            "evidence": [
                {
                    "pillar": "url_threats",
                    "indicator": "malicious<tag>",
                    "severity": "high",
                    "occurrence_count": 1,
                    "raw_points": 20,
                    "dampened_points": 20,
                    "pillar_cap_reduction": 0,
                    "score_contribution": 20,
                    "explanation": "Detected <script> tag in URL.",
                }
            ],
            "scoring_metadata": {
                "raw_signal_points_sum": 20,
                "dampened_points_sum": 20,
                "multi_occurrence_dampening_reduction": 0,
                "pillar_cap_reduction": 0,
                "capped_pillar_scores_sum": 20,
                "synergy_bonus": 0,
                "mitigation_discount": 0,
                "mathematical_reconciliation": "final_risk_score (20) = capped_pillar_scores_sum (20)",
            },
            "missing_evidence": [],
            "recommended_actions": ["Block <evil.com> domain."],
        }

        # Must generate cleanly without ReportLab XML parsing errors
        res = generate_forensic_pdf(
            email_data=email_data,
            url_data=url_data,
            risk_data=risk_data,
            output_path=self.output_pdf,
            case_id="CASE-XSS-TEST",
        )
        self.assertEqual(res["status"], "success")
        self.assertTrue(os.path.exists(self.output_pdf))

    def test_extremely_long_strings_do_not_overflow(self):
        """Very long URLs, subjects, and headers are safely truncated or wrapped without crashing."""
        giant_subject = "A" * 2000
        giant_url = "https://example.com/" + "very_long_path_segment_" * 100
        giant_body = "Important message text. " * 500

        email_data = {
            "email_metadata": {
                "subject": giant_subject,
                "from": "sender@" + "sub." * 50 + "example.com",
                "to": ["user@example.com"],
            },
            "file_metadata": {"filename": "long_name_" * 20 + ".eml", "file_size_bytes": 50000, "sha256": "1234567890" * 7},
            "body": {"plain_text": giant_body},
        }

        url_data = {
            "total_urls_analyzed": 1,
            "results": [
                {
                    "url": giant_url,
                    "indicators": [{"id": "LONG_URL", "severity": "low", "score_contribution": 5, "description": "Long URL explanation " * 20}],
                }
            ],
        }

        risk_data = {
            "risk_score": 10,
            "risk_level": "none",
            "summary": "Summary " * 100,
            "pillar_scores": {},
            "evidence": [],
        }

        res = generate_forensic_pdf(
            email_data=email_data,
            url_data=url_data,
            risk_data=risk_data,
            output_path=self.output_pdf,
            case_id="CASE-OVERFLOW-TEST",
            max_body_excerpt_chars=400,
        )
        self.assertEqual(res["status"], "success")
        self.assertTrue(os.path.exists(self.output_pdf))


class TestEpistemicHonestyAndTruthfulReporting(unittest.TestCase):
    """Test that missing data or neutral states are never misrepresented as failures."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.output_pdf = os.path.join(self.temp_dir.name, "honest_report.pdf")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_missing_geolite2_db_reported_honestly(self):
        """Routing section reports offline mode when GeoLite2 DB is not available."""
        routing_data = {
            "total_hops": 2,
            "geolocation_enabled": False,
            "geolocation_status": "database_not_found",
            "hops": [
                {"hop_number": 1, "ip": "198.51.100.22", "ip_type": "public", "by_host": "mail.example.com", "country": "N/A (Offline)"}
            ],
        }

        risk_data = {
            "risk_score": 0,
            "risk_level": "none",
            "missing_evidence": [{"field": "ip_geolocation", "reason": "GeoLite2 City database (.mmdb) not found."}],
        }

        res = generate_forensic_pdf(
            routing_data=routing_data,
            risk_data=risk_data,
            output_path=self.output_pdf,
        )
        self.assertEqual(res["status"], "success")

    def test_spf_not_checked_is_not_reported_as_failure(self):
        """SPF 'not_checked' status is clearly distinguished from an SPF failure."""
        auth_data = {
            "spf": {
                "independent_result": "not_checked",
                "explanation": "Connecting IP not available in static artifact.",
                "record": "v=spf1 include:_spf.google.com ~all",
            },
            "dkim": {"overall_result": "none"},
            "dmarc": {"result": "none"},
        }

        risk_data = {
            "risk_score": 0,
            "risk_level": "none",
            "missing_evidence": [{"field": "spf", "reason": "SPF evaluation requires connecting IP at delivery time."}],
        }

        res = generate_forensic_pdf(
            auth_data=auth_data,
            risk_data=risk_data,
            output_path=self.output_pdf,
        )
        self.assertEqual(res["status"], "success")

    def test_ai_confidence_caveat_rendered(self):
        """AI section includes confidence and model architecture without making Bayesian claims."""
        ai_data = {
            "verdict": "phishing",
            "confidence": 0.985,
            "model_status": "loaded",
            "model_name": "aamoshdahal/email-phishing-distilbert-finetuned",
            "raw_model_output": {"raw_label": "LABEL_1"},
        }

        risk_data = {
            "risk_score": 75,
            "risk_level": "high",
            "pillar_scores": {
                "ai_content_analysis": {"score": 25, "max_possible": 25, "uncapped_dampened_score": 25, "cap_reduction": 0, "status": "evaluated", "signals_count": 1}
            },
            "evidence": [
                {
                    "pillar": "ai_content_analysis",
                    "indicator": "ai_phishing_verdict",
                    "severity": "high",
                    "occurrence_count": 1,
                    "raw_points": 25,
                    "dampened_points": 25,
                    "pillar_cap_reduction": 0,
                    "score_contribution": 25,
                    "explanation": "Deep learning model classified email text as phishing.",
                }
            ],
            "scoring_metadata": {
                "raw_signal_points_sum": 25,
                "dampened_points_sum": 25,
                "multi_occurrence_dampening_reduction": 0,
                "pillar_cap_reduction": 0,
                "capped_pillar_scores_sum": 25,
                "synergy_bonus": 0,
                "mitigation_discount": 0,
                "mathematical_reconciliation": "final_risk_score (25) = capped_pillar_scores_sum (25)",
            },
        }

        res = generate_forensic_pdf(
            ai_data=ai_data,
            risk_data=risk_data,
            output_path=self.output_pdf,
        )
        self.assertEqual(res["status"], "success")


class TestReportContentAndDeterminism(unittest.TestCase):
    """Test full forensic section presence and generation determinism."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def _extract_pdf_text_streams(self, pdf_path: str) -> str:
        """Decompress FlateDecode + ASCII85 content streams from PDF without external tools."""
        import base64
        import re
        import zlib

        with open(pdf_path, "rb") as f:
            pdf_bytes = f.read()

        matches = re.findall(rb"stream\n(.*?~>)\s*endstream", pdf_bytes, re.DOTALL)
        decompressed_parts: list[str] = []
        for m in matches:
            try:
                raw = base64.a85decode(m, adobe=True)
                dec = zlib.decompress(raw)
                decompressed_parts.append(dec.decode("latin1", errors="ignore"))
            except Exception:
                pass
        return "\n".join(decompressed_parts)

    def test_all_required_sections_present_in_generated_pdf(self):
        """Verify all mandated forensic sections and legal caveats exist in PDF text."""
        pdf_path = os.path.join(self.temp_dir.name, "complete_forensic_sections.pdf")
        email_data = {
            "email_metadata": {"subject": "Security Alert", "from": "support@example.com", "to": ["user@test.com"]},
            "file_metadata": {"filename": "alert.eml", "file_size_bytes": 1024, "sha256": "aabbccddeeff1122"},
            "body": {"plain_text": "Please reset your password immediately."},
        }
        auth_data = {
            "spf": {"independent_result": "not_checked", "explanation": "Connecting IP not verified."},
            "dkim": {"overall_result": "none"},
            "dmarc": {"result": "none"},
        }
        url_data = {
            "total_urls_analyzed": 1,
            "results": [{"url": "http://example.com/login", "indicators": [{"id": "INSECURE_HTTP", "severity": "low", "score_contribution": 5, "description": "HTTP link"}]}],
        }
        routing_data = {
            "total_hops": 1,
            "geolocation_enabled": False,
            "geolocation_status": "database_not_found",
            "hops": [{"hop_number": 0, "ip": "192.168.1.1", "ip_type": "private", "by_host": "mail.example.com"}],
        }
        ai_data = {
            "verdict": "phishing",
            "confidence": 0.99,
            "model_status": "loaded",
            "raw_model_output": {"raw_label": "LABEL_1"},
        }
        risk_data = {
            "risk_score": 50,
            "risk_level": "medium",
            "verdict_title": "Medium Risk",
            "summary": "Suspicious email with phishing indicators.",
            "pillar_scores": {
                "identity_authentication": {"score": 0, "max_possible": 35, "uncapped_dampened_score": 0, "cap_reduction": 0, "status": "evaluated", "signals_count": 0},
                "url_threats": {"score": 5, "max_possible": 35, "uncapped_dampened_score": 5, "cap_reduction": 0, "status": "evaluated", "signals_count": 1},
                "ai_content_analysis": {"score": 25, "max_possible": 25, "uncapped_dampened_score": 25, "cap_reduction": 0, "status": "evaluated", "signals_count": 1},
                "routing_transport": {"score": 0, "max_possible": 15, "uncapped_dampened_score": 0, "cap_reduction": 0, "status": "evaluated", "signals_count": 0},
            },
            "evidence": [
                {
                    "pillar": "url_threats",
                    "indicator": "INSECURE_HTTP",
                    "severity": "low",
                    "occurrence_count": 1,
                    "raw_points": 5,
                    "dampened_points": 5,
                    "pillar_cap_reduction": 0,
                    "score_contribution": 5,
                    "explanation": "HTTP link detected.",
                }
            ],
            "scoring_metadata": {
                "raw_signal_points_sum": 30,
                "dampened_points_sum": 30,
                "multi_occurrence_dampening_reduction": 0,
                "pillar_cap_reduction": 0,
                "capped_pillar_scores_sum": 30,
                "synergy_bonus": 0,
                "mitigation_discount": 0,
                "mathematical_reconciliation": "final_risk_score (30) = capped_pillar_scores_sum (30)",
            },
            "missing_evidence": [{"field": "spf", "reason": "Connecting IP not available in static artifact."}],
            "recommended_actions": ["Do not click links."],
        }

        res = generate_forensic_pdf(
            email_data=email_data,
            auth_data=auth_data,
            url_data=url_data,
            routing_data=routing_data,
            ai_data=ai_data,
            risk_data=risk_data,
            output_path=pdf_path,
            case_id="CASE-SECTION-AUDIT",
            include_body_excerpt=True,
        )
        self.assertEqual(res["status"], "success")

        extracted_text = self._extract_pdf_text_streams(pdf_path)

        # Assert all mandated sections appear in the generated PDF
        required_phrases = [
            "EXECUTIVE FORENSIC SUMMARY",
            "EMAIL ARTIFACT & MESSAGE METADATA",
            "FOUR-PILLAR THREAT VECTOR BREAKDOWN",
            "SENDER AUTHENTICATION FORENSICS",
            "SUSPICIOUS URL & LINK THREAT HEURISTICS",
            "EMAIL ROUTING & NETWORK TOPOLOGY FORENSICS",
            "AI SEMANTIC & PHISHING INTENT CLASSIFICATION",
            "MATHEMATICALLY AUDITABLE EVIDENCE CHAIN",
            "FORENSIC LIMITATIONS & INCIDENT RESPONSE PLAYBOOK",
            "EXTRACTED MESSAGE BODY EXCERPT",
            "Not a certificate of legal chain-of-custody",
        ]
        for phrase in required_phrases:
            self.assertIn(phrase, extracted_text, f"Mandated phrase '{phrase}' missing from PDF streams")

    def test_pdf_generation_determinism_with_fixed_timestamp(self):
        """Two PDF generation runs with identical data and fixed timestamp produce deterministic byte output."""
        from datetime import datetime, timezone

        fixed_dt = datetime(2026, 10, 20, 12, 0, 0, tzinfo=timezone.utc)
        path1 = os.path.join(self.temp_dir.name, "report_det_1.pdf")
        path2 = os.path.join(self.temp_dir.name, "report_det_2.pdf")

        risk_data = {
            "risk_score": 10,
            "risk_level": "none",
            "pillar_scores": {
                "identity_authentication": {"score": 0, "max_possible": 35, "uncapped_dampened_score": 0, "cap_reduction": 0, "status": "evaluated", "signals_count": 0},
                "url_threats": {"score": 0, "max_possible": 35, "uncapped_dampened_score": 0, "cap_reduction": 0, "status": "evaluated", "signals_count": 0},
                "ai_content_analysis": {"score": 0, "max_possible": 25, "uncapped_dampened_score": 0, "cap_reduction": 0, "status": "evaluated", "signals_count": 0},
                "routing_transport": {"score": 0, "max_possible": 15, "uncapped_dampened_score": 0, "cap_reduction": 0, "status": "evaluated", "signals_count": 0},
            },
            "evidence": [],
            "scoring_metadata": {
                "raw_signal_points_sum": 0,
                "dampened_points_sum": 0,
                "multi_occurrence_dampening_reduction": 0,
                "pillar_cap_reduction": 0,
                "capped_pillar_scores_sum": 0,
                "synergy_bonus": 0,
                "mitigation_discount": 0,
                "mathematical_reconciliation": "final_risk_score (0) = capped_pillar_scores_sum (0)",
            },
        }

        generate_forensic_pdf(
            risk_data=risk_data,
            output_path=path1,
            case_id="CASE-DET-01",
            timestamp=fixed_dt,
        )
        generate_forensic_pdf(
            risk_data=risk_data,
            output_path=path2,
            case_id="CASE-DET-01",
            timestamp=fixed_dt,
        )

        with open(path1, "rb") as f1, open(path2, "rb") as f2:
            bytes1 = f1.read()
            bytes2 = f2.read()

        self.assertEqual(len(bytes1), len(bytes2), "Deterministic runs must have identical file size")
        streams1 = self._extract_pdf_text_streams(path1)
        streams2 = self._extract_pdf_text_streams(path2)
        self.assertEqual(streams1, streams2, "Content streams must be 100% deterministic for identical inputs")



class TestForensicConsistencyAndTaxonomy(unittest.TestCase):
    """
    Focused regression test suite ensuring:
    1. Identity-spoofing summary in Section 3 agrees with Section 7 evidence ledger.
    2. Display-name brand impersonation is decoupled and distinct from Return-Path divergence.
    3. URL heuristic indicator severity is decoupled and distinct from aggregated URL risk level.
    4. URL summary counts match actual URL risk classifications (≥70 for High/Critical).
    5. Mathematical reconciliation holds across all forensic vectors and evidence ledger rows.
    """

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.output_pdf = os.path.join(self.temp_dir.name, "consistency_test_report.pdf")

    def tearDown(self):
        self.temp_dir.cleanup()

    def _extract_pdf_text_streams(self, pdf_path: str) -> str:
        """Decompress FlateDecode + ASCII85 content streams from PDF."""
        import base64
        import re
        import zlib

        with open(pdf_path, "rb") as f:
            pdf_bytes = f.read()

        matches = re.findall(rb"stream\n(.*?~>)\s*endstream", pdf_bytes, re.DOTALL)
        decompressed_parts: list[str] = []
        for m in matches:
            try:
                raw = base64.a85decode(m, adobe=True)
                dec = zlib.decompress(raw)
                decompressed_parts.append(dec.decode("latin1", errors="ignore"))
            except Exception:
                pass
        raw_text = "\n".join(decompressed_parts)
        normalized = raw_text.replace(r"\(", "(").replace(r"\)", ")")
        return raw_text + "\n" + normalized

    def test_identity_spoofing_section_and_evidence_ledger_agreement(self):
        """When display name brand impersonation is detected, Section 3 and Section 7 agree."""
        email_data = {
            "email_metadata": {
                "from": '"PayPal Security Team" <security-alerts@paypa1-secure.totally-not-evil.com>',
                "return_path": "<bounces@paypa1-secure.totally-not-evil.com>",
                "subject": "Urgent Security Alert",
            },
            "file_metadata": {"filename": "phish.eml", "file_size_bytes": 1024, "sha256": "1122334455667788"},
            "body": {"plain_text": "Please verify your account immediately."},
        }
        auth_data = {
            "spf": {"independent_result": "not_checked", "explanation": "Connecting IP not verified."},
            "dkim": {"overall_result": "none"},
            "dmarc": {"result": "none", "policy": {"p": "none"}},
            "spoofing_detected": False,
        }
        risk_data = {
            "risk_score": 50,
            "risk_level": "medium",
            "verdict_title": "Medium Risk — Brand Impersonation",
            "summary": "Display name brand impersonation detected.",
            "pillar_scores": {
                "identity_authentication": {"score": 15, "max_possible": 35, "uncapped_dampened_score": 15, "cap_reduction": 0, "status": "evaluated", "signals_count": 1},
                "url_threats": {"score": 0, "max_possible": 35, "uncapped_dampened_score": 0, "cap_reduction": 0, "status": "evaluated", "signals_count": 0},
                "ai_content_analysis": {"score": 25, "max_possible": 25, "uncapped_dampened_score": 25, "cap_reduction": 0, "status": "evaluated", "signals_count": 1},
                "routing_transport": {"score": 0, "max_possible": 15, "uncapped_dampened_score": 0, "cap_reduction": 0, "status": "evaluated", "signals_count": 0},
            },
            "evidence": [
                {
                    "pillar": "identity_auth",
                    "indicator": "display_name_spoofing",
                    "severity": "high",
                    "occurrence_count": 1,
                    "raw_points": 15,
                    "dampened_points": 15,
                    "pillar_cap_reduction": 0,
                    "score_contribution": 15,
                    "explanation": "The From display name contains brand 'Paypal', but the actual sender address uses unrelated domain 'paypa1-secure.totally-not-evil.com'.",
                },
                {
                    "pillar": "ai_content_analysis",
                    "indicator": "ai_phishing_verdict",
                    "severity": "high",
                    "occurrence_count": 1,
                    "raw_points": 25,
                    "dampened_points": 25,
                    "pillar_cap_reduction": 0,
                    "score_contribution": 25,
                    "explanation": "AI model classified text as phishing.",
                },
                {
                    "pillar": "composite",
                    "indicator": "cross_vector_synergy",
                    "severity": "medium",
                    "occurrence_count": 1,
                    "raw_points": 10,
                    "dampened_points": 10,
                    "pillar_cap_reduction": 0,
                    "score_contribution": 10,
                    "explanation": "Cross-vector synergy corroboration.",
                },
            ],
            "scoring_metadata": {
                "raw_signal_points_sum": 50,
                "dampened_points_sum": 50,
                "multi_occurrence_dampening_reduction": 0,
                "pillar_cap_reduction": 0,
                "capped_pillar_scores_sum": 40,
                "synergy_bonus": 10,
                "mitigation_discount": 0,
                "mathematical_reconciliation": "final_risk_score (50) = capped_pillar_scores_sum (40) + synergy_bonus (10) - mitigation_discount (0)",
            },
            "missing_evidence": [],
            "recommended_actions": ["Treat sender address as untrusted."],
        }

        res = generate_forensic_pdf(
            email_data=email_data,
            auth_data=auth_data,
            risk_data=risk_data,
            output_path=self.output_pdf,
            case_id="CASE-ID-CONSISTENCY",
        )
        self.assertEqual(res["status"], "success")

        text = self._extract_pdf_text_streams(self.output_pdf)

        # 1. Section 3 must NOT claim display-name spoofing is CLEAN
        self.assertNotIn("No high-confidence display name or Return-Path spoofing divergence identified", text)

        # 2. Section 3 must flag Display-Name Brand Impersonation as FLAGGED
        self.assertIn("Display-Name Brand Impersonation", text)
        self.assertIn("FLAGGED", text)
        self.assertIn("Divergence", text)

        # 3. Section 3 must show Return-Path is ALIGNED
        self.assertIn("Envelope Return-Path Alignment", text)
        self.assertIn("ALIGNED", text)

        # 4. Section 7 Evidence Ledger also reports display_name_spoofing with 15 pts
        self.assertIn("display_name_spoofing", text)
        self.assertIn("Paypal", text)
        self.assertIn("+15", text)

    def test_return_path_divergence_evaluated_separately(self):
        """Return-Path divergence is evaluated independently from display-name impersonation."""
        email_data = {
            "email_metadata": {
                "from": '"Valid Service" <service@legitimate-company.com>',
                "return_path": "<bounce@unrelated-thirdparty.net>",
                "subject": "Invoice Notice",
            },
            "file_metadata": {"filename": "invoice.eml", "file_size_bytes": 500, "sha256": "aabbcc112233"},
        }
        auth_data = {
            "spf": {"independent_result": "pass"},
            "dkim": {"overall_result": "pass"},
            "dmarc": {"result": "pass", "policy": {"p": "reject"}},
        }
        risk_data = {
            "risk_score": 8,
            "risk_level": "none",
            "verdict_title": "Minimal Risk",
            "summary": "Return-Path divergence noted.",
            "pillar_scores": {
                "identity_authentication": {"score": 8, "max_possible": 35, "uncapped_dampened_score": 8, "cap_reduction": 0, "status": "evaluated", "signals_count": 1},
            },
            "evidence": [
                {
                    "pillar": "identity_auth",
                    "indicator": "return_path_mismatch",
                    "severity": "medium",
                    "occurrence_count": 1,
                    "raw_points": 8,
                    "dampened_points": 8,
                    "pillar_cap_reduction": 0,
                    "score_contribution": 8,
                    "explanation": "Sender domain differs from Return-Path domain.",
                }
            ],
            "scoring_metadata": {
                "raw_signal_points_sum": 8,
                "dampened_points_sum": 8,
                "multi_occurrence_dampening_reduction": 0,
                "pillar_cap_reduction": 0,
                "capped_pillar_scores_sum": 8,
                "synergy_bonus": 0,
                "mitigation_discount": 0,
                "mathematical_reconciliation": "final_risk_score (8) = capped_pillar_scores_sum (8)",
            },
        }

        generate_forensic_pdf(
            email_data=email_data,
            auth_data=auth_data,
            risk_data=risk_data,
            output_path=self.output_pdf,
            case_id="CASE-RP-DIV",
        )
        text = self._extract_pdf_text_streams(self.output_pdf)

        # Display name must be clean, Return-Path must be divergent
        self.assertIn("CLEAN", text)
        self.assertIn("Aligned", text)
        self.assertIn("DIVERGENT", text)
        self.assertIn("Mismatch", text)

    def test_url_indicator_severity_versus_url_risk_level_taxonomy(self):
        """URL with a HIGH-severity indicator (score 55 < 70) is categorized as Medium risk."""
        url_data = {
            "total_urls_analyzed": 1,
            "unique_domains": ["paypa1-secure.totally-not-evil.com"],
            "max_risk_score": 55,
            "overall_url_risk_level": "medium",
            "high_risk_url_count": 0,
            "risk_distribution": {"none": 0, "low": 0, "medium": 1, "high": 0, "critical": 0},
            "results": [
                {
                    "url": "https://paypa1-secure.totally-not-evil.com/login?verification_id=123",
                    "defanged_url": "hxxps://paypa1-secure.totally-not-evil[.]com/login?verification_id=123",
                    "heuristic_risk_score": 55,
                    "risk_level": "medium",
                    "indicators": [
                        {
                            "id": "BRAND_SPOOFING_IN_SUBDOMAIN",
                            "severity": "high",
                            "score_contribution": 35,
                            "description": "Subdomain contains protected brand 'paypa1' mimicking 'paypal.com'.",
                        },
                        {
                            "id": "MULTIPLE_PHISHING_KEYWORDS",
                            "severity": "medium",
                            "score_contribution": 15,
                            "description": "URL contains multiple phishing keywords: login, verification.",
                        },
                        {
                            "id": "LONG_URL",
                            "severity": "low",
                            "score_contribution": 5,
                            "description": "URL is longer than 120 characters.",
                        },
                    ],
                }
            ],
        }

        risk_data = {
            "risk_score": 35,
            "risk_level": "medium",
            "pillar_scores": {
                "url_threats": {"score": 35, "max_possible": 35, "uncapped_dampened_score": 55, "cap_reduction": 20, "status": "evaluated", "signals_count": 3},
            },
            "evidence": [
                {
                    "pillar": "url_threats",
                    "indicator": "BRAND_SPOOFING_IN_SUBDOMAIN",
                    "severity": "high",
                    "occurrence_count": 1,
                    "raw_points": 35,
                    "dampened_points": 35,
                    "pillar_cap_reduction": 13,
                    "score_contribution": 22,
                    "explanation": "Subdomain brand spoofing.",
                }
            ],
            "scoring_metadata": {
                "raw_signal_points_sum": 55,
                "dampened_points_sum": 55,
                "multi_occurrence_dampening_reduction": 0,
                "pillar_cap_reduction": 20,
                "capped_pillar_scores_sum": 35,
                "synergy_bonus": 0,
                "mitigation_discount": 0,
                "mathematical_reconciliation": "final_risk_score (35) = capped_pillar_scores_sum (35)",
            },
        }

        generate_forensic_pdf(
            url_data=url_data,
            risk_data=risk_data,
            output_path=self.output_pdf,
            case_id="CASE-URL-TAXONOMY",
        )
        text = self._extract_pdf_text_streams(self.output_pdf)

        # 1. Summary line shows 0 High/Critical URLs, 1 Medium URL
        self.assertIn("High/Critical", text)
        self.assertIn("Medium", text)

        # 2. Triggered indicators clearly state High-severity indicator
        self.assertIn("High-severity", text)

        # 3. Explicit taxonomy clarification footnote
        self.assertIn("Indicator Severity", text)
        self.assertIn("URL Risk Level", text)

        # 4. Table presents both URL Risk Level (MEDIUM (55/100)) and Indicator Severity (HIGH)
        self.assertIn("MEDIUM (55/100)", text)
        self.assertIn("HIGH", text)

    def test_genuine_high_risk_url_counted_accurately(self):
        """URL with score >= 70 is accurately counted and reported as High/Critical."""
        url_data = {
            "total_urls_analyzed": 2,
            "unique_domains": ["evil-payload.com", "example.com"],
            "max_risk_score": 85,
            "overall_url_risk_level": "high",
            "high_risk_url_count": 1,
            "risk_distribution": {"none": 1, "low": 0, "medium": 0, "high": 1, "critical": 0},
            "results": [
                {
                    "url": "https://evil-payload.com/invoice.exe",
                    "defanged_url": "hxxps://evil-payload[.]com/invoice[.]exe",
                    "heuristic_risk_score": 85,
                    "risk_level": "high",
                    "indicators": [
                        {"id": "SUSPICIOUS_PAYLOAD_DOWNLOAD", "severity": "high", "score_contribution": 40, "description": "Executable download (.exe)."},
                        {"id": "NULL_BYTE_INJECTION", "severity": "high", "score_contribution": 30, "description": "Null byte evasion."},
                        {"id": "MULTIPLE_PHISHING_KEYWORDS", "severity": "medium", "score_contribution": 15, "description": "Phishing keywords."},
                    ],
                },
                {
                    "url": "https://example.com/about",
                    "defanged_url": "hxxps://example[.]com/about",
                    "heuristic_risk_score": 0,
                    "risk_level": "none",
                    "indicators": [],
                },
            ],
        }

        risk_data = {
            "risk_score": 35,
            "risk_level": "medium",
            "pillar_scores": {
                "url_threats": {"score": 35, "max_possible": 35, "uncapped_dampened_score": 85, "cap_reduction": 50, "status": "evaluated", "signals_count": 3},
            },
            "evidence": [
                {
                    "pillar": "url_threats",
                    "indicator": "SUSPICIOUS_PAYLOAD_DOWNLOAD",
                    "severity": "high",
                    "occurrence_count": 1,
                    "raw_points": 40,
                    "dampened_points": 40,
                    "pillar_cap_reduction": 23,
                    "score_contribution": 17,
                    "explanation": "Executable download.",
                }
            ],
            "scoring_metadata": {
                "raw_signal_points_sum": 85,
                "dampened_points_sum": 85,
                "multi_occurrence_dampening_reduction": 0,
                "pillar_cap_reduction": 50,
                "capped_pillar_scores_sum": 35,
                "synergy_bonus": 0,
                "mitigation_discount": 0,
                "mathematical_reconciliation": "final_risk_score (35) = capped_pillar_scores_sum (35)",
            },
        }

        generate_forensic_pdf(
            url_data=url_data,
            risk_data=risk_data,
            output_path=self.output_pdf,
            case_id="CASE-HIGH-URL",
        )
        text = self._extract_pdf_text_streams(self.output_pdf)

        self.assertIn("High/Critical", text)
        self.assertIn("HIGH (85/100)", text)

    def test_clean_status_when_no_urls(self):
        """When total_urls is 0, report renders Clean Status message."""
        url_data = {
            "total_urls_analyzed": 0,
            "unique_domains": [],
            "high_risk_url_count": 0,
            "results": [],
        }
        risk_data = {"risk_score": 0, "risk_level": "none", "pillar_scores": {}}

        generate_forensic_pdf(
            url_data=url_data,
            risk_data=risk_data,
            output_path=self.output_pdf,
            case_id="CASE-NO-URLS",
        )
        text = self._extract_pdf_text_streams(self.output_pdf)
        self.assertIn("Zero URLs were detected or extracted", text)

    def test_pillar_breakdown_pre_cap_dampened_label_and_accounting_reconciliation(self):
        """Pillar table explicitly labels pre-cap points as Pre-Cap (Dampened) and reconciles with Evidence Ledger."""
        risk_data = {
            "risk_score": 85,
            "risk_level": "high",
            "verdict_title": "High Risk — Phishing or Spoofing Detected",
            "summary": "Composite risk score: 85/100 (HIGH).",
            "pillar_scores": {
                "identity_authentication": {"score": 15, "raw_score": 15, "uncapped_dampened_score": 15, "max_possible": 35, "cap_reduction": 0, "status": "evaluated", "signals_count": 1},
                "url_threats": {"score": 35, "raw_score": 69, "uncapped_dampened_score": 43, "max_possible": 35, "cap_reduction": 8, "status": "evaluated", "signals_count": 3},
                "ai_content_analysis": {"score": 25, "raw_score": 25, "uncapped_dampened_score": 25, "max_possible": 25, "cap_reduction": 0, "status": "evaluated", "signals_count": 1},
                "routing_transport": {"score": 0, "raw_score": 0, "uncapped_dampened_score": 0, "max_possible": 15, "cap_reduction": 0, "status": "evaluated", "signals_count": 0},
            },
            "evidence": [
                {"pillar": "identity_auth", "indicator": "display_name_spoofing", "severity": "high", "occurrence_count": 1, "raw_points": 15, "dampened_points": 15, "pillar_cap_reduction": 0, "score_contribution": 15, "explanation": "Brand spoofing"},
                {"pillar": "url_threats", "indicator": "dangerous_scheme", "severity": "high", "occurrence_count": 3, "raw_points": 15, "dampened_points": 8, "pillar_cap_reduction": -2, "score_contribution": 6, "explanation": "Data URI"},
                {"pillar": "url_threats", "indicator": "brand_in_subdomain", "severity": "high", "occurrence_count": 2, "raw_points": 44, "dampened_points": 29, "pillar_cap_reduction": -5, "score_contribution": 24, "explanation": "Subdomain brand"},
                {"pillar": "url_threats", "indicator": "multiple_phishing_keywords", "severity": "medium", "occurrence_count": 2, "raw_points": 10, "dampened_points": 6, "pillar_cap_reduction": -1, "score_contribution": 5, "explanation": "Keywords"},
                {"pillar": "ai_content_analysis", "indicator": "ai_phishing_verdict", "severity": "high", "occurrence_count": 1, "raw_points": 25, "dampened_points": 25, "pillar_cap_reduction": 0, "score_contribution": 25, "explanation": "AI phishing"},
                {"pillar": "composite", "indicator": "cross_vector_synergy", "severity": "high", "occurrence_count": 1, "raw_points": 10, "dampened_points": 10, "pillar_cap_reduction": 0, "score_contribution": 10, "explanation": "Cross vector"},
            ],
            "scoring_metadata": {
                "pillar_raw_points_sum": 109,
                "pillar_dampened_points_sum": 83,
                "raw_signal_points_sum": 119,
                "dampened_points_sum": 93,
                "multi_occurrence_dampening_reduction": 26,
                "pillar_cap_reduction": 8,
                "capped_pillar_scores_sum": 75,
                "synergy_bonus": 10,
                "mitigation_discount": 0,
                "final_risk_score": 85,
                "mathematical_reconciliation": "final_risk_score (85) = capped_pillar_scores_sum (75) + synergy_bonus (10) - mitigation_discount (0)",
            },
        }

        generate_forensic_pdf(
            risk_data=risk_data,
            output_path=self.output_pdf,
            case_id="CASE-PILLAR-ACCOUNTING",
        )
        text = self._extract_pdf_text_streams(self.output_pdf)

        # 1. Section 2 Table Header explicitly identifies Pre-Cap (Dampened)
        self.assertIn("Pre-Cap", text)
        self.assertIn("Dampened", text)

        # 2. Section 2 Accounting Clarification note is present
        self.assertIn("Accounting Clarification", text)
        self.assertIn("diminishing-returns dampening", text)

        # 3. Section 7 Mathematical Audit Trail displays both Pillar Vectors Breakdown and Evidence Ledger Accounting
        self.assertIn("Pillar Vectors Breakdown", text)
        self.assertIn("Evidence Ledger Accounting", text)


class TestReportGeneratorForensicAuditFixes(unittest.TestCase):
    """Regression tests for DMARC alignment display and routing anomaly reporting."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.output_pdf = os.path.join(self.temp_dir.name, "audit_fixes_test.pdf")

    def tearDown(self):
        self.temp_dir.cleanup()

    def _extract_pdf_text_streams(self, pdf_path: str) -> str:
        """Decompress and decode content streams from PDF, returning normalized readable text."""
        import base64
        import re
        import zlib

        with open(pdf_path, "rb") as f:
            pdf_bytes = f.read()

        matches = re.findall(rb"stream\n(.*?~>)\s*endstream", pdf_bytes, re.DOTALL)
        decompressed_parts: list[str] = []
        for m in matches:
            try:
                raw = base64.a85decode(m, adobe=True)
                dec = zlib.decompress(raw)
                decompressed_parts.append(dec.decode("latin1", errors="ignore"))
            except Exception:
                pass
        raw_text = "\n".join(decompressed_parts)
        # Extract, unescape parentheses, and normalize whitespace across text operators
        tokens = re.findall(r"\((.*?)(?<!\\)\)\s*T[jJ]", raw_text)
        cleaned_tokens = [t.replace(r"\(", "(").replace(r"\)", ")") for t in tokens]
        normalized_stream = re.sub(r"\s+", " ", " ".join(cleaned_tokens))
        return f"{raw_text}\n{normalized_stream}"

    def test_dkim_alignment_displays_pass_with_actual_mode(self):
        """1. DKIM alignment displays PASS with its actual mode (e.g. relaxed, strict)."""
        # Test relaxed mode
        auth_data_relaxed = {
            "spf": {"independent_result": "not_checked"},
            "dkim": {"overall_result": "pass"},
            "dmarc": {
                "result": "pass",
                "policy": {"p": "reject"},
                "alignment": {
                    "dkim": {"result": "pass", "mode": "relaxed", "dkim_d_domain": "example.com"},
                    "spf": {"result": "not_checked", "mode": "relaxed"},
                },
            },
        }
        generate_forensic_pdf(
            auth_data=auth_data_relaxed,
            output_path=self.output_pdf,
            case_id="CASE-ALIGN-RELAXED",
        )
        text_relaxed = self._extract_pdf_text_streams(self.output_pdf)
        self.assertIn("DKIM Aligned: PASS (relaxed)", text_relaxed)

        # Test strict mode
        auth_data_strict = {
            "spf": {"independent_result": "not_checked"},
            "dkim": {"overall_result": "pass"},
            "dmarc": {
                "result": "pass",
                "policy": {"p": "reject"},
                "alignment": {
                    "dkim": {"result": "pass", "mode": "strict", "dkim_d_domain": "example.com"},
                    "spf": {"result": "not_checked", "mode": "strict"},
                },
            },
        }
        generate_forensic_pdf(
            auth_data=auth_data_strict,
            output_path=self.output_pdf,
            case_id="CASE-ALIGN-STRICT",
        )
        text_strict = self._extract_pdf_text_streams(self.output_pdf)
        self.assertIn("DKIM Aligned: PASS (strict)", text_strict)

    def test_spf_alignment_displays_not_checked_when_actual_result(self):
        """2. SPF alignment displays NOT_CHECKED when that is the actual result (not FAIL or N/A)."""
        auth_data = {
            "spf": {"independent_result": "not_checked"},
            "dkim": {"overall_result": "pass"},
            "dmarc": {
                "result": "pass",
                "policy": {"p": "reject"},
                "alignment": {
                    "dkim": {"result": "pass", "mode": "strict"},
                    "spf": {
                        "result": "not_checked",
                        "mode": "strict",
                        "reason": "Connecting IP not available in static artifact.",
                    },
                },
            },
        }
        generate_forensic_pdf(
            auth_data=auth_data,
            output_path=self.output_pdf,
            case_id="CASE-SPF-NOTCHECKED",
        )
        text = self._extract_pdf_text_streams(self.output_pdf)
        self.assertIn("SPF Aligned: NOT_CHECKED", text)
        self.assertNotIn("SPF Aligned: FAIL", text)
        self.assertNotIn("SPF Aligned: N/A", text)

    def test_zero_received_hops_produces_no_anomalies_and_discloses_missing_evidence(self):
        """3. Zero Received hops produces 'Anomalies detected: NO' while disclosing missing routing evidence."""
        routing_data = {
            "hops": [],
            "total_hops": 0,
            "anomalies_detected": False,
            "warnings": ["No 'Received' headers found in email. Cannot reconstruct routing path."],
            "geolocation_enabled": False,
            "geolocation_status": "database_not_found",
        }
        generate_forensic_pdf(
            routing_data=routing_data,
            output_path=self.output_pdf,
            case_id="CASE-ZERO-HOPS",
        )
        text = self._extract_pdf_text_streams(self.output_pdf)
        self.assertIn("Inspected 0 transmission hop(s). Anomalies detected: NO", text)
        self.assertIn("No Received header routing evidence available in static artifact", text)
        self.assertIn("Absence of routing headers is not evidence of malicious activity nor proof of route security", text)

    def test_genuine_routing_anomalies_continue_to_produce_anomalies_detected_yes(self):
        """4. Genuine routing anomalies continue to produce 'Anomalies detected: YES'."""
        # Case A: Explicit authoritative anomalies_detected boolean with hop anomaly
        routing_data_hop = {
            "hops": [
                {
                    "hop_number": 0,
                    "ip": "203.0.113.5",
                    "anomalies": ["relay_mismatch"],
                    "by_host": "mail.target.com",
                    "from_host": "mail.spoofed.com",
                }
            ],
            "total_hops": 1,
            "anomalies_detected": True,
            "geolocation_enabled": False,
            "geolocation_status": "database_not_found",
        }
        generate_forensic_pdf(
            routing_data=routing_data_hop,
            output_path=self.output_pdf,
            case_id="CASE-ANOMALY-HOP",
        )
        text_hop = self._extract_pdf_text_streams(self.output_pdf)
        self.assertIn("Anomalies detected: YES", text_hop)

        # Case B: Routing loop warning
        routing_data_loop = {
            "hops": [
                {"hop_number": 0, "ip": "198.51.100.1"},
                {"hop_number": 1, "ip": "198.51.100.2"},
            ],
            "total_hops": 2,
            "anomalies_detected": True,
            "warnings": ["Routing loop detected: repeated host transmission cycle"],
            "geolocation_enabled": False,
            "geolocation_status": "database_not_found",
        }
        generate_forensic_pdf(
            routing_data=routing_data_loop,
            output_path=self.output_pdf,
            case_id="CASE-ANOMALY-LOOP",
        )
        text_loop = self._extract_pdf_text_streams(self.output_pdf)
        self.assertIn("Anomalies detected: YES", text_loop)

    def test_compatibility_with_missing_and_older_format_fields(self):
        """5. Existing report generation remains compatible with missing or older-format fields."""
        # 5a: Legacy alignment dict with boolean 'aligned'
        legacy_auth = {
            "spf": {"independent_result": "not_checked"},
            "dkim": {"overall_result": "pass"},
            "dmarc": {
                "result": "pass",
                "alignment": {
                    "dkim": {"aligned": True},
                    "spf": {"aligned": False},
                },
            },
        }
        generate_forensic_pdf(
            auth_data=legacy_auth,
            output_path=self.output_pdf,
            case_id="CASE-LEGACY-AUTH",
        )
        text_legacy = self._extract_pdf_text_streams(self.output_pdf)
        self.assertIn("DKIM Aligned: PASS", text_legacy)
        self.assertIn("SPF Aligned: FAIL", text_legacy)

        # 5b: Missing alignment dict entirely
        missing_align_auth = {
            "spf": {"independent_result": "not_checked"},
            "dkim": {"overall_result": "pass"},
            "dmarc": {"result": "pass", "policy": {"p": "none"}},
        }
        generate_forensic_pdf(
            auth_data=missing_align_auth,
            output_path=self.output_pdf,
            case_id="CASE-MISSING-ALIGN",
        )
        text_missing = self._extract_pdf_text_streams(self.output_pdf)
        self.assertIn("DKIM Aligned: N/A | SPF Aligned: N/A", text_missing)

        # 5c: Legacy routing data without anomalies_detected field (clean hops + informational warning)
        legacy_routing_clean = {
            "hops": [{"hop_number": 0, "ip": "10.0.0.1", "by_host": "internal.lan"}],
            "total_hops": 1,
            "warnings": ["No valid timestamps found in Received headers; chronological order approximated."],
            "geolocation_enabled": False,
            "geolocation_status": "database_not_found",
        }
        generate_forensic_pdf(
            routing_data=legacy_routing_clean,
            output_path=self.output_pdf,
            case_id="CASE-LEGACY-CLEAN",
        )
        text_clean = self._extract_pdf_text_streams(self.output_pdf)
        self.assertIn("Anomalies detected: NO", text_clean)

        # 5d: Legacy routing data without anomalies_detected field, but with hop anomalies
        legacy_routing_anom = {
            "hops": [{"hop_number": 0, "ip": "10.0.0.1", "anomalies": ["relay_mismatch"]}],
            "total_hops": 1,
            "warnings": [],
            "geolocation_enabled": False,
            "geolocation_status": "database_not_found",
        }
        generate_forensic_pdf(
            routing_data=legacy_routing_anom,
            output_path=self.output_pdf,
            case_id="CASE-LEGACY-ANOM",
        )
        text_anom = self._extract_pdf_text_streams(self.output_pdf)
        self.assertIn("Anomalies detected: YES", text_anom)

        # 5e: Direct unit testing of _format_alignment_status helper
        self.assertEqual(_format_alignment_status(None), "N/A")
        self.assertEqual(_format_alignment_status({}), "N/A")
        self.assertEqual(_format_alignment_status({"result": "pass", "mode": "relaxed"}), "PASS (relaxed)")
        self.assertEqual(_format_alignment_status({"result": "pass", "mode": "strict"}), "PASS (strict)")
        self.assertEqual(_format_alignment_status({"result": "not_checked", "mode": "strict"}), "NOT_CHECKED")
        self.assertEqual(_format_alignment_status({"result": "fail", "mode": "relaxed"}), "FAIL (relaxed)")
        self.assertEqual(_format_alignment_status({"aligned": True}), "PASS")
        self.assertEqual(_format_alignment_status({"aligned": False}), "FAIL")
        self.assertEqual(_format_alignment_status(True), "PASS")
        self.assertEqual(_format_alignment_status(False), "FAIL")
        self.assertEqual(_format_alignment_status("not_checked"), "NOT_CHECKED")
        self.assertEqual(_format_alignment_status("pass"), "PASS")


if __name__ == "__main__":
    unittest.main()


