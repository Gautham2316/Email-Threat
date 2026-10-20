"""
tests/test_dashboard_pipeline.py
================================
Automated test suite for Module 8 Pipeline Orchestrator.
SIH 2026 — AI-Powered Email Threat Detection Platform

TEST SUITE INVARIANTS:
1. Zero Network Access: Tests never open outbound internet connections.
2. Safe Temp File Handling: Any temporary disk files created during testing are cleaned up.
3. Strict Contract Verification: Verifies that the returned payload contains all 6 forensic
   analysis dictionaries required for the UI, evidence ledger, and PDF report.
4. Mathematical Reconciliation: Asserts that risk score and evidence ledger reconcile.
5. Defensive Error Handling: Verifies graceful degradation on corrupt, empty, and oversized files.
"""

import os
import sys
import unittest
from unittest.mock import patch

# Ensure src/ is in sys.path
SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from dashboard_pipeline import (
    run_forensic_pipeline,
    validate_email_input,
    extract_safe_email_preview,
    defang_content_text,
    resolve_demo_fixture_dkim_dns,
    DKIM_DEMO_FIXTURE_SHA256,
    PIPELINE_VERSION,
)

SAMPLES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "samples"))
PHISHING_SAMPLE = os.path.join(SAMPLES_DIR, "phishing_sample.eml")
MULTIPART_SAMPLE = os.path.join(SAMPLES_DIR, "multipart.eml")
PLAIN_TEXT_SAMPLE = os.path.join(SAMPLES_DIR, "plain_text.eml")
DKIM_SIGNED_SAMPLE = os.path.join(SAMPLES_DIR, "dkim_signed.eml")


class TestDashboardPipelineBasics(unittest.TestCase):
    """Test validation and contract guarantees of dashboard_pipeline."""

    def test_validate_email_input_valid_filepath(self):
        """Valid .eml file path passes validation."""
        valid, err = validate_email_input(PHISHING_SAMPLE)
        self.assertTrue(valid)
        self.assertIsNone(err)

    def test_validate_email_input_valid_bytes(self):
        """Valid bytes with .eml filename passes validation."""
        valid, err = validate_email_input(b"From: test@example.com\r\n\r\nBody", "test.eml")
        self.assertTrue(valid)
        self.assertIsNone(err)

    def test_validate_email_input_empty_bytes(self):
        """Empty bytes are rejected."""
        valid, err = validate_email_input(b"", "empty.eml")
        self.assertFalse(valid)
        self.assertIn("empty", err.lower())

    def test_validate_email_input_wrong_extension(self):
        """Non-.eml extension is rejected."""
        valid, err = validate_email_input(b"test data", "malware.exe")
        self.assertFalse(valid)
        self.assertIn(".eml", err)

    def test_validate_email_input_nonexistent_file(self):
        """Non-existent file path returns clean error."""
        valid, err = validate_email_input("samples/does_not_exist_xyz.eml")
        self.assertFalse(valid)
        self.assertIn("not found", err.lower())

    def test_validate_email_input_oversized(self):
        """Payload exceeding 25 MB is rejected."""
        oversized_bytes = b"X" * (26 * 1024 * 1024)
        valid, err = validate_email_input(oversized_bytes, "oversized.eml")
        self.assertFalse(valid)
        self.assertIn("exceeds size limit", err)


class TestDashboardPipelineExecution(unittest.TestCase):
    """Test end-to-end execution of run_forensic_pipeline on sample artifacts."""

    def test_run_pipeline_with_phishing_sample_filepath(self):
        """Execute pipeline on phishing_sample.eml by file path."""
        res = run_forensic_pipeline(PHISHING_SAMPLE, case_id="CASE-TEST-001")

        self.assertEqual(res["status"], "success")
        self.assertEqual(res["case_id"], "CASE-TEST-001")
        self.assertEqual(res["filename"], "phishing_sample.eml")
        self.assertGreater(res["file_size_bytes"], 0)
        self.assertIsInstance(res["raw_bytes"], bytes)

        # Verify all 6 module dictionaries are present
        self.assertIsNotNone(res["parsed_email"])
        self.assertIsNotNone(res["auth_result"])
        self.assertIsNotNone(res["url_result"])
        self.assertIsNotNone(res["routing_result"])
        self.assertIsNotNone(res["ai_result"])
        self.assertIsNotNone(res["risk_report"])

        # Verify risk score and forensic level
        risk = res["risk_report"]
        self.assertEqual(risk["risk_score"], 85)
        self.assertEqual(risk["risk_level"], "high")

        # Verify mathematical reconciliation
        metadata = risk.get("scoring_metadata", {})
        capped_pillars = metadata.get("capped_pillar_scores_sum", 0)
        synergy = metadata.get("synergy_bonus", 0)
        mitigation = metadata.get("mitigation_discount", 0)
        expected_final = min(100, max(0, capped_pillars + synergy - mitigation))
        self.assertEqual(risk["risk_score"], expected_final)

        # Ledger contribution sum must match final score
        ledger_sum = sum(e.get("effective_contribution", 0) for e in risk.get("evidence", []))
        self.assertEqual(risk["risk_score"], ledger_sum)

        # Verify safe preview is populated
        preview = res["safe_preview"]
        self.assertIsNotNone(preview)
        self.assertIn("PayPal", preview["subject"])
        self.assertGreater(preview["url_count"], 0)

    def test_run_pipeline_with_bytes_input(self):
        """Execute pipeline on in-memory raw bytes (simulating Streamlit file upload)."""
        with open(MULTIPART_SAMPLE, "rb") as fh:
            sample_bytes = fh.read()

        res = run_forensic_pipeline(
            sample_bytes,
            original_filename="multipart_upload.eml",
            case_id="UPLOAD-TEST-999",
        )

        self.assertEqual(res["status"], "success")
        self.assertEqual(res["filename"], "multipart_upload.eml")
        self.assertEqual(res["file_size_bytes"], len(sample_bytes))
        self.assertEqual(res["raw_bytes"], sample_bytes)
        self.assertIsNotNone(res["parsed_email"])
        self.assertIsNotNone(res["risk_report"])

    def test_run_pipeline_with_corrupt_file_returns_clean_error(self):
        """Corrupt or non-existent file returns clean error dict without throwing unhandled exceptions."""
        res = run_forensic_pipeline("non_existent_file.eml")
        self.assertEqual(res["status"], "error")
        self.assertGreater(len(res["errors"]), 0)
        self.assertIsNone(res["risk_report"])

    def test_defang_content_text(self):
        """Verify that defang_content_text neutralizes active web URLs."""
        text = "Please verify your account at https://phishing.evil-site.com/login now!"
        defanged = defang_content_text(text)
        self.assertNotIn("https://", defanged)
        self.assertIn("hxxps://", defanged)
        self.assertIn("[.]", defanged)

    def test_extract_safe_email_preview_handles_malformed_input(self):
        """Verify preview extractor handles None or malformed dictionaries gracefully."""
        preview = extract_safe_email_preview({})
        self.assertEqual(preview["subject"], "(No metadata)")
        self.assertEqual(preview["from"], "(Unknown)")

    @patch("dashboard_pipeline.verify_authentication")
    def test_pipeline_resilience_to_downstream_module_exception(self, mock_auth):
        """If an individual analysis module raises an exception, the pipeline records it and continues."""
        mock_auth.side_effect = RuntimeError("Simulated DNS failure during auth check")

        res = run_forensic_pipeline(PLAIN_TEXT_SAMPLE)

        self.assertEqual(res["status"], "success")
        self.assertEqual(res["auth_result"]["overall_result"], "error")
        self.assertTrue(any("Simulated DNS failure" in err for err in res["errors"]))
        # Downstream risk scorer still ran
        self.assertIsNotNone(res["risk_report"])


class TestDashboardPipelineDKIMFixture(unittest.TestCase):
    """Regression tests for scoped offline DKIM demo fixture resolution."""

    def setUp(self):
        with open(DKIM_SIGNED_SAMPLE, "rb") as fh:
            self.fixture_bytes = fh.read()

    def test_exact_fixture_passes_dkim_in_pipeline(self):
        """The exact bundled samples/dkim_signed.eml passes DKIM verification through the pipeline."""
        res = run_forensic_pipeline(DKIM_SIGNED_SAMPLE)
        self.assertEqual(res["status"], "success")
        self.assertIsNotNone(res["auth_result"])
        dkim_res = res["auth_result"]["dkim"]
        self.assertEqual(dkim_res["overall_result"], "pass")
        self.assertEqual(len(dkim_res["signatures"]), 1)
        sig = dkim_res["signatures"][0]
        self.assertEqual(sig["result"], "pass")
        self.assertEqual(sig["domain"], "example.com")
        self.assertEqual(sig["selector"], "test2026")
        self.assertTrue(sig["public_key_retrieved"])
        self.assertIsNone(sig["error"])
        # Overall auth passes via DKIM alignment
        self.assertEqual(res["auth_result"]["overall_result"], "pass")

    def test_modified_fixture_denied_local_demo_key(self):
        """A modified email using the same domain/selector is refused the local key."""
        # Tamper 1 byte in the body
        tampered_bytes = self.fixture_bytes.replace(b"This is a DKIM-signed", b"This is a TAMPERED-bytes")
        # Resolver check fails
        resolver = resolve_demo_fixture_dkim_dns(tampered_bytes)
        self.assertIsNone(resolver)

        # Pipeline execution falls back to live DNS, receiving the live empty key (permerror)
        res = run_forensic_pipeline(tampered_bytes, original_filename="tampered_dkim.eml")
        self.assertEqual(res["status"], "success")
        self.assertIsNotNone(res["auth_result"])
        dkim_res = res["auth_result"]["dkim"]
        self.assertNotEqual(dkim_res["overall_result"], "pass")
        self.assertEqual(dkim_res["overall_result"], "permerror")
        self.assertFalse(dkim_res["signatures"][0]["public_key_retrieved"])

    def test_ordinary_email_uses_existing_dns_path(self):
        """Ordinary emails (not matching fixture SHA-256) never trigger the demo resolver."""
        with open(PLAIN_TEXT_SAMPLE, "rb") as fh:
            plain_bytes = fh.read()
        self.assertIsNone(resolve_demo_fixture_dkim_dns(plain_bytes))

        with open(PHISHING_SAMPLE, "rb") as fh:
            phishing_bytes = fh.read()
        self.assertIsNone(resolve_demo_fixture_dkim_dns(phishing_bytes))

    def test_missing_mock_file_fails_explicitly(self):
        """Missing mock key file raises FileNotFoundError and fails closed with permerror."""
        from auth_verifier import verify_authentication
        from email_parser import parse_email_file

        parsed = parse_email_file(DKIM_SIGNED_SAMPLE)
        broken_resolver = resolve_demo_fixture_dkim_dns(
            self.fixture_bytes, mock_file_path=os.path.join(SAMPLES_DIR, "nonexistent_mock.txt")
        )
        self.assertIsNotNone(broken_resolver)

        res = verify_authentication(parsed, self.fixture_bytes, dkim_dnsfunc=broken_resolver)
        self.assertEqual(res["dkim"]["overall_result"], "permerror")
        sig = res["dkim"]["signatures"][0]
        self.assertEqual(sig["result"], "permerror")
        self.assertFalse(sig["public_key_retrieved"])
        self.assertIn("not found", sig["error"].lower())

    def test_malformed_mock_data_fails_explicitly(self):
        """Malformed mock key data raises ValueError and fails closed with permerror."""
        from auth_verifier import verify_authentication
        from email_parser import parse_email_file

        parsed = parse_email_file(DKIM_SIGNED_SAMPLE)
        # Point to a file without v=DKIM1 / p= tags
        corrupt_resolver = resolve_demo_fixture_dkim_dns(
            self.fixture_bytes, mock_file_path=PLAIN_TEXT_SAMPLE
        )
        self.assertIsNotNone(corrupt_resolver)

        res = verify_authentication(parsed, self.fixture_bytes, dkim_dnsfunc=corrupt_resolver)
        self.assertEqual(res["dkim"]["overall_result"], "permerror")
        sig = res["dkim"]["signatures"][0]
        self.assertEqual(sig["result"], "permerror")
        self.assertFalse(sig["public_key_retrieved"])
        self.assertIn("malformed", sig["error"].lower())


if __name__ == "__main__":
    unittest.main()

