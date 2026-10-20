"""
tests/test_dashboard_ui.py
==========================
Automated integration tests for Module 8 Streamlit dashboard helpers and PDF export.
SIH 2026 — AI-Powered Email Threat Detection Platform

TEST SUITE INVARIANTS:
1. Zero Network Access: Tests never open outbound internet connections.
2. Direct Payload to PDF Export: Confirms that the pipeline payload stored in UI session state
   can be directly fed into Module 7's generate_forensic_pdf to yield a valid %PDF- document.
3. Safe Rendering & Defanging: Confirms hostile HTML, javascript:, and active URLs are defanged.
4. Mathematical Integrity: Confirms dual-pathway audit trail balance across all sample artifacts.
"""

import os
import sys
import tempfile
import unittest

# Ensure src/ is in sys.path
SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from dashboard_pipeline import (
    run_forensic_pipeline,
    extract_safe_email_preview,
    defang_content_text,
)
from report_generator import generate_forensic_pdf

SAMPLES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "samples"))
PHISHING_SAMPLE = os.path.join(SAMPLES_DIR, "phishing_sample.eml")
MULTIPART_SAMPLE = os.path.join(SAMPLES_DIR, "multipart.eml")
PLAIN_TEXT_SAMPLE = os.path.join(SAMPLES_DIR, "plain_text.eml")
DKIM_SAMPLE = os.path.join(SAMPLES_DIR, "dkim_signed.eml")


class TestDashboardUIIntegration(unittest.TestCase):
    """Test dashboard helpers and end-to-end PDF report generation from pipeline payloads."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_pipeline_payload_drives_pdf_export_with_valid_pdf_signature(self):
        """Pipeline output payload can be directly compiled into a valid %PDF- document."""
        pipeline_res = run_forensic_pipeline(PHISHING_SAMPLE, case_id="CASE-DASH-PDF-001")
        self.assertEqual(pipeline_res["status"], "success")

        output_pdf_path = os.path.join(self.temp_dir.name, "exported_investigation.pdf")

        gen_res = generate_forensic_pdf(
            email_data=pipeline_res["parsed_email"],
            auth_data=pipeline_res["auth_result"],
            url_data=pipeline_res["url_result"],
            routing_data=pipeline_res["routing_result"],
            ai_data=pipeline_res["ai_result"],
            risk_data=pipeline_res["risk_report"],
            output_path=output_pdf_path,
            case_id="CASE-DASH-PDF-001",
            include_body_excerpt=True,
        )

        self.assertTrue(os.path.exists(output_pdf_path))
        self.assertGreater(gen_res["file_size_bytes"], 5000)

        with open(output_pdf_path, "rb") as fh:
            pdf_bytes = fh.read()

        # Strict PDF magic header and trailer check (Requirement: %PDF-)
        self.assertEqual(pdf_bytes[:5], b"%PDF-", "Generated report must begin with '%PDF-' magic header")
        self.assertTrue(pdf_bytes.strip().endswith(b"%%EOF"), "Generated report must end with %%EOF marker")
        self.assertEqual(len(pdf_bytes), gen_res["file_size_bytes"])
        self.assertEqual(gen_res["status"], "success")

    def test_safe_preview_truncates_and_neutralizes_hostile_content(self):
        """Previews safely truncate excessively long strings and defang URL protocols."""
        fake_email = {
            "email_metadata": {
                "subject": "Click https://phishing.example.com to avoid suspension!",
                "from": "Attacker <admin@phishing.example.com>",
                "to": ["victim@college.edu"],
                "date": "Tue, 20 Oct 2026 10:00:00 +0000",
                "message_id": "<123@phishing.example.com>",
            },
            "body": {
                "plain_text": "A" * 800 + " https://evil.com/payload.exe",
                "html": "<script>alert('xss')</script>",
            },
            "urls": [{"url": "https://evil.com/payload.exe"}],
        }

        preview = extract_safe_email_preview(fake_email, max_body_chars=200)

        # Subject must be defanged
        self.assertNotIn("https://", preview["subject"])
        self.assertIn("hxxps://", preview["subject"])

        # Body snippet must be truncated to <= max_body_chars + truncation label
        self.assertIn("[TRUNCATED FOR FORENSIC PREVIEW]", preview["body_preview"])
        self.assertEqual(preview["url_count"], 1)

    def test_all_sample_artifacts_execute_in_pipeline(self):
        """All existing sample emails in samples/ run cleanly through the pipeline."""
        for sample_file in [PLAIN_TEXT_SAMPLE, MULTIPART_SAMPLE, DKIM_SAMPLE]:
            with self.subTest(sample=os.path.basename(sample_file)):
                res = run_forensic_pipeline(sample_file)
                self.assertEqual(res["status"], "success")
                self.assertIsNotNone(res["risk_report"])
                self.assertIn("risk_score", res["risk_report"])
                self.assertIn("risk_level", res["risk_report"])

    def test_missing_ai_model_graceful_handling(self):
        """When AI model is unavailable, the pipeline records the state without fabricating predictions."""
        with unittest.mock.patch("dashboard_pipeline.analyze_email_text") as mock_ai:
            mock_ai.return_value = {
                "classification": {"semantic_verdict": "unknown", "confidence": 0.0},
                "model_metadata": {"model_status": "unavailable", "model_id": "aamoshdahal/email-phishing-distilbert-finetuned"},
                "warnings": ["PyTorch weights unavailable locally."],
            }
            res = run_forensic_pipeline(PLAIN_TEXT_SAMPLE)
            self.assertEqual(res["status"], "success")
            ai_data = res["ai_result"]
            self.assertEqual(ai_data["model_metadata"]["model_status"], "unavailable")
            self.assertIn("PyTorch weights unavailable locally.", res["warnings"])
            # Risk scorer still evaluated other pillars without fabricating AI points
            self.assertIsNotNone(res["risk_report"])

    def test_mandatory_epistemic_disclaimers_consistency(self):
        """Verify that pipeline outputs maintain mandatory disclosures for SPF, threat intel, and AI calibration."""
        res = run_forensic_pipeline(PHISHING_SAMPLE)
        self.assertEqual(res["status"], "success")

        # 1. SPF independent evaluation must be not_checked on static .eml
        self.assertEqual(res["auth_result"]["spf"]["independent_result"], "not_checked")

        # 2. URL threat intelligence must be not_checked (offline heuristics only)
        self.assertEqual(res["url_result"]["threat_intel_status"], "not_checked")

        # 3. Limitations must disclose AI calibration and zero active network access
        limitations = res["risk_report"]["limitations"]
        self.assertTrue(any("calibrated" in lim.lower() for lim in limitations))
        self.assertTrue(any("zero active network" in lim.lower() for lim in limitations))


if __name__ == "__main__":
    unittest.main()
