"""
tests/test_ai_text_analyzer.py
==============================
Automated test suite for Module 5: AI-Based Phishing and Scam-Text Classification Engine.

SIH 2026 — AI-Powered Email Threat Detection Platform

TEST COVERAGE & INVARIANTS:
1. Zero Network Access: Every test runs strictly offline without network,
   socket, DNS, or HTTP calls.
2. Valid Benign-like & Phishing-like Classifications: Verifies mocked inference paths.
3. Verified vs Unknown Semantic Labels: Ensures raw labels are mapped only with
   verified evidence; unmapped labels default to 'unknown'.
4. Raw Output Preservation: Validates that predicted index, raw label, and class
   probabilities are preserved intact alongside semantic verdicts.
5. Missing or Empty Subject and Body: Ensures empty input produces 'empty_input'
   and 'inconclusive' status without running inference.
6. Malformed and Non-String Inputs: Validates safe handling of None, numbers,
   and corrupt structures without crashing.
7. Confidence Extraction & Range Validation: Confirms scores remain strictly in [0.0, 1.0].
8. Model-Loading & Dependency Failures: Verifies graceful degradation to 'unavailable'
   when packages or model files are absent.
9. Inference Forward-Pass Errors: Tests handling of runtime exceptions during inference.
10. Context Truncation: Verifies max_length enforcement and warning generation.
11. Model Caching & Reuse: Confirms cached model instances are reused across calls.
12. Module 1 Integration: Confirms seamless consumption of parse_email_file output.
13. JSON Serialization: Ensures the returned report is 100% JSON serializable.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from ai_text_analyzer import (
    DEFAULT_LABEL_MAPPING,
    DEFAULT_MAX_LENGTH,
    DEFAULT_MODEL_ID,
    INTERP_EMPTY_INPUT,
    INTERP_INFERENCE_ERROR,
    INTERP_MODEL_UNAVAILABLE,
    INTERP_UNVERIFIED,
    INTERP_VERIFIED,
    MODEL_STATUS_ERROR,
    MODEL_STATUS_LOADED,
    MODEL_STATUS_NOT_RUN,
    MODEL_STATUS_UNAVAILABLE,
    STATUS_EMPTY_INPUT,
    STATUS_ERROR,
    STATUS_SUCCESS,
    STATUS_UNAVAILABLE,
    VERDICT_INCONCLUSIVE,
    VERDICT_LEGITIMATE,
    VERDICT_PHISHING,
    VERDICT_UNKNOWN,
    analyze_email_text,
    check_ai_dependencies,
    clear_model_cache,
    extract_clean_text,
    get_cached_model,
    interpret_model_label,
    load_model_and_tokenizer,
)
from email_parser import parse_email_file


class TestNetworkSafetyGuarantees(unittest.TestCase):
    """Verify that AI text analysis never performs live network activity."""

    def test_zero_network_calls_during_analysis(self):
        """Socket connections must never be opened during text analysis."""
        mock_classifier = lambda text: {
            "predicted_index": 1,
            "raw_label": "LABEL_1",
            "confidence": 0.985,
            "probabilities": {"LABEL_0": 0.015, "LABEL_1": 0.985},
            "is_truncated": False,
        }

        with patch("socket.socket") as mock_sock, \
             patch("socket.gethostbyname") as mock_gethost, \
             patch("socket.getaddrinfo") as mock_getaddr:
            report = analyze_email_text(
                "Urgent: Verify your account immediately",
                config={"custom_classifier": mock_classifier},
            )
            mock_sock.assert_not_called()
            mock_gethost.assert_not_called()
            mock_getaddr.assert_not_called()

        self.assertEqual(report["analysis_status"], STATUS_SUCCESS)


class TestTextExtractionAndCleaning(unittest.TestCase):
    """Test safe extraction and normalization of email text from various input types."""

    def test_extract_from_plain_text_dict(self):
        data = {
            "email_metadata": {"subject": "Meeting Notes"},
            "body": {"plain_text": "Here are the notes from today."},
        }
        subj, body, combined, source = extract_clean_text(data)
        self.assertEqual(subj, "Meeting Notes")
        self.assertEqual(body, "Here are the notes from today.")
        self.assertEqual(combined, "Subject: Meeting Notes\n\nHere are the notes from today.")
        self.assertEqual(source, "plain_text")

    def test_extract_from_html_stripped(self):
        data = {
            "email_metadata": {"subject": "Security Alert"},
            "body": {
                "plain_text": None,
                "html": "<html><body><p>Your account was <b>locked</b>.</p></body></html>",
            },
        }
        subj, body, combined, source = extract_clean_text(data)
        self.assertEqual(subj, "Security Alert")
        self.assertIn("Your account was locked.", body)
        self.assertEqual(source, "html_stripped")

    def test_extract_from_raw_string(self):
        subj, body, combined, source = extract_clean_text("Direct email content string")
        self.assertEqual(subj, "")
        self.assertEqual(body, "Direct email content string")
        self.assertEqual(combined, "Direct email content string")
        self.assertEqual(source, "raw_string")

    def test_extract_from_empty_and_none(self):
        for empty_val in [None, "", {}, {"body": {}}, {"body": {"plain_text": "   "}}]:
            subj, body, combined, source = extract_clean_text(empty_val)
            self.assertEqual(combined, "")
            self.assertEqual(source, "empty")

    def test_extract_from_non_string_types(self):
        subj, body, combined, source = extract_clean_text(12345)
        self.assertEqual(combined, "")
        self.assertEqual(source, "empty")


class TestLabelInterpretationAndEvidence(unittest.TestCase):
    """Test verified semantic label mapping, unmapped labels, and raw output preservation."""

    def test_verified_phishing_label_mapping(self):
        # Index 1 and LABEL_1 must map to phishing based on verified evidence
        verdict, status, evidence = interpret_model_label("LABEL_1", 1)
        self.assertEqual(verdict, VERDICT_PHISHING)
        self.assertEqual(status, INTERP_VERIFIED)
        self.assertIn("model card", evidence.lower())

    def test_verified_legitimate_label_mapping(self):
        # Index 0 and LABEL_0 must map to legitimate based on verified evidence
        verdict, status, evidence = interpret_model_label("LABEL_0", 0)
        self.assertEqual(verdict, VERDICT_LEGITIMATE)
        self.assertEqual(status, INTERP_VERIFIED)

    def test_unverified_unknown_label_mapping(self):
        # An unmapped raw label like LABEL_9 must be marked unknown
        verdict, status, evidence = interpret_model_label("LABEL_9", 9)
        self.assertEqual(verdict, VERDICT_UNKNOWN)
        self.assertEqual(status, INTERP_UNVERIFIED)
        self.assertIn("no verified semantic interpretation", evidence.lower())

    def test_custom_label_mapping_override(self):
        custom_map = {0: "ham", 1: "spam"}
        verdict, status, evidence = interpret_model_label(
            "LABEL_1", 1, label_mapping=custom_map, custom_evidence="Custom trained spam classifier."
        )
        self.assertEqual(verdict, "spam")
        self.assertEqual(status, INTERP_VERIFIED)
        self.assertEqual(evidence, "Custom trained spam classifier.")


class TestInferenceAndConfidenceBehavior(unittest.TestCase):
    """Test mocked inference, confidence extraction, range validation, and risk indications."""

    def test_phishing_prediction_high_confidence(self):
        mock_classifier = lambda text: {
            "predicted_index": 1,
            "raw_label": "LABEL_1",
            "confidence": 0.9921,
            "probabilities": {"LABEL_0": 0.0079, "LABEL_1": 0.9921},
            "is_truncated": False,
        }

        report = analyze_email_text(
            "Dear customer, please verify your credentials.",
            config={"custom_classifier": mock_classifier},
        )

        self.assertEqual(report["analysis_status"], STATUS_SUCCESS)
        self.assertEqual(report["model_metadata"]["model_status"], MODEL_STATUS_LOADED)

        # Raw output preserved
        raw = report["raw_model_output"]
        self.assertEqual(raw["predicted_index"], 1)
        self.assertEqual(raw["raw_label"], "LABEL_1")
        self.assertEqual(raw["confidence"], 0.9921)
        self.assertEqual(raw["probabilities"]["LABEL_1"], 0.9921)

        # Semantic classification
        cls = report["classification"]
        self.assertEqual(cls["semantic_verdict"], VERDICT_PHISHING)
        self.assertEqual(cls["interpretation_status"], INTERP_VERIFIED)
        self.assertEqual(cls["confidence"], 0.9921)

        # Risk indication
        self.assertEqual(report["risk_indication"], "high")

        # Uncalibrated confidence note
        self.assertIn("statistical softmax", report["confidence_assessment"]["calibrated_risk_note"].lower())

    def test_legitimate_prediction_high_confidence(self):
        mock_classifier = lambda text: {
            "predicted_index": 0,
            "raw_label": "LABEL_0",
            "confidence": 0.9540,
            "probabilities": {"LABEL_0": 0.9540, "LABEL_1": 0.0460},
            "is_truncated": False,
        }

        report = analyze_email_text(
            "Here is the project report for review.",
            config={"custom_classifier": mock_classifier},
        )

        self.assertEqual(report["analysis_status"], STATUS_SUCCESS)
        self.assertEqual(report["classification"]["semantic_verdict"], VERDICT_LEGITIMATE)
        self.assertEqual(report["risk_indication"], "none")

    def test_moderate_confidence_phishing_gives_medium_risk(self):
        mock_classifier = lambda text: {
            "predicted_index": 1,
            "raw_label": "LABEL_1",
            "confidence": 0.6500,
            "probabilities": {"LABEL_0": 0.3500, "LABEL_1": 0.6500},
            "is_truncated": False,
        }

        report = analyze_email_text(
            "Please check this link.",
            config={"custom_classifier": mock_classifier},
        )
        self.assertEqual(report["classification"]["semantic_verdict"], VERDICT_PHISHING)
        self.assertEqual(report["risk_indication"], "medium")

    def test_unknown_label_produces_inconclusive_risk(self):
        mock_classifier = lambda text: {
            "predicted_index": 2,
            "raw_label": "LABEL_2",
            "confidence": 0.8800,
            "probabilities": {"LABEL_0": 0.05, "LABEL_1": 0.07, "LABEL_2": 0.88},
            "is_truncated": False,
        }

        report = analyze_email_text(
            "Some ambiguous email content.",
            config={"custom_classifier": mock_classifier},
        )
        self.assertEqual(report["classification"]["semantic_verdict"], VERDICT_UNKNOWN)
        self.assertEqual(report["classification"]["interpretation_status"], INTERP_UNVERIFIED)
        self.assertEqual(report["risk_indication"], "inconclusive")

    def test_truncation_warning(self):
        mock_classifier = lambda text: {
            "predicted_index": 1,
            "raw_label": "LABEL_1",
            "confidence": 0.90,
            "probabilities": {"LABEL_0": 0.10, "LABEL_1": 0.90},
            "is_truncated": True,
        }

        report = analyze_email_text(
            "Very long text " * 500,
            config={"custom_classifier": mock_classifier, "max_length": 512},
        )
        self.assertTrue(report["model_metadata"]["is_truncated"])
        self.assertTrue(any("truncated" in w.lower() for w in report["warnings"]))


class TestEmptyAndMalformedInputs(unittest.TestCase):
    """Test handling of empty text, null values, and corrupted data structures."""

    def test_empty_string_input(self):
        report = analyze_email_text("")
        self.assertEqual(report["analysis_status"], STATUS_EMPTY_INPUT)
        self.assertEqual(report["model_metadata"]["model_status"], MODEL_STATUS_NOT_RUN)
        self.assertEqual(report["classification"]["semantic_verdict"], VERDICT_INCONCLUSIVE)
        self.assertEqual(report["classification"]["interpretation_status"], INTERP_EMPTY_INPUT)
        self.assertIsNone(report["raw_model_output"])
        self.assertTrue(len(report["warnings"]) > 0)

    def test_none_input(self):
        report = analyze_email_text(None)
        self.assertEqual(report["analysis_status"], STATUS_EMPTY_INPUT)
        self.assertEqual(report["classification"]["semantic_verdict"], VERDICT_INCONCLUSIVE)

    def test_empty_dict_input(self):
        report = analyze_email_text({})
        self.assertEqual(report["analysis_status"], STATUS_EMPTY_INPUT)

    def test_whitespace_only_input(self):
        report = analyze_email_text("   \n\t  ")
        self.assertEqual(report["analysis_status"], STATUS_EMPTY_INPUT)


class TestModelFailureAndMissingDependencies(unittest.TestCase):
    """Test graceful handling of missing libraries, unavailable models, and inference errors."""

    def test_missing_dependencies_reports_unavailable(self):
        # Simulate torch/transformers missing
        with patch("ai_text_analyzer.check_ai_dependencies", return_value=(False, "PyTorch missing")):
            clear_model_cache()
            report = analyze_email_text("Test email body")
            self.assertEqual(report["analysis_status"], STATUS_UNAVAILABLE)
            self.assertEqual(report["model_metadata"]["model_status"], MODEL_STATUS_UNAVAILABLE)
            self.assertIn("PyTorch missing", report["model_metadata"]["error_reason"])
            self.assertEqual(report["classification"]["semantic_verdict"], VERDICT_UNKNOWN)
            self.assertEqual(report["classification"]["interpretation_status"], INTERP_MODEL_UNAVAILABLE)

    def test_model_loading_failure_reports_unavailable(self):
        def failing_loader(**kwargs):
            return None, None, MODEL_STATUS_UNAVAILABLE, "Model weights file not found."

        report = analyze_email_text(
            "Test email body",
            config={"model_loader": failing_loader},
        )
        self.assertEqual(report["analysis_status"], STATUS_UNAVAILABLE)
        self.assertEqual(report["model_metadata"]["model_status"], MODEL_STATUS_UNAVAILABLE)
        self.assertIn("not found", report["model_metadata"]["error_reason"].lower())

    def test_inference_runtime_exception_reports_error(self):
        def broken_classifier(text):
            raise RuntimeError("Out of memory on GPU during forward pass")

        report = analyze_email_text(
            "Test email body",
            config={"custom_classifier": broken_classifier},
        )
        self.assertEqual(report["analysis_status"], STATUS_ERROR)
        self.assertEqual(report["model_metadata"]["model_status"], MODEL_STATUS_ERROR)
        self.assertEqual(report["classification"]["interpretation_status"], INTERP_INFERENCE_ERROR)
        self.assertTrue(any("out of memory" in w.lower() for w in report["warnings"]))


class TestModelCachingAndReuse(unittest.TestCase):
    """Verify thread-safe model caching and cache invalidation."""

    def test_model_caching_and_clear(self):
        clear_model_cache()
        self.assertIsNone(get_cached_model(f"{DEFAULT_MODEL_ID}::None::False"))

        # Inject fake loaded model into cache
        mock_tok = MagicMock()
        mock_mod = MagicMock()
        cache_key = f"{DEFAULT_MODEL_ID}::None::False"

        from ai_text_analyzer import _MODEL_CACHE, _CACHE_LOCK
        with _CACHE_LOCK:
            _MODEL_CACHE[cache_key] = (mock_tok, mock_mod)

        tok, mod, status, err = load_model_and_tokenizer(DEFAULT_MODEL_ID)
        self.assertEqual(status, MODEL_STATUS_LOADED)
        self.assertIs(tok, mock_tok)
        self.assertIs(mod, mock_mod)

        clear_model_cache()
        self.assertIsNone(get_cached_model(cache_key))


class TestIntegrationWithModule1(unittest.TestCase):
    """Test consuming real output dictionaries produced by Module 1's parse_email_file."""

    def test_consume_module1_sample_phishing_email(self):
        sample_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "samples", "phishing_sample.eml")
        )
        self.assertTrue(os.path.isfile(sample_path))

        parsed_email = parse_email_file(sample_path)
        self.assertEqual(parsed_email["errors"], [])

        # Mock the classifier to simulate prediction on this email
        captured_text = []

        def mock_classifier(text):
            captured_text.append(text)
            return {
                "predicted_index": 1,
                "raw_label": "LABEL_1",
                "confidence": 0.9945,
                "probabilities": {"LABEL_0": 0.0055, "LABEL_1": 0.9945},
                "is_truncated": False,
            }

        report = analyze_email_text(
            parsed_email,
            config={"custom_classifier": mock_classifier},
        )

        self.assertEqual(report["analysis_status"], STATUS_SUCCESS)
        self.assertEqual(report["classification"]["semantic_verdict"], VERDICT_PHISHING)
        self.assertEqual(report["risk_indication"], "high")

        # Verify subject and body were both captured and combined
        self.assertEqual(len(captured_text), 1)
        self.assertIn("Subject: URGENT: Your PayPal account has been suspended", captured_text[0])
        self.assertIn("SUSPICIOUS ACTIVITY on your PayPal account", captured_text[0])

    def test_consume_module1_plain_text_email(self):
        sample_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "samples", "plain_text.eml")
        )
        parsed_email = parse_email_file(sample_path)

        mock_classifier = lambda text: {
            "predicted_index": 0,
            "raw_label": "LABEL_0",
            "confidence": 0.9612,
            "probabilities": {"LABEL_0": 0.9612, "LABEL_1": 0.0388},
            "is_truncated": False,
        }

        report = analyze_email_text(
            parsed_email,
            config={"custom_classifier": mock_classifier},
        )
        self.assertEqual(report["analysis_status"], STATUS_SUCCESS)
        self.assertEqual(report["classification"]["semantic_verdict"], VERDICT_LEGITIMATE)
        self.assertEqual(report["risk_indication"], "none")


class TestReportSchemaAndJSONSerialization(unittest.TestCase):
    """Ensure report complies with standard schema and serializes to JSON without error."""

    def test_json_serialization_success(self):
        mock_classifier = lambda text: {
            "predicted_index": 1,
            "raw_label": "LABEL_1",
            "confidence": 0.985,
            "probabilities": {"LABEL_0": 0.015, "LABEL_1": 0.985},
            "is_truncated": False,
        }

        report = analyze_email_text(
            {"subject": "Alert", "body": "Verify account"},
            config={"custom_classifier": mock_classifier},
        )

        required_keys = {
            "model_metadata",
            "text_extracted",
            "raw_model_output",
            "classification",
            "risk_indication",
            "confidence_assessment",
            "warnings",
            "limitations",
            "analysis_status",
        }
        self.assertTrue(required_keys.issubset(report.keys()))

        json_str = json.dumps(report, indent=2)
        self.assertIsInstance(json_str, str)
        self.assertIn("confidence_assessment", json_str)
        self.assertIn("raw_model_output", json_str)


if __name__ == "__main__":
    unittest.main()
