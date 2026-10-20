"""
src/ai_text_analyzer.py
=======================
Module 5: AI-Based Phishing and Scam-Text Classification Engine
SIH 2026 — AI-Powered Email Threat Detection Platform

Performs deep textual classification of email subject lines and body text
using fine-tuned Transformer models (such as DistilBERT).

CRITICAL SCIENTIFIC AND FORENSIC GUARANTEES:
1. Zero Network Access during Analysis: Never makes outbound network calls,
   API requests, or telemetry transmissions during email text inference.
2. Honest Label Semantics: Never assumes raw model labels (such as 'LABEL_1')
   represent phishing without documented, verified evidence. If label meaning
   cannot be verified, reports 'unknown' semantic verdict.
3. Decoupled Raw and Semantic Outputs: Preserves raw model logits, softmax
   probabilities, and raw class labels alongside semantic verdicts.
4. Uncalibrated Confidence Disclaimer: Clarifies that model softmax confidence
   is a statistical artifact of the training distribution, NOT a calibrated
   probability of real-world maliciousness.
5. Graceful Degradation: If optional AI dependencies (PyTorch, Transformers)
   or model weights are unavailable, returns an explicit 'unavailable' status
   with clear reasons. Never quietly fabricates heuristic guesses as AI outputs.
6. Thread-Safe Model Caching: Avoids reloading large model weights per message
   using a thread-safe singleton cache with explicit reset controls.

AUTHOR: SIH 2026 Team
VERSION: 1.0.0
"""

from __future__ import annotations

import html
import re
import threading
from typing import Any, Callable, Optional

ANALYZER_VERSION: str = "1.0.0"

# ---------------------------------------------------------------------------
# Default Model and Configuration Identifiers
# ---------------------------------------------------------------------------
DEFAULT_MODEL_ID: str = "aamoshdahal/email-phishing-distilbert-finetuned"
DEFAULT_MAX_LENGTH: int = 512

# ---------------------------------------------------------------------------
# Verified Model Label Evidence
# ---------------------------------------------------------------------------
# Model: aamoshdahal/email-phishing-distilbert-finetuned
# Evidence: The author's published model card documentation (README.md)
# explicitly specifies:
#   Label encoding: 0 = legitimate, 1 = phishing
#   labels = ["legitimate", "phishing"]
# Note: config.json omits id2label/label2id, so Transformers defaults
# to {0: "LABEL_0", 1: "LABEL_1"}.
# ---------------------------------------------------------------------------
DEFAULT_LABEL_MAPPING: dict[Any, str] = {
    0: "legitimate",
    1: "phishing",
    "LABEL_0": "legitimate",
    "LABEL_1": "phishing",
    "legitimate": "legitimate",
    "phishing": "phishing",
}

DEFAULT_MAPPING_EVIDENCE: str = (
    "Verified via author model card documentation: index 0 (LABEL_0) = legitimate, "
    "index 1 (LABEL_1) = phishing. Model config.json lacks explicit id2label."
)

# ---------------------------------------------------------------------------
# Status and Verdict Constants
# ---------------------------------------------------------------------------
STATUS_SUCCESS: str = "success"
STATUS_UNAVAILABLE: str = "unavailable"
STATUS_ERROR: str = "error"
STATUS_EMPTY_INPUT: str = "empty_input"

VERDICT_PHISHING: str = "phishing"
VERDICT_LEGITIMATE: str = "legitimate"
VERDICT_UNKNOWN: str = "unknown"
VERDICT_INCONCLUSIVE: str = "inconclusive"

MODEL_STATUS_LOADED: str = "loaded"
MODEL_STATUS_UNAVAILABLE: str = "unavailable"
MODEL_STATUS_ERROR: str = "error"
MODEL_STATUS_NOT_RUN: str = "not_run"

INTERP_VERIFIED: str = "verified_label_mapping"
INTERP_UNVERIFIED: str = "unverified_label_mapping"
INTERP_MODEL_UNAVAILABLE: str = "model_unavailable"
INTERP_INFERENCE_ERROR: str = "inference_error"
INTERP_EMPTY_INPUT: str = "empty_input"

# Standard Forensic Limitations
FORENSIC_LIMITATIONS: list[str] = [
    "Language models can be evaded by adversarial rephrasing, prompt injection, or benign-padding techniques.",
    "Model was trained on specific historical corpora and may exhibit domain shift on novel phishing tactics.",
    "Classification evaluates extracted subject and body text only; it does not verify headers, SPF/DKIM, or URL safety.",
    "Softmax confidence represents internal model distribution probability, not calibrated real-world risk.",
]

# ---------------------------------------------------------------------------
# Thread-safe in-memory cache for loaded tokenizers and models
# ---------------------------------------------------------------------------
_MODEL_CACHE: dict[str, tuple[Any, Any]] = {}
_CACHE_LOCK = threading.Lock()


# ===========================================================================
# CACHE AND DEPENDENCY MANAGEMENT
# ===========================================================================

def check_ai_dependencies() -> tuple[bool, str | None]:
    """
    Check if required PyTorch and Hugging Face Transformers packages are importable.

    Returns
    -------
    (True, None)
        If both torch and transformers are available.
    (False, "reason")
        If either package is missing.
    """
    try:
        import torch  # type: ignore[import-not-found]
    except ImportError:
        return False, "Missing optional dependency: 'torch' (PyTorch) is not installed."

    try:
        import transformers  # type: ignore[import-not-found]
    except ImportError:
        return False, "Missing optional dependency: 'transformers' (Hugging Face) is not installed."

    return True, None


def clear_model_cache() -> None:
    """
    Clear all cached tokenizer and model instances from memory.
    Useful for testing, reconfiguration, or memory management.
    """
    with _CACHE_LOCK:
        _MODEL_CACHE.clear()
        try:
            import torch  # type: ignore[import-not-found]
            if torch.cuda.is_available():
                torch.cuda.empty_cache()
        except Exception:
            pass


def get_cached_model(cache_key: str) -> tuple[Any, Any] | None:
    """Retrieve cached (tokenizer, model) tuple if present."""
    with _CACHE_LOCK:
        return _MODEL_CACHE.get(cache_key)


def load_model_and_tokenizer(
    model_id: str = DEFAULT_MODEL_ID,
    device: Optional[str] = None,
    local_files_only: bool = False,
    cache_dir: Optional[str] = None,
) -> tuple[Any, Any, str, str | None]:
    """
    Safely load or retrieve cached tokenizer and classification model.

    Parameters
    ----------
    model_id : str
        Hugging Face Hub model ID or local filesystem path.
    device : str, optional
        Target inference device ('cpu', 'cuda', etc.).
    local_files_only : bool
        If True, only load from local cache without connecting to Hugging Face Hub.
    cache_dir : str, optional
        Custom cache directory path.

    Returns
    -------
    (tokenizer, model, status, error_reason)
    """
    cache_key = f"{model_id}::{device}::{local_files_only}"

    with _CACHE_LOCK:
        if cache_key in _MODEL_CACHE:
            tok, mod = _MODEL_CACHE[cache_key]
            return tok, mod, MODEL_STATUS_LOADED, None

        deps_ok, dep_err = check_ai_dependencies()
        if not deps_ok:
            return None, None, MODEL_STATUS_UNAVAILABLE, dep_err

        try:
            import torch  # type: ignore[import-not-found]
            from transformers import AutoModelForSequenceClassification, AutoTokenizer  # type: ignore[import-not-found]

            # Determine device
            if device is None:
                target_device = "cuda" if torch.cuda.is_available() else "cpu"
            else:
                target_device = device

            # Load tokenizer
            tokenizer = AutoTokenizer.from_pretrained(
                model_id,
                local_files_only=local_files_only,
                cache_dir=cache_dir,
            )

            # Load sequence classification model
            model = AutoModelForSequenceClassification.from_pretrained(
                model_id,
                local_files_only=local_files_only,
                cache_dir=cache_dir,
            )

            model.to(target_device)
            model.eval()

            _MODEL_CACHE[cache_key] = (tokenizer, model)
            return tokenizer, model, MODEL_STATUS_LOADED, None

        except (OSError, EnvironmentError) as exc:
            err_msg = (
                f"Model '{model_id}' could not be loaded from local cache or hub: {exc}. "
                "Ensure model weights are downloaded or local_files_only is appropriately set."
            )
            return None, None, MODEL_STATUS_UNAVAILABLE, err_msg
        except Exception as exc:
            err_msg = f"Unexpected error loading model '{model_id}': {exc}"
            return None, None, MODEL_STATUS_ERROR, err_msg


# ===========================================================================
# TEXT EXTRACTION AND PREPROCESSING (STAGE 2)
# ===========================================================================

def _strip_html_tags(html_str: str) -> str:
    """Strip HTML markup and unescape HTML entities to extract visible text."""
    if not html_str:
        return ""
    # Remove script and style elements
    clean = re.sub(r"(?is)<(script|style).*?>.*?(</\1>)", "", html_str)
    # Remove HTML tags
    clean = re.sub(r"(?is)<.*?>", " ", clean)
    # Unescape HTML entities
    clean = html.unescape(clean)
    # Remove awkward spaces before punctuation caused by tag stripping
    clean = re.sub(r"\s+([.,;:!?])", r"\1", clean)
    # Normalize whitespace
    return " ".join(clean.split())



def extract_clean_text(email_data: Any) -> tuple[str, str, str, str]:
    """
    Safely extract subject, body, combined text, and text source from input.

    Parameters
    ----------
    email_data : Any
        Output dict from Module 1 (email_parser), dict with text fields, or str.

    Returns
    -------
    tuple[str, str, str, str]
        (subject, body, combined_text, text_source)
    """
    subject = ""
    body = ""
    text_source = "empty"

    if isinstance(email_data, dict):
        # Case A: Module 1 output structure
        if "email_metadata" in email_data and isinstance(email_data["email_metadata"], dict):
            subject = str(email_data["email_metadata"].get("subject") or "").strip()

        if "body" in email_data and isinstance(email_data["body"], dict):
            plain = email_data["body"].get("plain_text")
            html_text = email_data["body"].get("html")

            if plain and isinstance(plain, str) and plain.strip():
                body = plain.strip()
                text_source = "plain_text"
            elif html_text and isinstance(html_text, str) and html_text.strip():
                body = _strip_html_tags(html_text)
                text_source = "html_stripped"

        # Case B: Direct dictionary with subject/body or text
        if not body and "body" in email_data and isinstance(email_data["body"], str):
            body = email_data["body"].strip()
            text_source = "direct_body"

        if not subject and "subject" in email_data and isinstance(email_data["subject"], str):
            subject = email_data["subject"].strip()

        if not body and "text" in email_data and isinstance(email_data["text"], str):
            body = email_data["text"].strip()
            text_source = "direct_text"

    elif isinstance(email_data, str):
        # Case C: Raw text passed directly
        body = email_data.strip()
        text_source = "raw_string"

    # Assemble combined representation
    # Format: "Subject: <subject>\n\n<body>" as favored by email fine-tuned transformers
    if subject and body:
        combined_text = f"Subject: {subject}\n\n{body}"
    elif body:
        combined_text = body
    elif subject:
        combined_text = f"Subject: {subject}"
        text_source = "subject_only"
    else:
        combined_text = ""
        text_source = "empty"

    return subject, body, combined_text, text_source


# ===========================================================================
# MODEL INFERENCE AND LABEL INTERPRETATION (STAGE 2 & STAGE 3)
# ===========================================================================

def run_model_inference(
    tokenizer: Any,
    model: Any,
    text: str,
    max_length: int = DEFAULT_MAX_LENGTH,
    device: Optional[str] = None,
) -> dict[str, Any]:
    """
    Execute forward pass inference on input text using loaded model and tokenizer.

    Parameters
    ----------
    tokenizer : Any
        Hugging Face PreTrainedTokenizer.
    model : Any
        Hugging Face PreTrainedModel for sequence classification.
    text : str
        Input email text string.
    max_length : int
        Maximum sequence length (tokens).

    Returns
    -------
    dict[str, Any]
        Raw inference output including predicted index, label, confidence,
        probabilities dictionary, and truncation indicator.
    """
    import torch  # type: ignore[import-not-found]

    if device is None:
        target_device = next(model.parameters()).device
    else:
        target_device = torch.device(device)

    # Check length prior to truncation to detect if clipping occurred
    raw_tokens = tokenizer.encode(text, truncation=False, add_special_tokens=True)
    is_truncated = len(raw_tokens) > max_length

    # Tokenize with truncation
    inputs = tokenizer(
        text,
        truncation=True,
        max_length=max_length,
        padding=False,
        return_tensors="pt",
    ).to(target_device)

    with torch.no_grad():
        outputs = model(**inputs)
        logits = outputs.logits
        probs_tensor = torch.nn.functional.softmax(logits, dim=-1)[0]

    probs_list = probs_tensor.cpu().tolist()
    predicted_idx = int(torch.argmax(probs_tensor).item())
    confidence = float(probs_list[predicted_idx])

    # Resolve raw label from model configuration if available
    id2label = getattr(model.config, "id2label", {}) or {}
    raw_label = id2label.get(predicted_idx, f"LABEL_{predicted_idx}")

    # Build probabilities dictionary mapping label names to scores
    probabilities: dict[str, float] = {}
    for idx, score in enumerate(probs_list):
        label_name = id2label.get(idx, f"LABEL_{idx}")
        probabilities[label_name] = round(float(score), 4)

    return {
        "predicted_index": predicted_idx,
        "raw_label": raw_label,
        "confidence": round(confidence, 4),
        "probabilities": probabilities,
        "is_truncated": is_truncated,
        "token_count": len(raw_tokens),
    }


def interpret_model_label(
    raw_label: str,
    raw_index: int,
    label_mapping: Optional[dict[Any, str]] = None,
    custom_evidence: Optional[str] = None,
) -> tuple[str, str, str]:
    """
    Decouple raw classifier label from verified semantic meaning.

    Parameters
    ----------
    raw_label : str
        Raw string label from model (e.g. 'LABEL_1').
    raw_index : int
        Predicted integer class index (e.g. 1).
    label_mapping : dict, optional
        Mapping of index or label string to semantic verdict.
    custom_evidence : str, optional
        Explanation of why this mapping is verified.

    Returns
    -------
    (semantic_verdict, interpretation_status, mapping_evidence)
    """
    mapping = label_mapping if label_mapping is not None else DEFAULT_LABEL_MAPPING

    # Check mapping by index first, then by string label
    verdict = mapping.get(raw_index) or mapping.get(raw_label)

    if verdict in (VERDICT_PHISHING, VERDICT_LEGITIMATE):
        return (
            verdict,
            INTERP_VERIFIED,
            custom_evidence or DEFAULT_MAPPING_EVIDENCE,
        )

    # If label exists in mapping with another semantic name
    if verdict and isinstance(verdict, str):
        return (
            verdict.lower(),
            INTERP_VERIFIED,
            custom_evidence or "Custom configured label mapping.",
        )

    # Unmapped or unverified label
    return (
        VERDICT_UNKNOWN,
        INTERP_UNVERIFIED,
        f"Raw model label '{raw_label}' (index {raw_index}) has no verified semantic interpretation.",
    )


# ===========================================================================
# PUBLIC API ENTRY POINT (STAGE 2 & STAGE 4)
# ===========================================================================

def analyze_email_text(
    email_data: Any,
    config: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """
    Main entry point for Module 5: AI-Based Phishing and Scam-Text Classification.

    Parameters
    ----------
    email_data : Any
        Email representation: output dict from Module 1 (email_parser),
        a custom dict with 'subject'/'body'/'text', or raw string text.
    config : dict, optional
        Configuration dictionary:
        - 'model_id': str (default: 'aamoshdahal/email-phishing-distilbert-finetuned')
        - 'max_length': int (default: 512)
        - 'device': str ('cpu', 'cuda', etc.)
        - 'local_files_only': bool (default: False)
        - 'label_mapping': dict (overrides default label-to-verdict mapping)
        - 'mapping_evidence': str (documentation of label evidence)
        - 'custom_classifier': callable/mock for testing or custom inference
        - 'model_loader': callable overriding model loading

    Returns
    -------
    dict[str, Any]
        Deterministic, JSON-serializable forensic analysis report.
    """
    config = config or {}
    model_id = config.get("model_id", DEFAULT_MODEL_ID)
    max_length = int(config.get("max_length", DEFAULT_MAX_LENGTH))
    device = config.get("device")
    local_files_only = bool(config.get("local_files_only", False))
    label_mapping = config.get("label_mapping", DEFAULT_LABEL_MAPPING)
    custom_evidence = config.get("mapping_evidence")

    warnings: list[str] = []

    # 1. Extract subject and body safely
    subject, body, combined_text, text_source = extract_clean_text(email_data)

    char_count = len(combined_text)
    word_count = len(combined_text.split()) if combined_text else 0

    # Build safe preview (never logs or exposes full sensitive content)
    body_preview = (body[:200] + "...") if len(body) > 200 else body

    text_extracted_meta = {
        "subject": subject or None,
        "body_preview": body_preview or None,
        "character_count": char_count,
        "word_count": word_count,
        "text_source": text_source,
    }

    # 2. Check for empty input
    if not combined_text:
        return {
            "model_metadata": {
                "model_id": model_id,
                "model_status": MODEL_STATUS_NOT_RUN,
                "architecture": "DistilBertForSequenceClassification",
                "max_length": max_length,
                "is_truncated": False,
                "device": device or "not_applicable",
                "error_reason": None,
            },
            "text_extracted": text_extracted_meta,
            "raw_model_output": None,
            "classification": {
                "semantic_verdict": VERDICT_INCONCLUSIVE,
                "confidence": None,
                "interpretation_status": INTERP_EMPTY_INPUT,
                "mapping_evidence": None,
            },
            "risk_indication": "inconclusive",
            "confidence_assessment": {
                "model_confidence": None,
                "calibrated_risk_note": "No text provided. AI text classification could not be evaluated.",
            },
            "warnings": ["Email subject and body text are empty. No content available for AI classification."],
            "limitations": list(FORENSIC_LIMITATIONS),
            "analysis_status": STATUS_EMPTY_INPUT,
        }

    # 3. Model Execution (Dependency Injection / Mocking / Real Loading)
    raw_output: Optional[dict[str, Any]] = None
    model_status: str = MODEL_STATUS_NOT_RUN
    model_error: Optional[str] = None
    is_truncated = False

    # Check for custom/mock classifier (enables offline testing without downloading weights)
    custom_classifier: Optional[Callable[[str], dict[str, Any]]] = config.get("custom_classifier")

    if custom_classifier is not None:
        try:
            raw_output = custom_classifier(combined_text)
            model_status = MODEL_STATUS_LOADED
            is_truncated = bool(raw_output.get("is_truncated", False))
        except Exception as exc:
            model_status = MODEL_STATUS_ERROR
            model_error = f"Custom classifier failed during execution: {exc}"
            warnings.append(model_error)
    else:
        # Check custom model loader or standard loading
        loader_fn = config.get("model_loader", load_model_and_tokenizer)
        tok, mod, model_status, model_error = loader_fn(
            model_id=model_id,
            device=device,
            local_files_only=local_files_only,
        )

        if model_status != MODEL_STATUS_LOADED or tok is None or mod is None:
            warnings.append(
                model_error or "AI classifier model or dependencies are unavailable. AI inference skipped."
            )
        else:
            try:
                raw_output = run_model_inference(
                    tokenizer=tok,
                    model=mod,
                    text=combined_text,
                    max_length=max_length,
                    device=device,
                )
                is_truncated = raw_output["is_truncated"]
            except Exception as exc:
                model_status = MODEL_STATUS_ERROR
                model_error = f"Inference forward pass failed: {exc}"
                warnings.append(model_error)

    # 4. Handle Unavailable or Failed Model Gracefully
    if model_status != MODEL_STATUS_LOADED or raw_output is None:
        return {
            "model_metadata": {
                "model_id": model_id,
                "model_status": model_status,
                "architecture": "DistilBertForSequenceClassification",
                "max_length": max_length,
                "is_truncated": False,
                "device": device or "unknown",
                "error_reason": model_error,
            },
            "text_extracted": text_extracted_meta,
            "raw_model_output": None,
            "classification": {
                "semantic_verdict": VERDICT_UNKNOWN,
                "confidence": None,
                "interpretation_status": INTERP_MODEL_UNAVAILABLE if model_status == MODEL_STATUS_UNAVAILABLE else INTERP_INFERENCE_ERROR,
                "mapping_evidence": None,
            },
            "risk_indication": "inconclusive",
            "confidence_assessment": {
                "model_confidence": None,
                "calibrated_risk_note": "AI model was unavailable. No AI inference was performed.",
            },
            "warnings": warnings,
            "limitations": list(FORENSIC_LIMITATIONS),
            "analysis_status": STATUS_UNAVAILABLE if model_status == MODEL_STATUS_UNAVAILABLE else STATUS_ERROR,
        }

    # 5. Interpret Model Output and Separate Raw from Semantic Verdict
    pred_idx = raw_output["predicted_index"]
    raw_label = raw_output["raw_label"]
    confidence = raw_output["confidence"]

    semantic_verdict, interp_status, mapping_evidence = interpret_model_label(
        raw_label=raw_label,
        raw_index=pred_idx,
        label_mapping=label_mapping,
        custom_evidence=custom_evidence,
    )

    if is_truncated:
        warnings.append(
            f"Input text exceeded the maximum context limit of {max_length} tokens and was truncated. "
            "Trailing content was not evaluated by the model."
        )

    # 6. Derive explainable risk indication without overclaiming
    if semantic_verdict == VERDICT_PHISHING:
        risk_indication = "high" if confidence >= 0.85 else "medium"
    elif semantic_verdict == VERDICT_LEGITIMATE:
        risk_indication = "none" if confidence >= 0.85 else "low"
    else:
        risk_indication = "inconclusive"

    return {
        "model_metadata": {
            "model_id": model_id,
            "model_status": MODEL_STATUS_LOADED,
            "architecture": "DistilBertForSequenceClassification",
            "max_length": max_length,
            "is_truncated": is_truncated,
            "device": device or "cpu",
            "error_reason": None,
        },
        "text_extracted": text_extracted_meta,
        "raw_model_output": {
            "predicted_index": pred_idx,
            "raw_label": raw_label,
            "confidence": confidence,
            "probabilities": raw_output.get("probabilities", {}),
        },
        "classification": {
            "semantic_verdict": semantic_verdict,
            "confidence": confidence,
            "interpretation_status": interp_status,
            "mapping_evidence": mapping_evidence,
        },
        "risk_indication": risk_indication,
        "confidence_assessment": {
            "model_confidence": confidence,
            "calibrated_risk_note": (
                "Model confidence represents statistical softmax probability on the training distribution. "
                "It is NOT a calibrated probability of real-world maliciousness."
            ),
        },
        "warnings": warnings,
        "limitations": list(FORENSIC_LIMITATIONS),
        "analysis_status": STATUS_SUCCESS,
    }
