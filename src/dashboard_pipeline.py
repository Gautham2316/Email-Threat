"""
src/dashboard_pipeline.py
=========================
Module 8: Analysis Pipeline Orchestration for Interactive Forensic Dashboard
SIH 2026 — AI-Powered Email Threat Detection and Forensic Intelligence Platform

This module bridges the web UI (Module 8) with the existing forensic analysis
engines (Modules 1 through 6) and reporting system (Module 7).

KEY ARCHITECTURAL RESPONSIBILITIES:
1. Accept input either as a filesystem path or as in-memory raw bytes (from file upload).
2. Enforce defensive validation (25 MB limit, .eml format, non-empty content).
3. Securely handle temporary disk artifacts and guarantee safe cleanup.
4. Orchestrate Modules 1 to 6 deterministically, preserving byte fidelity for DKIM.
5. Return a unified, structured analysis payload containing all intermediate forensic
   dictionaries needed for interactive UI tabs, audit trails, and PDF export.
6. Provide safe text extraction and defanging helpers for untrusted email content.
"""
from __future__ import annotations

import hashlib
import os
import re
import tempfile
import time
from datetime import datetime, timezone
from typing import Any, Callable

from src.email_parser import parse_email_file, MAX_FILE_SIZE_BYTES
from src.auth_verifier import verify_authentication
from src.url_analyzer import analyze_urls, defang_url
from src.routing_analyzer import analyze_email_routing
from src.ai_text_analyzer import analyze_email_text
from src.risk_scorer import calculate_email_risk


PIPELINE_VERSION: str = "1.0.0"

# Exact SHA-256 digest of the bundled samples/dkim_signed.eml fixture
DKIM_DEMO_FIXTURE_SHA256: str = (
    "18d8790c953075b2d3f79532e46d58b19f1590dbbca4cbbd0887f2b42195ee2d"
)
DKIM_DEMO_SELECTOR_DOMAIN: bytes = b"test2026._domainkey.example.com"


def resolve_demo_fixture_dkim_dns(
    raw_bytes: bytes,
    mock_file_path: str | None = None,
) -> Callable[[bytes, float], bytes | None] | None:
    """
    Construct a scoped DKIM DNS resolver specifically and exclusively for the
    bundled offline demo fixture (samples/dkim_signed.eml).

    Security & Integrity Guarantees:
    1. Positive Fixture Identification: ONLY activated if the raw email bytes match
       DKIM_DEMO_FIXTURE_SHA256 exactly. Domain or selector names alone NEVER trigger it.
    2. Zero Fabrication: Reads the genuine public key from samples/dkim_dns_mock.txt
       on demand and validates that it is present, non-empty, and contains a valid DKIM tag.
    3. Fail-Closed Design: If the mock file is missing or malformed, raises an explicit
       exception which auth_verifier marks as permerror (never a false pass).
    4. Scope Isolation: For any selector/domain other than test2026._domainkey.example.com,
       delegates directly to dkim.get_txt.
    5. Invariance: Returns None for any other email artifact, ensuring 100% production
       DNS verification behavior.
    """
    if not isinstance(raw_bytes, bytes) or len(raw_bytes) == 0:
        return None

    calculated_hash = hashlib.sha256(raw_bytes).hexdigest()
    if calculated_hash != DKIM_DEMO_FIXTURE_SHA256:
        return None

    if mock_file_path is None:
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        mock_file_path = os.path.join(project_root, "samples", "dkim_dns_mock.txt")

    def _demo_dkim_dns(name: bytes, timeout: float = 5.0) -> bytes | None:
        normalized = (
            name.strip(b".").lower()
            if isinstance(name, bytes)
            else str(name).encode().strip(b".").lower()
        )
        if normalized == DKIM_DEMO_SELECTOR_DOMAIN:
            if not os.path.isfile(mock_file_path):
                raise FileNotFoundError(f"DKIM mock DNS file not found: {mock_file_path}")
            with open(mock_file_path, "r", encoding="utf-8") as f:
                record = f.read().strip()
            if not record or "v=DKIM1" not in record or "p=" not in record:
                raise ValueError(f"Malformed or empty DKIM record in {mock_file_path}")
            return record.encode("utf-8")
        import dkim
        return dkim.get_txt(name, timeout=timeout)

    return _demo_dkim_dns


def validate_email_input(
    input_data: str | bytes,
    original_filename: str | None = None,
) -> tuple[bool, str | None]:
    """
    Validate that the provided input is a valid .eml file or byte payload.

    Parameters
    ----------
    input_data : str | bytes
        Filesystem path to .eml file or raw in-memory bytes.
    original_filename : str, optional
        Filename when input_data is bytes.

    Returns
    -------
    tuple[bool, str | None]
        (True, None) if valid, or (False, "error message") if invalid.
    """
    if input_data is None:
        return False, "Input data is None. Please provide a valid .eml file."

    if isinstance(input_data, bytes):
        if len(input_data) == 0:
            return False, "Uploaded file is empty (0 bytes)."
        if len(input_data) > MAX_FILE_SIZE_BYTES:
            size_mb = len(input_data) / (1024 * 1024)
            limit_mb = MAX_FILE_SIZE_BYTES / (1024 * 1024)
            return False, f"Uploaded file exceeds size limit ({size_mb:.1f} MB > {limit_mb:.0f} MB)."
        if original_filename:
            base, ext = os.path.splitext(original_filename)
            if ext.lower() != ".eml":
                return False, f"File '{original_filename}' does not have a .eml extension."
        return True, None

    if isinstance(input_data, str):
        if not input_data.strip():
            return False, "File path string is empty."
        if not os.path.exists(input_data):
            return False, f"Email file not found at: '{input_data}'"
        if not os.path.isfile(input_data):
            return False, f"Path is not a regular file: '{input_data}'"
        base, ext = os.path.splitext(input_data)
        if ext.lower() != ".eml":
            return False, f"File '{input_data}' must have a .eml extension."
        size = os.path.getsize(input_data)
        if size == 0:
            return False, f"Email file '{input_data}' is empty (0 bytes)."
        if size > MAX_FILE_SIZE_BYTES:
            size_mb = size / (1024 * 1024)
            limit_mb = MAX_FILE_SIZE_BYTES / (1024 * 1024)
            return False, f"File exceeds size limit ({size_mb:.1f} MB > {limit_mb:.0f} MB)."
        return True, None

    return False, f"Unsupported input type '{type(input_data).__name__}'. Expected str or bytes."


def defang_content_text(text: str) -> str:
    """
    Defang URLs and suspicious protocols in arbitrary plain text for safe UI rendering.
    """
    if not text:
        return ""
    # Defang http/https schemes
    defanged = re.sub(r"https?://", lambda m: "hxxps://" if "https" in m.group(0).lower() else "hxxp://", text)
    # Defang domain dots in obvious URL-like contexts
    defanged = re.sub(r"(hxxps?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=]+)", lambda m: m.group(1).replace(".", "[.]"), defanged)
    return defanged


def extract_safe_email_preview(
    parsed_email: dict[str, Any],
    max_body_chars: int = 500,
) -> dict[str, Any]:
    """
    Extract safe, sanitized, and defanged preview metadata suitable for UI cards.

    Guarantees:
    - Never renders active HTML or scripts.
    - Defangs any URLs found in subject or snippet.
    - Truncates body safely to prevent UI overflow.
    """
    if not parsed_email or not isinstance(parsed_email, dict):
        return {
            "subject": "(No metadata)",
            "from": "(Unknown)",
            "to": [],
            "date": "(Not specified)",
            "message_id": None,
            "body_preview": "(No body content)",
            "url_count": 0,
            "is_multipart": False,
        }

    meta = parsed_email.get("email_metadata", {})
    body = parsed_email.get("body", {})
    plain_text = body.get("plain_text") or parsed_email.get("body_text") or ""
    html_text = body.get("html") or ""

    # Choose plain text first, or strip tags if only html is present
    display_body = plain_text
    if not display_body and html_text:
        # Simple plain-text fallback representation
        display_body = re.sub(r"<[^>]+>", " ", html_text)
        display_body = " ".join(display_body.split())

    if len(display_body) > max_body_chars:
        snippet = display_body[:max_body_chars] + " ... [TRUNCATED FOR FORENSIC PREVIEW]"
    else:
        snippet = display_body or "(No readable text body found in message)"

    defanged_subject = defang_content_text(meta.get("subject") or "(No Subject)")
    defanged_snippet = defang_content_text(snippet)

    return {
        "subject": defanged_subject,
        "from": meta.get("from") or "(No Sender Specified)",
        "to": meta.get("to") or [],
        "cc": meta.get("cc") or [],
        "date": meta.get("date") or "(Date Header Missing)",
        "message_id": meta.get("message_id") or "(No Message-ID)",
        "body_preview": defanged_snippet,
        "url_count": len(parsed_email.get("urls", [])),
        "is_multipart": bool(plain_text and html_text),
    }


def run_forensic_pipeline(
    eml_input: str | bytes,
    *,
    original_filename: str | None = None,
    case_id: str | None = None,
) -> dict[str, Any]:
    """
    Execute Modules 1 through 6 on an email artifact and return the unified
    forensic analysis payload.

    Parameters
    ----------
    eml_input : str | bytes
        Filesystem path to .eml file or raw in-memory bytes of the .eml artifact.
    original_filename : str, optional
        Original filename if eml_input is bytes.
    case_id : str, optional
        Case or ticket reference ID (e.g. 'SIH-2026-CASE-001').

    Returns
    -------
    dict[str, Any]
        Structured payload containing:
        - status: 'success' | 'error'
        - case_id: str
        - filename: str
        - file_size_bytes: int
        - raw_bytes: bytes (preserved for DKIM & PDF export)
        - parsed_email: dict (Module 1)
        - auth_result: dict (Module 2)
        - url_result: dict (Module 3)
        - routing_result: dict (Module 4)
        - ai_result: dict (Module 5)
        - risk_report: dict (Module 6)
        - safe_preview: dict
        - pipeline_metadata: dict
        - errors: list[str]
        - warnings: list[str]
    """
    start_time = time.time()
    errors: list[str] = []
    warnings: list[str] = []
    modules_executed: list[str] = []

    case_id = case_id or f"CASE-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"

    # 1. Input Validation
    is_valid, validation_error = validate_email_input(eml_input, original_filename)
    if not is_valid:
        exec_duration = time.time() - start_time
        filename = original_filename or (os.path.basename(eml_input) if isinstance(eml_input, str) else "unknown.eml")
        size_bytes = len(eml_input) if isinstance(eml_input, bytes) else (os.path.getsize(eml_input) if os.path.exists(str(eml_input)) else 0)
        return {
            "status": "error",
            "case_id": case_id,
            "filename": filename,
            "file_size_bytes": size_bytes,
            "raw_bytes": eml_input if isinstance(eml_input, bytes) else b"",
            "parsed_email": None,
            "auth_result": None,
            "url_result": None,
            "routing_result": None,
            "ai_result": None,
            "risk_report": None,
            "safe_preview": None,
            "pipeline_metadata": {
                "executed_at": datetime.now(timezone.utc).isoformat(),
                "execution_time_seconds": round(exec_duration, 4),
                "pipeline_version": PIPELINE_VERSION,
                "modules_executed": [],
            },
            "errors": [validation_error],
            "warnings": [],
        }

    # 2. Materialize filesystem path and raw bytes
    temp_path: str | None = None
    target_path: str = ""
    raw_bytes: bytes = b""

    try:
        if isinstance(eml_input, bytes):
            raw_bytes = eml_input
            # Create a secure temporary file with .eml suffix
            with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as tf:
                tf.write(raw_bytes)
                temp_path = tf.name
            target_path = temp_path
            filename = original_filename or "uploaded_email.eml"
        else:
            target_path = eml_input
            filename = original_filename or os.path.basename(target_path)
            try:
                with open(target_path, "rb") as fh:
                    raw_bytes = fh.read()
            except Exception as e:
                errors.append(f"Failed to read file bytes: {e}")
                return {
                    "status": "error",
                    "case_id": case_id,
                    "filename": filename,
                    "file_size_bytes": 0,
                    "raw_bytes": b"",
                    "parsed_email": None,
                    "auth_result": None,
                    "url_result": None,
                    "routing_result": None,
                    "ai_result": None,
                    "risk_report": None,
                    "safe_preview": None,
                    "pipeline_metadata": {
                        "executed_at": datetime.now(timezone.utc).isoformat(),
                        "execution_time_seconds": round(time.time() - start_time, 4),
                        "pipeline_version": PIPELINE_VERSION,
                        "modules_executed": [],
                    },
                    "errors": errors,
                    "warnings": [],
                }

        # 3. Module 1: Email Ingestion and Parsing
        parsed_email = parse_email_file(target_path)
        modules_executed.append("email_parser")

        # Attach raw bytes and override filename with user-provided name if applicable
        parsed_email["raw_bytes"] = raw_bytes
        if original_filename:
            parsed_email["file_metadata"]["filename"] = original_filename

        if parsed_email.get("errors"):
            errors.extend(parsed_email["errors"])
        if parsed_email.get("parse_warnings"):
            warnings.extend(parsed_email["parse_warnings"])

        # If fatal parsing error prevented metadata extraction, abort gracefully
        if not parsed_email.get("headers") and errors:
            exec_duration = time.time() - start_time
            return {
                "status": "error",
                "case_id": case_id,
                "filename": filename,
                "file_size_bytes": len(raw_bytes),
                "raw_bytes": raw_bytes,
                "parsed_email": parsed_email,
                "auth_result": None,
                "url_result": None,
                "routing_result": None,
                "ai_result": None,
                "risk_report": None,
                "safe_preview": extract_safe_email_preview(parsed_email),
                "pipeline_metadata": {
                    "executed_at": datetime.now(timezone.utc).isoformat(),
                    "execution_time_seconds": round(exec_duration, 4),
                    "pipeline_version": PIPELINE_VERSION,
                    "modules_executed": modules_executed,
                },
                "errors": errors,
                "warnings": warnings,
            }

        # 4. Module 2: Authentication Verification (SPF, DKIM, DMARC)
        try:
            demo_dkim_resolver = resolve_demo_fixture_dkim_dns(raw_bytes)
            auth_result = verify_authentication(
                parsed_email, raw_bytes=raw_bytes, dkim_dnsfunc=demo_dkim_resolver
            )
            modules_executed.append("auth_verifier")
            if auth_result.get("warnings"):
                warnings.extend(auth_result["warnings"])
        except Exception as exc:
            errors.append(f"Authentication verifier encountered an internal error: {exc}")
            auth_result = {
                "overall_result": "error",
                "overall_result_reason": f"Execution error: {exc}",
                "spf": {"lookup_result": "error", "independent_result": "not_checked"},
                "dkim": {"overall_result": "error", "signatures": []},
                "dmarc": {"result": "error"},
                "warnings": [str(exc)],
            }

        # 5. Module 3: URL Threat Analysis
        try:
            url_result = analyze_urls(parsed_email.get("urls", []))
            modules_executed.append("url_analyzer")
            if url_result.get("warnings"):
                warnings.extend(url_result["warnings"])
        except Exception as exc:
            errors.append(f"URL analyzer encountered an internal error: {exc}")
            url_result = {
                "total_urls_analyzed": len(parsed_email.get("urls", [])),
                "max_risk_score": 0,
                "overall_url_risk_level": "error",
                "results": [],
                "warnings": [str(exc)],
            }

        # 6. Module 4: Email Routing Hop Trace & IP Geolocation
        try:
            routing_result = analyze_email_routing(parsed_email.get("received_headers", []), raw_bytes=raw_bytes)
            modules_executed.append("routing_analyzer")
            if routing_result.get("warnings"):
                warnings.extend(routing_result["warnings"])
        except Exception as exc:
            errors.append(f"Routing analyzer encountered an internal error: {exc}")
            routing_result = {
                "hops": [],
                "unique_ips": [],
                "anomalies_detected": False,
                "warnings": [str(exc)],
            }

        # 7. Module 5: AI Phishing & Scam Intent Classification
        try:
            body_text = parsed_email.get("body", {}).get("plain_text") or parsed_email.get("body_text", "")
            ai_result = analyze_email_text(body_text)
            modules_executed.append("ai_text_analyzer")
            if ai_result.get("warnings"):
                warnings.extend(ai_result["warnings"])
        except Exception as exc:
            errors.append(f"AI text analyzer encountered an internal error: {exc}")
            ai_result = {
                "classification": {"semantic_verdict": "error", "confidence": 0.0},
                "model_metadata": {"model_status": "error", "model_id": "unavailable"},
                "warnings": [str(exc)],
            }

        # 8. Module 6: Evidence-Based Multi-Pillar Risk Scorer
        try:
            risk_report = calculate_email_risk(
                parsed_email=parsed_email,
                auth_result=auth_result,
                url_result=url_result,
                routing_result=routing_result,
                ai_result=ai_result,
            )
            modules_executed.append("risk_scorer")
        except Exception as exc:
            errors.append(f"Risk scorer encountered an internal error: {exc}")
            risk_report = {
                "risk_score": 0,
                "risk_level": "inconclusive",
                "verdict_title": "Analysis Error",
                "verdict_description": f"Risk assessment could not complete: {exc}",
                "pillar_scores": {},
                "evidence_contributions": [],
                "scoring_metadata": {},
                "missing_evidence": [],
                "recommendations": ["Investigate email parsing errors."],
            }

        # Extract safe preview for user interface
        safe_preview = extract_safe_email_preview(parsed_email)

        exec_duration = time.time() - start_time
        return {
            "status": "success",
            "case_id": case_id,
            "filename": filename,
            "file_size_bytes": len(raw_bytes),
            "raw_bytes": raw_bytes,
            "parsed_email": parsed_email,
            "auth_result": auth_result,
            "url_result": url_result,
            "routing_result": routing_result,
            "ai_result": ai_result,
            "risk_report": risk_report,
            "safe_preview": safe_preview,
            "pipeline_metadata": {
                "executed_at": datetime.now(timezone.utc).isoformat(),
                "execution_time_seconds": round(exec_duration, 4),
                "pipeline_version": PIPELINE_VERSION,
                "modules_executed": modules_executed,
            },
            "errors": errors,
            "warnings": warnings,
        }

    finally:
        # Guarantee removal of temporary disk file if created
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass
