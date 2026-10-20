"""
src/risk_scorer.py
==================
Module 6: Evidence-Based Email Risk Scoring Engine
SIH 2026 — AI-Powered Email Threat Detection Platform

Synthesizes, cross-correlates, and aggregates forensic findings across
Modules 1 through 5 into a unified, explainable, bounded email threat assessment.

FOUR-PILLAR EVIDENCE MODEL:
1. Identity & Authentication Integrity (Modules 1 & 2):
   Evaluates SPF/DKIM/DMARC evidence, domain alignment, and display-name spoofing.
   Budget Cap: 35 points.
2. URL & Link Threat Heuristics (Module 3):
   Evaluates brand spoofing in subdomains, credential authority, dangerous schemes,
   payload downloads, path traversal, and homoglyphs with multi-URL dampening.
   Budget Cap: 35 points.
3. AI Textual & Phishing Intent Classification (Module 5):
   Evaluates deep semantic model classification and confidence with statistical caveats.
   Budget Cap: 25 points.
4. Transport & Routing Anomalies (Module 4):
   Evaluates transmission hops, unverified boundaries, and timestamp consistency.
   Budget Cap: 15 points.

CRITICAL FORENSIC AND ETHICAL GUARANTEES:
1. Zero Network Access: Never performs external network requests, DNS queries,
   or URL visiting.
2. Honest Absence of Evidence: Missing evidence (such as 'not_checked' SPF,
   unavailable GeoLite2 database, or absent AI model) is strictly NEUTRAL and
   never penalizes the score.
3. Multi-Signal Correlated Dampening: Multiple instances of the same indicator
   are dampened with diminishing returns to prevent artificial score inflation.
4. Single-Signal Safeguard: A single isolated heuristic (such as a shortened URL
   or unfamiliar TLD) cannot push an email into 'high' or 'critical' risk.
5. Strict Range Bounding: The composite risk score is strictly bounded in [0, 100].
6. Complete Mathematical Auditability: Every evidence item clearly distinguishes
   raw points, dampened points, pillar cap adjustments, and effective contributions,
   reconciling exactly with pillar and composite risk scores.

AUTHOR: SIH 2026 Team
VERSION: 1.0.0
"""

from __future__ import annotations

import json
from typing import Any, Optional

SCORING_VERSION: str = "1.0.0"
SCORER_VERSION: str = SCORING_VERSION

# ---------------------------------------------------------------------------
# Risk Level Thresholds
# ---------------------------------------------------------------------------
THRESHOLD_NONE_MAX: int = 19       # 0 - 19: None / Benign
THRESHOLD_LOW_MAX: int = 39        # 20 - 39: Low
THRESHOLD_MEDIUM_MAX: int = 69     # 40 - 69: Medium
THRESHOLD_HIGH_MAX: int = 89       # 70 - 89: High
                                   # 90 - 100: Critical

RISK_LEVEL_NONE: str = "none"
RISK_LEVEL_LOW: str = "low"
RISK_LEVEL_MEDIUM: str = "medium"
RISK_LEVEL_HIGH: str = "high"
RISK_LEVEL_CRITICAL: str = "critical"
RISK_LEVEL_INCONCLUSIVE: str = "inconclusive"

RISK_LEVEL_THRESHOLDS: dict[str, tuple[int, int]] = {
    RISK_LEVEL_NONE: (0, THRESHOLD_NONE_MAX),
    RISK_LEVEL_LOW: (20, THRESHOLD_LOW_MAX),
    RISK_LEVEL_MEDIUM: (40, THRESHOLD_MEDIUM_MAX),
    RISK_LEVEL_HIGH: (70, THRESHOLD_HIGH_MAX),
    RISK_LEVEL_CRITICAL: (90, 100),
}

# ---------------------------------------------------------------------------
# Maximum Weight Allocations Per Pillar
# ---------------------------------------------------------------------------
PILLAR_WEIGHT_AUTH: int = 35    # Identity & Authentication
PILLAR_WEIGHT_URL: int = 35     # URL & Link Threats
PILLAR_WEIGHT_AI: int = 25      # AI Text & Phishing Intent
PILLAR_WEIGHT_ROUTING: int = 15 # Routing & Transport

PILLAR_BUDGETS: dict[str, int] = {
    "identity_auth": PILLAR_WEIGHT_AUTH,
    "url_threats": PILLAR_WEIGHT_URL,
    "ai_content": PILLAR_WEIGHT_AI,
    "routing_transport": PILLAR_WEIGHT_ROUTING,
}

DIMINISHING_RETURNS_SCALE: tuple[float, ...] = (1.0, 1.3, 1.5)

# ---------------------------------------------------------------------------
# High-Profile Brand Names for Display-Name Spoofing Detection
# ---------------------------------------------------------------------------
KNOWN_BRANDS: tuple[str, ...] = (
    "paypal", "microsoft", "office365", "outlook", "google", "gmail",
    "apple", "icloud", "amazon", "netflix", "facebook", "instagram",
    "whatsapp", "chase", "bank of america", "wells fargo", "citibank",
    "dhl", "fedex", "usps", "adobe", "dropbox", "docusign", "sbi", "hdfc",
)


def _determine_risk_level(score: int) -> str:
    """Map numeric score in [0, 100] to semantic risk level string."""
    if score <= THRESHOLD_NONE_MAX:
        return RISK_LEVEL_NONE
    elif score <= THRESHOLD_LOW_MAX:
        return RISK_LEVEL_LOW
    elif score <= THRESHOLD_MEDIUM_MAX:
        return RISK_LEVEL_MEDIUM
    elif score <= THRESHOLD_HIGH_MAX:
        return RISK_LEVEL_HIGH
    else:
        return RISK_LEVEL_CRITICAL


# ===========================================================================
# HELPER EXTRACTION & ATTRIBUTION FUNCTIONS
# ===========================================================================

def _extract_domain(email_address: str | None) -> str | None:
    """Extract domain from an email address string like 'User <user@example.com>'."""
    if not email_address or not isinstance(email_address, str):
        return None
    cleaned = email_address.strip()
    if "<" in cleaned and ">" in cleaned:
        cleaned = cleaned.split("<")[1].split(">")[0].strip()
    if "@" in cleaned:
        return cleaned.split("@")[1].strip().lower()
    return None


def _check_display_name_spoofing(from_header: str | None) -> tuple[bool, str | None, str | None]:
    """
    Check if a high-profile brand name appears in the display name while the
    underlying email address belongs to an unrelated domain.
    """
    if not from_header or not isinstance(from_header, str):
        return False, None, None

    clean = from_header.strip()
    if "<" not in clean or ">" not in clean:
        return False, None, None

    display_name = clean.split("<")[0].strip().strip('"').strip("'").lower()
    email_addr = clean.split("<")[1].split(">")[0].strip().lower()

    if not display_name or "@" not in email_addr:
        return False, None, None

    addr_domain = email_addr.split("@")[1].strip().lower()

    for brand in KNOWN_BRANDS:
        brand_token = brand.replace(" ", "")
        if brand in display_name or brand_token in display_name:
            if brand_token not in addr_domain and brand.replace(" ", "") not in addr_domain:
                return True, brand, addr_domain

    return False, None, None


def _attribute_pillar_budget(
    evidence_items: list[dict[str, Any]],
    pillar_budget: int,
) -> tuple[int, int, list[dict[str, Any]]]:
    """
    Reconcile individual evidence items against a pillar's maximum budget cap.

    If the sum of dampened points exceeds the pillar budget cap, points are
    distributed proportionally using the Largest Remainder Method (Hamilton-Hare quota).
    This ensures that the sum of 'effective_contribution' (and 'score_contribution')
    EXACTLY equals the capped pillar score, eliminating credit reconciliation discrepancies.

    Returns:
        (capped_score, uncapped_dampened_total, updated_evidence_items)
    """
    if not evidence_items:
        return 0, 0, []

    uncapped_total = sum(e.get("dampened_points", 0) for e in evidence_items)
    if uncapped_total == 0:
        for e in evidence_items:
            e["effective_contribution"] = 0
            e["score_contribution"] = 0
            e["contribution"] = 0
            e["pillar_cap_reduction"] = 0
        return 0, 0, evidence_items

    capped_score = min(pillar_budget, uncapped_total)

    if uncapped_total <= pillar_budget:
        # No capping needed; dampened points are the effective contribution
        for e in evidence_items:
            dp = e.get("dampened_points", 0)
            e["effective_contribution"] = dp
            e["score_contribution"] = dp
            e["contribution"] = dp
            e["pillar_cap_reduction"] = 0
        return capped_score, uncapped_total, evidence_items

    # Uncapped total exceeds budget: distribute capped_score proportionally
    scale = capped_score / uncapped_total
    allocated: list[int] = []
    remainders: list[tuple[float, int]] = []

    for idx, e in enumerate(evidence_items):
        dp = e.get("dampened_points", 0)
        exact = dp * scale
        base_alloc = int(exact)
        rem = exact - base_alloc
        allocated.append(base_alloc)
        remainders.append((rem, idx))

    # Distribute leftover points to largest remainders
    leftover = capped_score - sum(allocated)
    remainders.sort(key=lambda x: x[0], reverse=True)
    for i in range(leftover):
        allocated[remainders[i][1]] += 1

    for idx, e in enumerate(evidence_items):
        eff = allocated[idx]
        dp = e.get("dampened_points", 0)
        e["effective_contribution"] = eff
        e["score_contribution"] = eff
        e["contribution"] = eff
        e["pillar_cap_reduction"] = eff - dp

    return capped_score, uncapped_total, evidence_items


# ===========================================================================
# PILLAR EVALUATION LOGIC
# ===========================================================================

def _evaluate_identity_and_auth(
    email_data: Optional[dict[str, Any]],
    auth_data: Optional[dict[str, Any]],
) -> tuple[int, int, list[dict[str, Any]], list[dict[str, Any]], list[dict[str, str]], str]:
    """
    Evaluate Pillar 1: Identity & Authentication Integrity.
    Budget Cap: 35 points.
    """
    evidence: list[dict[str, Any]] = []
    positive_signals: list[dict[str, Any]] = []
    missing_evidence: list[dict[str, str]] = []
    status = "not_evaluated"

    if email_data is None and auth_data is None:
        return 0, 0, evidence, positive_signals, [{"field": "authentication", "reason": "Authentication data not supplied."}], status

    status = "evaluated"

    # 1. Inspect Header-Level Identity Divergences (Module 1)
    if email_data and isinstance(email_data, dict):
        meta = email_data.get("email_metadata", {})
        headers = email_data.get("headers", {})
        from_val = meta.get("from") or headers.get("from") or email_data.get("from")
        return_path = meta.get("return_path") or headers.get("return-path") or email_data.get("return_path")

        # A. Display name brand spoofing
        is_spoof, brand, domain = _check_display_name_spoofing(from_val)
        if is_spoof and brand and domain:
            evidence.append({
                "id": "AUTH_DISPLAY_NAME_BRAND_MISMATCH",
                "indicator": "display_name_spoofing",
                "title": f"Display Name Brand Impersonation ({brand.title()})",
                "source_module": "email_parser",
                "pillar": "identity_auth",
                "evidence_type": "heuristic_indicator",
                "severity": "high",
                "occurrence_count": 1,
                "base_points": 15,
                "raw_points": 15,
                "dampened_points": 15,
                "pillar_cap_reduction": 0,
                "effective_contribution": 15,
                "score_contribution": 15,
                "contribution": 15,
                "explanation": (
                    f"The From display name contains brand '{brand.title()}', but the actual sender "
                    f"address uses unrelated domain '{domain}'."
                ),
            })

        # B. From domain vs. Return-Path domain divergence
        from_dom = _extract_domain(from_val)
        rp_dom = _extract_domain(return_path)
        if from_dom and rp_dom and from_dom != rp_dom:
            evidence.append({
                "id": "AUTH_RETURN_PATH_DIVERGENCE",
                "indicator": "return_path_mismatch",
                "title": "Sender and Return-Path Domain Mismatch",
                "source_module": "email_parser",
                "pillar": "identity_auth",
                "evidence_type": "heuristic_indicator",
                "severity": "medium",
                "occurrence_count": 1,
                "base_points": 8,
                "raw_points": 8,
                "dampened_points": 8,
                "pillar_cap_reduction": 0,
                "effective_contribution": 8,
                "score_contribution": 8,
                "contribution": 8,
                "explanation": (
                    f"Message displays sender domain '{from_dom}', but bounce Return-Path points "
                    f"to divergent domain '{rp_dom}'."
                ),
            })

    # 2. Inspect Authentication Results (Module 2)
    if auth_data and isinstance(auth_data, dict):
        if auth_data.get("spoofing_detected"):
            evidence.append({
                "id": "AUTH_SPOOFING_CONFIRMED",
                "indicator": "spoofing_detected",
                "title": "Identity Spoofing Detected",
                "source_module": "auth_verifier",
                "pillar": "identity_auth",
                "evidence_type": "observed_fact",
                "severity": "high",
                "occurrence_count": 1,
                "base_points": 15,
                "raw_points": 15,
                "dampened_points": 15,
                "pillar_cap_reduction": 0,
                "effective_contribution": 15,
                "score_contribution": 15,
                "contribution": 15,
                "explanation": "Authentication verifier flagged active domain or identity spoofing.",
            })

        # A. DKIM verification
        dkim_info = auth_data.get("dkim", {})
        dkim_overall = dkim_info.get("overall_result") or dkim_info.get("status")

        if dkim_overall == "pass":
            positive_signals.append({
                "id": "AUTH_DKIM_PASS",
                "indicator": "dkim_pass",
                "title": "Valid Cryptographic DKIM Signature",
                "source_module": "auth_verifier",
                "pillar": "identity_auth",
                "description": "Email body and headers verified intact against the domain public key.",
                "mitigation_points": 10,
            })
        elif dkim_overall == "fail":
            evidence.append({
                "id": "AUTH_DKIM_FAIL",
                "indicator": "dkim_fail",
                "title": "DKIM Cryptographic Signature Failure",
                "source_module": "auth_verifier",
                "pillar": "identity_auth",
                "evidence_type": "observed_fact",
                "severity": "high",
                "occurrence_count": 1,
                "base_points": 20,
                "raw_points": 20,
                "dampened_points": 20,
                "pillar_cap_reduction": 0,
                "effective_contribution": 20,
                "score_contribution": 20,
                "contribution": 20,
                "explanation": "DKIM signature verification failed, indicating content tampering or key mismatch.",
            })
        elif dkim_overall in ("none", "not_checked", None):
            pass

        # B. DMARC policy check
        dmarc_info = auth_data.get("dmarc", {})
        dmarc_res = dmarc_info.get("result") or dmarc_info.get("status")
        policy = dmarc_info.get("policy")
        policy_str = policy.get("p") if isinstance(policy, dict) else str(policy or "none")

        if dmarc_res == "fail":
            pts = 25 if policy_str in ("reject", "quarantine") else 18
            evidence.append({
                "id": "AUTH_DMARC_FAIL",
                "indicator": "dmarc_fail",
                "title": f"DMARC Policy Failure (policy={policy_str})",
                "source_module": "auth_verifier",
                "pillar": "identity_auth",
                "evidence_type": "observed_fact",
                "severity": "high" if policy_str in ("reject", "quarantine") else "medium",
                "occurrence_count": 1,
                "base_points": pts,
                "raw_points": pts,
                "dampened_points": pts,
                "pillar_cap_reduction": 0,
                "effective_contribution": pts,
                "score_contribution": pts,
                "contribution": pts,
                "explanation": "Email failed DMARC domain alignment and authentication checks.",
            })
        elif dmarc_res == "pass":
            positive_signals.append({
                "id": "AUTH_DMARC_PASS",
                "indicator": "dmarc_pass",
                "title": "DMARC Alignment Verified",
                "source_module": "auth_verifier",
                "pillar": "identity_auth",
                "description": "Sender domain aligns with verified cryptographic authentication.",
                "mitigation_points": 10,
            })

        # C. SPF - Strictly enforce honest absence
        spf_info = auth_data.get("spf", {})
        spf_ind = spf_info.get("independent_result") or spf_info.get("status")
        if spf_ind in ("not_checked", "none", None):
            missing_evidence.append({
                "field": "spf",
                "reason": "SPF delivery-time connecting IP was not independently verified from static file.",
            })

    capped_score, uncapped_total, evidence = _attribute_pillar_budget(evidence, PILLAR_WEIGHT_AUTH)
    return capped_score, uncapped_total, evidence, positive_signals, missing_evidence, status


def _evaluate_url_threats(
    url_data: Optional[dict[str, Any]],
) -> tuple[int, int, list[dict[str, Any]], list[dict[str, Any]], list[dict[str, str]], str]:
    """
    Evaluate Pillar 2: URL & Link Threats.
    Budget Cap: 35 points with multi-URL dampening and credit attribution.
    """
    evidence: list[dict[str, Any]] = []
    positive_signals: list[dict[str, Any]] = []
    missing_evidence: list[dict[str, str]] = []
    status = "not_evaluated"

    if url_data is None or not isinstance(url_data, dict):
        return 0, 0, evidence, positive_signals, [{"field": "url_analysis", "reason": "URL analysis data not supplied."}], status

    total_urls = url_data.get("total_urls_analyzed", 0)
    analysis_status = url_data.get("analysis_status")

    if total_urls == 0 and analysis_status == "no_urls":
        return 0, 0, evidence, positive_signals, missing_evidence, "no_urls"

    url_results = url_data.get("results")
    findings_list = url_data.get("findings")
    indicators_list = url_data.get("indicators")

    items_to_process: list[dict[str, Any]] = []
    if isinstance(findings_list, list):
        items_to_process.extend(findings_list)
    if isinstance(indicators_list, list):
        items_to_process.extend(indicators_list)
    if isinstance(url_results, list):
        for u in url_results:
            if isinstance(u, dict):
                inds = u.get("indicators", [])
                if isinstance(inds, list):
                    items_to_process.extend(inds)

    if not items_to_process and total_urls == 0:
        return 0, 0, evidence, positive_signals, missing_evidence, "no_urls"

    status = "evaluated"

    # Group indicators across URLs to apply intra-indicator diminishing returns
    seen_indicators: dict[str, list[dict[str, Any]]] = {}
    for item in items_to_process:
        if not isinstance(item, dict):
            continue
        ind_key = str(item.get("id") or item.get("indicator") or "UNKNOWN").upper()
        if ind_key not in seen_indicators:
            seen_indicators[ind_key] = []
        seen_indicators[ind_key].append(item)

    # Evaluate unique indicators with diminishing returns for repeated occurrences
    for ind_id, items in seen_indicators.items():
        count = len(items)
        sample = items[0]
        base_score = 0
        severity = sample.get("severity") or "low"
        explanation = sample.get("description") or sample.get("explanation") or ""

        if any(term in ind_id for term in ("EXECUTABLE", "PAYLOAD")):
            base_score = 35
            severity = "critical"
            if not explanation:
                explanation = "Link points directly to an executable, script, or dangerous archive payload."
        elif any(term in ind_id for term in ("DANGEROUS_SCHEME", "JAVASCRIPT", "DATA_SCHEME", "FILE_SCHEME")):
            base_score = 35
            severity = "critical"
            if not explanation:
                explanation = "Executable or dangerous URI scheme detected in email link."
        elif any(term in ind_id for term in ("BRAND_SPOOFING", "BRAND_NAME_MISMATCH", "BRAND_IN_SUBDOMAIN")):
            base_score = 22
            severity = "high"
            if not explanation:
                explanation = "Deceptive brand spoofing detected in domain or subdomain structure."
        elif any(term in ind_id for term in ("EMBEDDED_CREDENTIALS", "EMBEDDED_USER", "CREDENTIAL")):
            base_score = 20
            severity = "high"
            if not explanation:
                explanation = "Deceptive credentials or host authority embedded in URL authority segment."
        elif any(term in ind_id for term in ("PATH_TRAVERSAL", "NULL_BYTE", "PERCENT_ENCODING")):
            base_score = 18
            severity = "high"
            if not explanation:
                explanation = "Evasion or path manipulation sequence detected in URL."
        elif any(term in ind_id for term in ("PUNYCODE", "HOMOGRAPH")):
            base_score = 18
            severity = "high"
            if not explanation:
                explanation = "Punycode or non-Latin homograph mimicking legitimate ASCII domain."
        elif "IP_ADDRESS" in ind_id or "IP_HOST" in ind_id:
            if "PRIVATE" in ind_id or "LOOPBACK" in ind_id:
                base_score = 10
                severity = "medium"
                if not explanation:
                    explanation = "Link references private or internal network IP address."
            else:
                base_score = 15
                severity = "medium"
                if not explanation:
                    explanation = "URL uses bare public IP address instead of registered domain."
        elif any(term in ind_id for term in ("SHORTENER", "HIGH_RISK_TLD", "TLD", "INSECURE_HTTP")):
            base_score = 5
            severity = "low"
            if not explanation:
                explanation = "Informational heuristic risk indicator (shortener, high-abuse TLD, or unencrypted HTTP)."
        else:
            base_score = 5
            severity = "low"
            if not explanation:
                explanation = "General heuristic URL anomaly."

        # Apply multi-URL repetition dampening: 1st full, 2nd +30%, 3rd+ +20%
        multiplier = 1.0
        if count == 2:
            multiplier = DIMINISHING_RETURNS_SCALE[1]
        elif count >= 3:
            multiplier = DIMINISHING_RETURNS_SCALE[2]

        raw_pts = base_score * count
        dampened_pts = round(base_score * multiplier)

        norm_ind = ind_id.lower()
        if "shortener" in norm_ind:
            indicator_label = "shortener_service"
        elif "tld" in norm_ind:
            indicator_label = "high_risk_tld"
        elif "brand" in norm_ind:
            indicator_label = "brand_in_subdomain"
        elif "payload" in norm_ind or "exe" in norm_ind:
            indicator_label = "executable_payload"
        elif "scheme" in norm_ind:
            indicator_label = "dangerous_scheme"
        else:
            indicator_label = norm_ind

        evidence.append({
            "id": f"URL_{ind_id}",
            "indicator": indicator_label,
            "title": ind_id.replace("_", " ").title(),
            "source_module": "url_analyzer",
            "pillar": "url_threats",
            "evidence_type": "heuristic_indicator",
            "severity": severity,
            "occurrence_count": count,
            "base_points": base_score,
            "raw_points": raw_pts,
            "dampened_points": dampened_pts,
            "multi_occurrence_dampening_reduction": raw_pts - dampened_pts,
            "pillar_cap_reduction": 0,
            "effective_contribution": dampened_pts,
            "score_contribution": dampened_pts,
            "contribution": dampened_pts,
            "explanation": f"{explanation} (Found {count} occurrence{'s' if count > 1 else ''}).",
        })

    # If URLs are present and completely clean
    max_risk = url_data.get("max_risk_score", 0)
    high_count = url_data.get("high_risk_urls") or url_data.get("high_risk_url_count") or 0
    suspicious_count = url_data.get("suspicious_urls") or 0

    if total_urls > 0 and max_risk == 0 and not seen_indicators and high_count == 0 and suspicious_count == 0:
        positive_signals.append({
            "id": "URL_ALL_CLEAN",
            "indicator": "clean_urls",
            "title": "Clean URLs Analyzed",
            "source_module": "url_analyzer",
            "pillar": "url_threats",
            "description": f"Analyzed {total_urls} URL(s) with no suspicious heuristic indicators detected.",
            "mitigation_points": 5,
        })

    capped_score, uncapped_total, evidence = _attribute_pillar_budget(evidence, PILLAR_WEIGHT_URL)
    return capped_score, uncapped_total, evidence, positive_signals, missing_evidence, status


def _evaluate_ai_content(
    ai_data: Optional[dict[str, Any]],
) -> tuple[int, int, list[dict[str, Any]], list[dict[str, Any]], list[dict[str, str]], str]:
    """
    Evaluate Pillar 3: AI Textual & Intent Classification.
    Budget Cap: 25 points.
    """
    evidence: list[dict[str, Any]] = []
    positive_signals: list[dict[str, Any]] = []
    missing_evidence: list[dict[str, str]] = []
    status = "not_evaluated"

    if ai_data is None or not isinstance(ai_data, dict):
        return 0, 0, evidence, positive_signals, [{"field": "ai_phishing_classifier", "reason": "AI text classification data not supplied."}], status

    meta = ai_data.get("model_metadata", {})
    cls_info = ai_data.get("classification", {})
    model_status = meta.get("model_status") or ai_data.get("model_status")
    analysis_status = ai_data.get("analysis_status")

    if model_status == "unavailable" or analysis_status in ("unavailable", "skipped"):
        missing_evidence.append({
            "field": "ai_phishing_classifier",
            "reason": "AI text classification model was unavailable; AI intent analysis skipped.",
        })
        return 0, 0, evidence, positive_signals, missing_evidence, "unavailable"

    if analysis_status == "empty_input":
        missing_evidence.append({
            "field": "ai_phishing_classifier",
            "reason": "Email text was empty; AI classification was not run.",
        })
        return 0, 0, evidence, positive_signals, missing_evidence, "empty_input"

    if model_status == "error" or analysis_status == "error":
        missing_evidence.append({
            "field": "ai_phishing_classifier",
            "reason": "AI model inference encountered a runtime error.",
        })
        return 0, 0, evidence, positive_signals, missing_evidence, "error"

    verdict = cls_info.get("semantic_verdict") or ai_data.get("verdict")
    if not isinstance(verdict, str):
        return 0, 0, evidence, positive_signals, missing_evidence, "unknown"

    verdict_lower = verdict.lower()
    conf_raw = cls_info.get("confidence") if cls_info.get("confidence") is not None else ai_data.get("confidence")
    try:
        confidence = float(conf_raw) if conf_raw is not None else 0.0
    except (ValueError, TypeError):
        confidence = 0.0

    status = "evaluated"

    if verdict_lower == "phishing":
        score_contrib = round(confidence * PILLAR_WEIGHT_AI)
        severity = "high" if confidence >= 0.85 else "medium"

        evidence.append({
            "id": "AI_PHISHING_INTENT_DETECTED",
            "indicator": "ai_phishing_verdict",
            "title": f"AI Intent Classification: Phishing ({confidence:.1%} confidence)",
            "source_module": "ai_text_analyzer",
            "pillar": "ai_content",
            "evidence_type": "ai_prediction",
            "severity": severity,
            "occurrence_count": 1,
            "base_points": PILLAR_WEIGHT_AI,
            "raw_points": score_contrib,
            "dampened_points": score_contrib,
            "pillar_cap_reduction": 0,
            "effective_contribution": score_contrib,
            "score_contribution": score_contrib,
            "contribution": score_contrib,
            "explanation": (
                f"Pretrained transformer model classified email text as phishing with {confidence:.1%} confidence. "
                "Confidence represents the model's internal token classification distribution, "
                "NOT a calibrated real-world probability that the email is malicious."
            ),
        })
    elif verdict_lower in ("legitimate", "benign", "clean"):
        if confidence >= 0.80:
            positive_signals.append({
                "id": "AI_LEGITIMATE_CONTENT_PREDICTION",
                "indicator": "ai_benign_verdict",
                "title": f"AI Intent Classification: Legitimate ({confidence:.1%} confidence)",
                "source_module": "ai_text_analyzer",
                "pillar": "ai_content",
                "description": "Model classified text as consistent with benign email correspondence.",
                "mitigation_points": 8,
            })

    capped_score, uncapped_total, evidence = _attribute_pillar_budget(evidence, PILLAR_WEIGHT_AI)
    return capped_score, uncapped_total, evidence, positive_signals, missing_evidence, status


def _evaluate_routing_transport(
    routing_data: Optional[dict[str, Any]],
) -> tuple[int, int, list[dict[str, Any]], list[dict[str, Any]], list[dict[str, str]], str]:
    """
    Evaluate Pillar 4: Transport & Routing Anomalies.
    Budget Cap: 15 points.
    Strict Invariant: Public IPs, foreign geolocations, and missing GeoIP DB are 0 points (NEUTRAL).
    """
    evidence: list[dict[str, Any]] = []
    positive_signals: list[dict[str, Any]] = []
    missing_evidence: list[dict[str, str]] = []
    status = "not_evaluated"

    if routing_data is None or not isinstance(routing_data, dict):
        return 0, 0, evidence, positive_signals, [{"field": "routing_analysis", "reason": "Routing analysis data not supplied."}], status

    # 1. GeoIP Database Status - Strictly NEUTRAL (check first)
    geo_summary = routing_data.get("geolocation_summary", {})
    provider = str(geo_summary.get("provider_used", ""))
    geo_status = str(routing_data.get("geolocation_status", ""))
    geo_enabled = routing_data.get("geolocation_enabled", True)

    if not geo_enabled or "unconfigured" in provider.lower() or "not_found" in geo_status.lower() or "database_not_found" in geo_status.lower() or "none" in provider.lower():
        missing_evidence.append({
            "field": "ip_geolocation",
            "reason": "Offline GeoLite2 database was not configured; IP geolocation lookup was skipped.",
        })

    hops = routing_data.get("hops")
    warnings = routing_data.get("warnings") or routing_data.get("global_warnings") or []
    if not isinstance(warnings, list):
        warnings = []

    if hops is None and not warnings and not routing_data.get("anomalies_detected"):
        return 0, 0, evidence, positive_signals, missing_evidence, "no_hops"

    status = "evaluated"

    # Check for actual transport anomalies (loop, RFC1918 after public, relay mismatch)
    has_anomalies = bool(routing_data.get("anomalies_detected"))
    if has_anomalies or any("loop" in str(w).lower() or "mismatch" in str(w).lower() for w in warnings):
        evidence.append({
            "id": "ROUTING_TRANSPORT_ANOMALY",
            "indicator": "transport_anomaly",
            "title": "Routing / Transport Header Anomaly Detected",
            "source_module": "routing_analyzer",
            "pillar": "routing_transport",
            "evidence_type": "heuristic_indicator",
            "severity": "medium",
            "occurrence_count": 1,
            "base_points": 10,
            "raw_points": 10,
            "dampened_points": 10,
            "pillar_cap_reduction": 0,
            "effective_contribution": 10,
            "score_contribution": 10,
            "contribution": 10,
            "explanation": "Received header chain exhibits transport anomalies (e.g., relay mismatch, loop, or boundary inversion).",
        })

    capped_score, uncapped_total, evidence = _attribute_pillar_budget(evidence, PILLAR_WEIGHT_ROUTING)
    return capped_score, uncapped_total, evidence, positive_signals, missing_evidence, status


# ===========================================================================
# RECOMMENDATIONS ENGINE
# ===========================================================================

def _generate_recommendations(
    risk_level: str,
    evidence: list[dict[str, Any]],
    has_missing_evidence: bool = False,
    all_positive: bool = False,
) -> list[str]:
    """Generate practical, actionable cybersecurity recommendations tied to findings."""
    recs: list[str] = []
    evidence_ids = {e.get("id", "") for e in evidence}
    evidence_indicators = {e.get("indicator", "") for e in evidence}

    if risk_level in (RISK_LEVEL_CRITICAL, RISK_LEVEL_HIGH):
        recs.append("Do NOT interact with this email, click any embedded links, or download attachments.")
        if any("BRAND" in eid for eid in evidence_ids) or "display_name_spoofing" in evidence_indicators:
            recs.append("If this message claims to be from a financial or service provider, access your account directly via the official bookmarked URL.")
        if any("PAYLOAD" in eid or "SCHEME" in eid for eid in evidence_ids) or "executable_payload" in evidence_indicators:
            recs.append("Isolate the email and alert your system administrator: dangerous payload or script link detected.")
        if any("AUTH" in eid for eid in evidence_ids):
            recs.append("Report message as spoofed/phishing to your IT security or mail administrator.")
    elif risk_level == RISK_LEVEL_MEDIUM:
        recs.append("Exercise caution: this message contains suspicious indicators.")
        recs.append("Verify the sender's identity through an independent, trusted channel (such as a phone call or direct message).")
        recs.append("Inspect destination URLs before navigating to them.")
    elif risk_level == RISK_LEVEL_LOW:
        recs.append("Exercise standard vigilance. A minor informational anomaly was detected.")
    elif risk_level == RISK_LEVEL_NONE:
        if has_missing_evidence and not all_positive:
            recs.append("No negative threat indicators were detected, but some security verifications were incomplete or skipped. Exercise standard caution before trusting unfamiliar senders.")
        else:
            recs.append("No significant threat indicators detected. Follow standard organizational email hygiene.")
    else:
        recs.append("Insufficient data to complete risk evaluation. Review individual module reports manually.")

    return recs


# ===========================================================================
# PUBLIC API ENTRY POINT (MODULE 6)
# ===========================================================================

def calculate_email_risk(
    analysis_results: Optional[dict[str, Any]] = None,
    *,
    email_data: Optional[dict[str, Any]] = None,
    parsed_email: Optional[dict[str, Any]] = None,
    auth_data: Optional[dict[str, Any]] = None,
    auth_result: Optional[dict[str, Any]] = None,
    url_data: Optional[dict[str, Any]] = None,
    url_result: Optional[dict[str, Any]] = None,
    routing_data: Optional[dict[str, Any]] = None,
    routing_result: Optional[dict[str, Any]] = None,
    ai_data: Optional[dict[str, Any]] = None,
    ai_result: Optional[dict[str, Any]] = None,
    raw_bytes: Optional[bytes] = None,
    auto_analyze: bool = False,
    config: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """
    Main entry point for Module 6: Evidence-Based Email Risk Scoring Engine.

    Synthesizes outputs across Modules 1 through 5 into an explainable, bounded,
    mathematically auditable email threat assessment dictionary.

    Parameters
    ----------
    analysis_results : dict, optional
        Combined results dictionary or output from Module 1 (email_parser).
    email_data / parsed_email : dict, optional
        Direct output from Module 1 (email_parser).
    auth_data / auth_result : dict, optional
        Direct output from Module 2 (auth_verifier).
    url_data / url_result : dict, optional
        Direct output from Module 3 (url_analyzer).
    routing_data / routing_result : dict, optional
        Direct output from Module 4 (routing_analyzer).
    ai_data / ai_result : dict, optional
        Direct output from Module 5 (ai_text_analyzer).
    raw_bytes : bytes, optional
        Original email bytes if available.
    auto_analyze : bool
        If True and only email_data is provided, automatically executes missing
        modules to provide a full evaluation. Default is False.
    config : dict, optional
        Custom scoring configuration options.

    Returns
    -------
    dict[str, Any]
        Complete explainable risk assessment report.
    """
    config = config or {}

    # Normalize parameter aliases
    email_data = email_data or parsed_email
    auth_data = auth_data or auth_result
    url_data = url_data or url_result
    routing_data = routing_data or routing_result
    ai_data = ai_data or ai_result

    # 1. Unpack and Resolve Inputs
    if analysis_results and isinstance(analysis_results, dict):
        if "file_metadata" in analysis_results and "email_metadata" in analysis_results:
            email_data = analysis_results
        else:
            email_data = email_data or analysis_results.get("email") or analysis_results.get("parsed_email")
            auth_data = auth_data or analysis_results.get("auth") or analysis_results.get("auth_verifier") or analysis_results.get("auth_result")
            url_data = url_data or analysis_results.get("url") or analysis_results.get("url_analyzer") or analysis_results.get("url_result")
            routing_data = routing_data or analysis_results.get("routing") or analysis_results.get("routing_analyzer") or analysis_results.get("routing_result")
            ai_data = ai_data or analysis_results.get("ai") or analysis_results.get("ai_text_analyzer") or analysis_results.get("ai_result")

    # 2. Optional Auto-Pipeline Execution
    evaluated_modules: list[str] = []
    if email_data and isinstance(email_data, dict):
        evaluated_modules.append("email_parser")

        if auto_analyze:
            if auth_data is None:
                try:
                    from src.auth_verifier import verify_authentication
                    auth_data = verify_authentication(email_data, raw_bytes=raw_bytes)
                except Exception:
                    pass

            if url_data is None:
                try:
                    from src.url_analyzer import analyze_urls
                    url_data = analyze_urls(email_data)
                except Exception:
                    pass

            if routing_data is None:
                try:
                    from src.routing_analyzer import analyze_email_routing
                    routing_data = analyze_email_routing(email_data, raw_bytes=raw_bytes)
                except Exception:
                    pass

            if ai_data is None:
                try:
                    from src.ai_text_analyzer import analyze_email_text
                    ai_data = analyze_email_text(email_data)
                except Exception:
                    pass

    if auth_data and isinstance(auth_data, dict):
        evaluated_modules.append("auth_verifier")
    if url_data and isinstance(url_data, dict):
        evaluated_modules.append("url_analyzer")
    if routing_data and isinstance(routing_data, dict):
        evaluated_modules.append("routing_analyzer")
    if ai_data and isinstance(ai_data, dict):
        evaluated_modules.append("ai_text_analyzer")

    # 3. Evaluate the 4 Pillars
    p1_score, p1_uncapped, p1_ev, p1_pos, p1_miss, p1_status = _evaluate_identity_and_auth(email_data, auth_data)
    p2_score, p2_uncapped, p2_ev, p2_pos, p2_miss, p2_status = _evaluate_url_threats(url_data)
    p3_score, p3_uncapped, p3_ev, p3_pos, p3_miss, p3_status = _evaluate_ai_content(ai_data)
    p4_score, p4_uncapped, p4_ev, p4_pos, p4_miss, p4_status = _evaluate_routing_transport(routing_data)

    all_evidence = p1_ev + p2_ev + p3_ev + p4_ev
    all_positive = p1_pos + p2_pos + p3_pos + p4_pos
    all_missing = p1_miss + p2_miss + p3_miss + p4_miss

    p1_raw = sum(e.get("raw_points", 0) for e in p1_ev)
    p2_raw = sum(e.get("raw_points", 0) for e in p2_ev)
    p3_raw = sum(e.get("raw_points", 0) for e in p3_ev)
    p4_raw = sum(e.get("raw_points", 0) for e in p4_ev)

    total_capped_pillars = p1_score + p2_score + p3_score + p4_score
    total_raw_signals = sum(e.get("raw_points", 0) for e in all_evidence)
    total_dampened_points = sum(e.get("dampened_points", 0) for e in all_evidence)
    total_pillar_cap_reduction = (p1_uncapped - p1_score) + (p2_uncapped - p2_score) + (p3_uncapped - p3_score) + (p4_uncapped - p4_score)
    total_multi_occurrence_dampening = max(0, total_raw_signals - total_dampened_points)

    # 4. Check for Inconclusive / Insufficient Data
    if not evaluated_modules or all(s in ("not_evaluated", "no_urls", "no_hops") for s in [p1_status, p2_status, p3_status, p4_status]):
        if total_capped_pillars == 0:
            return {
                "analysis_status": "inconclusive",
                "risk_score": 0,
                "risk_level": RISK_LEVEL_NONE,
                "summary": "Insufficient module outputs provided to calculate an evidence-based risk score.",
                "verdict_title": "Inconclusive Assessment",
                "pillar_scores": {
                    "identity_authentication": {"score": 0, "raw_score": 0, "uncapped_dampened_score": 0, "max_possible": PILLAR_WEIGHT_AUTH, "cap_reduction": 0, "status": p1_status, "signals_count": 0},
                    "url_threats": {"score": 0, "raw_score": 0, "uncapped_dampened_score": 0, "max_possible": PILLAR_WEIGHT_URL, "cap_reduction": 0, "status": p2_status, "signals_count": 0},
                    "ai_content_analysis": {"score": 0, "raw_score": 0, "uncapped_dampened_score": 0, "max_possible": PILLAR_WEIGHT_AI, "cap_reduction": 0, "status": p3_status, "signals_count": 0},
                    "routing_transport": {"score": 0, "raw_score": 0, "uncapped_dampened_score": 0, "max_possible": PILLAR_WEIGHT_ROUTING, "cap_reduction": 0, "status": p4_status, "signals_count": 0},
                },
                "evidence": [],
                "positive_signals": [],
                "limitations": [
                    "No forensic evidence could be extracted from provided inputs.",
                    "Absence of threat indicators does not confirm legitimacy when critical verification modules were skipped or unavailable.",
                ],
                "missing_evidence": all_missing or [{"field": "all", "reason": "No analysis modules supplied."}],
                "recommended_actions": ["Provide valid module results or email data to perform a risk assessment."],
                "scoring_metadata": {
                    "engine_version": SCORING_VERSION,
                    "scoring_method": "Multi-Pillar Evidence Fusion with Proportional Cap Attribution",
                    "pillar_raw_points_sum": 0,
                    "pillar_dampened_points_sum": 0,
                    "raw_signal_points_sum": 0,
                    "dampened_points_sum": 0,
                    "multi_occurrence_dampening_reduction": 0,
                    "pillar_cap_reduction": 0,
                    "capped_pillar_scores_sum": 0,
                    "synergy_bonus": 0,
                    "mitigation_discount": 0,
                    "single_signal_safeguard_applied": False,
                    "single_signal_safeguard_reduction": 0,
                    "pre_clamp_score": 0,
                    "final_risk_score": 0,
                    "mathematical_reconciliation": "final_risk_score (0) = capped_pillar_scores_sum (0) + synergy_bonus (0) - mitigation_discount (0)",
                    "evaluated_modules": evaluated_modules,
                },
            }

    # 5. Cross-Pillar Synergies and Mitigation Adjustments
    # A. Multi-Vector Synergy Bonus:
    # Triggered when multiple independent pillars independently flag significant threats:
    # (Auth >= 15, URLs >= 15, AI >= 15, Routing >= 10)
    active_threat_pillars = (
        (1 if p1_score >= 15 else 0)
        + (1 if p2_score >= 15 else 0)
        + (1 if p3_score >= 15 else 0)
        + (1 if p4_score >= 10 else 0)
    )
    synergy_bonus = 10 if active_threat_pillars >= 2 else 0
    if synergy_bonus > 0:
        all_evidence.append({
            "id": "CROSS_VECTOR_SYNERGY_BONUS",
            "indicator": "cross_vector_synergy",
            "title": "Cross-Vector Corroboration Synergy",
            "source_module": "risk_scorer",
            "pillar": "composite",
            "evidence_type": "cross_vector_synergy",
            "severity": "high",
            "occurrence_count": 1,
            "base_points": synergy_bonus,
            "raw_points": synergy_bonus,
            "dampened_points": synergy_bonus,
            "pillar_cap_reduction": 0,
            "effective_contribution": synergy_bonus,
            "score_contribution": synergy_bonus,
            "contribution": synergy_bonus,
            "explanation": "Multiple independent detection vectors independently confirmed significant threats.",
        })

    # B. Mitigating Positive Signals (e.g. Valid DKIM + DMARC alignment)
    # Mitigations cannot reduce score if an active critical payload or dangerous URI scheme is present
    has_critical_payload = any(e.get("severity") == "critical" for e in all_evidence)
    raw_mitigation_points = sum(p.get("mitigation_points", 0) for p in all_positive)
    if has_critical_payload:
        total_mitigation = 0
        mitigation_revoked = True
    else:
        total_mitigation = raw_mitigation_points
        mitigation_revoked = False

    # C. Single-Signal Safeguard:
    # An isolated low-severity heuristic cannot produce a score > 25 (cannot exceed low risk ceiling)
    negative_evidence = [e for e in all_evidence if e.get("pillar") != "composite"]
    pre_safeguard_score = total_capped_pillars + synergy_bonus - total_mitigation

    safeguard_applied = False
    safeguard_reduction = 0
    if len(negative_evidence) == 1 and negative_evidence[0].get("severity") == "low":
        if pre_safeguard_score > 25:
            safeguard_reduction = pre_safeguard_score - 25
            safeguard_applied = True
            computed_score = 25
        else:
            computed_score = pre_safeguard_score
    else:
        computed_score = pre_safeguard_score

    final_score = max(0, min(100, computed_score))
    risk_level = _determine_risk_level(final_score)

    # D. Determine Risk Level & Explanatory Title
    if final_score <= THRESHOLD_NONE_MAX:
        # Distinguish confirmed clean verification from absence of evidence
        if all_missing and not all_positive:
            verdict_title = "Minimal Threat Detected (Incomplete Verification)"
        else:
            verdict_title = "Minimal or No Threat Detected"
    elif final_score <= THRESHOLD_LOW_MAX:
        verdict_title = "Low Risk — Minor Anomalies"
    elif final_score <= THRESHOLD_MEDIUM_MAX:
        verdict_title = "Medium Risk — Suspicious Indicators"
    elif final_score <= THRESHOLD_HIGH_MAX:
        verdict_title = "High Risk — Phishing or Spoofing Detected"
    else:
        verdict_title = "Critical Threat — Severe Phishing or Malicious Payload"

    # 6. Summary Text
    summary_parts: list[str] = []
    summary_parts.append(f"Composite risk score: {final_score}/100 ({risk_level.upper()}).")
    if negative_evidence:
        top_ev = sorted(negative_evidence, key=lambda e: e.get("score_contribution", 0), reverse=True)[0]
        summary_parts.append(f"Primary threat indicator: {top_ev.get('title', 'Unknown')}.")
    else:
        summary_parts.append("No negative threat indicators were triggered.")

    if all_positive:
        summary_parts.append(f"{len(all_positive)} positive security verification(s) confirmed.")
    elif all_missing and final_score <= THRESHOLD_NONE_MAX:
        summary_parts.append(f"Note: {len(all_missing)} security check(s) were unverified or missing (see missing_evidence).")

    summary = " ".join(summary_parts)

    recommendations = _generate_recommendations(
        risk_level,
        all_evidence,
        has_missing_evidence=bool(all_missing),
        all_positive=bool(all_positive),
    )

    # 7. Standard Forensic Limitations
    limitations: list[str] = [
        "Risk score is an evidence-based heuristic fusion, not an absolute guarantee of safety or maliciousness.",
        "Missing or unverified checks (such as offline GeoIP, unverified SPF, or absent AI models) are treated neutrally and do not penalize.",
        "Absence of negative indicators does not confirm safety when major verification modules were skipped or unavailable.",
        "AI text classification confidence represents model token distribution probability, NOT a calibrated real-world likelihood of maliciousness.",
        "Zero active network requests were made; threat intelligence reputations remain unverified.",
    ]

    # Reconciliation string for forensic transparency
    reconciliation_str = (
        f"final_risk_score ({final_score}) = "
        f"capped_pillar_scores_sum ({total_capped_pillars}) "
        f"+ synergy_bonus ({synergy_bonus}) "
        f"- mitigation_discount ({total_mitigation})"
    )
    if safeguard_applied:
        reconciliation_str += f" - safeguard_reduction ({safeguard_reduction})"

    analysis_status = "completed"

    return {
        "analysis_status": analysis_status,
        "risk_score": final_score,
        "risk_level": risk_level,
        "summary": summary,
        "verdict_title": verdict_title,
        "pillar_scores": {
            "identity_authentication": {
                "score": p1_score,
                "raw_score": p1_raw,
                "uncapped_dampened_score": p1_uncapped,
                "max_possible": PILLAR_WEIGHT_AUTH,
                "cap_reduction": p1_uncapped - p1_score,
                "status": p1_status,
                "signals_count": len(p1_ev),
            },
            "url_threats": {
                "score": p2_score,
                "raw_score": p2_raw,
                "uncapped_dampened_score": p2_uncapped,
                "max_possible": PILLAR_WEIGHT_URL,
                "cap_reduction": p2_uncapped - p2_score,
                "status": p2_status,
                "signals_count": len(p2_ev),
            },
            "ai_content_analysis": {
                "score": p3_score,
                "raw_score": p3_raw,
                "uncapped_dampened_score": p3_uncapped,
                "max_possible": PILLAR_WEIGHT_AI,
                "cap_reduction": p3_uncapped - p3_score,
                "status": p3_status,
                "signals_count": len(p3_ev),
            },
            "routing_transport": {
                "score": p4_score,
                "raw_score": p4_raw,
                "uncapped_dampened_score": p4_uncapped,
                "max_possible": PILLAR_WEIGHT_ROUTING,
                "cap_reduction": p4_uncapped - p4_score,
                "status": p4_status,
                "signals_count": len(p4_ev),
            },
        },
        "evidence": all_evidence,
        "positive_signals": all_positive,
        "limitations": limitations,
        "missing_evidence": all_missing,
        "recommended_actions": recommendations,
        "scoring_metadata": {
            "engine_version": SCORING_VERSION,
            "scoring_method": "Multi-Pillar Evidence Fusion with Proportional Cap Attribution",
            "pillar_raw_points_sum": total_raw_signals,
            "pillar_dampened_points_sum": total_dampened_points,
            "raw_signal_points_sum": total_raw_signals + synergy_bonus,
            "dampened_points_sum": total_dampened_points + synergy_bonus,
            "multi_occurrence_dampening_reduction": total_multi_occurrence_dampening,
            "pillar_cap_reduction": total_pillar_cap_reduction,
            "capped_pillar_scores_sum": total_capped_pillars,
            "synergy_bonus": synergy_bonus,
            "mitigation_discount": total_mitigation,
            "mitigation_revoked_by_critical_payload": mitigation_revoked,
            "single_signal_safeguard_applied": safeguard_applied,
            "single_signal_safeguard_reduction": safeguard_reduction,
            "pre_clamp_score": computed_score,
            "final_risk_score": final_score,
            "mathematical_reconciliation": reconciliation_str,
            "evaluated_modules": evaluated_modules,
        },
    }


# Convenience Alias
calculate_risk_score = calculate_email_risk
