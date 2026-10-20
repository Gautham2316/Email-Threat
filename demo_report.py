"""
demo_report.py
==============
Demonstration script for Module 7: PDF Forensic Report Generator.
SIH 2026 — AI-Powered Email Threat Detection Platform

This script demonstrates the end-to-end analysis pipeline:
1. Ingests and parses a sample email ('samples/phishing_sample.eml').
2. Executes authentication verification (SPF / DKIM / DMARC).
3. Analyzes embedded URLs and indicators.
4. Performs email routing hop analysis.
5. Runs AI-based phishing and scam-text intent classification.
6. Synthesizes all findings through the evidence-based risk scorer (Module 6).
7. Compiles an auditable, publication-grade PDF forensic report (Module 7).

Usage:
    .\\.venv\\Scripts\\python.exe demo_report.py
"""

import os
import sys

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.email_parser import parse_email_file
from src.auth_verifier import verify_authentication
from src.url_analyzer import analyze_urls
from src.routing_analyzer import analyze_email_routing
from src.ai_text_analyzer import analyze_email_text
from src.risk_scorer import calculate_email_risk
from src.report_generator import generate_forensic_pdf


def run_demonstration(
    sample_file: str = "samples/phishing_sample.eml",
    output_pdf: str = "reports/phishing_sample_forensic_report.pdf",
    case_id: str = "SIH-2026-DEMO-001",
) -> dict:
    """Run full forensic pipeline and output PDF report."""
    print("=" * 72)
    print("SIH 2026 — AI-POWERED EMAIL THREAT DETECTION PLATFORM")
    print("MODULE 7 DEMONSTRATION: PDF FORENSIC REPORT GENERATION")
    print("=" * 72)

    sample_path = os.path.join(PROJECT_ROOT, sample_file)
    if not os.path.exists(sample_path):
        raise FileNotFoundError(f"Sample file not found at: {sample_path}")

    print(f"\n[Step 1/7] Ingesting & Parsing Email Artifact: {sample_file} ...")
    parsed_email = parse_email_file(sample_path)
    print(f"  * Extracted Subject : {parsed_email.get('email_metadata', {}).get('subject')}")
    print(f"  * Extracted Sender  : {parsed_email.get('email_metadata', {}).get('from')}")
    print(f"  * Extracted URLs    : {len(parsed_email.get('urls', []))} link(s)")

    print("\n[Step 2/7] Verifying Sender Authentication (SPF, DKIM, DMARC) ...")
    raw_bytes = parsed_email.get("raw_bytes")
    if not raw_bytes and os.path.exists(sample_path):
        with open(sample_path, "rb") as f:
            raw_bytes = f.read()
    if raw_bytes:
        parsed_email["raw_bytes"] = raw_bytes
    auth_result = verify_authentication(parsed_email, raw_bytes=raw_bytes)
    print(f"  * SPF Independent   : {auth_result.get('spf', {}).get('independent_result', 'not_checked')}")
    print(f"  * DKIM Status       : {auth_result.get('dkim', {}).get('overall_result', 'none')}")
    print(f"  * DMARC Result      : {auth_result.get('dmarc', {}).get('result', 'none')}")

    print("\n[Step 3/7] Analyzing URL & Link Threat Heuristics ...")
    url_result = analyze_urls(parsed_email.get("urls", []))
    print(f"  * URLs Analyzed     : {url_result.get('total_urls_analyzed', 0)}")
    print(f"  * Max Risk Score    : {url_result.get('max_risk_score', 0)}")

    print("\n[Step 4/7] Analyzing Email Transmission Hops & Routing ...")
    routing_result = analyze_email_routing(parsed_email.get("received_headers", []), raw_bytes=raw_bytes)
    hops_count = len(routing_result.get("hops", []))
    anomalies_flag = routing_result.get("anomalies_detected", False)
    print(f"  * Total Hops        : {hops_count}")
    print(f"  * Anomalies Flagged : {'YES' if anomalies_flag else 'NO'}")

    print("\n[Step 5/7] Executing AI Phishing & Scam Intent Analysis ...")
    body_text = parsed_email.get("body", {}).get("plain_text") or parsed_email.get("body_text", "")
    ai_result = analyze_email_text(body_text)
    ai_verdict = ai_result.get("classification", {}).get("semantic_verdict") or ai_result.get("verdict")
    ai_conf = ai_result.get("classification", {}).get("confidence") or ai_result.get("confidence")
    print(f"  * AI Verdict        : {ai_verdict}")
    print(f"  * Model Confidence  : {ai_conf}")

    print("\n[Step 6/7] Synthesizing Multi-Pillar Evidence Risk Score ...")
    risk_report = calculate_email_risk(
        parsed_email=parsed_email,
        auth_result=auth_result,
        url_result=url_result,
        routing_result=routing_result,
        ai_result=ai_result,
    )
    final_score = risk_report.get("risk_score")
    risk_level = risk_report.get("risk_level")
    print(f"  * Final Risk Score  : {final_score} / 100 ({risk_level.upper()})")
    print(f"  * Verdict Title     : {risk_report.get('verdict_title')}")
    print(f"  * Reconciliation    : {risk_report.get('scoring_metadata', {}).get('mathematical_reconciliation')}")

    print("\n[Step 7/7] Generating PDF Forensic Intelligence Report ...")
    target_pdf = os.path.join(PROJECT_ROOT, output_pdf)
    gen_result = generate_forensic_pdf(
        email_data=parsed_email,
        auth_data=auth_result,
        url_data=url_result,
        routing_data=routing_result,
        ai_data=ai_result,
        risk_data=risk_report,
        output_path=target_pdf,
        case_id=case_id,
        include_body_excerpt=True,
    )

    print("\n" + "=" * 72)
    print("DEMONSTRATION REPORT GENERATED SUCCESSFULLY")
    print("=" * 72)
    print(f"Exact Generated PDF Path : {gen_result['pdf_path']}")
    print(f"PDF File Size            : {gen_result['file_size_bytes']:,} bytes")
    print(f"Case Reference ID        : {gen_result['case_id']}")
    print(f"Final Risk Score         : {gen_result['risk_score']} / 100 ({gen_result['risk_level'].upper()})")
    print(f"Generation Timestamp     : {gen_result['generated_at']}")
    print("=" * 72 + "\n")

    return gen_result


if __name__ == "__main__":
    run_demonstration()
