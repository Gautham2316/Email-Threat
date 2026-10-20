# src/__init__.py
# SIH 2026 - AI-Powered Email Threat Detection Platform
from src.email_parser import parse_email_file
from src.auth_verifier import verify_authentication
from src.url_analyzer import analyze_urls, defang_url
from src.routing_analyzer import analyze_email_routing
from src.ai_text_analyzer import analyze_email_text
from src.risk_scorer import calculate_email_risk, calculate_risk_score
from src.report_generator import generate_forensic_pdf, generate_email_forensic_report
from src.dashboard_pipeline import run_forensic_pipeline, extract_safe_email_preview

__all__ = [
    "parse_email_file",
    "verify_authentication",
    "analyze_urls",
    "defang_url",
    "analyze_email_routing",
    "analyze_email_text",
    "calculate_email_risk",
    "calculate_risk_score",
    "generate_forensic_pdf",
    "generate_email_forensic_report",
    "run_forensic_pipeline",
    "extract_safe_email_preview",
]



