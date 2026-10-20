"""
app.py
======
Module 8: Interactive Forensic Intelligence Dashboard
SIH 2026 — AI-Powered Email Threat Detection and Forensic Intelligence Platform

A lightweight, local, explainable Streamlit dashboard for forensic email analysis.

KEY CAPABILITIES:
1. Ingestion of .eml email artifacts via drag-and-drop or built-in sample loaders.
2. Safe defanged preview of email metadata and body without rendering HTML or scripts.
3. Execution of Modules 1 through 6 via src.dashboard_pipeline.
4. Multi-pillar risk scoreboard with Pre-Cap (Dampened) and Capped points.
5. In-depth forensic inspection tabs (Auth, URLs, Routing, AI NLP, Ledger, Recommendations).
6. One-click generation and download of publication-grade PDF investigation reports (Module 7).
7. Strict epistemic honesty disclosures for SPF, GeoIP, threat intel, and AI confidence.
"""

from __future__ import annotations

import hashlib
import io
import os
import sys
import tempfile
from datetime import datetime, timezone
from typing import Any

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import streamlit as st
import pandas as pd

from src.dashboard_pipeline import (
    run_forensic_pipeline,
    extract_safe_email_preview,
    defang_content_text,
    validate_email_input,
)
from src.url_analyzer import defang_url
from src.report_generator import generate_forensic_pdf


# -----------------------------------------------------------------------------
# PAGE CONFIGURATION & STYLING
# -----------------------------------------------------------------------------

st.set_page_config(
    page_title="AI Email Threat Detection & Forensic Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for clean forensic badge styling and readability
st.markdown(
    """
    <style>
    .threat-banner-critical {
        background-color: #ffebee;
        border-left: 6px solid #d32f2f;
        padding: 12px 16px;
        border-radius: 4px;
        color: #b71c1c;
        margin-bottom: 1rem;
    }
    .threat-banner-high {
        background-color: #fff3e0;
        border-left: 6px solid #e65100;
        padding: 12px 16px;
        border-radius: 4px;
        color: #bf360c;
        margin-bottom: 1rem;
    }
    .threat-banner-medium {
        background-color: #fffde7;
        border-left: 6px solid #fbc02d;
        padding: 12px 16px;
        border-radius: 4px;
        color: #f57f17;
        margin-bottom: 1rem;
    }
    .threat-banner-low {
        background-color: #e8f5e9;
        border-left: 6px solid #2e7d32;
        padding: 12px 16px;
        border-radius: 4px;
        color: #1b5e20;
        margin-bottom: 1rem;
    }
    .audit-box {
        background-color: #f8f9fa;
        border: 1px solid #dee2e6;
        border-radius: 6px;
        padding: 14px;
        font-family: monospace;
        font-size: 0.9rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# -----------------------------------------------------------------------------
# SESSION STATE INITIALIZATION
# -----------------------------------------------------------------------------

if "pipeline_result" not in st.session_state:
    st.session_state["pipeline_result"] = None

if "active_artifact_bytes" not in st.session_state:
    st.session_state["active_artifact_bytes"] = None

if "active_artifact_filename" not in st.session_state:
    st.session_state["active_artifact_filename"] = None

if "case_id" not in st.session_state:
    st.session_state["case_id"] = "SIH-2026-CASE-001"

if "generated_pdf_bytes" not in st.session_state:
    st.session_state["generated_pdf_bytes"] = None


# -----------------------------------------------------------------------------
# SIDEBAR: CASE MANAGEMENT & SAMPLE LOADERS
# -----------------------------------------------------------------------------

with st.sidebar:
    st.markdown("### 🛡️ Forensic Control Panel")
    st.markdown("**Platform**: SIH 2026 Cybersecurity Intelligence")
    st.markdown("---")

    case_input = st.text_input(
        "Investigative Case Reference ID",
        value=st.session_state["case_id"],
        help="Unique reference tracking ID for forensic audit logs.",
    )
    if case_input != st.session_state["case_id"]:
        st.session_state["case_id"] = case_input.strip() or "SIH-2026-CASE-001"

    st.markdown("#### 📂 Load Demonstration Samples")
    st.caption("Quickly evaluate pre-packaged email artifacts:")

    sample_col1, sample_col2 = st.columns(2)
    with sample_col1:
        if st.button("🚨 Phishing", use_container_width=True):
            sample_path = os.path.join(PROJECT_ROOT, "samples", "phishing_sample.eml")
            if os.path.exists(sample_path):
                with open(sample_path, "rb") as fh:
                    st.session_state["active_artifact_bytes"] = fh.read()
                    st.session_state["active_artifact_filename"] = "phishing_sample.eml"
                    st.session_state["pipeline_result"] = None
                    st.session_state["generated_pdf_bytes"] = None
                st.rerun()

        if st.button("📄 Plain Text", use_container_width=True):
            sample_path = os.path.join(PROJECT_ROOT, "samples", "plain_text.eml")
            if os.path.exists(sample_path):
                with open(sample_path, "rb") as fh:
                    st.session_state["active_artifact_bytes"] = fh.read()
                    st.session_state["active_artifact_filename"] = "plain_text.eml"
                    st.session_state["pipeline_result"] = None
                    st.session_state["generated_pdf_bytes"] = None
                st.rerun()

    with sample_col2:
        if st.button("🔑 DKIM Signed", use_container_width=True):
            sample_path = os.path.join(PROJECT_ROOT, "samples", "dkim_signed.eml")
            if os.path.exists(sample_path):
                with open(sample_path, "rb") as fh:
                    st.session_state["active_artifact_bytes"] = fh.read()
                    st.session_state["active_artifact_filename"] = "dkim_signed.eml"
                    st.session_state["pipeline_result"] = None
                    st.session_state["generated_pdf_bytes"] = None
                st.rerun()

        if st.button("📦 Multipart", use_container_width=True):
            sample_path = os.path.join(PROJECT_ROOT, "samples", "multipart.eml")
            if os.path.exists(sample_path):
                with open(sample_path, "rb") as fh:
                    st.session_state["active_artifact_bytes"] = fh.read()
                    st.session_state["active_artifact_filename"] = "multipart.eml"
                    st.session_state["pipeline_result"] = None
                    st.session_state["generated_pdf_bytes"] = None
                st.rerun()

    st.markdown("---")
    st.markdown("#### ⚖️ Epistemic & Forensic Disclosures")
    st.info(
        "• **Zero Network Requests**: URLs and senders are analyzed completely offline. External threat intelligence is reported as `not_checked`.\n\n"
        "• **SPF Passive Context**: SPF evaluation is `not_checked` on static `.eml` files without trusted SMTP connection metadata.\n\n"
        "• **Defanged Links**: All displayed URLs are modified (`hxxps://`) to prevent accidental web navigation.\n\n"
        "• **AI Confidence Caveat**: DistilBERT scores represent training domain likelihood, NOT calibrated real-world probabilities of maliciousness."
    )


# -----------------------------------------------------------------------------
# MAIN HEADER
# -----------------------------------------------------------------------------

st.title("🛡️ AI-Powered Email Threat Detection & Forensic Intelligence Platform")
st.markdown(
    "**SIH 2026** — *Explainable, Multi-Pillar Forensic Threat Analysis, Evidence-Based Scoring, and PDF Intelligence Reporting.*"
)
st.markdown("---")


# -----------------------------------------------------------------------------
# STEP 1: FILE INGESTION & UPLOAD
# -----------------------------------------------------------------------------

st.subheader("1. Ingest Email Artifact (.eml)")

upload_col1, upload_col2 = st.columns([2, 1])

with upload_col1:
    uploaded_file = st.file_uploader(
        "Upload raw .eml file (Max 25 MB)",
        type=["eml"],
        help="Upload an RFC-2822 email file. The file is analyzed strictly locally.",
    )

if uploaded_file is not None:
    file_bytes = uploaded_file.getvalue()
    if file_bytes != st.session_state["active_artifact_bytes"]:
        st.session_state["active_artifact_bytes"] = file_bytes
        st.session_state["active_artifact_filename"] = uploaded_file.name
        st.session_state["pipeline_result"] = None
        st.session_state["generated_pdf_bytes"] = None

with upload_col2:
    st.markdown("##### Current Loaded Artifact")
    curr_fn = st.session_state.get("active_artifact_filename")
    curr_bytes = st.session_state.get("active_artifact_bytes")
    if curr_bytes:
        st.success(f"**File**: `{curr_fn}` ({len(curr_bytes):,} bytes)")
        if st.button("Clear Loaded Artifact", use_container_width=True):
            st.session_state["active_artifact_bytes"] = None
            st.session_state["active_artifact_filename"] = None
            st.session_state["pipeline_result"] = None
            st.session_state["generated_pdf_bytes"] = None
            st.rerun()
    else:
        st.warning("No artifact loaded yet. Upload an `.eml` or select a sample.")


# -----------------------------------------------------------------------------
# STEP 2: SAFE PREVIEW & ANALYSIS TRIGGER
# -----------------------------------------------------------------------------

if st.session_state["active_artifact_bytes"]:
    # Validate payload
    raw_b = st.session_state["active_artifact_bytes"]
    fn = st.session_state["active_artifact_filename"] or "email.eml"
    valid, err_msg = validate_email_input(raw_b, fn)

    if not valid:
        st.error(f"❌ Upload Validation Error: {err_msg}")
    else:
        with st.expander("👁️ Safe Pre-Analysis Inspection (Defanged Plain Text)", expanded=True):
            # Parse quickly for preview without heavy AI run
            with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as tf:
                tf.write(raw_b)
                t_path = tf.name
            try:
                from src.email_parser import parse_email_file
                quick_parsed = parse_email_file(t_path)
                preview = extract_safe_email_preview(quick_parsed)
            finally:
                if os.path.exists(t_path):
                    os.remove(t_path)

            meta_c1, meta_c2, meta_c3 = st.columns(3)
            with meta_c1:
                st.text_input("Subject", value=preview["subject"], disabled=True)
                st.text_input("Sender (From)", value=preview["from"], disabled=True)
            with meta_c2:
                recipients_str = ", ".join(preview["to"]) if preview["to"] else "(None)"
                st.text_input("Recipient (To)", value=recipients_str, disabled=True)
                st.text_input("Date", value=preview["date"], disabled=True)
            with meta_c3:
                st.text_input("Message-ID", value=preview["message_id"] or "(Missing)", disabled=True)
                st.text_input("Extracted URLs", value=f"{preview['url_count']} link(s)", disabled=True)

            st.caption("🔒 Defanged Text Body Preview (Script tags & hyperlinks neutralized):")
            st.text_area(
                "Body Excerpt",
                value=preview["body_preview"],
                height=110,
                disabled=True,
                label_visibility="collapsed",
            )

        # Analysis Button
        analyze_btn = st.button("🔍 Run Multi-Pillar Forensic Analysis", type="primary", use_container_width=True)

        if analyze_btn:
            with st.spinner("Executing Forensic Pipeline (Parsing, Cryptographic DKIM, URL Heuristics, Hop Trace, AI Intent)..."):
                result = run_forensic_pipeline(
                    raw_b,
                    original_filename=fn,
                    case_id=st.session_state["case_id"],
                )
                st.session_state["pipeline_result"] = result
                st.session_state["generated_pdf_bytes"] = None
            st.rerun()


# -----------------------------------------------------------------------------
# STEP 3: RESULTS DASHBOARD (POST-ANALYSIS)
# -----------------------------------------------------------------------------

pipeline_res = st.session_state.get("pipeline_result")

if pipeline_res:
    if pipeline_res.get("status") == "error":
        st.error(f"❌ Analysis Pipeline Error: {pipeline_res.get('errors')}")
    else:
        risk_report = pipeline_res["risk_report"]
        score = risk_report["risk_score"]
        level = risk_report["risk_level"].lower()
        title = risk_report.get("verdict_title", "Threat Analysis Complete")
        summary_text = risk_report.get("summary", "")
        metadata = risk_report.get("scoring_metadata", {})

        st.markdown("---")
        st.subheader("2. Forensic Threat Evaluation Scoreboard")

        # Top Metric Cards
        col_m1, col_m2, col_m3, col_m4 = st.columns(4)

        with col_m1:
            st.metric("Overall Threat Score", f"{score} / 100")

        with col_m2:
            st.metric("Assigned Threat Level", level.upper())

        with col_m3:
            capped_pts = metadata.get("capped_pillar_scores_sum", 0)
            syn = metadata.get("synergy_bonus", 0)
            mit = metadata.get("mitigation_discount", 0)
            st.metric("Pillar Math", f"{capped_pts} + {syn} - {mit}")

        with col_m4:
            exec_time = pipeline_res["pipeline_metadata"]["execution_time_seconds"]
            st.metric("Analysis Duration", f"{exec_time:.2f} s")

        # Visual Threat Banner
        banner_class = f"threat-banner-{level if level in ['critical', 'high', 'medium', 'low'] else 'low'}"
        st.markdown(
            f"""
            <div class="{banner_class}">
                <h4 style="margin: 0 0 6px 0;">{title} (Score: {score}/100 — {level.upper()} RISK)</h4>
                <p style="margin: 0; font-size: 0.95rem;">{summary_text}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # ---------------------------------------------------------------------
        # FOUR-PILLAR THREAT BREAKDOWN TABLE
        # ---------------------------------------------------------------------
        st.markdown("##### 🏛️ Four-Pillar Scoring Breakdown")
        pillar_scores = risk_report.get("pillar_scores", {})

        pillar_table_data = [
            {
                "Pillar Vector": "Identity & Authentication (SPF, DKIM, Sender)",
                "Weight": "25%",
                "Max Cap": pillar_scores.get("identity_authentication", {}).get("max_possible", 25),
                "Pre-Cap (Dampened)": pillar_scores.get("identity_authentication", {}).get("uncapped_dampened_score", 0),
                "Capped Score": pillar_scores.get("identity_authentication", {}).get("score", 0),
                "Cap Adjustment": -pillar_scores.get("identity_authentication", {}).get("cap_reduction", 0),
                "Status": pillar_scores.get("identity_authentication", {}).get("status", "normal").upper(),
            },
            {
                "Pillar Vector": "URL Threat Heuristics (Links, Schemes, Spoofs)",
                "Weight": "35%",
                "Max Cap": pillar_scores.get("url_threats", {}).get("max_possible", 35),
                "Pre-Cap (Dampened)": pillar_scores.get("url_threats", {}).get("uncapped_dampened_score", 0),
                "Capped Score": pillar_scores.get("url_threats", {}).get("score", 0),
                "Cap Adjustment": -pillar_scores.get("url_threats", {}).get("cap_reduction", 0),
                "Status": pillar_scores.get("url_threats", {}).get("status", "normal").upper(),
            },
            {
                "Pillar Vector": "AI NLP Intent Classification (DistilBERT Phishing)",
                "Weight": "25%",
                "Max Cap": pillar_scores.get("ai_content_analysis", {}).get("max_possible", 25),
                "Pre-Cap (Dampened)": pillar_scores.get("ai_content_analysis", {}).get("uncapped_dampened_score", 0),
                "Capped Score": pillar_scores.get("ai_content_analysis", {}).get("score", 0),
                "Cap Adjustment": -pillar_scores.get("ai_content_analysis", {}).get("cap_reduction", 0),
                "Status": pillar_scores.get("ai_content_analysis", {}).get("status", "normal").upper(),
            },
            {
                "Pillar Vector": "Routing & Transport Anomalies (Hop Trace, RFC 1918)",
                "Weight": "15%",
                "Max Cap": pillar_scores.get("routing_transport", {}).get("max_possible", 15),
                "Pre-Cap (Dampened)": pillar_scores.get("routing_transport", {}).get("uncapped_dampened_score", 0),
                "Capped Score": pillar_scores.get("routing_transport", {}).get("score", 0),
                "Cap Adjustment": -pillar_scores.get("routing_transport", {}).get("cap_reduction", 0),
                "Status": pillar_scores.get("routing_transport", {}).get("status", "normal").upper(),
            },
        ]
        st.dataframe(pd.DataFrame(pillar_table_data), use_container_width=True, hide_index=True)
        st.caption("* Note: Pre-Cap (Dampened) reflects multi-occurrence diminishing-returns dampening before applying the pillar budget cap.")

        # ---------------------------------------------------------------------
        # TABBED FORENSIC INVESTIGATION WORKSTATION
        # ---------------------------------------------------------------------
        st.markdown("---")
        st.subheader("3. Comprehensive Forensic Investigation Tabs")

        tab_auth, tab_url, tab_routing, tab_ai, tab_ledger, tab_recs = st.tabs([
            "🔑 Authentication & Identity",
            "🔗 URL Threat Analysis",
            "🌐 Email Routing & IP Trace",
            "🤖 AI Phishing Classification",
            "⚖️ Evidence Ledger & Audit Trail",
            "📋 Recommendations & Limitations",
        ])

        # --- TAB 1: AUTHENTICATION ---
        with tab_auth:
            st.markdown("#### Sender Authentication & Identity Verification")
            auth_data = pipeline_res["auth_result"]
            observed = auth_data.get("observed_evidence", {})

            col_a1, col_a2, col_a3 = st.columns(3)
            with col_a1:
                spf_ind = auth_data.get("spf", {}).get("independent_result", "not_checked")
                st.metric("SPF Verification", spf_ind.upper())
                st.caption("Independent evaluation requires original SMTP connection IP (absent in static `.eml`).")
            with col_a2:
                dkim_res = auth_data.get("dkim", {}).get("overall_result", "none")
                st.metric("DKIM Signature", dkim_res.upper())
                st.caption("Cryptographic signature evaluation over raw email bytes.")
            with col_a3:
                dmarc_res = auth_data.get("dmarc", {}).get("result", "none")
                st.metric("DMARC Policy Check", dmarc_res.upper())
                st.caption("Evaluated domain alignment against Header From.")

            st.markdown("##### Observed Header Claims vs Independent Verification")
            auth_rows = [
                {"Attribute": "Header From", "Observed Value": observed.get("header_from", "(None)"), "Trust Level": "UNTRUSTED (Sender Controlled)"},
                {"Attribute": "Return-Path", "Observed Value": observed.get("return_path", "(None)"), "Trust Level": observed.get("envelope_domain_trust", "UNTRUSTED")},
                {"Attribute": "Received-SPF Header", "Observed Value": observed.get("received_spf_header", "(None)"), "Trust Level": observed.get("received_spf_trust", "UNTRUSTED")},
                {"Attribute": "DKIM Signatures Found", "Observed Value": f"{observed.get('dkim_signature_headers_count', 0)} signature header(s)", "Trust Level": "Cryptographically Checked"},
            ]
            st.dataframe(pd.DataFrame(auth_rows), use_container_width=True, hide_index=True)

        # --- TAB 2: URL THREAT ANALYSIS ---
        with tab_url:
            st.markdown("#### Embedded Link & URL Threat Analysis")
            url_data = pipeline_res["url_result"]
            total_u = url_data.get("total_urls_analyzed", 0)
            max_u_score = url_data.get("max_risk_score", 0)
            u_level = url_data.get("overall_url_risk_level", "none")

            col_u1, col_u2, col_u3 = st.columns(3)
            with col_u1:
                st.metric("Total URLs Analyzed", total_u)
            with col_u2:
                st.metric("Max URL Threat Score", f"{max_u_score} / 100")
            with col_u3:
                st.metric("Overall URL Level", u_level.upper())

            st.info("ℹ️ **Zero Network Access Notice**: URLs are analyzed strictly through local lexical and structural heuristics. Reputation status: `not_checked`.")

            if total_u > 0 and url_data.get("results"):
                url_rows = []
                for u_item in url_data["results"]:
                    raw_u = u_item.get("raw_url", "")
                    defanged_u = defang_url(raw_u)
                    indicators = [ind.get("id") for ind in u_item.get("indicators", [])]
                    url_rows.append({
                        "Defanged URL": defanged_u,
                        "Hostname / Domain": u_item.get("hostname", "(Unknown)"),
                        "Risk Score": u_item.get("heuristic_risk_score", 0),
                        "Risk Level": u_item.get("risk_level", "none").upper(),
                        "Triggered Heuristic Indicators": ", ".join(indicators) if indicators else "None",
                    })
                st.dataframe(pd.DataFrame(url_rows), use_container_width=True, hide_index=True)
            else:
                st.success("Clean Status: No embedded URLs were detected in this email.")

        # --- TAB 3: ROUTING & INFRASTRUCTURE ---
        with tab_routing:
            st.markdown("#### Email Transmission Hop Trace & IP Infrastructure")
            routing_data = pipeline_res["routing_result"]
            hops = routing_data.get("hops", [])

            col_r1, col_r2 = st.columns(2)
            with col_r1:
                st.metric("Total Mail Server Hops", len(hops))
            with col_r2:
                anom = routing_data.get("anomalies_detected", False)
                st.metric("Routing Anomalies Detected", "YES" if anom else "NO")

            geo_summary = routing_data.get("geolocation_summary", {})
            st.caption(f"🌍 GeoIP Provider: `{geo_summary.get('provider_used', 'None')}`. {geo_summary.get('forensic_disclaimer', '')}")

            if hops:
                hop_rows = []
                for h in hops:
                    hop_rows.append({
                        "Hop #": h.get("hop_index", 0),
                        "Receiving Host (By)": h.get("by_host") or "(Unspecified)",
                        "Sending Host (From)": h.get("from_host") or "(Unspecified)",
                        "Hop IP Address": h.get("hop_ip") or "(No IP)",
                        "IP Classification": h.get("ip_classification", "unknown"),
                        "Parsed Delay (sec)": h.get("delay_seconds") if h.get("delay_seconds") is not None else "N/A",
                    })
                st.dataframe(pd.DataFrame(hop_rows), use_container_width=True, hide_index=True)
            else:
                st.warning("No 'Received' headers found to reconstruct routing timeline.")

        # --- TAB 4: AI NLP CLASSIFICATION ---
        with tab_ai:
            st.markdown("#### Pretrained AI Intent Classification")
            ai_data = pipeline_res["ai_result"]
            classification = ai_data.get("classification", {})
            model_meta = ai_data.get("model_metadata", {})

            col_ai1, col_ai2 = st.columns(2)
            with col_ai1:
                verdict = classification.get("semantic_verdict") or ai_data.get("verdict", "unknown")
                st.metric("AI Semantic Verdict", verdict.upper())
            with col_ai2:
                confidence = classification.get("confidence") or ai_data.get("confidence", 0.0)
                st.metric("Model Softmax Confidence", f"{confidence:.4f}")

            st.warning(
                "⚠️ **Epistemic Calibration Caveat**: Pretrained DistilBERT softmax scores represent "
                "sequence correlation inside the model's training corpus, **NOT** a calibrated real-world "
                "Bayesian probability of fraud or maliciousness. It is weighted as one evidence signal (25% weight) "
                "alongside cryptographic and lexical proofs."
            )

            st.markdown("##### Model Architecture & Inference Telemetry")
            ai_rows = [
                {"Attribute": "Model Identifier", "Value": model_meta.get("model_id", "aamoshdahal/email-phishing-distilbert-finetuned")},
                {"Attribute": "Model Architecture", "Value": model_meta.get("architecture", "DistilBertForSequenceClassification")},
                {"Attribute": "Inference Device", "Value": model_meta.get("device_used", "CPU")},
                {"Attribute": "Execution Status", "Value": model_meta.get("model_status", "executed")},
            ]
            st.dataframe(pd.DataFrame(ai_rows), use_container_width=True, hide_index=True)

        # --- TAB 5: EVIDENCE LEDGER & AUDIT TRAIL ---
        with tab_ledger:
            st.markdown("#### Itemized Evidence Ledger")
            evidence_items = risk_report.get("evidence", [])

            if evidence_items:
                ledger_rows = []
                for ev in evidence_items:
                    ledger_rows.append({
                        "Evidence ID": ev.get("id"),
                        "Pillar": ev.get("pillar"),
                        "Severity": ev.get("severity", "none").upper(),
                        "Base Pts": ev.get("base_points", 0),
                        "Count": ev.get("occurrence_count", 1),
                        "Raw Pts": ev.get("raw_points", 0),
                        "Dampened Pts": ev.get("dampened_points", 0),
                        "Cap Reduction": ev.get("pillar_cap_reduction", 0),
                        "Effective Contribution": ev.get("effective_contribution", 0),
                        "Forensic Explanation": ev.get("explanation", ""),
                    })
                st.dataframe(pd.DataFrame(ledger_rows), use_container_width=True, hide_index=True)

            st.markdown("##### 📐 Dual-Pathway Mathematical Audit Trail")
            p_raw = metadata.get("pillar_raw_points_sum", 0)
            p_dim = metadata.get("multi_occurrence_dampening_reduction", 0)
            p_damp = metadata.get("pillar_dampened_points_sum", 0)
            p_cap = metadata.get("pillar_cap_reduction", 0)
            p_capped = metadata.get("capped_pillar_scores_sum", 0)
            syn_b = metadata.get("synergy_bonus", 0)
            mit_d = metadata.get("mitigation_discount", 0)

            l_raw = metadata.get("raw_signal_points_sum", 0)
            l_damp = metadata.get("dampened_points_sum", 0)

            st.markdown(
                f"""
                <div class="audit-box">
                <b>1. Pillar Vectors Pathway:</b><br/>
                &nbsp;&nbsp;{p_raw} Raw Signal Pts - {p_dim} Diminishing Returns = {p_damp} Pre-Cap (Dampened) Pts<br/>
                &nbsp;&nbsp;{p_damp} Pre-Cap Pts - {p_cap} Budget Cap Reduction = {p_capped} Capped Pillar Pts<br/>
                &nbsp;&nbsp;{p_capped} Capped Pts + {syn_b} Synergy Bonus - {mit_d} Mitigation = <b>{score} Final Risk Score</b><br/><br/>
                <b>2. Evidence Ledger Pathway:</b><br/>
                &nbsp;&nbsp;{l_raw} Total Raw Points (including synergy) - {p_dim} Diminishing Returns Reduction = {l_damp} Total Dampened Points<br/>
                &nbsp;&nbsp;{l_damp} Total Dampened Points - {p_cap} Budget Cap Reduction = <b>{score} Effective Ledger Contribution</b>
                </div>
                """,
                unsafe_allow_html=True,
            )

        # --- TAB 6: RECOMMENDATIONS & LIMITATIONS ---
        with tab_recs:
            st.markdown("#### Recommended Investigative Actions & Mitigation")
            recs = risk_report.get("recommended_actions", [])
            for i, r in enumerate(recs, 1):
                st.markdown(f"**{i}.** {r}")

            st.markdown("##### ⚠️ Missing or Inconclusive Evidence")
            missing = risk_report.get("missing_evidence", [])
            if missing:
                for m in missing:
                    st.warning(f"• **{m.get('pillar', 'General')}**: {m.get('description', '')}")
            else:
                st.info("No missing evidence categories were flagged.")

            st.markdown("##### 📌 Standard Forensic Limitations")
            limits = risk_report.get("limitations", [])
            for lim in limits:
                st.caption(f"• {lim}")


        # ---------------------------------------------------------------------
        # STEP 4: PDF REPORT EXPORT INTEGRATION
        # ---------------------------------------------------------------------
        st.markdown("---")
        st.subheader("4. Official Forensic Intelligence Report Export")
        st.markdown("Generate a publication-grade, auditable PDF report directly from the active forensic payload.")

        pdf_col1, pdf_col2 = st.columns([1, 2])

        with pdf_col1:
            gen_pdf_btn = st.button("📄 Generate PDF Investigation Report", type="secondary", use_container_width=True)

        if gen_pdf_btn:
            with st.spinner("Compiling ReportLab Forensic PDF Document..."):
                with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tf:
                    temp_pdf_path = tf.name

                try:
                    pdf_result = generate_forensic_pdf(
                        email_data=pipeline_res["parsed_email"],
                        auth_data=pipeline_res["auth_result"],
                        url_data=pipeline_res["url_result"],
                        routing_data=pipeline_res["routing_result"],
                        ai_data=pipeline_res["ai_result"],
                        risk_data=pipeline_res["risk_report"],
                        output_path=temp_pdf_path,
                        case_id=st.session_state["case_id"],
                        include_body_excerpt=True,
                    )
                    with open(temp_pdf_path, "rb") as fh:
                        pdf_bytes = fh.read()
                        st.session_state["generated_pdf_bytes"] = pdf_bytes
                finally:
                    if os.path.exists(temp_pdf_path):
                        os.remove(temp_pdf_path)

        with pdf_col2:
            if st.session_state.get("generated_pdf_bytes"):
                pdf_b = st.session_state["generated_pdf_bytes"]
                # Verify PDF signature %PDF-
                if pdf_b.startswith(b"%PDF-"):
                    sha256_hash = hashlib.sha256(pdf_b).hexdigest()
                    out_filename = f"{st.session_state['case_id']}_forensic_report.pdf"
                    st.download_button(
                        label="⬇️ Download Official Forensic Report (PDF)",
                        data=pdf_b,
                        file_name=out_filename,
                        mime="application/pdf",
                        type="primary",
                        use_container_width=True,
                    )
                    st.caption(f"✓ Valid PDF Document ({len(pdf_b):,} bytes) | SHA-256: `{sha256_hash[:16]}...{sha256_hash[-8:]}`")
                else:
                    st.error("Error: Generated file does not contain a valid %PDF- magic header.")
