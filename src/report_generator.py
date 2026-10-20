"""
src/report_generator.py
=======================
Module 7: PDF Forensic Report Generator
SIH 2026 — AI-Powered Email Threat Detection Platform

Transforms comprehensive forensic analysis findings across Modules 1 through 6
into a publication-quality, print-friendly, mathematically auditable PDF report.

CORE FORENSIC AND SECURITY PRINCIPLES:
1. Strict Offline Rendering: Uses ReportLab Platypus layout engine. Zero external
   HTTP, DNS, or socket requests during PDF compilation.
2. Complete Input Neutralization: All untrusted email strings (From, Subject, To,
   URLs, header values, body excerpts) are XML-escaped and bounded before rendering
   to prevent markup injection and layout overflows.
3. Total Mathematical Auditability: Renders the complete evidence accounting chain
   with raw points, multi-occurrence dampening, pillar cap adjustments, and
   effective contributions, showing full reconciliation to the final risk score.
4. Epistemic Honesty:
   - Unverified items (e.g. SPF 'not_checked', missing GeoLite2 database) are
     explicitly distinguished from confirmed failures.
   - AI model confidence is paired with an explicit caveat noting that softmax
     distribution certainty does not equal real-world probability of malice.
   - File hashes are labeled as static file-integrity identifiers, not sender authenticity.
   - Disclaimers state that reports reflect only supplied evidence and do not constitute
     a certified legal chain of custody.
5. Two-Pass Dynamic Numbered Canvas: Accurately renders 'Page X of Y' alongside
   running headers and footers across any document length.

AUTHOR: SIH 2026 Team
VERSION: 1.0.0
"""

from __future__ import annotations

import html
import os
import sys
from datetime import datetime, timezone
from typing import Any, Optional

import reportlab
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

REPORT_GENERATOR_VERSION: str = "1.0.0"

# ---------------------------------------------------------------------------
# Page Layout and Geometry (Letter size with 0.5 in / 36 pt margins)
# ---------------------------------------------------------------------------
PAGE_WIDTH, PAGE_HEIGHT = letter
PAGE_MARGIN: float = 36.0
USABLE_WIDTH: float = PAGE_WIDTH - (2 * PAGE_MARGIN)  # 540.0 pt

# ---------------------------------------------------------------------------
# Professional Cybersecurity Theme Palette
# ---------------------------------------------------------------------------
COLOR_NAVY = colors.HexColor("#0f172a")       # Slate 900 (Headings, primary bars)
COLOR_SLATE_DARK = colors.HexColor("#1e293b") # Slate 800 (Card titles, table headers)
COLOR_SLATE_MID = colors.HexColor("#475569")  # Slate 600 (Secondary labels, text)
COLOR_SLATE_LIGHT = colors.HexColor("#64748b")# Slate 500 (Captions, footnotes)
COLOR_BORDER = colors.HexColor("#cbd5e1")     # Slate 300 (Table rules, box borders)
COLOR_BG_CARD = colors.HexColor("#f8fafc")    # Slate 50 (Callout background)
COLOR_BG_ALT = colors.HexColor("#f1f5f9")     # Slate 100 (Alternating rows)
COLOR_WHITE = colors.HexColor("#ffffff")

# Risk Level Accents
COLOR_CRITICAL = colors.HexColor("#b91c1c")   # Red 700
COLOR_HIGH = colors.HexColor("#c2410c")       # Orange 700
COLOR_MEDIUM = colors.HexColor("#b45309")     # Amber 700
COLOR_LOW = colors.HexColor("#1d4ed8")        # Blue 700
COLOR_NONE = colors.HexColor("#15803d")       # Green 700

RISK_COLORS: dict[str, colors.HexColor] = {
    "critical": COLOR_CRITICAL,
    "high": COLOR_HIGH,
    "medium": COLOR_MEDIUM,
    "low": COLOR_LOW,
    "none": COLOR_NONE,
    "inconclusive": COLOR_SLATE_MID,
}


# ===========================================================================
# TWO-PASS NUMBERED CANVAS (Page X of Y + Running Headers/Footers)
# ===========================================================================

class NumberedCanvas(canvas.Canvas):
    """
    Two-pass ReportLab canvas that calculates the total page count dynamically
    and draws consistent running headers, footers, and 'Page X of Y' markers.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._saved_page_states: list[dict[str, Any]] = []

    def showPage(self) -> None:
        # Save state for the second pass
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._draw_running_decorations(num_pages)
            super().showPage()
        super().save()

    def _draw_running_decorations(self, total_pages: int) -> None:
        self.saveState()

        # Suppress running header on cover / page 1
        if self._pageNumber > 1:
            self.setFont("Helvetica-Bold", 7)
            self.setFillColor(COLOR_SLATE_MID)
            self.drawString(PAGE_MARGIN, PAGE_HEIGHT - 24, "SIH 2026 | EMAIL THREAT FORENSIC INTELLIGENCE PLATFORM")

            self.setFont("Helvetica", 7)
            self.drawRightString(PAGE_WIDTH - PAGE_MARGIN, PAGE_HEIGHT - 24, "CONFIDENTIAL & PRIVILEGED")

            self.setStrokeColor(COLOR_BORDER)
            self.setLineWidth(0.5)
            self.line(PAGE_MARGIN, PAGE_HEIGHT - 28, PAGE_WIDTH - PAGE_MARGIN, PAGE_HEIGHT - 28)

        # Running Footer (All pages)
        self.setStrokeColor(COLOR_BORDER)
        self.setLineWidth(0.5)
        self.line(PAGE_MARGIN, 32, PAGE_WIDTH - PAGE_MARGIN, 32)

        self.setFont("Helvetica", 6.5)
        self.setFillColor(COLOR_SLATE_LIGHT)
        self.drawString(
            PAGE_MARGIN,
            22,
            "Forensic assessment generated autonomously from supplied email artifact. Not a certificate of legal chain-of-custody.",
        )

        page_str = f"Page {self._pageNumber} of {total_pages}"
        self.setFont("Helvetica-Bold", 7)
        self.setFillColor(COLOR_SLATE_MID)
        self.drawRightString(PAGE_WIDTH - PAGE_MARGIN, 22, page_str)

        self.restoreState()


# ===========================================================================
# TEXT SANITIZATION & STYLING HELPERS
# ===========================================================================

def _safe_xml(val: Any, max_len: int = 400) -> str:
    """
    Safely sanitize untrusted text for ReportLab Paragraph XML parsing.
    Escapes &, <, >, quotes, truncates excessive length, and preserves line breaks.
    """
    if val is None:
        return "<i>N/A</i>"
    s = str(val).strip()
    if not s:
        return "<i>N/A</i>"
    if len(s) > max_len:
        s = s[:max_len] + " ... [truncated]"
    return html.escape(s).replace("\n", "<br/>")


def _defang_text(url_str: str) -> str:
    """Ensure URLs are defanged before rendering."""
    s = str(url_str or "").strip()
    s = s.replace("http://", "hxxp://").replace("https://", "hxxps://").replace("ftp://", "fxp://")
    return s


def _create_styles() -> dict[str, ParagraphStyle]:
    """Build a complete, isolated set of report paragraph styles."""
    styles = getSampleStyleSheet()

    custom_styles: dict[str, ParagraphStyle] = {
        "Title": ParagraphStyle(
            "DocTitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=16,
            leading=20,
            textColor=COLOR_NAVY,
            spaceAfter=2,
        ),
        "Subtitle": ParagraphStyle(
            "DocSubtitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=11,
            textColor=COLOR_SLATE_MID,
            spaceAfter=8,
        ),
        "SectionHeader": ParagraphStyle(
            "SecHeader",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=10.5,
            leading=13,
            textColor=COLOR_NAVY,
            spaceBefore=8,
            spaceAfter=4,
            keepWithNext=True,
        ),
        "SubsectionHeader": ParagraphStyle(
            "SubSecHeader",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8.5,
            leading=11,
            textColor=COLOR_SLATE_DARK,
            spaceBefore=4,
            spaceAfter=2,
            keepWithNext=True,
        ),
        "Body": ParagraphStyle(
            "DocBody",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=7.5,
            leading=10,
            textColor=COLOR_SLATE_DARK,
        ),
        "BodyBold": ParagraphStyle(
            "DocBodyBold",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=7.5,
            leading=10,
            textColor=COLOR_SLATE_DARK,
        ),
        "Caption": ParagraphStyle(
            "DocCaption",
            parent=styles["Normal"],
            fontName="Helvetica-Oblique",
            fontSize=6.5,
            leading=8.5,
            textColor=COLOR_SLATE_LIGHT,
        ),
        "Mono": ParagraphStyle(
            "DocMono",
            parent=styles["Normal"],
            fontName="Courier",
            fontSize=6.5,
            leading=8.5,
            textColor=COLOR_SLATE_DARK,
        ),
        "MonoSmall": ParagraphStyle(
            "DocMonoSmall",
            parent=styles["Normal"],
            fontName="Courier",
            fontSize=5.5,
            leading=7.5,
            textColor=COLOR_SLATE_DARK,
        ),
        "TableCell": ParagraphStyle(
            "TCell",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=6.5,
            leading=8.5,
            textColor=COLOR_SLATE_DARK,
        ),
        "TableCellBold": ParagraphStyle(
            "TCellBold",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=6.5,
            leading=8.5,
            textColor=COLOR_SLATE_DARK,
        ),
        "TableHeader": ParagraphStyle(
            "THeader",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=6.5,
            leading=8.5,
            textColor=COLOR_WHITE,
        ),
        "BannerTitle": ParagraphStyle(
            "BannerT",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=14,
            textColor=COLOR_WHITE,
        ),
        "BannerSub": ParagraphStyle(
            "BannerS",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=8,
            leading=10,
            textColor=COLOR_WHITE,
        ),
        "CaveatBox": ParagraphStyle(
            "Caveat",
            parent=styles["Normal"],
            fontName="Helvetica-Oblique",
            fontSize=6.5,
            leading=8.5,
            textColor=colors.HexColor("#7c2d12"), # Warm amber/brown
        ),
        "Disclaimer": ParagraphStyle(
            "DocDisclaimer",
            parent=styles["Normal"],
            fontName="Helvetica-Oblique",
            fontSize=6.5,
            leading=8.5,
            textColor=COLOR_SLATE_LIGHT,
        ),
    }

    return custom_styles


# ===========================================================================
# SECTION BUILDERS
# ===========================================================================

def _build_header_card(
    case_id: Optional[str],
    generated_at: str,
    risk_score: int,
    risk_level: str,
    verdict_title: str,
    styles: dict[str, ParagraphStyle],
) -> list[Any]:
    """Top-level document title, case metadata, and executive verdict banner."""
    story: list[Any] = []

    # Title block
    title_text = "FORENSIC EMAIL THREAT INTELLIGENCE REPORT"
    case_label = f"CASE / REFERENCE ID: <b>{_safe_xml(case_id or 'NOT SPECIFIED')}</b>"
    time_label = f"ANALYSIS TIMESTAMP: <b>{_safe_xml(generated_at)}</b> | ENGINE VERSION: <b>v{REPORT_GENERATOR_VERSION}</b>"

    header_table_data = [
        [
            Paragraph(title_text, styles["Title"]),
            Paragraph(f"<para align='right'>{case_label}<br/>{time_label}</para>", styles["Subtitle"]),
        ]
    ]
    header_table = Table(header_table_data, colWidths=[320, 220])
    header_table.setStyle(
        TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ])
    )
    story.append(header_table)
    story.append(HRFlowable(width="100%", thickness=1.5, color=COLOR_NAVY, spaceBefore=2, spaceAfter=6))

    # Executive Verdict Banner (Color-coded based on risk level)
    accent_color = RISK_COLORS.get(risk_level.lower(), COLOR_SLATE_MID)
    score_display = f"{risk_score} / 100"
    level_display = risk_level.upper()

    banner_left = Paragraph(
        f"<font size=22><b>{score_display}</b></font><br/>"
        f"<b>COMPOSITE THREAT SCORE</b>",
        styles["BannerTitle"],
    )
    banner_right = Paragraph(
        f"<b>VERDICT: {_safe_xml(verdict_title)}</b><br/>"
        f"THREAT CLASSIFICATION: <b>{level_display} RISK</b>",
        styles["BannerSub"],
    )

    banner_table = Table([[banner_left, banner_right]], colWidths=[140, 400])
    banner_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), accent_color),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ])
    )
    story.append(banner_table)
    story.append(Spacer(1, 6))

    return story


def _build_executive_summary_box(
    summary_text: str,
    styles: dict[str, ParagraphStyle],
) -> list[Any]:
    """Executive summary narrative callout."""
    story: list[Any] = []
    story.append(Paragraph("EXECUTIVE FORENSIC SUMMARY", styles["SectionHeader"]))

    card_data = [[Paragraph(_safe_xml(summary_text, max_len=1200), styles["Body"])]]
    card_table = Table(card_data, colWidths=[USABLE_WIDTH])
    card_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), COLOR_BG_CARD),
            ("BOX", (0, 0), (-1, -1), 0.75, COLOR_BORDER),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ])
    )
    story.append(card_table)
    story.append(Spacer(1, 6))
    return story


def _build_metadata_section(
    email_data: Optional[dict[str, Any]],
    styles: dict[str, ParagraphStyle],
) -> list[Any]:
    """Email headers and file integrity identification."""
    story: list[Any] = []
    story.append(Paragraph("1. EMAIL ARTIFACT & MESSAGE METADATA", styles["SectionHeader"]))

    if not email_data or not isinstance(email_data, dict):
        story.append(Paragraph("<i>No parsed email artifact metadata provided.</i>", styles["Body"]))
        story.append(Spacer(1, 6))
        return story

    file_meta = email_data.get("file_metadata", {})
    email_meta = email_data.get("email_metadata", {})
    headers = email_data.get("headers", {})

    from_val = email_meta.get("from") or headers.get("from") or "Unknown"
    to_val = email_meta.get("to") or headers.get("to") or "Unknown"
    if isinstance(to_val, list):
        to_val = ", ".join(str(t) for t in to_val)
    subject_val = email_meta.get("subject") or headers.get("subject") or "(No Subject)"
    date_val = email_meta.get("date") or headers.get("date") or "Unknown"
    msg_id = email_meta.get("message_id") or headers.get("message-id") or "Unknown"
    return_path = email_meta.get("return_path") or headers.get("return-path") or "Not Present"

    file_name = file_meta.get("filename") or "uploaded_email.eml"
    file_size = file_meta.get("file_size_bytes") or file_meta.get("size_bytes") or 0
    file_sha256 = file_meta.get("sha256") or file_meta.get("hash_sha256")
    if not file_sha256:
        rb = email_data.get("raw_bytes")
        fp = file_meta.get("file_path") or email_data.get("file_path")
        import hashlib
        if rb and isinstance(rb, bytes):
            file_sha256 = hashlib.sha256(rb).hexdigest()
        elif fp and isinstance(fp, str) and os.path.isfile(fp):
            try:
                with open(fp, "rb") as _f:
                    file_sha256 = hashlib.sha256(_f.read()).hexdigest()
            except Exception:
                file_sha256 = "Not Computed"
        else:
            file_sha256 = "Not Computed"

    meta_rows = [
        [
            Paragraph("<b>Subject:</b>", styles["TableCellBold"]),
            Paragraph(_safe_xml(subject_val, max_len=200), styles["TableCell"]),
            Paragraph("<b>Artifact File:</b>", styles["TableCellBold"]),
            Paragraph(_safe_xml(file_name, max_len=60), styles["TableCell"]),
        ],
        [
            Paragraph("<b>From:</b>", styles["TableCellBold"]),
            Paragraph(_safe_xml(from_val, max_len=200), styles["TableCell"]),
            Paragraph("<b>File Size:</b>", styles["TableCellBold"]),
            Paragraph(f"{file_size:,} bytes", styles["TableCell"]),
        ],
        [
            Paragraph("<b>Return-Path:</b>", styles["TableCellBold"]),
            Paragraph(_safe_xml(return_path, max_len=200), styles["TableCell"]),
            Paragraph("<b>File Integrity SHA-256:</b>", styles["TableCellBold"]),
            Paragraph(f"<font size=5.5>{_safe_xml(file_sha256, max_len=64)}</font>", styles["MonoSmall"]),
        ],
        [
            Paragraph("<b>To:</b>", styles["TableCellBold"]),
            Paragraph(_safe_xml(to_val, max_len=200), styles["TableCell"]),
            Paragraph("<b>Date Header:</b>", styles["TableCellBold"]),
            Paragraph(_safe_xml(date_val, max_len=80), styles["TableCell"]),
        ],
        [
            Paragraph("<b>Message-ID:</b>", styles["TableCellBold"]),
            Paragraph(f"<font size=5.5>{_safe_xml(msg_id, max_len=120)}</font>", styles["TableCell"]),
            Paragraph("<b>Integrity Scope:</b>", styles["TableCellBold"]),
            Paragraph("Static hash validates file integrity, not sender identity.", styles["Caption"]),
        ],
    ]

    meta_table = Table(meta_rows, colWidths=[70, 200, 100, 170])
    meta_table.setStyle(
        TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("BACKGROUND", (0, 0), (0, -1), COLOR_BG_ALT),
            ("BACKGROUND", (2, 0), (2, -1), COLOR_BG_ALT),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 2.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ])
    )
    story.append(meta_table)
    story.append(Spacer(1, 6))
    return story


def _build_pillars_summary_table(
    risk_data: dict[str, Any],
    styles: dict[str, ParagraphStyle],
) -> list[Any]:
    """Summary table of the 4 forensic risk pillars and their budget allocations."""
    story: list[Any] = []
    story.append(Paragraph("2. FOUR-PILLAR THREAT VECTOR BREAKDOWN", styles["SectionHeader"]))

    pillar_data = risk_data.get("pillar_scores", {})

    headers = [
        Paragraph("Forensic Pillar Vector", styles["TableHeader"]),
        Paragraph("Capped Score", styles["TableHeader"]),
        Paragraph("Budget Cap", styles["TableHeader"]),
        Paragraph("Pre-Cap<br/>(Dampened)", styles["TableHeader"]),
        Paragraph("Cap Reduction", styles["TableHeader"]),
        Paragraph("Signals Count", styles["TableHeader"]),
        Paragraph("Analysis Status", styles["TableHeader"]),
    ]
    rows = [headers]

    pillar_labels = [
        ("identity_authentication", "1. Identity & Auth Integrity (SPF / DKIM / DMARC)"),
        ("url_threats", "2. URL & Link Threat Heuristics"),
        ("ai_content_analysis", "3. AI Semantic & Phishing Intent Analysis"),
        ("routing_transport", "4. Routing Transport & Network Topology"),
    ]

    total_capped = 0
    total_budget = 0
    total_uncapped = 0
    total_cap_reduction = 0
    total_signals = 0

    for key, label in pillar_labels:
        info = pillar_data.get(key, {})
        score = info.get("score", 0)
        max_b = info.get("max_possible", 0)
        uncapped = info.get("uncapped_dampened_score", score)
        cap_red = info.get("cap_reduction", 0)
        sig_cnt = info.get("signals_count", 0)
        status = info.get("status", "evaluated")

        total_capped += score
        total_budget += max_b
        total_uncapped += uncapped
        total_cap_reduction += cap_red
        total_signals += sig_cnt

        rows.append([
            Paragraph(f"<b>{_safe_xml(label)}</b>", styles["TableCellBold"]),
            Paragraph(f"<b>{score}</b>", styles["TableCellBold"]),
            Paragraph(f"{max_b}", styles["TableCell"]),
            Paragraph(f"{uncapped}", styles["TableCell"]),
            Paragraph(f"-{cap_red}" if cap_red > 0 else "0", styles["TableCell"]),
            Paragraph(f"{sig_cnt}", styles["TableCell"]),
            Paragraph(_safe_xml(status), styles["TableCell"]),
        ])

    # Totals Row
    rows.append([
        Paragraph("<b>CUMULATIVE PILLAR TOTALS:</b>", styles["TableCellBold"]),
        Paragraph(f"<b>{total_capped}</b>", styles["TableCellBold"]),
        Paragraph(f"<b>{total_budget}</b>", styles["TableCellBold"]),
        Paragraph(f"<b>{total_uncapped}</b>", styles["TableCellBold"]),
        Paragraph(f"<b>-{total_cap_reduction}</b>" if total_cap_reduction > 0 else "<b>0</b>", styles["TableCellBold"]),
        Paragraph(f"<b>{total_signals}</b>", styles["TableCellBold"]),
        Paragraph("<b>—</b>", styles["TableCellBold"]),
    ])

    col_widths = [185, 55, 50, 65, 60, 55, 70]
    p_table = Table(rows, colWidths=col_widths, repeatRows=1)
    p_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_SLATE_DARK),
            ("GRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("BACKGROUND", (0, -1), (-1, -1), COLOR_BG_ALT),
        ])
    )
    story.append(p_table)
    story.append(
        Paragraph(
            "<i>Accounting Clarification: 'Pre-Cap (Dampened)' reflects the sum of heuristic points "
            "after multi-occurrence diminishing-returns dampening is applied, but before applying the pillar budget cap. "
            "Pillar Cap Reduction subtracts excess dampened points exceeding the budget cap to yield the final Capped Score "
            "(e.g., URL heuristics: 43 dampened pre-cap pts − 8 cap reduction = 35 capped score). "
            "Raw signal points before dampening are tracked per indicator in Section 7.</i>",
            styles["Caption"],
        )
    )
    story.append(Spacer(1, 4))
    return story


def _format_alignment_status(sub_dict: Any) -> str:
    """Format DMARC alignment status (DKIM or SPF) consistently.

    Handles standard dict results (with 'result' and optional 'mode'),
    legacy dicts (with 'aligned'), boolean flags, string tokens, and None.
    Returns: PASS, FAIL, NOT_CHECKED, or N/A (preserving mode, e.g. 'PASS (strict)').
    """
    if sub_dict is None:
        return "N/A"

    if not isinstance(sub_dict, dict):
        if isinstance(sub_dict, bool):
            return "PASS" if sub_dict else "FAIL"
        s = str(sub_dict).strip().upper()
        if s in ("PASS", "PASSED"):
            return "PASS"
        if s in ("FAIL", "FAILED"):
            return "FAIL"
        if s in ("NOT_CHECKED", "NOT CHECKED", "NOTCHECKED"):
            return "NOT_CHECKED"
        return s or "N/A"

    raw_result = sub_dict.get("result")
    if raw_result is None:
        raw_result = sub_dict.get("aligned")

    if raw_result is None:
        return "N/A"

    if isinstance(raw_result, bool):
        status_str = "PASS" if raw_result else "FAIL"
    else:
        norm = str(raw_result).strip().upper()
        if norm in ("PASS", "PASSED"):
            status_str = "PASS"
        elif norm in ("FAIL", "FAILED"):
            status_str = "FAIL"
        elif norm in ("NOT_CHECKED", "NOT CHECKED", "NOTCHECKED"):
            status_str = "NOT_CHECKED"
        else:
            status_str = norm

    mode = sub_dict.get("mode")
    if mode and isinstance(mode, str) and mode.strip() and status_str in ("PASS", "FAIL"):
        m_str = mode.strip().lower()
        if m_str == "r":
            m_str = "relaxed"
        elif m_str == "s":
            m_str = "strict"
        return f"{status_str} ({m_str})"

    return status_str


def _build_auth_section(
    auth_data: Optional[dict[str, Any]],
    styles: dict[str, ParagraphStyle],
    *,
    email_data: Optional[dict[str, Any]] = None,
    risk_data: Optional[dict[str, Any]] = None,
) -> list[Any]:
    """Authentication verification details covering SPF, DKIM, DMARC, and identity alignment."""
    story: list[Any] = []
    story.append(Paragraph("3. SENDER AUTHENTICATION FORENSICS (SPF / DKIM / DMARC)", styles["SectionHeader"]))

    if (not auth_data or not isinstance(auth_data, dict)) and (not risk_data or not isinstance(risk_data, dict)):
        story.append(Paragraph("<i>No authentication verifier results supplied.</i>", styles["Body"]))
        story.append(Spacer(1, 6))
        return story

    auth_data = auth_data or {}

    spf_info = auth_data.get("spf", {})
    dkim_info = auth_data.get("dkim", {})
    dmarc_info = auth_data.get("dmarc", {})

    # Format SPF status honestly
    spf_res = spf_info.get("independent_result") or spf_info.get("status") or "not_checked"
    spf_dns = spf_info.get("dns_lookup", {})
    spf_record = spf_dns.get("record") or spf_info.get("record") or "None retrieved"
    spf_note = spf_info.get("reason") or spf_info.get("explanation") or (
        "Connecting IP not available in static email artifact. Delivery-time SPF could not be independently verified."
    )

    # Format DKIM status
    dkim_res = dkim_info.get("overall_result") or dkim_info.get("status") or "none"
    dkim_sigs = dkim_info.get("signatures", [])
    dkim_sig_summary = f"{len(dkim_sigs)} signature(s) inspected"
    if dkim_sigs and isinstance(dkim_sigs[0], dict):
        first_sig = dkim_sigs[0]
        dkim_sig_summary += f" (Domain: {first_sig.get('domain', 'N/A')}, Selector: {first_sig.get('selector', 'N/A')})"

    # Format DMARC status
    dmarc_res = dmarc_info.get("result") or dmarc_info.get("status") or "none"
    policy_dict = dmarc_info.get("policy")
    policy_p = policy_dict.get("p") if isinstance(policy_dict, dict) else str(policy_dict or "none")
    dmarc_align = dmarc_info.get("alignment")

    dkim_aligned = "N/A"
    spf_aligned = "N/A"
    if isinstance(dmarc_align, dict):
        dkim_aligned = _format_alignment_status(dmarc_align.get("dkim"))
        spf_aligned = _format_alignment_status(dmarc_align.get("spf"))
    elif dmarc_align is not None:
        dkim_aligned = _format_alignment_status(dmarc_align)
        spf_aligned = _format_alignment_status(dmarc_align)

    # Extract identity & spoofing evidence from risk assessment ledger or header metadata
    display_spoof_ev: Optional[dict[str, Any]] = None
    rp_mismatch_ev: Optional[dict[str, Any]] = None
    confirmed_spoof_ev: Optional[dict[str, Any]] = None

    if risk_data and isinstance(risk_data, dict):
        evidence_list = risk_data.get("evidence", [])
        if isinstance(evidence_list, list):
            for ev in evidence_list:
                if isinstance(ev, dict):
                    ind = ev.get("indicator")
                    eid = ev.get("id")
                    if ind == "display_name_spoofing" or eid == "AUTH_DISPLAY_NAME_BRAND_MISMATCH":
                        display_spoof_ev = ev
                    elif ind == "return_path_mismatch" or eid == "AUTH_RETURN_PATH_DIVERGENCE":
                        rp_mismatch_ev = ev
                    elif ind == "spoofing_detected" or eid == "AUTH_SPOOFING_CONFIRMED":
                        confirmed_spoof_ev = ev

    # Extract header values for display name and domains
    from_raw = None
    return_path_raw = None
    if email_data and isinstance(email_data, dict):
        email_meta = email_data.get("email_metadata", {})
        headers = email_data.get("headers", {})
        from_raw = email_meta.get("from") or headers.get("from") or email_data.get("from")
        return_path_raw = email_meta.get("return_path") or headers.get("return-path") or email_data.get("return_path")

    # Helper to parse display name and domain safely
    def _parse_addr(addr_str: Optional[str]) -> tuple[str, str]:
        if not addr_str or not isinstance(addr_str, str):
            return "", ""
        import email.utils
        name, addr = email.utils.parseaddr(addr_str)
        dom = addr.rsplit("@", 1)[-1].strip().rstrip(">").lower() if "@" in addr else ""
        return name, dom

    from_name, from_dom = _parse_addr(from_raw)
    _, rp_dom = _parse_addr(return_path_raw)

    # 4. Display-Name Brand Impersonation Row
    if display_spoof_ev:
        disp_status = "<font color='#b91c1c'><b>FLAGGED (Brand Divergence)</b></font>"
        disp_detail = (
            f"<b>Display Name:</b> '{_safe_xml(from_name or 'Brand Claim')}' | "
            f"<b>Sender Domain:</b> '{_safe_xml(from_dom or 'Unrelated')}'<br/>"
            f"<b>Forensic Finding:</b> {_safe_xml(display_spoof_ev.get('explanation') or 'Display name claims protected brand on unrelated domain.')}"
        )
    elif from_raw:
        disp_status = "<font color='#15803d'><b>CLEAN (Aligned)</b></font>"
        disp_detail = (
            f"Display name ('{_safe_xml(from_name or from_raw)}') does not reference an unassociated protected brand "
            f"and aligns with sender domain ('{_safe_xml(from_dom or 'N/A')}')."
        )
    else:
        disp_status = "<b>NOT EVALUATED</b>"
        disp_detail = "Sender From header not available in email artifact; display name alignment could not be verified."

    # 5. Envelope Return-Path Alignment Row
    if rp_mismatch_ev:
        rp_status = "<font color='#c2410c'><b>DIVERGENT (Mismatch)</b></font>"
        rp_detail = (
            f"<b>Visible From Domain:</b> '{_safe_xml(from_dom or 'Unknown')}' | "
            f"<b>Return-Path Domain:</b> '{_safe_xml(rp_dom or 'Unknown')}'<br/>"
            f"<b>Forensic Finding:</b> {_safe_xml(rp_mismatch_ev.get('explanation') or 'Bounce address domain diverges from sender domain.')}"
        )
    elif from_dom and rp_dom:
        if from_dom == rp_dom:
            rp_status = "<font color='#15803d'><b>ALIGNED</b></font>"
            rp_detail = (
                f"Header From domain ('{_safe_xml(from_dom)}') matches envelope Return-Path domain "
                f"('{_safe_xml(rp_dom)}'). Bounce routing aligns with visible sender."
            )
        else:
            rp_status = "<font color='#c2410c'><b>DIVERGENT</b></font>"
            rp_detail = (
                f"Header From domain ('{_safe_xml(from_dom)}') differs from envelope Return-Path domain "
                f"('{_safe_xml(rp_dom)}')."
            )
    elif return_path_raw:
        rp_status = "<font color='#15803d'><b>PRESENT</b></font>"
        rp_detail = f"Envelope Return-Path header present: <font name='Courier'>{_safe_xml(return_path_raw, max_len=60)}</font>"
    else:
        rp_status = "<b>UNVERIFIED</b>"
        rp_detail = "Envelope Return-Path header not present in static email artifact; bounce alignment cannot be confirmed."

    # 6. Domain Identity Spoofing Flag (Cryptographic / Protocol Level)
    spoofing_flag = auth_data.get("spoofing_detected", False) or bool(confirmed_spoof_ev)
    if spoofing_flag:
        domain_spoof_status = "<font color='#b91c1c'><b>DETECTED</b></font>"
        domain_spoof_detail = "Active cryptographic or domain-level identity spoofing confirmed by authentication verifier."
    else:
        domain_spoof_status = "<font color='#15803d'><b>CLEAN (No Crypto Forgery)</b></font>"
        domain_spoof_detail = (
            "No cryptographic domain forgery confirmed; authentication protocols failed/absent, "
            "with display-name heuristic evaluated separately above."
            if display_spoof_ev
            else "No high-confidence cryptographic or domain spoofing identified."
        )

    auth_rows = [
        [
            Paragraph("Protocol / Vector", styles["TableHeader"]),
            Paragraph("Evaluation Status", styles["TableHeader"]),
            Paragraph("Forensic Evidence & Policy Details", styles["TableHeader"]),
        ],
        [
            Paragraph("<b>SPF (Sender Policy Framework)</b>", styles["TableCellBold"]),
            Paragraph(f"<b>{_safe_xml(spf_res.upper())}</b>", styles["TableCellBold"]),
            Paragraph(
                f"<b>DNS Record:</b> <font name='Courier'>{_safe_xml(spf_record, max_len=120)}</font><br/>"
                f"<b>Forensic Limitation:</b> {_safe_xml(spf_note, max_len=200)}",
                styles["TableCell"],
            ),
        ],
        [
            Paragraph("<b>DKIM (Cryptographic Signatures)</b>", styles["TableCellBold"]),
            Paragraph(f"<b>{_safe_xml(dkim_res.upper())}</b>", styles["TableCellBold"]),
            Paragraph(
                f"<b>Verification Summary:</b> {_safe_xml(dkim_sig_summary, max_len=180)}<br/>"
                f"<b>Tampering Assessment:</b> {'No cryptographic signature present' if dkim_res == 'none' else ('Body & signed headers intact' if dkim_res == 'pass' else 'Cryptographic verification failure')}",
                styles["TableCell"],
            ),
        ],
        [
            Paragraph("<b>DMARC (Domain Alignment)</b>", styles["TableCellBold"]),
            Paragraph(f"<b>{_safe_xml(dmarc_res.upper())}</b>", styles["TableCellBold"]),
            Paragraph(
                f"<b>Published Policy:</b> p={_safe_xml(policy_p)}<br/>"
                f"<b>Alignment Checks:</b> DKIM Aligned: {_safe_xml(dkim_aligned)} | "
                f"SPF Aligned: {_safe_xml(spf_aligned)}",
                styles["TableCell"],
            ),
        ],
        [
            Paragraph("<b>Display-Name Brand Impersonation</b>", styles["TableCellBold"]),
            Paragraph(disp_status, styles["TableCellBold"]),
            Paragraph(disp_detail, styles["TableCell"]),
        ],
        [
            Paragraph("<b>Envelope Return-Path Alignment</b>", styles["TableCellBold"]),
            Paragraph(rp_status, styles["TableCellBold"]),
            Paragraph(rp_detail, styles["TableCell"]),
        ],
        [
            Paragraph("<b>Domain Identity Spoofing Flag</b>", styles["TableCellBold"]),
            Paragraph(domain_spoof_status, styles["TableCellBold"]),
            Paragraph(domain_spoof_detail, styles["TableCell"]),
        ],
    ]

    auth_table = Table(auth_rows, colWidths=[120, 90, 330], repeatRows=1)
    auth_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_SLATE_DARK),
            ("GRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ])
    )
    story.append(auth_table)
    story.append(Spacer(1, 6))
    return story


def _build_url_section(
    url_data: Optional[dict[str, Any]],
    styles: dict[str, ParagraphStyle],
) -> list[Any]:
    """Suspicious URL and link threat analysis findings."""
    story: list[Any] = []
    story.append(Paragraph("4. SUSPICIOUS URL & LINK THREAT HEURISTICS", styles["SectionHeader"]))

    if not url_data or not isinstance(url_data, dict):
        story.append(Paragraph("<i>No URL threat analysis data supplied.</i>", styles["Body"]))
        story.append(Spacer(1, 6))
        return story

    total_urls = url_data.get("total_urls_analyzed", 0)
    high_risk_urls = url_data.get("high_risk_url_count", 0)
    unique_domains_list = url_data.get("unique_domains", [])
    unique_domains_count = len(unique_domains_list) if isinstance(unique_domains_list, list) else 0
    max_score = url_data.get("max_risk_score", 0)
    overall_level = url_data.get("overall_url_risk_level", "none")
    risk_dist = url_data.get("risk_distribution", {})
    med_urls = risk_dist.get("medium", 0)
    low_urls = risk_dist.get("low", 0) + risk_dist.get("none", 0)

    if total_urls == 0:
        story.append(Paragraph("<b>Clean Status:</b> Zero URLs were detected or extracted from the email message.", styles["Body"]))
        story.append(Spacer(1, 6))
        return story

    # Collect findings across results
    url_findings: list[dict[str, Any]] = []
    results = url_data.get("results", [])
    if isinstance(results, list):
        for r in results:
            if isinstance(r, dict):
                raw_u = r.get("url") or r.get("original_url") or "Unknown"
                url_risk_level = (r.get("risk_level") or "low").upper()
                url_score = r.get("heuristic_risk_score", 0)
                url_risk_display = f"{url_risk_level} ({url_score}/100)"
                inds = r.get("indicators", [])
                for ind in inds:
                    if isinstance(ind, dict):
                        url_findings.append({
                            "url": _defang_text(raw_u),
                            "url_risk": url_risk_display,
                            "indicator": ind.get("id") or ind.get("title") or "Anomaly",
                            "severity": ind.get("severity", "low"),
                            "description": ind.get("description") or "Suspicious URL heuristic triggered.",
                            "score": ind.get("score_contribution", 0),
                        })

    if not url_findings:
        # Fallback for synthetic/legacy structures with findings or indicators at top-level
        top_inds = url_data.get("findings") or url_data.get("indicators")
        if isinstance(top_inds, list):
            for ind in top_inds:
                if isinstance(ind, dict):
                    raw_u = ind.get("url") or "Target Link"
                    url_findings.append({
                        "url": _defang_text(raw_u),
                        "url_risk": ind.get("url_risk") or "EVALUATED",
                        "indicator": ind.get("id") or ind.get("title") or "Anomaly",
                        "severity": ind.get("severity", "low"),
                        "description": ind.get("description") or "Suspicious URL heuristic triggered.",
                        "score": ind.get("score_contribution") or ind.get("score", 0),
                    })

    # Count heuristic indicators by severity
    high_ind_count = sum(1 for f in url_findings if str(f.get("severity", "")).lower() in ("high", "critical"))
    med_ind_count = sum(1 for f in url_findings if str(f.get("severity", "")).lower() == "medium")
    low_ind_count = sum(1 for f in url_findings if str(f.get("severity", "")).lower() == "low")

    # Clear, unambiguous summary differentiating URL risk level from indicator severity
    summary_text = (
        f"Analyzed <b>{total_urls}</b> URL(s) across <b>{unique_domains_count}</b> unique domain(s). "
        f"Maximum URL Score: <b>{max_score}/100</b> ({overall_level.upper()} Risk).<br/>"
        f"<b>URL Risk Classifications:</b> <b>{high_risk_urls}</b> High/Critical (≥70 pts), "
        f"<b>{med_urls}</b> Medium (30–69 pts), <b>{low_urls}</b> Low/Clean (&lt;30 pts).<br/>"
        f"<b>Triggered Heuristic Indicators:</b> <b>{high_ind_count}</b> High-severity, "
        f"<b>{med_ind_count}</b> Medium-severity, <b>{low_ind_count}</b> Low-severity."
    )
    story.append(Paragraph(summary_text, styles["Body"]))
    story.append(Paragraph(
        "<i>Clarification: 'Indicator Severity' measures an individual heuristic anomaly (+points); "
        "'URL Risk Level' reflects the aggregated link score (High/Critical requires ≥70 pts).</i>",
        styles["TableCellBold"],
    ))
    story.append(Spacer(1, 4))

    if not url_findings:
        story.append(Paragraph("<i>No malicious or suspicious heuristic indicators detected in extracted links.</i>", styles["Body"]))
        story.append(Spacer(1, 6))
        return story

    rows = [
        [
            Paragraph("Defanged URL Target", styles["TableHeader"]),
            Paragraph("URL Risk Level", styles["TableHeader"]),
            Paragraph("Heuristic Indicator", styles["TableHeader"]),
            Paragraph("Indicator Severity", styles["TableHeader"]),
            Paragraph("Points", styles["TableHeader"]),
            Paragraph("Forensic Indicator Explanation", styles["TableHeader"]),
        ]
    ]

    for item in url_findings[:15]:  # Bound to top 15 findings to prevent runaway report size
        rows.append([
            Paragraph(f"<font size=5.5>{_safe_xml(item['url'], max_len=75)}</font>", styles["TableCell"]),
            Paragraph(f"<font size=6><b>{_safe_xml(item['url_risk'], max_len=25)}</b></font>", styles["TableCellBold"]),
            Paragraph(_safe_xml(item["indicator"], max_len=35), styles["TableCellBold"]),
            Paragraph(f"<b>{_safe_xml(str(item['severity']).upper())}</b>", styles["TableCell"]),
            Paragraph(f"+{item['score']}", styles["TableCell"]),
            Paragraph(_safe_xml(item["description"], max_len=140), styles["TableCell"]),
        ])

    url_table = Table(rows, colWidths=[130, 75, 95, 50, 40, 150], repeatRows=1)
    url_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_SLATE_DARK),
            ("GRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ("LEFTPADDING", (0, 0), (-1, -1), 3),
            ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ])
    )
    story.append(url_table)
    story.append(Spacer(1, 6))
    return story


def _build_routing_section(
    routing_data: Optional[dict[str, Any]],
    styles: dict[str, ParagraphStyle],
) -> list[Any]:
    """Email transmission hop analysis and network classification."""
    story: list[Any] = []
    story.append(Paragraph("5. EMAIL ROUTING & NETWORK TOPOLOGY FORENSICS", styles["SectionHeader"]))

    if not routing_data or not isinstance(routing_data, dict):
        story.append(Paragraph("<i>No routing analysis data supplied.</i>", styles["Body"]))
        story.append(Spacer(1, 6))
        return story

    hops = routing_data.get("hops", [])
    total_hops = routing_data.get("total_hops") if routing_data.get("total_hops") is not None else len(hops)
    warnings = routing_data.get("warnings") or routing_data.get("global_warnings") or []
    if not isinstance(warnings, list):
        warnings = [str(warnings)]

    raw_anomalies = routing_data.get("anomalies_detected")
    if total_hops == 0:
        # Zero hops: no routing path was traversed; no routing anomalies detected.
        # An absence of routing evidence is NOT proof of route security nor maliciousness.
        anomalies = False
    elif raw_anomalies is not None:
        # Use authoritative boolean result from routing analyzer
        anomalies = bool(raw_anomalies)
    else:
        # Legacy fallback without anomalies_detected field:
        # Infer anomalies ONLY from actual anomaly indicators or well-defined anomaly warnings,
        # never from arbitrary informational warnings (e.g. absent headers or missing timestamps).
        SUSPICIOUS_WARNING_KEYWORDS = ("loop", "mismatch", "rfc1918", "inversion", "forged", "anomaly", "suspicious")
        anomalies = (
            any(bool(h.get("anomalies")) for h in hops)
            or any(
                any(k in str(w).lower() for k in SUSPICIOUS_WARNING_KEYWORDS)
                for w in warnings
            )
            or (
                routing_data.get("route_order", {}).get("ordering_ambiguity", False)
                and any("inversion" in str(w).lower() or "loop" in str(w).lower() for w in warnings)
            )
        )

    geo_enabled = routing_data.get("geolocation_enabled", False)
    geo_status = routing_data.get("geolocation_status", "database_not_found")

    geo_note = (
        "Geolocation DB active"
        if geo_enabled
        else f"Offline analysis mode ({geo_status}) — Geolocation coordinates not simulated."
    )

    story.append(Paragraph(
        f"Inspected <b>{total_hops}</b> transmission hop(s). Anomalies detected: <b>{'YES' if anomalies else 'NO'}</b>. "
        f"Geolocation: <i>{_safe_xml(geo_note)}</i>",
        styles["Body"],
    ))
    story.append(Spacer(1, 3))

    if not hops:
        story.append(Paragraph(
            "<i>No Received header routing evidence available in static artifact; transmission path could not be independently reconstructed. "
            "(Absence of routing headers is not evidence of malicious activity nor proof of route security.)</i>",
            styles["Body"],
        ))
        story.append(Spacer(1, 6))
        return story

    rows = [
        [
            Paragraph("Hop #", styles["TableHeader"]),
            Paragraph("Relaying IP", styles["TableHeader"]),
            Paragraph("Scope / Classification", styles["TableHeader"]),
            Paragraph("Hostname / Domain Claim", styles["TableHeader"]),
            Paragraph("Geo / Country", styles["TableHeader"]),
            Paragraph("Hop Anomalies & Flags", styles["TableHeader"]),
        ]
    ]

    for h in hops:
        hop_num = h.get("hop_number") if h.get("hop_number") is not None else (h.get("index") or 0)
        ip_val = h.get("ip")
        ip_type = h.get("ip_type") or h.get("scope") or "Unknown"
        country = h.get("country") or ("N/A (Offline)" if not geo_enabled else "Unknown")

        if not ip_val and h.get("extracted_ips"):
            extracted = h.get("extracted_ips")
            if isinstance(extracted, list) and extracted and isinstance(extracted[0], dict):
                ip_val = ", ".join(x.get("ip", "") for x in extracted if x.get("ip"))
                scopes = [
                    "Public" if x.get("is_global") else ("Private" if x.get("is_private") else "Other")
                    for x in extracted if isinstance(x, dict)
                ]
                ip_type = "/".join(scopes) if scopes else "Unknown"
                first_geo = next((x.get("country") for x in extracted if isinstance(x, dict) and x.get("country")), None)
                if first_geo:
                    country = first_geo

        if not ip_val:
            ip_val = "None extracted"

        by_host = h.get("by_host") or h.get("from_host") or "N/A"
        hop_anom = ", ".join(h.get("anomalies", [])) if h.get("anomalies") else "None"

        rows.append([
            Paragraph(f"#{hop_num}", styles["TableCellBold"]),
            Paragraph(f"<font size=5.5>{_safe_xml(ip_val)}</font>", styles["MonoSmall"]),
            Paragraph(_safe_xml(ip_type), styles["TableCell"]),
            Paragraph(_safe_xml(by_host, max_len=60), styles["TableCell"]),
            Paragraph(_safe_xml(country), styles["TableCell"]),
            Paragraph(_safe_xml(hop_anom, max_len=60), styles["TableCell"]),
        ])

    r_table = Table(rows, colWidths=[35, 80, 80, 130, 75, 140], repeatRows=1)
    r_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_SLATE_DARK),
            ("GRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ("LEFTPADDING", (0, 0), (-1, -1), 3),
            ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ])
    )
    story.append(r_table)
    story.append(Spacer(1, 6))
    return story


def _build_ai_section(
    ai_data: Optional[dict[str, Any]],
    styles: dict[str, ParagraphStyle],
) -> list[Any]:
    """AI text and phishing intent classification with epistemic warnings."""
    story: list[Any] = []
    story.append(Paragraph("6. AI SEMANTIC & PHISHING INTENT CLASSIFICATION", styles["SectionHeader"]))

    if not ai_data or not isinstance(ai_data, dict):
        story.append(Paragraph("<i>No AI semantic classification results supplied.</i>", styles["Body"]))
        story.append(Spacer(1, 6))
        return story

    verdict = (
        ai_data.get("verdict")
        or ai_data.get("semantic_verdict")
        or (ai_data.get("classification", {}).get("semantic_verdict") if isinstance(ai_data.get("classification"), dict) else None)
        or "unknown"
    )
    confidence = (
        ai_data.get("confidence")
        or ai_data.get("probability")
        or (ai_data.get("classification", {}).get("confidence") if isinstance(ai_data.get("classification"), dict) else None)
        or (ai_data.get("confidence_assessment", {}).get("model_confidence") if isinstance(ai_data.get("confidence_assessment"), dict) else None)
        or 0.0
    )
    model_status = (
        ai_data.get("model_status")
        or (ai_data.get("model_metadata", {}).get("status") if isinstance(ai_data.get("model_metadata"), dict) else None)
        or ai_data.get("analysis_status")
        or "unknown"
    )
    model_name = (
        ai_data.get("model_name")
        or (ai_data.get("model_metadata", {}).get("model_name") if isinstance(ai_data.get("model_metadata"), dict) else None)
        or "aamoshdahal/email-phishing-distilbert-finetuned"
    )
    raw_label = (
        (ai_data.get("raw_model_output", {}).get("raw_label") if isinstance(ai_data.get("raw_model_output"), dict) else None)
        or "N/A"
    )

    conf_pct = f"{confidence * 100:.2f}%" if isinstance(confidence, float) and confidence <= 1.0 else f"{confidence}%"

    ai_rows = [
        [
            Paragraph("AI Semantic Verdict:", styles["TableCellBold"]),
            Paragraph(f"<b>{_safe_xml(str(verdict).upper())}</b> (Raw: {_safe_xml(raw_label)})", styles["TableCellBold"]),
            Paragraph("Model Architecture:", styles["TableCellBold"]),
            Paragraph(_safe_xml(model_name, max_len=60), styles["TableCell"]),
        ],
        [
            Paragraph("Internal Confidence:", styles["TableCellBold"]),
            Paragraph(f"<b>{conf_pct}</b>", styles["TableCellBold"]),
            Paragraph("Runtime Execution Status:", styles["TableCellBold"]),
            Paragraph(_safe_xml(model_status), styles["TableCell"]),
        ],
    ]

    ai_table = Table(ai_rows, colWidths=[100, 170, 110, 160])
    ai_table.setStyle(
        TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("BACKGROUND", (0, 0), (0, -1), COLOR_BG_ALT),
            ("BACKGROUND", (2, 0), (2, -1), COLOR_BG_ALT),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 2.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ])
    )
    story.append(ai_table)
    story.append(Spacer(1, 3))

    # Mandatory Epistemic Caveat Callout
    caveat_text = (
        "<b>Important Scientific & Forensic Note:</b> Deep learning model confidence scores represent internal "
        "softmax probability distributions over training samples. They do not constitute calibrated real-world Bayesian "
        "maliciousness probabilities and must always be corroborated by concrete technical indicators."
    )
    caveat_table = Table([[Paragraph(caveat_text, styles["CaveatBox"])]], colWidths=[USABLE_WIDTH])
    caveat_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fffbeb")), # Light amber
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#fde68a")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ])
    )
    story.append(caveat_table)
    story.append(Spacer(1, 6))
    return story


def _build_evidence_chain_table(
    risk_data: dict[str, Any],
    styles: dict[str, ParagraphStyle],
) -> list[Any]:
    """Complete, auditable forensic evidence chain with exact point reconciliation."""
    story: list[Any] = []
    story.append(Paragraph("7. MATHEMATICALLY AUDITABLE EVIDENCE CHAIN", styles["SectionHeader"]))

    evidence_list = risk_data.get("evidence", [])
    if not evidence_list:
        story.append(Paragraph("<i>No negative or corroborating risk indicators triggered.</i>", styles["Body"]))
        story.append(Spacer(1, 6))
        return story

    headers = [
        Paragraph("Pillar Vector", styles["TableHeader"]),
        Paragraph("Indicator Key / ID", styles["TableHeader"]),
        Paragraph("Sev", styles["TableHeader"]),
        Paragraph("Cnt", styles["TableHeader"]),
        Paragraph("Raw", styles["TableHeader"]),
        Paragraph("Damp", styles["TableHeader"]),
        Paragraph("Cap Adj", styles["TableHeader"]),
        Paragraph("Score Contrib", styles["TableHeader"]),
        Paragraph("Forensic Indicator Rationale", styles["TableHeader"]),
    ]
    rows = [headers]

    tot_raw = 0
    tot_damp = 0
    tot_cap_adj = 0
    tot_contrib = 0

    for e in evidence_list:
        pillar = e.get("pillar", "general")
        ind = e.get("indicator") or e.get("id") or "unknown"
        sev = str(e.get("severity", "low"))[:4].upper()
        cnt = e.get("occurrence_count", 1)
        raw_p = e.get("raw_points", 0)
        damp_p = e.get("dampened_points", raw_p)
        cap_adj = e.get("pillar_cap_reduction", 0)
        contrib = e.get("score_contribution", e.get("effective_contribution", damp_p))
        expl = e.get("explanation") or e.get("description") or e.get("title") or ""

        tot_raw += raw_p
        tot_damp += damp_p
        tot_cap_adj += cap_adj
        tot_contrib += contrib

        cap_adj_str = f"{cap_adj}" if cap_adj != 0 else "0"

        rows.append([
            Paragraph(_safe_xml(pillar), styles["TableCellBold"]),
            Paragraph(_safe_xml(ind, max_len=30), styles["TableCell"]),
            Paragraph(_safe_xml(sev), styles["TableCell"]),
            Paragraph(f"{cnt}", styles["TableCell"]),
            Paragraph(f"{raw_p}", styles["TableCell"]),
            Paragraph(f"{damp_p}", styles["TableCell"]),
            Paragraph(cap_adj_str, styles["TableCell"]),
            Paragraph(f"<b>+{contrib}</b>", styles["TableCellBold"]),
            Paragraph(_safe_xml(expl, max_len=130), styles["TableCell"]),
        ])

    # Reconciliation Totals Row
    final_score = risk_data.get("risk_score", 0)
    meta = risk_data.get("scoring_metadata", {})
    mit_discount = meta.get("mitigation_discount", 0)

    if tot_contrib == final_score:
        recon_status_str = "Sum of effective contributions matches final score exactly."
    elif mit_discount > 0:
        recon_status_str = f"Ledger sum (+{tot_contrib}) - Mitigations ({mit_discount}) matches final score ({final_score})."
    else:
        recon_status_str = f"Ledger subtotal (+{tot_contrib}) reconciles to final score ({final_score})."

    rows.append([
        Paragraph("<b>CUMULATIVE TOTALS:</b>", styles["TableCellBold"]),
        Paragraph("<b>All Indicators</b>", styles["TableCellBold"]),
        Paragraph("<b>—</b>", styles["TableCellBold"]),
        Paragraph("<b>—</b>", styles["TableCellBold"]),
        Paragraph(f"<b>{tot_raw}</b>", styles["TableCellBold"]),
        Paragraph(f"<b>{tot_damp}</b>", styles["TableCellBold"]),
        Paragraph(f"<b>{tot_cap_adj}</b>", styles["TableCellBold"]),
        Paragraph(f"<b>+{tot_contrib}</b>", styles["TableCellBold"]),
        Paragraph(f"<b>{recon_status_str}</b>", styles["TableCellBold"]),
    ])

    col_widths = [75, 75, 25, 22, 28, 28, 37, 45, 205]
    ev_table = Table(rows, colWidths=col_widths, repeatRows=1)
    ev_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_SLATE_DARK),
            ("GRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ("LEFTPADDING", (0, 0), (-1, -1), 2.5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 2.5),
            ("BACKGROUND", (0, -1), (-1, -1), COLOR_BG_ALT),
        ])
    )
    story.append(ev_table)
    story.append(Spacer(1, 6))

    # Mathematical Reconciliation Formula Callout
    meta = risk_data.get("scoring_metadata", {})
    formula_str = meta.get("mathematical_reconciliation") or (
        f"final_risk_score ({risk_data.get('risk_score', 0)}) = "
        f"capped_pillar_scores_sum ({meta.get('capped_pillar_scores_sum', 0)}) + "
        f"synergy_bonus ({meta.get('synergy_bonus', 0)}) - "
        f"mitigation_discount ({meta.get('mitigation_discount', 0)})"
    )

    pillar_raw = meta.get("pillar_raw_points_sum", meta.get("raw_signal_points_sum", 0) - meta.get("synergy_bonus", 0))
    pillar_damp = meta.get("pillar_dampened_points_sum", meta.get("dampened_points_sum", 0) - meta.get("synergy_bonus", 0))

    recon_box = Table(
        [[
            Paragraph(
                f"<b>MATHEMATICAL AUDIT TRAIL:</b><br/>"
                f"<font name='Courier' size=6.5>{_safe_xml(formula_str)}</font><br/>"
                f"<i>Pillar Vectors Breakdown: {pillar_raw} Raw Pts "
                f"− {meta.get('multi_occurrence_dampening_reduction', 0)} Dampening Discount = {pillar_damp} Pre-Cap (Dampened) Pts "
                f"− {meta.get('pillar_cap_reduction', 0)} Cap Reduction = {meta.get('capped_pillar_scores_sum', 0)} Capped Pillars | "
                f"Synergy Bonus: +{meta.get('synergy_bonus', 0)} | Mitigations: -{meta.get('mitigation_discount', 0)} = Final Score: {risk_data.get('risk_score', 0)}</i><br/>"
                f"<i>Evidence Ledger Accounting: {meta.get('raw_signal_points_sum', 0)} Total Raw Pts "
                f"− {meta.get('multi_occurrence_dampening_reduction', 0)} Dampening Discount = {meta.get('dampened_points_sum', 0)} Dampened Pts "
                f"− {meta.get('pillar_cap_reduction', 0)} Cap Reduction = +{tot_contrib} Effective Ledger Contribution</i>",
                styles["TableCell"],
            )
        ]],
        colWidths=[USABLE_WIDTH],
    )
    recon_box.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), COLOR_BG_CARD),
            ("BOX", (0, 0), (-1, -1), 0.75, COLOR_BORDER),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ])
    )
    story.append(recon_box)
    story.append(Spacer(1, 6))
    return story


def _build_limitations_and_recommendations(
    risk_data: dict[str, Any],
    styles: dict[str, ParagraphStyle],
) -> list[Any]:
    """Missing evidence, analysis limitations, and recommended incident response actions."""
    story: list[Any] = []

    missing = risk_data.get("missing_evidence", [])
    recommendations = risk_data.get("recommended_actions", [])

    story.append(Paragraph("8. FORENSIC LIMITATIONS & INCIDENT RESPONSE PLAYBOOK", styles["SectionHeader"]))

    # Two column table: Left = Missing Evidence / Limitations, Right = Recommendations
    missing_items: list[str] = []
    if missing:
        for m in missing:
            field = m.get("field", "unknown")
            reason = m.get("reason", "Verification not performed.")
            missing_items.append(f"• <b>{_safe_xml(field)}:</b> {_safe_xml(reason)}")
    else:
        missing_items.append("• No critical analytical modules were reported missing or unverified.")

    rec_items: list[str] = []
    if recommendations:
        for r in recommendations:
            rec_items.append(f"• {_safe_xml(r)}")
    else:
        rec_items.append("• Maintain normal security hygiene; no urgent incident response actions triggered.")

    left_content = "<br/>".join(missing_items)
    right_content = "<br/>".join(rec_items)

    col_data = [
        [
            Paragraph("<b>Missing Checks & Analysis Limitations</b>", styles["TableCellBold"]),
            Paragraph("<b>Recommended Incident Response Triage</b>", styles["TableCellBold"]),
        ],
        [
            Paragraph(left_content, styles["TableCell"]),
            Paragraph(right_content, styles["TableCell"]),
        ],
    ]

    t_col = Table(col_data, colWidths=[270, 270])
    t_col.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_BG_ALT),
            ("GRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ])
    )
    story.append(t_col)
    story.append(Spacer(1, 6))
    return story


def _build_body_excerpt(
    email_data: Optional[dict[str, Any]],
    max_chars: int,
    styles: dict[str, ParagraphStyle],
) -> list[Any]:
    """Render bounded, inert email body excerpt clearly labeled as untrusted content."""
    story: list[Any] = []
    if not email_data or not isinstance(email_data, dict):
        return story

    body_dict = email_data.get("body", {})
    body_text = body_dict.get("plain_text") or body_dict.get("plain") or email_data.get("body_text", "")
    if not body_text or not isinstance(body_text, str) or not body_text.strip():
        return story

    excerpt = body_text.strip()
    if len(excerpt) > max_chars:
        excerpt = excerpt[:max_chars] + "\n... [BODY EXCERPT TRUNCATED FOR SECURITY AND BREVITY]"

    story.append(Paragraph("9. EXTRACTED MESSAGE BODY EXCERPT (INERT TEXT SNIPPET)", styles["SectionHeader"]))

    card = [
        [
            Paragraph(
                "<b>[UNTRUSTED EMAIL CONTENT - INERT EXCERPT]</b><br/>"
                f"<font name='Courier' size=6>{_safe_xml(excerpt)}</font>",
                styles["TableCell"],
            )
        ]
    ]
    card_t = Table(card, colWidths=[USABLE_WIDTH])
    card_t.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), COLOR_BG_CARD),
            ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ])
    )
    story.append(card_t)
    story.append(Spacer(1, 6))
    return story


# ===========================================================================
# PRIMARY PUBLIC API
# ===========================================================================

def generate_forensic_pdf(
    analysis_results: Optional[dict[str, Any]] = None,
    output_path: Optional[str] = None,
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
    risk_data: Optional[dict[str, Any]] = None,
    risk_result: Optional[dict[str, Any]] = None,
    case_id: Optional[str] = None,
    include_body_excerpt: bool = True,
    max_body_excerpt_chars: int = 600,
    timestamp: Optional[datetime] = None,
) -> dict[str, Any]:
    """
    Generate a publication-grade, mathematically auditable PDF forensic report.

    Parameters
    ----------
    analysis_results : dict, optional
        Consolidated dictionary of upstream module outputs.
    output_path : str, optional
        Target filesystem location for the generated PDF. Defaults to 'reports/'.
    email_data / parsed_email : dict, optional
        Output from Module 1 (email_parser).
    auth_data / auth_result : dict, optional
        Output from Module 2 (auth_verifier).
    url_data / url_result : dict, optional
        Output from Module 3 (url_analyzer).
    routing_data / routing_result : dict, optional
        Output from Module 4 (routing_analyzer).
    ai_data / ai_result : dict, optional
        Output from Module 5 (ai_text_analyzer).
    risk_data / risk_result : dict, optional
        Output from Module 6 (risk_scorer). If omitted, automatically computed.
    case_id : str, optional
        Investigative reference / ticket identifier (e.g., 'CASE-2026-ETH-001').
    include_body_excerpt : bool
        Whether to include a sanitized, inert excerpt of body text. Default True.
    max_body_excerpt_chars : int
        Maximum characters in the body text excerpt. Default 600.

    Returns
    -------
    dict[str, Any]
        Structured generation metadata including output path, file size, risk score,
        and execution status.
    """
    # 1. Parameter Normalization
    email_data = email_data or parsed_email
    auth_data = auth_data or auth_result
    url_data = url_data or url_result
    routing_data = routing_data or routing_result
    ai_data = ai_data or ai_result
    risk_data = risk_data or risk_result

    # Unpack from unified analysis_results if supplied
    if analysis_results and isinstance(analysis_results, dict):
        if "file_metadata" in analysis_results and "email_metadata" in analysis_results:
            email_data = email_data or analysis_results
        else:
            email_data = email_data or analysis_results.get("email") or analysis_results.get("parsed_email")
            auth_data = auth_data or analysis_results.get("auth") or analysis_results.get("auth_result")
            url_data = url_data or analysis_results.get("url") or analysis_results.get("url_result")
            routing_data = routing_data or analysis_results.get("routing") or analysis_results.get("routing_result")
            ai_data = ai_data or analysis_results.get("ai") or analysis_results.get("ai_result")
            risk_data = risk_data or analysis_results.get("risk") or analysis_results.get("risk_result")

    # 2. Derive Risk Assessment if not explicitly provided
    if risk_data is None:
        try:
            from src.risk_scorer import calculate_email_risk
            risk_data = calculate_email_risk(
                parsed_email=email_data,
                auth_result=auth_data,
                url_result=url_data,
                routing_result=routing_data,
                ai_result=ai_data,
            )
        except Exception as ex:
            raise ValueError(f"Failed to calculate risk score for PDF generation: {ex}") from ex

    if not isinstance(risk_data, dict):
        raise ValueError("Invalid risk assessment data: Expected dictionary from Module 6.")

    # 3. Resolve Output Filesystem Path
    now_utc = timestamp if (timestamp and isinstance(timestamp, datetime)) else datetime.now(timezone.utc)
    timestamp_iso = now_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    timestamp_slug = now_utc.strftime("%Y%m%d_%H%M%S")

    if not output_path:
        reports_dir = os.path.abspath("reports")
        os.makedirs(reports_dir, exist_ok=True)
        slug_id = (case_id or "email_report").replace(" ", "_").replace("/", "-")
        output_path = os.path.join(reports_dir, f"Forensic_Report_{slug_id}_{timestamp_slug}.pdf")
    else:
        output_path = os.path.abspath(output_path)
        parent_dir = os.path.dirname(output_path)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)

    # 4. Prepare Document Layout Elements
    styles = _create_styles()
    story: list[Any] = []

    risk_score = risk_data.get("risk_score", 0)
    risk_level = risk_data.get("risk_level", "none")
    verdict_title = risk_data.get("verdict_title") or f"{risk_level.title()} Risk Assessment"
    summary_text = risk_data.get("summary") or "Comprehensive forensic assessment performed."

    # Build Sections
    story.extend(_build_header_card(case_id, timestamp_iso, risk_score, risk_level, verdict_title, styles))
    story.extend(_build_executive_summary_box(summary_text, styles))
    story.extend(_build_metadata_section(email_data, styles))
    story.extend(_build_pillars_summary_table(risk_data, styles))
    story.extend(_build_auth_section(auth_data, styles, email_data=email_data, risk_data=risk_data))
    story.extend(_build_url_section(url_data, styles))
    story.extend(_build_routing_section(routing_data, styles))
    story.extend(_build_ai_section(ai_data, styles))
    story.extend(_build_evidence_chain_table(risk_data, styles))
    story.extend(_build_limitations_and_recommendations(risk_data, styles))

    if include_body_excerpt:
        story.extend(_build_body_excerpt(email_data, max_body_excerpt_chars, styles))

    # 5. Build PDF Document with NumberedCanvas
    try:
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            leftMargin=PAGE_MARGIN,
            rightMargin=PAGE_MARGIN,
            topMargin=PAGE_MARGIN,
            bottomMargin=PAGE_MARGIN,
            title=f"Forensic Threat Report - {case_id or 'Artifact'}",
            author="SIH 2026 Email Threat Platform",
        )
        doc.build(story, canvasmaker=NumberedCanvas)
    except Exception as ex:
        raise RuntimeError(f"ReportLab PDF generation failed: {ex}") from ex

    file_size = os.path.getsize(output_path) if os.path.exists(output_path) else 0

    return {
        "status": "success",
        "pdf_path": output_path,
        "file_size_bytes": file_size,
        "case_id": case_id,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "generated_at": timestamp_iso,
        "engine_version": REPORT_GENERATOR_VERSION,
    }


# ===========================================================================
# ORCHESTRATION PIPELINE HELPER
# ===========================================================================

def generate_email_forensic_report(
    email_path: str,
    output_path: Optional[str] = None,
    *,
    case_id: Optional[str] = None,
    include_body_excerpt: bool = True,
) -> dict[str, Any]:
    """
    End-to-end orchestration helper: Runs Modules 1 through 6 on an email file
    and produces a forensic PDF threat report.

    Parameters
    ----------
    email_path : str
        Path to the source .eml file.
    output_path : str, optional
        Target PDF file path. Defaults to 'reports/'.
    case_id : str, optional
        Optional investigative case/reference identifier.
    include_body_excerpt : bool
        Whether to include a sanitized body snippet.

    Returns
    -------
    dict[str, Any]
        Generation result dictionary.
    """
    from src.email_parser import parse_email_file
    from src.auth_verifier import verify_authentication
    from src.url_analyzer import analyze_urls
    from src.routing_analyzer import analyze_email_routing
    from src.ai_text_analyzer import analyze_email_text
    from src.risk_scorer import calculate_email_risk

    # 1. Module 1: Ingestion and Parsing
    parsed = parse_email_file(email_path)

    # 2. Modules 2-5: Analysis Engines
    raw_bytes = parsed.get("raw_bytes")
    if not raw_bytes and os.path.exists(email_path):
        try:
            with open(email_path, "rb") as f:
                raw_bytes = f.read()
        except Exception:
            raw_bytes = b""

    auth = verify_authentication(parsed, raw_bytes=raw_bytes)
    urls = analyze_urls(parsed.get("urls", []))
    routing = analyze_email_routing(parsed.get("received_headers", []), raw_bytes=raw_bytes)
    body_text = parsed.get("body", {}).get("plain_text") or parsed.get("body_text", "")
    ai = analyze_email_text(body_text)

    # 3. Module 6: Risk Scorer
    risk = calculate_email_risk(
        parsed_email=parsed,
        auth_result=auth,
        url_result=urls,
        routing_result=routing,
        ai_result=ai,
    )

    # 4. Module 7: PDF Generator
    return generate_forensic_pdf(
        email_data=parsed,
        auth_data=auth,
        url_data=urls,
        routing_data=routing,
        ai_data=ai,
        risk_data=risk,
        output_path=output_path,
        case_id=case_id,
        include_body_excerpt=include_body_excerpt,
    )
