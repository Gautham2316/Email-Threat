"""
src/email_parser.py
===================
Module 1: Email Ingestion and Parsing Engine
SIH 2026 — AI-Powered Email Threat Detection Platform

PURPOSE
-------
Accept a .eml file path, validate it, and extract its contents into a
structured Python dictionary that all future modules can consume.

SECURITY RULES (never break these)
-----------------------------------
1. URLs are extracted for analysis only. They are NEVER visited or opened.
2. Attachments are detected but NEVER executed or opened.
3. HTML is extracted as raw text only. It is NEVER rendered in a browser.
4. This module makes NO network requests of any kind.
5. Email data is NEVER transmitted to any external service.

DEPENDENCIES
------------
Only Python standard library modules are used. No pip installs required.
  - email       : built-in RFC-2822 parser
  - html.parser : built-in HTML tag extractor (no BeautifulSoup needed)
  - re          : built-in regular expressions
  - os          : built-in file system access
  - datetime    : built-in timestamp generation

AUTHOR  : SIH 2026 Team
VERSION : 1.0.0
"""

from __future__ import annotations   # Allows "list[str]" hint style on Python < 3.10

import email
import email.policy
import email.utils
import os
import re
from datetime import datetime, timezone
from email import message_from_bytes
from email.header import decode_header, make_header
from html.parser import HTMLParser
from typing import Any


# ======================================================================
# CONSTANTS
# ======================================================================

PARSER_VERSION: str = "1.0.0"

# Maximum file size we will accept (25 MB is generous for any real email).
# This prevents someone from feeding us a 2 GB file and crashing the process.
MAX_FILE_SIZE_BYTES: int = 25 * 1024 * 1024  # 25 MB

# Regular expression that matches http:// and https:// URLs in plain text.
_URL_REGEX: re.Pattern[str] = re.compile(
    r"https?://"                                # Must start with http:// or https://
    r"[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+", # Everything that can legally follow
    re.IGNORECASE
)

# Characters that end a sentence but should NOT be part of a URL when
# the URL appears inside plain text surrounded by punctuation.
_URL_TRAILING_JUNK: str = ".,;)\"'><\\"


# ======================================================================
# SECTION A — FILE VALIDATION
# ======================================================================

def validate_eml_file(file_path: str) -> tuple[bool, str | None]:
    """
    Check that the given path points to a readable, non-empty .eml file that
    does not exceed the size limit.

    Parameters
    ----------
    file_path : str
        The path to check.

    Returns
    -------
    (True, None)
        If the file is valid and ready to parse.
    (False, "error message")
        If validation fails. The caller should record the error and stop.

    This function does NOT read the file contents — it only inspects metadata.
    """
    # Does the path exist at all?
    if not os.path.exists(file_path):
        return False, f"File not found: '{file_path}'"

    # Is it actually a file (not a directory or device)?
    if not os.path.isfile(file_path):
        return False, f"Path is not a regular file: '{file_path}'"

    # Does it have the .eml extension? (case-insensitive check)
    _, extension = os.path.splitext(file_path)
    if extension.lower() != ".eml":
        return False, (
            f"Wrong file type: expected '.eml' but got '{extension}'. "
            "Only standard .eml files are accepted."
        )

    # Is the file readable (not locked by another process)?
    if not os.access(file_path, os.R_OK):
        return False, f"Permission denied - cannot read: '{file_path}'"

    # Is the file empty?
    size = os.path.getsize(file_path)
    if size == 0:
        return False, "File is empty (0 bytes). Nothing to parse."

    # Is the file too large?
    if size > MAX_FILE_SIZE_BYTES:
        limit_mb = MAX_FILE_SIZE_BYTES // (1024 * 1024)
        return False, (
            f"File is too large: {size:,} bytes "
            f"(limit is {limit_mb} MB = {MAX_FILE_SIZE_BYTES:,} bytes)."
        )

    return True, None   # All checks passed


# ======================================================================
# SECTION B — HEADER DECODING HELPERS
# ======================================================================

def _decode_header_value(raw: str | None) -> str | None:
    """
    Turn a potentially encoded email header into a plain Unicode string.

    Email headers can be encoded in Base64 or quoted-printable when they
    contain non-ASCII characters.  For example:

        Subject: =?UTF-8?B?SGVsbG8gV29ybGQ=?=

    ...should become: "Hello World"

    Parameters
    ----------
    raw : str or None
        The raw header value as returned by Python's email library.

    Returns
    -------
    str or None
        Decoded Unicode string, or None if the input was None.
        If decoding fails, the raw value is returned unchanged.
    """
    if raw is None:
        return None
    try:
        # make_header(decode_header(raw)) handles all encoding types
        return str(make_header(decode_header(raw)))
    except Exception:
        # Fall back to the raw value -- it is still useful for investigation
        return raw


def _get_address_list(msg: email.message.Message, header_name: str) -> list[str]:
    """
    Extract a list of email addresses from a header that may contain multiple
    addresses separated by commas (e.g. To, Cc, Bcc).

    Parameters
    ----------
    msg : email.message.Message
        The parsed email object.
    header_name : str
        Name of the header to read, e.g. "To" or "Cc".

    Returns
    -------
    list[str]
        Formatted strings like "Alice <alice@example.com>".
        Returns an empty list if the header is absent or unparseable.

    Example
    -------
    "To: Alice <a@ex.com>, Bob <b@ex.com>"
    becomes ["Alice <a@ex.com>", "Bob <b@ex.com>"]
    """
    all_values = msg.get_all(header_name, [])
    if not all_values:
        return []

    addresses: list[str] = []
    for raw_val in all_values:
        decoded = _decode_header_value(raw_val)
        if not decoded:
            continue
        # email.utils.getaddresses handles "Name <addr>", bare addresses,
        # and comma-separated lists in one call.
        parsed_pairs = email.utils.getaddresses([decoded])
        for display_name, addr in parsed_pairs:
            if not addr:
                continue   # Skip malformed entries with no actual address
            if display_name:
                addresses.append(f"{display_name} <{addr}>")
            else:
                addresses.append(addr)
    return addresses


# ======================================================================
# SECTION C — BODY EXTRACTION
# ======================================================================

def _decode_part_payload(
    part: email.message.Message,
    warnings: list[str]
) -> str | None:
    """
    Decode the raw bytes of a single MIME part into a Python string.

    Email parts can use different character encodings (UTF-8, latin-1, etc.).
    We try the declared charset first, then fall back gracefully so we never
    silently discard content.

    Parameters
    ----------
    part : email.message.Message
        A single MIME part (e.g. the text/plain portion of a multipart email).
    warnings : list[str]
        A mutable list to append warning messages to.

    Returns
    -------
    str or None
        The decoded text, or None if decoding failed completely.
    """
    # get_payload(decode=True) handles quoted-printable and base64 transfer
    # encoding automatically and returns raw bytes.
    raw_bytes = part.get_payload(decode=True)
    if raw_bytes is None:
        return None

    # Use the charset declared in the Content-Type header, default to utf-8.
    charset = part.get_content_charset() or "utf-8"

    try:
        # errors="replace" substitutes ? for bytes that cannot be decoded,
        # rather than throwing an exception.
        return raw_bytes.decode(charset, errors="replace")
    except LookupError:
        # LookupError means Python does not know this charset name at all.
        warnings.append(
            f"Unknown charset '{charset}' in email part. Falling back to latin-1."
        )
        return raw_bytes.decode("latin-1", errors="replace")
    except Exception as exc:
        warnings.append(f"Body decoding error: {exc}. Returning raw bytes as latin-1.")
        return raw_bytes.decode("latin-1", errors="replace")


def extract_body(
    msg: email.message.Message,
    warnings: list[str]
) -> dict[str, str | None]:
    """
    Walk the MIME tree of an email and extract the plain-text and HTML body
    parts.

    Handles:
    - Simple single-part emails (just text/plain or just text/html)
    - multipart/alternative emails (text + HTML, pick the first of each)
    - Nested multipart structures (walks the entire tree)
    - Attachments (skipped -- detected by Content-Disposition: attachment)

    Parameters
    ----------
    msg : email.message.Message
        The root of the parsed email object.
    warnings : list[str]
        A mutable list to append warning messages to.

    Returns
    -------
    dict with keys:
        plain_text    (str or None) : decoded plain-text content
        html          (str or None) : decoded HTML content
        charset_plain (str or None) : charset used for the plain-text part
        charset_html  (str or None) : charset used for the HTML part
    """
    plain_text: str | None = None
    html_content: str | None = None
    charset_plain: str | None = None
    charset_html: str | None = None

    if msg.is_multipart():
        # msg.walk() visits every part in the MIME tree, depth-first.
        for part in msg.walk():
            content_type = part.get_content_type()

            # Skip the multipart container nodes -- they have no body.
            if content_type.startswith("multipart/"):
                continue

            # Skip attachments -- we identify them but never read their content.
            disposition = str(part.get_content_disposition() or "")
            if "attachment" in disposition.lower():
                continue

            # First text/plain part wins
            if content_type == "text/plain" and plain_text is None:
                plain_text = _decode_part_payload(part, warnings)
                charset_plain = part.get_content_charset()

            # First text/html part wins
            elif content_type == "text/html" and html_content is None:
                html_content = _decode_part_payload(part, warnings)
                charset_html = part.get_content_charset()
    else:
        # Simple single-part email
        content_type = msg.get_content_type()
        if content_type == "text/plain":
            plain_text = _decode_part_payload(msg, warnings)
            charset_plain = msg.get_content_charset()
        elif content_type == "text/html":
            html_content = _decode_part_payload(msg, warnings)
            charset_html = msg.get_content_charset()
        else:
            warnings.append(
                f"Single-part email has unrecognised content type: '{content_type}'. "
                "Body could not be extracted as text."
            )

    return {
        "plain_text": plain_text,
        "html": html_content,
        "charset_plain": charset_plain,
        "charset_html": charset_html,
    }


# ======================================================================
# SECTION D — URL EXTRACTION
# ======================================================================

class _HrefExtractor(HTMLParser):
    """
    A minimal HTML parser that collects URLs from href, src, and action
    attributes of HTML tags.

    We use Python's built-in HTMLParser so we need zero external libraries.
    This class is private (starts with _) and only used inside this module.

    SECURITY: This class only COLLECTS URLs. It never opens, visits,
    or makes requests to any URL it finds.

    Example usage:
        extractor = _HrefExtractor()
        extractor.feed("<a href='https://example.com'>click</a>")
        print(extractor.urls)   # ["https://example.com"]
    """

    def __init__(self) -> None:
        super().__init__()
        self.urls: list[str] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]]
    ) -> None:
        """Called automatically by HTMLParser for every opening HTML tag."""
        attr_dict = dict(attrs)
        # These HTML attributes commonly contain URLs
        for attr_name in ("href", "src", "action", "data-url", "data-href"):
            value = attr_dict.get(attr_name)
            if value and isinstance(value, str):
                url = value.strip()
                if url.lower().startswith(("http://", "https://")):
                    self.urls.append(url)

    def error(self, message: str) -> None:
        """Suppress parse errors -- we want best-effort extraction, not crashes."""
        pass


def _extract_urls_from_html(html_content: str) -> list[str]:
    """
    Extract HTTP/HTTPS URLs from HTML content using two complementary methods:
      1. Parse HTML tags and read href/src attributes (catches link targets)
      2. Apply the URL regex to the raw HTML text (catches URLs in text nodes)

    Parameters
    ----------
    html_content : str
        Raw HTML string from an email body part.

    Returns
    -------
    list[str]
        Combined, undeduped list of found URLs (deduplication happens later).

    SECURITY: URLs are collected only. None are visited.
    """
    # Method 1: structured HTML attribute extraction
    extractor = _HrefExtractor()
    try:
        extractor.feed(html_content)
    except Exception:
        pass   # Even broken HTML yields what was parsed before the error

    # Method 2: regex over the raw HTML catches URLs in visible text and
    # URL-like strings that appear outside of href attributes.
    regex_hits = _URL_REGEX.findall(html_content)

    return extractor.urls + regex_hits


def _extract_urls_from_text(text_content: str) -> list[str]:
    """
    Extract HTTP/HTTPS URLs from plain-text email content using regex.

    Parameters
    ----------
    text_content : str
        The decoded plain-text body of the email.

    Returns
    -------
    list[str]
        Raw list of found URLs (may contain duplicates).

    SECURITY: URLs are collected only. None are visited.
    """
    return _URL_REGEX.findall(text_content)


def build_url_list(
    text_urls: list[str],
    html_urls: list[str]
) -> list[dict[str, Any]]:
    """
    Merge URLs from plain text and HTML sources, deduplicate them, and record
    which source(s) each URL came from and how many times it appeared.

    The output is a list of dicts, each containing:
        url      (str)       : the cleaned URL
        found_in (list[str]) : sources -- "plain_text" and/or "html"
        count    (int)       : total number of times this URL appeared

    Parameters
    ----------
    text_urls : list[str]
        URLs found in the plain-text body.
    html_urls : list[str]
        URLs found in the HTML body.

    Returns
    -------
    list[dict]
        Deduplicated, annotated URL entries.
    """
    url_map: dict[str, dict[str, Any]] = {}

    def _register(url: str, source: str) -> None:
        clean = url.rstrip(_URL_TRAILING_JUNK)
        if not clean:
            return
        if clean not in url_map:
            url_map[clean] = {"url": clean, "found_in": [], "count": 0}
        if source not in url_map[clean]["found_in"]:
            url_map[clean]["found_in"].append(source)
        url_map[clean]["count"] += 1

    for url in text_urls:
        _register(url, "plain_text")
    for url in html_urls:
        _register(url, "html")

    return list(url_map.values())


# ======================================================================
# SECTION E — EMPTY RESULT SKELETON
# ======================================================================

def _build_empty_result(file_path: str) -> dict[str, Any]:
    """
    Create the output dictionary pre-filled with safe default values.

    Why do this upfront?
    Because if parsing fails halfway through, we still return a complete,
    consistent structure. Future modules can always rely on every key
    being present. Missing data is represented as None or [], never as
    a missing key that would cause a KeyError.

    Parameters
    ----------
    file_path : str
        The file path provided by the caller.

    Returns
    -------
    dict
        The skeleton result with all keys present and defaults set.
    """
    return {
        # Information about the file itself (not the email contents)
        "file_metadata": {
            "filename": os.path.basename(file_path),
            "file_path": os.path.abspath(file_path),
            "file_size_bytes": None,
            "parsed_at": datetime.now(timezone.utc).isoformat(),
            "parser_version": PARSER_VERSION,
        },
        # Standard email header fields
        "email_metadata": {
            "from": None,
            "to": [],
            "cc": [],
            "reply_to": None,
            "subject": None,
            "date": None,
            "message_id": None,
            "return_path": None,
            "sender": None,
            "mime_version": None,
            "content_type": None,
            "x_mailer": None,
            "x_originating_ip": None,
        },
        # All headers preserved exactly as they appear in the file
        "headers": {
            "raw_headers": []  # list of {"name": str, "value": str}
        },
        # Received headers in original order (first = most recent mail server hop)
        "received_headers": [],
        # Security/authentication-related headers
        "authentication_headers": {
            "authentication_results": [],    # list of str (there can be multiple)
            "received_spf": None,
            "dkim_signature": None,
            "arc_authentication_results": [],
            "dmarc_evidence": None,          # Extracted from Authentication-Results
        },
        # Email body content
        "body": {
            "plain_text": None,
            "html": None,
            "charset_plain": None,   # e.g. "utf-8"
            "charset_html": None,
        },
        # All URLs found in the email (never visited)
        "urls": [],          # list of {"url", "found_in", "count"}
        # Non-fatal issues encountered during parsing
        "parse_warnings": [],
        # Fatal issues that prevented full parsing
        "errors": [],
    }


# ======================================================================
# SECTION F — MAIN PUBLIC FUNCTION
# ======================================================================

def parse_email_file(file_path: str) -> dict[str, Any]:
    """
    Parse a .eml file and return all extracted data in a structured dictionary.

    This is the single public entry point for Module 1.  All future modules
    should call this function and consume the returned dictionary.

    Parameters
    ----------
    file_path : str
        Absolute or relative path to the .eml file to parse.

    Returns
    -------
    dict
        A structured dictionary with the following top-level keys:
            file_metadata          : info about the file (name, size, parse time)
            email_metadata         : standard fields (From, To, Subject, Date, ...)
            headers                : all raw headers in original order
            received_headers       : Received headers (routing trace)
            authentication_headers : SPF, DKIM, DMARC evidence headers
            body                   : plain_text and html content
            urls                   : extracted URLs with source and count
            parse_warnings         : non-fatal issues
            errors                 : fatal issues that stopped full parsing

    Notes
    -----
    - This function always returns a dict with all keys present.
    - On validation failure, errors[] is populated and other fields are None/[].
    - This function makes ZERO network requests.
    - URLs in result["urls"] must NEVER be visited by any code in this module.

    Examples
    --------
    >>> result = parse_email_file("samples/plain_text.eml")
    >>> print(result["email_metadata"]["subject"])
    'Hello from the test suite'
    >>> print(len(result["urls"]))
    1
    """
    # -- Initialise the result skeleton ----------------------------------------
    result = _build_empty_result(file_path)
    warnings: list[str] = result["parse_warnings"]
    errors: list[str]   = result["errors"]

    # -- Step 1: Validate the file ---------------------------------------------
    is_valid, validation_error = validate_eml_file(file_path)
    if not is_valid:
        errors.append(validation_error)   # type: ignore[arg-type]
        return result

    result["file_metadata"]["file_size_bytes"] = os.path.getsize(file_path)

    # -- Step 2: Read the file as raw bytes ------------------------------------
    # We read bytes (not text) so the email library can detect encodings itself.
    try:
        with open(file_path, "rb") as fh:
            raw_bytes = fh.read()
    except PermissionError:
        errors.append(f"Permission denied when reading '{file_path}'.")
        return result
    except OSError as exc:
        errors.append(f"OS error while reading file: {exc}")
        return result

    # -- Step 3: Parse the raw bytes into a Message object --------------------
    # We use email.policy.compat32 (the default) for widest compatibility.
    # Real-world emails often violate the RFC in minor ways; compat32 is lenient.
    try:
        msg = message_from_bytes(raw_bytes, policy=email.policy.compat32)
    except Exception as exc:
        errors.append(f"Email library failed to parse the file: {exc}")
        return result

    if msg is None:
        errors.append("Parsed message is None -- file may be severely malformed.")
        return result

    # -- Step 4: Preserve ALL raw headers in original order -------------------
    # msg.items() returns (name, value) tuples in the order they appear in the file.
    result["headers"]["raw_headers"] = [
        {"name": name, "value": value}
        for name, value in msg.items()
    ]

    # -- Step 5: Extract standard email metadata ------------------------------
    meta = result["email_metadata"]
    meta["from"]             = _decode_header_value(msg.get("From"))
    meta["to"]               = _get_address_list(msg, "To")
    meta["cc"]               = _get_address_list(msg, "Cc")
    meta["reply_to"]         = _decode_header_value(msg.get("Reply-To"))
    meta["subject"]          = _decode_header_value(msg.get("Subject"))
    meta["date"]             = _decode_header_value(msg.get("Date"))
    meta["message_id"]       = _decode_header_value(msg.get("Message-ID"))
    meta["return_path"]      = _decode_header_value(msg.get("Return-Path"))
    meta["sender"]           = _decode_header_value(msg.get("Sender"))
    meta["mime_version"]     = _decode_header_value(msg.get("MIME-Version"))
    meta["content_type"]     = _decode_header_value(msg.get("Content-Type"))
    meta["x_mailer"]         = _decode_header_value(msg.get("X-Mailer"))
    meta["x_originating_ip"] = _decode_header_value(msg.get("X-Originating-IP"))

    # Warn if important fields are absent (but do NOT crash)
    for field, header_name in [("from", "From"), ("subject", "Subject"), ("date", "Date")]:
        if not meta[field]:
            warnings.append(
                f"Missing header: '{header_name}' was not found in this email."
            )

    # -- Step 6: Extract Received headers (routing trace) ---------------------
    # get_all() returns every occurrence of a repeated header in document order.
    # For Received headers: the FIRST one is the most recent mail server hop.
    received_all = msg.get_all("Received") or []
    result["received_headers"] = [h.strip() for h in received_all]

    if not received_all:
        warnings.append(
            "No 'Received' headers found. "
            "Cannot reconstruct email routing path. "
            "This is unusual and may indicate header stripping."
        )

    # -- Step 7: Extract authentication headers --------------------------------
    auth = result["authentication_headers"]

    # Authentication-Results can appear multiple times (once per mail server)
    auth_results_raw = msg.get_all("Authentication-Results") or []
    auth["authentication_results"] = [h.strip() for h in auth_results_raw]

    spf_raw = msg.get("Received-SPF")
    auth["received_spf"] = spf_raw.strip() if spf_raw else None

    dkim_raw = msg.get("DKIM-Signature")
    auth["dkim_signature"] = dkim_raw.strip() if dkim_raw else None

    arc_raw = msg.get_all("ARC-Authentication-Results") or []
    auth["arc_authentication_results"] = [h.strip() for h in arc_raw]

    # DMARC evidence: pull lines that mention "dmarc" from Authentication-Results
    # NOTE: We record what the header SAYS. We do NOT verify it is correct.
    dmarc_lines = [
        line for line in auth["authentication_results"]
        if "dmarc" in line.lower()
    ]
    if dmarc_lines:
        auth["dmarc_evidence"] = " | ".join(dmarc_lines)

    # -- Step 8: Extract body content ------------------------------------------
    body_data = extract_body(msg, warnings)
    result["body"].update(body_data)

    if result["body"]["plain_text"] is None and result["body"]["html"] is None:
        warnings.append(
            "No readable body content found (neither text/plain nor text/html). "
            "The email may be attachment-only or severely malformed."
        )

    # -- Step 9: Extract URLs --------------------------------------------------
    # SECURITY: URLs are collected for forensic analysis only.
    # They are NEVER visited, fetched, or passed to any network function.
    text_urls = _extract_urls_from_text(result["body"]["plain_text"] or "")
    html_urls = _extract_urls_from_html(result["body"]["html"] or "")
    result["urls"] = build_url_list(text_urls, html_urls)

    return result
