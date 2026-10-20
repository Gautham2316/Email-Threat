"""
tests/test_email_parser.py
==========================
Automated tests for Module 1: Email Ingestion and Parsing Engine.

Test framework : Python's built-in unittest (no external test runner needed)
How to run     : python -m unittest discover -s tests -v
               : or: python -m unittest tests.test_email_parser -v

Test cases covered
------------------
TC-01  Normal plain-text email (samples/plain_text.eml)
TC-02  Multipart email with plain text and HTML (samples/multipart.eml)
TC-03  Multiple Received headers  (samples/phishing_sample.eml)
TC-04  Authentication-Result headers present (samples/multipart.eml)
TC-05  Multiple URLs in both text and HTML (samples/phishing_sample.eml)
TC-06  Missing optional headers (synthetic email built in-memory)
TC-07  Empty file (synthetic)
TC-08  Malformed / non-email file (synthetic)
TC-09  Invalid file path (does not exist)
TC-10  Wrong file extension (.txt instead of .eml)
TC-11  Suspicious-looking link is extracted but NOT visited
TC-12  Encoded Subject header is decoded correctly (samples/multipart.eml)
TC-13  URL deduplication works correctly

SECURITY RULE: No test in this file makes any network request.
All test data is synthetic (fake). No real emails or credentials are used.
"""

import os
import sys
import tempfile
import textwrap
import unittest

# ---------------------------------------------------------------------------
# Make sure we can import from src/ regardless of where the test is run from.
# ---------------------------------------------------------------------------
# __file__ is the path to this test file.
# We go two levels up (tests/ -> Email-Threat/) to reach the project root.
_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_HERE)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from src.email_parser import (
    parse_email_file,
    validate_eml_file,
    build_url_list,
    MAX_FILE_SIZE_BYTES,
)

# ---------------------------------------------------------------------------
# Helper: path to a sample file
# ---------------------------------------------------------------------------
def _sample(filename: str) -> str:
    """Return the absolute path to a file in the samples/ directory."""
    return os.path.join(_PROJECT_ROOT, "samples", filename)


# ---------------------------------------------------------------------------
# Helper: write a temporary .eml file from a string and return its path
# ---------------------------------------------------------------------------
def _make_temp_eml(content: bytes | str, suffix: str = ".eml") -> str:
    """
    Write content to a named temporary file on disk and return the path.
    The file is NOT automatically deleted -- callers are responsible for cleanup
    using a try/finally block or self.addCleanup().
    """
    if isinstance(content, str):
        content = content.encode("utf-8")
    fd, path = tempfile.mkstemp(suffix=suffix)
    try:
        os.write(fd, content)
    finally:
        os.close(fd)
    return path


# ============================================================================
# TC-01 to TC-05 : Tests using sample .eml files from the samples/ directory
# ============================================================================

class TestPlainTextEmail(unittest.TestCase):
    """TC-01: Normal plain-text email."""

    @classmethod
    def setUpClass(cls):
        """Parse the plain-text sample once; all tests share the result."""
        cls.result = parse_email_file(_sample("plain_text.eml"))

    def test_no_errors(self):
        """Parsing should complete without fatal errors."""
        self.assertEqual(
            self.result["errors"], [],
            msg=f"Unexpected errors: {self.result['errors']}"
        )

    def test_from_extracted(self):
        """The From field should be extracted."""
        self.assertIsNotNone(self.result["email_metadata"]["from"])
        self.assertIn("alice@example-sender.com", self.result["email_metadata"]["from"])

    def test_to_extracted(self):
        """The To field should contain at least one address."""
        self.assertGreater(len(self.result["email_metadata"]["to"]), 0)
        to_str = " ".join(self.result["email_metadata"]["to"])
        self.assertIn("bob@example-recipient.com", to_str)

    def test_subject_extracted(self):
        """The Subject should be extracted and non-empty."""
        self.assertIsNotNone(self.result["email_metadata"]["subject"])
        self.assertIn("test suite", self.result["email_metadata"]["subject"])

    def test_date_extracted(self):
        """The Date header should be present."""
        self.assertIsNotNone(self.result["email_metadata"]["date"])

    def test_message_id_extracted(self):
        """The Message-ID should be extracted."""
        self.assertIsNotNone(self.result["email_metadata"]["message_id"])

    def test_plain_text_body_extracted(self):
        """The plain-text body should be present and contain expected content."""
        body = self.result["body"]["plain_text"]
        self.assertIsNotNone(body)
        self.assertIn("Hello Bob", body)

    def test_html_body_absent(self):
        """A plain-text-only email should have no HTML body."""
        self.assertIsNone(self.result["body"]["html"])

    def test_url_extracted(self):
        """The URL in the body should be extracted."""
        urls = [entry["url"] for entry in self.result["urls"]]
        self.assertTrue(
            any("example.com" in u for u in urls),
            msg=f"Expected a URL from example.com in {urls}"
        )

    def test_file_metadata(self):
        """File metadata should report the correct filename."""
        self.assertEqual(
            self.result["file_metadata"]["filename"], "plain_text.eml"
        )

    def test_file_size_positive(self):
        """File size should be a positive integer."""
        self.assertIsNotNone(self.result["file_metadata"]["file_size_bytes"])
        self.assertGreater(self.result["file_metadata"]["file_size_bytes"], 0)


class TestMultipartEmail(unittest.TestCase):
    """TC-02: Multipart email containing plain text and HTML."""

    @classmethod
    def setUpClass(cls):
        cls.result = parse_email_file(_sample("multipart.eml"))

    def test_no_errors(self):
        self.assertEqual(self.result["errors"], [])

    def test_plain_text_body_present(self):
        """Multipart email must have a plain-text part."""
        self.assertIsNotNone(self.result["body"]["plain_text"])

    def test_html_body_present(self):
        """Multipart email must have an HTML part."""
        self.assertIsNotNone(self.result["body"]["html"])
        self.assertIn("<html>", self.result["body"]["html"].lower())

    def test_plain_text_content(self):
        """Plain-text body should contain expected text."""
        self.assertIn("Weekly Digest", self.result["body"]["plain_text"])

    def test_html_content(self):
        """HTML body should contain a hyperlink."""
        self.assertIn("href", self.result["body"]["html"].lower())

    def test_cc_extracted(self):
        """The Cc field should be extracted."""
        self.assertGreater(len(self.result["email_metadata"]["cc"]), 0)

    def test_reply_to_extracted(self):
        """The Reply-To field should be extracted."""
        self.assertIsNotNone(self.result["email_metadata"]["reply_to"])

    def test_multiple_urls(self):
        """A multipart email with links should yield multiple distinct URLs."""
        self.assertGreater(len(self.result["urls"]), 1)

    def test_url_sources(self):
        """URLs should be attributed to their correct source."""
        sources_seen = set()
        for entry in self.result["urls"]:
            for source in entry["found_in"]:
                sources_seen.add(source)
        self.assertIn("plain_text", sources_seen)
        self.assertIn("html", sources_seen)


class TestMultipleReceivedHeaders(unittest.TestCase):
    """TC-03: Email with multiple Received headers (routing trace)."""

    @classmethod
    def setUpClass(cls):
        cls.result = parse_email_file(_sample("phishing_sample.eml"))

    def test_no_fatal_errors(self):
        self.assertEqual(self.result["errors"], [])

    def test_received_headers_present(self):
        """phishing_sample.eml has 3 Received headers."""
        self.assertGreaterEqual(len(self.result["received_headers"]), 2)

    def test_received_headers_are_strings(self):
        """Each Received header entry should be a non-empty string."""
        for header in self.result["received_headers"]:
            self.assertIsInstance(header, str)
            self.assertGreater(len(header), 0)


class TestAuthenticationHeaders(unittest.TestCase):
    """TC-04: Email with Authentication-Result, DKIM, SPF, DMARC headers."""

    @classmethod
    def setUpClass(cls):
        # multipart.eml has passing auth; phishing_sample.eml has failing auth.
        cls.pass_result = parse_email_file(_sample("multipart.eml"))
        cls.fail_result = parse_email_file(_sample("phishing_sample.eml"))

    def test_auth_results_extracted_passing(self):
        """Authentication-Results header should be extracted from multipart.eml."""
        auth = self.pass_result["authentication_headers"]
        self.assertGreater(len(auth["authentication_results"]), 0)

    def test_dkim_extracted_passing(self):
        """DKIM-Signature should be extracted from multipart.eml."""
        self.assertIsNotNone(
            self.pass_result["authentication_headers"]["dkim_signature"]
        )

    def test_spf_extracted_passing(self):
        """Received-SPF should be extracted from multipart.eml."""
        self.assertIsNotNone(
            self.pass_result["authentication_headers"]["received_spf"]
        )

    def test_dmarc_evidence_extracted_passing(self):
        """DMARC evidence should be extracted from Authentication-Results."""
        self.assertIsNotNone(
            self.pass_result["authentication_headers"]["dmarc_evidence"]
        )

    def test_auth_results_extracted_failing(self):
        """phishing_sample.eml should also have Authentication-Results."""
        auth = self.fail_result["authentication_headers"]
        self.assertGreater(len(auth["authentication_results"]), 0)
        # Check the header says 'fail' -- we record what it says, not our opinion
        combined = " ".join(auth["authentication_results"]).lower()
        self.assertIn("fail", combined)


class TestMultipleURLs(unittest.TestCase):
    """TC-05: Multiple URLs in the phishing sample email."""

    @classmethod
    def setUpClass(cls):
        cls.result = parse_email_file(_sample("phishing_sample.eml"))

    def test_urls_extracted(self):
        """Should extract at least 3 distinct URLs from the phishing sample."""
        self.assertGreaterEqual(len(self.result["urls"]), 3)

    def test_urls_are_dicts(self):
        """Every URL entry should be a dict with the expected keys."""
        for entry in self.result["urls"]:
            self.assertIn("url", entry)
            self.assertIn("found_in", entry)
            self.assertIn("count", entry)

    def test_suspicious_url_not_visited(self):
        """
        SECURITY TEST: The parser must NOT attempt to open any extracted URL.

        We verify this indirectly: parse the phishing email and confirm we
        receive a completed result dict (proving the parser returned without
        hanging on a network request). If any URL had been fetched, the test
        would either hang indefinitely or raise a connection error.

        This test also documents that suspicious links are handled safely.
        """
        urls = [entry["url"] for entry in self.result["urls"]]
        # The suspicious URL should be present in the extracted list
        self.assertTrue(
            any("totally-not-evil.com" in u for u in urls),
            msg="Suspicious URL was not extracted at all"
        )
        # The function returned a result dict -- URLs were not followed
        self.assertIsInstance(self.result, dict)
        self.assertEqual(self.result["errors"], [])


# ============================================================================
# TC-06 to TC-10 : Tests using synthetic emails built in memory
# ============================================================================

class TestMissingOptionalHeaders(unittest.TestCase):
    """TC-06: Email with many optional headers absent."""

    MINIMAL_EML = textwrap.dedent("""\
        From: sender@example.com
        Subject: Minimal email

        This email has no Date, no Message-ID, no Received, no MIME headers.
        Just the bare minimum to be parseable.
    """)

    def setUp(self):
        self.path = _make_temp_eml(self.MINIMAL_EML)
        self.addCleanup(os.remove, self.path)

    def test_parses_without_crash(self):
        """Parser must not crash on an email with many missing headers."""
        result = parse_email_file(self.path)
        self.assertIsInstance(result, dict)

    def test_no_fatal_errors(self):
        result = parse_email_file(self.path)
        self.assertEqual(result["errors"], [])

    def test_warnings_for_missing_date(self):
        """A warning should be issued for the missing Date header."""
        result = parse_email_file(self.path)
        combined = " ".join(result["parse_warnings"]).lower()
        self.assertIn("date", combined)

    def test_missing_to_is_empty_list(self):
        """Absent To field should be an empty list, not None."""
        result = parse_email_file(self.path)
        self.assertEqual(result["email_metadata"]["to"], [])

    def test_missing_received_triggers_warning(self):
        """Absent Received headers should trigger a warning, not an error."""
        result = parse_email_file(self.path)
        combined = " ".join(result["parse_warnings"]).lower()
        self.assertIn("received", combined)

    def test_body_still_extracted(self):
        """Even with minimal headers, the body should be extracted."""
        result = parse_email_file(self.path)
        self.assertIsNotNone(result["body"]["plain_text"])
        self.assertIn("bare minimum", result["body"]["plain_text"])


class TestEmptyFile(unittest.TestCase):
    """TC-07: File that exists but is completely empty (0 bytes)."""

    def setUp(self):
        # Create a real empty file on disk
        fd, self.path = tempfile.mkstemp(suffix=".eml")
        os.close(fd)
        self.addCleanup(os.remove, self.path)

    def test_returns_error_not_exception(self):
        """An empty file should produce an error entry, not a Python exception."""
        result = parse_email_file(self.path)
        self.assertGreater(len(result["errors"]), 0)

    def test_error_mentions_empty(self):
        """The error message should mention the file is empty."""
        result = parse_email_file(self.path)
        combined = " ".join(result["errors"]).lower()
        self.assertIn("empty", combined)

    def test_result_structure_intact(self):
        """Even on failure, the result dict should have all expected keys."""
        result = parse_email_file(self.path)
        for key in ("file_metadata", "email_metadata", "body", "urls",
                    "parse_warnings", "errors"):
            self.assertIn(key, result)


class TestMalformedEmail(unittest.TestCase):
    """TC-08: File with a .eml extension but clearly not a valid email."""

    JUNK_CONTENT = b"\x00\x01\x02\x03 This is garbage data \xff\xfe\xfd"

    def setUp(self):
        self.path = _make_temp_eml(self.JUNK_CONTENT)
        self.addCleanup(os.remove, self.path)

    def test_does_not_crash(self):
        """Parser must not raise an unhandled exception on malformed content."""
        try:
            result = parse_email_file(self.path)
        except Exception as exc:
            self.fail(f"parse_email_file raised an exception: {exc}")

    def test_returns_dict(self):
        """Result must always be a dict, even for malformed input."""
        result = parse_email_file(self.path)
        self.assertIsInstance(result, dict)

    def test_result_keys_present(self):
        """All top-level keys must be present regardless of parse outcome."""
        result = parse_email_file(self.path)
        expected_keys = {
            "file_metadata", "email_metadata", "headers",
            "received_headers", "authentication_headers",
            "body", "urls", "parse_warnings", "errors",
        }
        for key in expected_keys:
            self.assertIn(key, result, msg=f"Missing key: '{key}'")


class TestInvalidFilePath(unittest.TestCase):
    """TC-09: File path that does not exist on disk."""

    NONEXISTENT_PATH = "/this/path/does/not/exist/fake_email.eml"

    def test_returns_error_not_exception(self):
        """A missing file should produce an error, not an unhandled exception."""
        result = parse_email_file(self.NONEXISTENT_PATH)
        self.assertGreater(len(result["errors"]), 0)

    def test_error_mentions_not_found(self):
        """The error message should say the file was not found."""
        result = parse_email_file(self.NONEXISTENT_PATH)
        combined = " ".join(result["errors"]).lower()
        self.assertIn("not found", combined)

    def test_metadata_still_has_filename(self):
        """Even on failure, the filename should be recorded in file_metadata."""
        result = parse_email_file(self.NONEXISTENT_PATH)
        self.assertEqual(
            result["file_metadata"]["filename"], "fake_email.eml"
        )


class TestWrongFileExtension(unittest.TestCase):
    """TC-10: File with wrong extension (.txt instead of .eml)."""

    def setUp(self):
        self.path = _make_temp_eml(b"From: a@b.com\n\nHello", suffix=".txt")
        self.addCleanup(os.remove, self.path)

    def test_rejected_with_error(self):
        """A .txt file should be rejected with an error."""
        result = parse_email_file(self.path)
        self.assertGreater(len(result["errors"]), 0)

    def test_error_mentions_extension(self):
        """The error message should mention the file type problem."""
        result = parse_email_file(self.path)
        combined = " ".join(result["errors"]).lower()
        # Should mention either "eml", "type", or "extension"
        self.assertTrue(
            any(word in combined for word in ("eml", "type", "extension")),
            msg=f"Error message unclear: {combined}"
        )


# ============================================================================
# TC-11 to TC-13 : Focused unit tests for specific functions
# ============================================================================

class TestSuspiciousLinkNotVisited(unittest.TestCase):
    """
    TC-11: A suspicious-looking URL must be extracted but NEVER visited.

    This test verifies the security guarantee by checking:
    1. The URL appears in the result["urls"] list (extraction works).
    2. The test itself completes immediately (no network hang).
    3. No exception related to network access is raised.
    """

    PHISHING_EML = textwrap.dedent("""\
        From: evil@phisher.example.com
        To: target@victim.example.com
        Subject: Click here immediately!
        Date: Thu, 01 Jan 2026 00:00:00 +0000
        MIME-Version: 1.0
        Content-Type: text/plain; charset=utf-8

        Click here: http://absolutely-fake-malicious-domain.example-test.invalid/steal-data
        And here: https://another-fake-domain.example-test.invalid/login?phish=true
    """)

    def setUp(self):
        self.path = _make_temp_eml(self.PHISHING_EML)
        self.addCleanup(os.remove, self.path)

    def test_suspicious_url_is_extracted(self):
        """The suspicious URL must appear in the output."""
        result = parse_email_file(self.path)
        urls = [entry["url"] for entry in result["urls"]]
        self.assertTrue(
            any("example-test.invalid" in u for u in urls),
            msg=f"Suspicious URL not found in: {urls}"
        )

    def test_url_not_visited(self):
        """
        The parser must return a result immediately (it is synchronous with no
        network calls). If any URL had been visited, the parser would either
        hang for seconds (DNS timeout) or raise a connection error -- neither
        of which happens with our implementation.
        """
        import time
        start = time.monotonic()
        result = parse_email_file(self.path)
        elapsed = time.monotonic() - start
        # Parsing a tiny file should take well under 2 seconds.
        # A real network request to .invalid would timeout after ~30 seconds.
        self.assertLess(
            elapsed, 2.0,
            msg="Parser took too long -- possible network request detected!"
        )
        self.assertIsInstance(result, dict)

    def test_url_marked_as_found_in_plain_text(self):
        """The suspicious URL should be attributed to 'plain_text' source."""
        result = parse_email_file(self.path)
        for entry in result["urls"]:
            if "example-test.invalid" in entry["url"]:
                self.assertIn("plain_text", entry["found_in"])
                break


class TestEncodedSubjectDecoding(unittest.TestCase):
    """TC-12: Encoded Subject header (Base64 UTF-8) is decoded correctly."""

    @classmethod
    def setUpClass(cls):
        # multipart.eml has: Subject: =?UTF-8?b?V2Vla2x5IERpZ2VzdCDigJQgSXNzdWUgNDI=?=
        # which decodes to: "Weekly Digest — Issue 42"
        cls.result = parse_email_file(_sample("multipart.eml"))

    def test_subject_is_decoded_unicode(self):
        """The encoded subject must be decoded into readable Unicode text."""
        subject = self.result["email_metadata"]["subject"]
        self.assertIsNotNone(subject)
        # After decoding, should contain readable text, not the =?UTF-8? encoding
        self.assertNotIn("=?", subject)
        self.assertIn("Weekly Digest", subject)


class TestURLDeduplication(unittest.TestCase):
    """TC-13: URL deduplication keeps one entry per unique URL."""

    def test_same_url_in_both_sources_is_deduplicated(self):
        """A URL that appears in both plain_text and html should be one entry."""
        shared_url = "https://shared.example.com/page"
        text_urls = [shared_url, shared_url]   # appears twice in text
        html_urls = [shared_url]               # and once in HTML

        result = build_url_list(text_urls, html_urls)

        # Should only be ONE entry, not three
        matching = [e for e in result if e["url"] == shared_url]
        self.assertEqual(len(matching), 1)

    def test_deduplicated_entry_has_both_sources(self):
        """A URL seen in both sources should list both in found_in."""
        shared_url = "https://shared.example.com/page"
        result = build_url_list([shared_url], [shared_url])
        entry = result[0]
        self.assertIn("plain_text", entry["found_in"])
        self.assertIn("html", entry["found_in"])

    def test_count_reflects_total_occurrences(self):
        """The count field should reflect the total number of times URL appeared."""
        url = "https://counted.example.com/"
        result = build_url_list([url, url, url], [url])  # 3 + 1 = 4
        entry = next(e for e in result if e["url"] == url)
        self.assertEqual(entry["count"], 4)

    def test_different_urls_are_separate_entries(self):
        """Two different URLs should produce two separate entries."""
        result = build_url_list(
            ["https://site-a.example.com"],
            ["https://site-b.example.com"]
        )
        self.assertEqual(len(result), 2)

    def test_trailing_punctuation_stripped(self):
        """A URL followed by a period (as in a sentence) should be cleaned."""
        raw_url = "https://clean.example.com/path"
        result = build_url_list([raw_url + "."], [])
        # After stripping the trailing period, the URL should be clean
        self.assertEqual(result[0]["url"], raw_url)


class TestValidateEmlFile(unittest.TestCase):
    """Unit tests for the validate_eml_file helper function."""

    def test_nonexistent_path_fails(self):
        ok, err = validate_eml_file("/does/not/exist.eml")
        self.assertFalse(ok)
        self.assertIn("not found", err.lower())

    def test_wrong_extension_fails(self):
        fd, path = tempfile.mkstemp(suffix=".txt")
        os.close(fd)
        try:
            ok, err = validate_eml_file(path)
            self.assertFalse(ok)
        finally:
            os.remove(path)

    def test_empty_file_fails(self):
        fd, path = tempfile.mkstemp(suffix=".eml")
        os.close(fd)
        try:
            ok, err = validate_eml_file(path)
            self.assertFalse(ok)
            self.assertIn("empty", err.lower())
        finally:
            os.remove(path)

    def test_valid_file_passes(self):
        path = _make_temp_eml(b"From: a@b.com\n\nHello")
        try:
            ok, err = validate_eml_file(path)
            self.assertTrue(ok)
            self.assertIsNone(err)
        finally:
            os.remove(path)


# ============================================================================
# Entry point — run tests directly with:  python tests/test_email_parser.py
# ============================================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)
