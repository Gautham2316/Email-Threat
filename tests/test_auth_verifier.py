"""
tests/test_auth_verifier.py
===========================
Automated test suite for Module 2: SPF, DKIM, and DMARC Authentication Verifier.

RULES & INVARIANTS:
1. Zero Network Access: Every DNS query in this suite is fully mocked.
2. Three-Layer Evidence Model:
   - Layer 1: Observed untrusted header claims preserved as-is.
   - Layer 2: Independent cryptographic/DNS verifications.
   - Layer 3: Derived verdicts and conclusions.
3. SPF Invariance: SPF independent_result is ALWAYS 'not_checked' for uploaded files.
4. DMARC Invariance: DMARC never emits 'fail' for uploaded files.
5. Public Suffix List (PSL): Org-domain determination uses PSL-aware rules (tldextract snapshot).
6. Non-Destructive: Does not modify or re-encode raw bytes during verification.
"""

import os
import sys
import unittest
from unittest.mock import patch

SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src'))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from auth_verifier import (
    verify_authentication,
    _org_domain,
    _domains_align,
    _parse_dmarc_record,
    _parse_tag_value_list,
    _extract_domain_from_address,
    _build_spf_result,
    _build_dkim_result,
    _build_dmarc_result,
)
from email_parser import parse_email_file

MOCK_DKIM_PUB_KEY = (
    "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAl9r14+D97P2YuEGPsb"
    "ZEh9tbNRAbL2sDyMj4v9TH4F+cmEBW08jggK2f42KqjJkl9slEtTyY2xwtcTqhdELc8u423Q+9zrQrv5"
    "1m4MoXpWqtCo0XIddf13/sgkN4oLpcTKxuxql/KqqSScLkos5RFRNokr95aOV97E4rpU/TOnpWo5LRRx"
    "bB54GWZ33+npOHEVAKGyfu9nXNtZgyXO/2KTU8mpT0ryVHbWy5sywV2NjXrPss0vlC947T36XOdPp8M9"
    "y1Qb6ad21RxtWMEzu96ibg8x7Ldnd6lNkre85Wye01fQBeQTqO0sqQbZSFgiQXz2atTlNXLIL8VeLnp5"
    "7b8wIDAQAB"
)

def _mock_dkim_dns(name, timeout=5):
    if b'test2026._domainkey.example.com' in name:
        return MOCK_DKIM_PUB_KEY.encode('utf-8')
    return None


class TestPSLOrgDomain(unittest.TestCase):
    """Test Public Suffix List aware organizational domain extraction and alignment."""

    def test_standard_2_label_tld(self):
        self.assertEqual(_org_domain("mail.example.com"), "example.com")
        self.assertEqual(_org_domain("sub.mail.example.com"), "example.com")
        self.assertEqual(_org_domain("example.com"), "example.com")

    def test_multilabel_cctld_co_uk(self):
        # Must not take last two labels (.co.uk is TLD, org domain is example.co.uk)
        self.assertEqual(_org_domain("mail.example.co.uk"), "example.co.uk")
        self.assertEqual(_org_domain("deep.sub.example.co.uk"), "example.co.uk")
        self.assertEqual(_org_domain("example.co.uk"), "example.co.uk")

    def test_multilabel_cctld_gov_in(self):
        self.assertEqual(_org_domain("portal.meity.gov.in"), "meity.gov.in")
        self.assertEqual(_org_domain("meity.gov.in"), "meity.gov.in")

    def test_domains_align_relaxed_same_org(self):
        self.assertTrue(_domains_align("mail.example.com", "billing.example.com", "relaxed"))
        self.assertTrue(_domains_align("sub.dept.example.co.uk", "example.co.uk", "relaxed"))

    def test_domains_align_relaxed_different_org(self):
        self.assertFalse(_domains_align("mail.example.com", "mail.attacker.com", "relaxed"))

    def test_domains_align_relaxed_cctld_shared_suffix(self):
        # Two distinct companies under .co.uk must NOT align
        self.assertFalse(_domains_align("alpha.co.uk", "beta.co.uk", "relaxed"))
        self.assertFalse(_domains_align("dept.gov.in", "other.gov.in", "relaxed"))

    def test_domains_align_strict_exact_match_only(self):
        self.assertTrue(_domains_align("mail.example.com", "mail.example.com", "strict"))
        self.assertFalse(_domains_align("mail.example.com", "billing.example.com", "strict"))
        self.assertFalse(_domains_align("sub.example.com", "example.com", "strict"))


class TestTagValueAndDMARCParser(unittest.TestCase):
    """Test RFC tag-value string parsing and DMARC record structural parser."""

    def test_parse_tag_value_list(self):
        tags = _parse_tag_value_list("v=DMARC1; p=reject; rua=mailto:d@example.com; pct=100")
        self.assertEqual(tags.get("v"), "DMARC1")
        self.assertEqual(tags.get("p"), "reject")
        self.assertEqual(tags.get("rua"), "mailto:d@example.com")
        self.assertEqual(tags.get("pct"), "100")

    def test_parse_tag_value_list_extra_spaces_and_semicolons(self):
        tags = _parse_tag_value_list("  v = DMARC1 ;  p = quarantine ;;  ")
        self.assertEqual(tags.get("v"), "DMARC1")
        self.assertEqual(tags.get("p"), "quarantine")

    def test_parse_dmarc_record_standard(self):
        rec = "v=DMARC1; p=quarantine; sp=reject; adkim=s; aspf=r; pct=100; rua=mailto:rep@example.com"
        parsed = _parse_dmarc_record(rec)
        self.assertNotIn("_error", parsed)
        self.assertEqual(parsed["v"], "DMARC1")
        self.assertEqual(parsed["p"], "quarantine")
        self.assertEqual(parsed["sp"], "reject")
        self.assertEqual(parsed["adkim"], "s")
        self.assertEqual(parsed["aspf"], "r")
        self.assertEqual(parsed["pct"], 100)
        self.assertEqual(parsed["rua"], ["mailto:rep@example.com"])

    def test_parse_dmarc_record_defaults(self):
        rec = "v=DMARC1; p=none"
        parsed = _parse_dmarc_record(rec)
        self.assertEqual(parsed["sp"], "none")
        self.assertEqual(parsed["adkim"], "r")
        self.assertEqual(parsed["aspf"], "r")
        self.assertEqual(parsed["pct"], 100)

    def test_parse_dmarc_record_invalid_policy(self):
        rec = "v=DMARC1; p=allow"
        parsed = _parse_dmarc_record(rec)
        self.assertIn("_error", parsed)

    def test_parse_dmarc_record_missing_version(self):
        rec = "p=reject; rua=mailto:rep@example.com"
        parsed = _parse_dmarc_record(rec)
        self.assertIn("_error", parsed)


class TestSPFVerification(unittest.TestCase):
    """Test SPF DNS lookup, evidence preservation, and independent_result invariance."""

    def test_spf_independent_result_always_not_checked(self):
        parsed = {
            "email_metadata": {"return_path": "<sender@example.com>"},
            "authentication_headers": {}
        }
        def mock_dns(dom):
            return ["v=spf1 ip4:192.0.2.1 -all"], "retrieved", None

        spf = _build_spf_result(parsed, dns_txt_func=mock_dns)
        self.assertEqual(spf["independent_result"], "not_checked")
        self.assertIn("connecting IP", spf["independent_result_reason"])
        self.assertEqual(spf["dns_policy"]["lookup_result"], "retrieved")
        self.assertEqual(spf["dns_policy"]["raw_record"], "v=spf1 ip4:192.0.2.1 -all")
        self.assertIn("NOT been evaluated", spf["dns_policy"]["retrieval_note"])

    def test_spf_dns_policy_none_when_no_record(self):
        parsed = {
            "email_metadata": {"return_path": "<sender@example.com>"},
            "authentication_headers": {}
        }
        def mock_dns(dom):
            return [], "none", "NXDOMAIN: example.com"

        spf = _build_spf_result(parsed, dns_txt_func=mock_dns)
        self.assertEqual(spf["independent_result"], "not_checked")
        self.assertEqual(spf["dns_policy"]["lookup_result"], "none")
        self.assertIn("NXDOMAIN", spf["dns_policy"]["error"])

    def test_spf_dns_policy_permerror_on_multiple_records(self):
        parsed = {
            "email_metadata": {"return_path": "<sender@example.com>"},
            "authentication_headers": {}
        }
        def mock_dns(dom):
            return ["v=spf1 ip4:192.0.2.1 -all", "v=spf1 mx -all"], "retrieved", None

        spf = _build_spf_result(parsed, dns_txt_func=mock_dns)
        self.assertEqual(spf["dns_policy"]["lookup_result"], "permerror")
        self.assertIn("Multiple SPF records", spf["dns_policy"]["error"])

    def test_spf_dns_policy_temperror_on_timeout(self):
        parsed = {
            "email_metadata": {"return_path": "<sender@example.com>"},
            "authentication_headers": {}
        }
        def mock_dns(dom):
            return [], "temperror", "DNS timed out after 5 s"

        spf = _build_spf_result(parsed, dns_txt_func=mock_dns)
        self.assertEqual(spf["dns_policy"]["lookup_result"], "temperror")
        self.assertTrue(len(spf["errors"]) > 0)

    def test_spf_preserves_untrusted_return_path_and_received_spf(self):
        parsed = {
            "email_metadata": {"return_path": "<alice@dept.example.com>"},
            "authentication_headers": {
                "received_spf": "Pass (mailfrom) identity=mailfrom; client-ip=192.0.2.1;"
            }
        }
        def mock_dns(dom):
            return ["v=spf1 -all"], "retrieved", None

        spf = _build_spf_result(parsed, dns_txt_func=mock_dns)
        self.assertEqual(spf["envelope_domain_evidence"]["extracted_domain"], "dept.example.com")
        self.assertIn("UNTRUSTED", spf["envelope_domain_evidence"]["trust"])
        self.assertEqual(spf["mta_reported"]["parsed_verdict"], "pass")
        self.assertIn("UNTRUSTED", spf["mta_reported"]["trust"])

    def test_spf_handles_missing_return_path(self):
        parsed = {
            "email_metadata": {"return_path": None},
            "authentication_headers": {}
        }
        spf = _build_spf_result(parsed)
        self.assertEqual(spf["independent_result"], "not_checked")
        self.assertIsNone(spf["envelope_domain_evidence"]["extracted_domain"])
        self.assertTrue(len(spf["warnings"]) > 0)


class TestDKIMVerification(unittest.TestCase):
    """Test DKIM cryptographic signature verification on raw bytes with mocked DNS."""

    def setUp(self):
        sample_path = os.path.join(os.path.dirname(__file__), "..", "samples", "dkim_signed.eml")
        with open(sample_path, "rb") as f:
            self.raw_bytes = f.read()
        self.parsed = parse_email_file(sample_path)

    def test_dkim_valid_signature_passes(self):
        dkim_res = _build_dkim_result(self.parsed, self.raw_bytes, dnsfunc=_mock_dkim_dns)
        self.assertEqual(dkim_res["overall_result"], "pass")
        self.assertEqual(len(dkim_res["signatures"]), 1)
        sig = dkim_res["signatures"][0]
        self.assertEqual(sig["result"], "pass")
        self.assertEqual(sig["domain"], "example.com")
        self.assertEqual(sig["selector"], "test2026")
        self.assertTrue(sig["public_key_retrieved"])

    def test_dkim_modified_body_fails(self):
        tampered_bytes = self.raw_bytes.replace(b"This is a DKIM-signed", b"Tampered body content")
        dkim_res = _build_dkim_result(self.parsed, tampered_bytes, dnsfunc=_mock_dkim_dns)
        self.assertEqual(dkim_res["overall_result"], "fail")
        self.assertEqual(dkim_res["signatures"][0]["result"], "fail")
        self.assertIn("hash mismatch", dkim_res["signatures"][0]["error"].lower())

    def test_dkim_modified_signed_header_fails(self):
        tampered_bytes = self.raw_bytes.replace(b"Subject: DKIM signed", b"Subject: TAMPERED Subject")
        dkim_res = _build_dkim_result(self.parsed, tampered_bytes, dnsfunc=_mock_dkim_dns)
        self.assertEqual(dkim_res["overall_result"], "fail")
        self.assertEqual(dkim_res["signatures"][0]["result"], "fail")

    def test_dkim_modified_unsigned_header_passes(self):
        # Adding an unsigned header does not break DKIM signatures over specified headers
        tampered_bytes = b"X-Spam-Scanned: yes\r\n" + self.raw_bytes
        dkim_res = _build_dkim_result(self.parsed, tampered_bytes, dnsfunc=_mock_dkim_dns)
        self.assertEqual(dkim_res["overall_result"], "pass")
        self.assertEqual(dkim_res["signatures"][0]["result"], "pass")

    def test_dkim_missing_public_key_permerror(self):
        def no_key_dns(name, timeout=5):
            return None

        dkim_res = _build_dkim_result(self.parsed, self.raw_bytes, dnsfunc=no_key_dns)
        self.assertEqual(dkim_res["overall_result"], "permerror")
        self.assertEqual(dkim_res["signatures"][0]["result"], "permerror")

    def test_dkim_dns_timeout_temperror(self):
        import dkim
        def timeout_dns(name, timeout=5):
            raise dkim.DnsTimeoutError("Simulated DNS timeout")

        dkim_res = _build_dkim_result(self.parsed, self.raw_bytes, dnsfunc=timeout_dns)
        self.assertEqual(dkim_res["overall_result"], "temperror")
        self.assertEqual(dkim_res["signatures"][0]["result"], "temperror")

    def test_dkim_multiple_signatures_one_passes(self):
        # Prepend an invalid DKIM signature header
        bogus_sig = (
            b"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=bad.com; s=s1; "
            b"h=from:to; bh=invalidbh=; b=invalidb=\r\n"
        )
        multi_sig_bytes = bogus_sig + self.raw_bytes
        dkim_res = _build_dkim_result(self.parsed, multi_sig_bytes, dnsfunc=_mock_dkim_dns)
        self.assertEqual(len(dkim_res["signatures"]), 2)
        # One valid, one invalid -> overall is pass
        self.assertEqual(dkim_res["overall_result"], "pass")

    def test_dkim_no_signature(self):
        plain_path = os.path.join(os.path.dirname(__file__), "..", "samples", "plain_text.eml")
        with open(plain_path, "rb") as f:
            raw = f.read()
        parsed = parse_email_file(plain_path)
        dkim_res = _build_dkim_result(parsed, raw, dnsfunc=_mock_dkim_dns)
        self.assertEqual(dkim_res["overall_result"], "none")
        self.assertEqual(len(dkim_res["signatures"]), 0)

    def test_dkim_body_length_limit_flagged_in_warnings(self):
        # Inject an l= tag into the signature header to verify warning detection
        l_bytes = self.raw_bytes.replace(b"q=dns/txt;", b"q=dns/txt; l=200;")
        dkim_res = _build_dkim_result(self.parsed, l_bytes, dnsfunc=_mock_dkim_dns)
        self.assertTrue(any("l= tag present" in w for w in dkim_res["warnings"]))


class TestDMARCVerification(unittest.TestCase):
    """Test DMARC evaluation, alignment checking, and uploaded-file invariants."""

    def test_dmarc_pass_via_aligned_dkim_relaxed(self):
        parsed = {
            "email_metadata": {"from": "Alice <alice@example.com>"},
            "authentication_headers": {}
        }
        spf_res = {"envelope_domain_evidence": {"extracted_domain": "example.com"}}
        dkim_res = {
            "overall_result": "pass",
            "signatures": [{"result": "pass", "domain": "sub.example.com"}]
        }
        def mock_dns(dom):
            if dom == "_dmarc.example.com":
                return ["v=DMARC1; p=reject; adkim=r"], "retrieved", None
            return [], "none", "NXDOMAIN"

        dmarc = _build_dmarc_result(parsed, spf_res, dkim_res, dns_txt_func=mock_dns)
        self.assertEqual(dmarc["result"], "pass")
        self.assertEqual(dmarc["alignment"]["dkim"]["result"], "pass")
        self.assertEqual(dmarc["alignment"]["dkim"]["mode"], "relaxed")

    def test_dmarc_strict_dkim_alignment_fails_on_subdomain(self):
        parsed = {
            "email_metadata": {"from": "Alice <alice@example.com>"},
            "authentication_headers": {}
        }
        spf_res = {"envelope_domain_evidence": {"extracted_domain": "example.com"}}
        dkim_res = {
            "overall_result": "pass",
            "signatures": [{"result": "pass", "domain": "sub.example.com"}]
        }
        def mock_dns(dom):
            if dom == "_dmarc.example.com":
                return ["v=DMARC1; p=reject; adkim=s"], "retrieved", None
            return [], "none", "NXDOMAIN"

        dmarc = _build_dmarc_result(parsed, spf_res, dkim_res, dns_txt_func=mock_dns)
        # Strict mode requires exact domain match; sub.example.com != example.com
        self.assertEqual(dmarc["alignment"]["dkim"]["result"], "fail")
        # Invariance: DMARC is indeterminate, NOT fail, because SPF is not evaluatable
        self.assertEqual(dmarc["result"], "indeterminate")
        self.assertIn("SPF cannot be evaluated", dmarc["result_reason"])

    def test_dmarc_never_emits_fail_for_uploaded_file(self):
        parsed = {
            "email_metadata": {"from": "Alice <alice@example.com>"},
            "authentication_headers": {}
        }
        spf_res = {"envelope_domain_evidence": {"extracted_domain": "attacker.com"}}
        dkim_res = {
            "overall_result": "fail",
            "signatures": [{"result": "fail", "domain": "attacker.com"}]
        }
        def mock_dns(dom):
            if dom == "_dmarc.example.com":
                return ["v=DMARC1; p=reject"], "retrieved", None
            return [], "none", "NXDOMAIN"

        dmarc = _build_dmarc_result(parsed, spf_res, dkim_res, dns_txt_func=mock_dns)
        # MUST NEVER be 'fail' for an uploaded file
        self.assertNotEqual(dmarc["result"], "fail")
        self.assertEqual(dmarc["result"], "indeterminate")

    def test_dmarc_fallback_to_org_domain(self):
        # From: user@sub.example.com -> _dmarc.sub.example.com is NXDOMAIN,
        # but _dmarc.example.com exists
        parsed = {
            "email_metadata": {"from": "Alice <alice@sub.example.com>"},
            "authentication_headers": {}
        }
        spf_res = {"envelope_domain_evidence": {}}
        dkim_res = {
            "overall_result": "pass",
            "signatures": [{"result": "pass", "domain": "example.com"}]
        }
        def mock_dns(dom):
            if dom == "_dmarc.sub.example.com":
                return [], "none", "NXDOMAIN"
            if dom == "_dmarc.example.com":
                return ["v=DMARC1; p=quarantine"], "retrieved", None
            return [], "none", "NXDOMAIN"

        dmarc = _build_dmarc_result(parsed, spf_res, dkim_res, dns_txt_func=mock_dns)
        self.assertEqual(dmarc["dns_lookup"]["record_from"], "organizational_domain")
        self.assertEqual(dmarc["policy"]["p"], "quarantine")
        self.assertEqual(dmarc["result"], "pass")

    def test_dmarc_dns_lookup_none(self):
        parsed = {
            "email_metadata": {"from": "Alice <alice@example.com>"},
            "authentication_headers": {}
        }
        def mock_dns(dom):
            return [], "none", "NXDOMAIN: example.com"

        dmarc = _build_dmarc_result(parsed, {}, {}, dns_txt_func=mock_dns)
        self.assertEqual(dmarc["result"], "none")
        self.assertIsNone(dmarc["policy"])

    def test_dmarc_dns_lookup_temperror(self):
        parsed = {
            "email_metadata": {"from": "Alice <alice@example.com>"},
            "authentication_headers": {}
        }
        def mock_dns(dom):
            return [], "temperror", "Timeout connecting to nameserver"

        dmarc = _build_dmarc_result(parsed, {}, {}, dns_txt_func=mock_dns)
        self.assertEqual(dmarc["result"], "temperror")

    def test_dmarc_malformed_record_permerror(self):
        parsed = {
            "email_metadata": {"from": "Alice <alice@example.com>"},
            "authentication_headers": {}
        }
        def mock_dns(dom):
            return ["v=DMARC1; p=invalid_action"], "retrieved", None

        dmarc = _build_dmarc_result(parsed, {}, {}, dns_txt_func=mock_dns)
        self.assertEqual(dmarc["result"], "permerror")
        self.assertIn("Malformed DMARC record", dmarc["result_reason"])


class TestEndToEndIntegration(unittest.TestCase):
    """End-to-end integration tests for verify_authentication."""

    def setUp(self):
        self.sample_path = os.path.join(os.path.dirname(__file__), "..", "samples", "dkim_signed.eml")
        with open(self.sample_path, "rb") as f:
            self.raw_bytes = f.read()
        self.parsed = parse_email_file(self.sample_path)

    def test_verify_authentication_full_pass(self):
        def mock_txt_dns(dom):
            if dom == "_dmarc.example.com":
                return ["v=DMARC1; p=reject"], "retrieved", None
            if dom == "example.com":
                return ["v=spf1 -all"], "retrieved", None
            return [], "none", "NXDOMAIN"

        report = verify_authentication(
            self.parsed,
            self.raw_bytes,
            dkim_dnsfunc=_mock_dkim_dns,
            dns_txt_func=mock_txt_dns,
        )
        self.assertEqual(report["overall_result"], "pass")
        self.assertIn("verified", report["summary"])
        self.assertEqual(report["dkim"]["overall_result"], "pass")
        self.assertEqual(report["spf"]["independent_result"], "not_checked")
        self.assertEqual(report["dmarc"]["result"], "pass")
        self.assertIn("observed_evidence", report)
        self.assertEqual(report["verifier_version"], "1.0.0")

    def test_verify_authentication_invalid_inputs(self):
        res1 = verify_authentication("not a dict", b"raw")
        self.assertEqual(res1["overall_result"], "not_checked")
        self.assertTrue(len(res1["errors"]) > 0)

        res2 = verify_authentication({}, b"")
        self.assertEqual(res2["overall_result"], "not_checked")
        self.assertTrue(len(res2["errors"]) > 0)

    def test_integration_with_module1_samples(self):
        # Verify that existing samples work without error
        for sample_name in ["plain_text.eml", "multipart.eml", "phishing_sample.eml"]:
            path = os.path.join(os.path.dirname(__file__), "..", "samples", sample_name)
            with open(path, "rb") as f:
                raw = f.read()
            parsed = parse_email_file(path)
            report = verify_authentication(
                parsed,
                raw,
                dkim_dnsfunc=lambda name, timeout=5: None,
                dns_txt_func=lambda dom: ([], "none", "NXDOMAIN"),
            )
            self.assertIn("overall_result", report)
            self.assertIn(report["overall_result"], ("pass", "fail", "indeterminate", "not_checked"))
            self.assertIn("spf", report)
            self.assertIn("dkim", report)
            self.assertIn("dmarc", report)
            self.assertIn("observed_evidence", report)


if __name__ == "__main__":
    unittest.main()
