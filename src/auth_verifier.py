# src/auth_verifier.py  Module 2: SPF, DKIM, DMARC Authentication Verification
# SIH 2026 - AI-Powered Email Threat Detection Platform
#
# THREE-LAYER EVIDENCE MODEL
#   Layer 1  OBSERVED EVIDENCE   (UNTRUSTED - header claims)
#   Layer 2  INDEPENDENTLY VERIFIED
#              DKIM: dkimpy cryptographic verification on raw bytes
#              SPF : DNS TXT record retrieval ONLY - mechanisms NOT evaluated
#              DMARC: DNS TXT retrieval, structural parsing, DKIM alignment
#   Layer 3  DERIVED CONCLUSIONS
#
# CRITICAL LIMITATIONS
#   SPF independent_result is ALWAYS not_checked for uploaded files.
#   Mechanisms (include: redirect= a mx ip4: ip6:) are NOT evaluated.
#   DMARC never emits fail for uploaded files - SPF cannot be verified.
#   org-domain uses tldextract bundled PSL snapshot (no network, no cache).
#
# DEPENDENCIES: dnspython>=2.9.0  dkimpy>=1.1.8  tldextract>=5.4.0
# VERSION: 1.0.0
from __future__ import annotations
import email as _stdlib_email
import email.policy
from datetime import datetime, timezone
from email.utils import parseaddr
from typing import Any, Callable
import dns.exception
import dns.resolver
import dkim
import tldextract as _tldextract

VERIFIER_VERSION: str = '1.0.0'
DNS_TIMEOUT: float = 5.0
_DMARC_POLICIES: frozenset = frozenset({'none', 'quarantine', 'reject'})
_TLD_EXTRACT = _tldextract.TLDExtract(
    cache_dir=None, suffix_list_urls=(), fallback_to_snapshot=True)


def _org_domain(domain: str) -> str:
    """PSL-aware organisational domain. Uses bundled snapshot, no HTTP."""
    ext = _TLD_EXTRACT(domain.lower().strip())
    if ext.domain and ext.suffix:
        return f'{ext.domain}.{ext.suffix}'
    return domain.lower().strip()


def _domains_align(d1: str, d2: str, mode: str = 'relaxed') -> bool:
    d1, d2 = d1.lower().strip(), d2.lower().strip()
    if mode == 'strict':
        return d1 == d2
    return _org_domain(d1) == _org_domain(d2)


def _query_txt_records(
    domain: str, *, timeout: float = DNS_TIMEOUT
) -> tuple[list[str], str, str | None]:
    try:
        answers = dns.resolver.resolve(domain, 'TXT', lifetime=timeout)
        records: list[str] = []
        for rdata in answers:
            joined = b''.join(rdata.strings).decode('utf-8', errors='replace')
            records.append(joined)
        return records, 'retrieved', None
    except dns.resolver.NXDOMAIN:
        return [], 'none', f"NXDOMAIN: {domain}"
    except dns.resolver.NoAnswer:
        return [], 'none', f"No TXT records at: {domain}"
    except dns.resolver.NoNameservers:
        return [], 'temperror', 'No nameservers reachable'
    except dns.exception.Timeout:
        return [], 'temperror', f"DNS timed out after {timeout:.0f} s"
    except dns.resolver.YXDOMAIN:
        return [], 'permerror', 'Malformed DNS name (YXDOMAIN)'
    except Exception as exc:  # pragma: no cover
        return [], 'temperror', f"Unexpected DNS error: {exc}"


def _extract_domain_from_address(raw: str | None) -> str | None:
    if not raw:
        return None
    _, addr = parseaddr(raw)
    addr = addr.strip().strip('<>')
    if '@' in addr:
        part = addr.rsplit('@', 1)[1].strip()
        return part.lower() if part else None
    return None


def _parse_tag_value_list(raw: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for segment in raw.split(';'):
        segment = segment.strip()
        if '=' in segment:
            key, _, val = segment.partition('=')
            tags[key.strip().lower()] = val.strip()
    return tags


def _get_dkim_signature_headers(raw_bytes: bytes) -> list[str]:
    msg = _stdlib_email.message_from_bytes(
        raw_bytes, policy=_stdlib_email.policy.compat32)
    return msg.get_all('DKIM-Signature') or []


def _build_spf_result(
    parsed_result: dict[str, Any],
    *,
    dns_txt_func: Callable | None = None,
) -> dict[str, Any]:
    """Build the SPF section.
    independent_result is always not_checked for uploaded files.
    dns_policy: DNS TXT lookup ONLY - mechanisms NOT evaluated.
    mta_reported: Received-SPF preserved as UNTRUSTED evidence.
    """
    result: dict[str, Any] = {
        'independent_result': 'not_checked',
        'independent_result_reason': (
            'SPF evaluation requires the connecting IP at delivery time. '
            'This cannot be reliably determined from an uploaded .eml file.'),
        'dns_policy': {
            'domain_queried': None,
            'domain_source': None,
            'lookup_result': 'not_checked',
            'raw_record': None,
            'retrieval_note': (
                'Only the raw SPF DNS TXT record has been retrieved. '
                'Mechanisms include: redirect= a mx ip4: ip6: have NOT been '
                'evaluated. Full evaluation requires a trusted connecting IP.'),
            'error': None,
        },
        'envelope_domain_evidence': {
            'raw_return_path': None,
            'extracted_domain': None,
            'trust': (
                'UNTRUSTED - Return-Path is written by the sending system '
                'and is not verified as the SMTP MAIL FROM at delivery.'),
        },
        'mta_reported': {
            'raw': None,
            'parsed_verdict': None,
            'source_header': 'Received-SPF',
            'trust': (
                'UNTRUSTED - Received-SPF was written by the original '
                'receiving MTA, not by this tool.'),
        },
        'method': 'dns_txt_lookup_only',
        'warnings': [],
        'errors': [],
    }

    meta = parsed_result.get('email_metadata') or {}
    return_path_raw = meta.get('return_path')
    result['envelope_domain_evidence']['raw_return_path'] = return_path_raw
    envelope_domain = _extract_domain_from_address(return_path_raw)
    result['envelope_domain_evidence']['extracted_domain'] = envelope_domain

    if not envelope_domain:
        result['warnings'].append(
            'Return-Path header absent/unparseable; SPF DNS lookup skipped.')
        result['dns_policy']['error'] = 'No envelope-sender domain available'
    else:
        result['dns_policy']['domain_queried'] = envelope_domain
        result['dns_policy']['domain_source'] = 'Return-Path header (untrusted)'
        query_fn = dns_txt_func or _query_txt_records
        records, status, dns_error = query_fn(envelope_domain)
        if status == 'retrieved':
            spf_recs = [r for r in records if r.lower().startswith('v=spf1')]
            if not spf_recs:
                result['dns_policy']['lookup_result'] = 'none'
                result['dns_policy']['error'] = (
                    f"No v=spf1 record at {envelope_domain!r}")
            elif len(spf_recs) > 1:
                result['dns_policy']['lookup_result'] = 'permerror'
                result['dns_policy']['error'] = (
                    f"Multiple SPF records at {envelope_domain!r} - RFC7208 requires 1")
            else:
                result['dns_policy']['lookup_result'] = 'retrieved'
                result['dns_policy']['raw_record'] = spf_recs[0]
        elif status == 'none':
            result['dns_policy']['lookup_result'] = 'none'
            result['dns_policy']['error'] = dns_error
        elif status == 'temperror':
            result['dns_policy']['lookup_result'] = 'temperror'
            result['dns_policy']['error'] = dns_error
            result['errors'].append(f"SPF DNS temperror: {dns_error}")
        else:
            result['dns_policy']['lookup_result'] = 'permerror'
            result['dns_policy']['error'] = dns_error
            result['errors'].append(f"SPF DNS permerror: {dns_error}")

    auth_hdrs = parsed_result.get('authentication_headers') or {}
    received_spf_raw = auth_hdrs.get('received_spf')
    if received_spf_raw:
        result['mta_reported']['raw'] = received_spf_raw
        first = received_spf_raw.strip().split()[0].lower()
        known = {'pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror'}
        if first in known:
            result['mta_reported']['parsed_verdict'] = first

    return result


def _verify_one_dkim_signature(
    raw_bytes: bytes, idx: int, raw_sig_header: str,
    *, dnsfunc: Callable | None = None,
) -> dict[str, Any]:
    """Verify one DKIM signature via dkimpy on original raw bytes.
    Results: pass | fail | permerror | temperror | indeterminate
    """
    tags = _parse_tag_value_list(raw_sig_header)
    entry: dict[str, Any] = {
        'index': idx,
        'domain': tags.get('d'),
        'selector': tags.get('s'),
        'algorithm': tags.get('a'),
        'canonicalization': tags.get('c', 'simple/simple'),
        'signed_headers': (
            [h.strip() for h in tags['h'].split(':')] if tags.get('h') else []),
        'body_length_limit': None,
        'has_body_length_limit': False,
        'timestamp_signed': tags.get('t'),
        'timestamp_expiry': tags.get('x'),
        'public_key_retrieved': False,
        'result': 'indeterminate',
        'error': None,
        'method': 'dkimpy_DKIM.verify_cryptographic',
        'raw_bytes_used': True,
    }
    l_tag = tags.get('l')
    if l_tag is not None:
        try:
            entry['body_length_limit'] = int(l_tag)
            entry['has_body_length_limit'] = True
        except ValueError:
            pass
    if not entry['selector'] or not entry['domain']:
        entry['result'] = 'permerror'
        entry['error'] = 'DKIM signature missing required d= or s= tag'
        return entry

    effective_dnsfunc = dnsfunc if dnsfunc is not None else dkim.get_txt
    dns_name = f"{entry['selector']}._domainkey.{entry['domain']}."
    try:
        pk, keysize, ktag, _ = dkim.load_pk_from_dns(
            dns_name.encode('utf-8'), dnsfunc=effective_dnsfunc, timeout=DNS_TIMEOUT
        )
        entry['public_key_retrieved'] = True
    except dkim.DnsTimeoutError as exc:
        entry['result'] = 'temperror'
        entry['error'] = f"DNS timeout during key retrieval: {exc}"
        return entry
    except dkim.KeyFormatError as exc:
        entry['result'] = 'permerror'
        entry['error'] = f"DKIM public key error: {exc}"
        return entry
    except dns.exception.Timeout as exc:
        entry['result'] = 'temperror'
        entry['error'] = f"DNS timeout during key retrieval: {exc}"
        return entry
    except Exception as exc:
        el = str(exc).lower()
        entry['result'] = 'temperror' if 'timeout' in el else 'permerror'
        entry['error'] = f"Error retrieving DKIM public key: {exc}"
        return entry

    verify_kwargs: dict[str, Any] = {}
    if dnsfunc is not None:
        verify_kwargs['dnsfunc'] = dnsfunc
    try:
        d = dkim.DKIM(raw_bytes)
        verified = d.verify(idx=idx, **verify_kwargs)
        if verified:
            entry['result'] = 'pass'
        else:
            entry['result'] = 'fail'
            entry['error'] = (
                'Hash mismatch - body or signed headers may have been modified.')
    except dkim.ValidationError as exc:
        entry['result'] = 'fail'
        entry['error'] = f"DKIM validation error: {exc}"
    except Exception as exc:
        entry['result'] = 'fail'
        entry['error'] = f"DKIM verification error: {exc}"
    return entry


def _build_dkim_result(
    parsed_result: dict[str, Any], raw_bytes: bytes,
    *, dnsfunc: Callable | None = None,
) -> dict[str, Any]:
    """Build DKIM section by verifying every DKIM-Signature header.
    raw_bytes must be original .eml bytes - dkimpy hashes the exact sequence.
    overall_result: none | pass | fail | permerror | temperror
    """
    out: dict[str, Any] = {
        'overall_result': 'none',
        'overall_result_reason': 'No DKIM-Signature header present',
        'signatures': [],
        'verification_method': (
            'dkimpy cryptographic verification. Original email bytes used.'),
        'raw_bytes_used': True,
        'warnings': [],
        'errors': [],
    }
    sig_headers = _get_dkim_signature_headers(raw_bytes)
    if not sig_headers:
        return out
    any_pass = False
    for idx, hdr in enumerate(sig_headers):
        entry = _verify_one_dkim_signature(raw_bytes, idx, hdr, dnsfunc=dnsfunc)
        out['signatures'].append(entry)
        if entry['result'] == 'pass':
            any_pass = True
        if entry.get('has_body_length_limit'):
            out['warnings'].append(
                f"Sig {idx} d={entry['domain']!r}: l= tag present "
                f"(limit {entry['body_length_limit']} bytes). Content after "
                "the signed portion is unauthenticated.")
    if any_pass:
        out['overall_result'] = 'pass'
        out['overall_result_reason'] = (
            'At least one DKIM signature cryptographically verified.')
    else:
        sig_results = [s['result'] for s in out['signatures']]
        if all(r == 'permerror' for r in sig_results):
            out['overall_result'] = 'permerror'
            out['overall_result_reason'] = (
                'All signatures had permanent errors (key not found/malformed).')
        elif 'temperror' in sig_results and 'fail' not in sig_results:
            out['overall_result'] = 'temperror'
            out['overall_result_reason'] = (
                'DNS temporary error; no signatures succeeded.')
        else:
            out['overall_result'] = 'fail'
            out['overall_result_reason'] = (
                'All DKIM signatures failed cryptographic verification.')
    return out


def _parse_dmarc_record(raw_record: str) -> dict[str, Any]:
    """Parse DMARC TXT record. Returns tags dict or {'_error': ...}."""
    tags = _parse_tag_value_list(raw_record)
    if tags.get('v', '').upper() != 'DMARC1':
        return {'_error': "Record does not begin with v=DMARC1", '_raw': raw_record}
    p_val = tags.get('p', '').lower()
    if p_val not in _DMARC_POLICIES:
        return {'_error': f"Invalid p= tag: {p_val!r}. Must be none/quarantine/reject",
                '_raw': raw_record}
    sp_val = tags.get('sp', '').lower()
    if sp_val not in _DMARC_POLICIES:
        sp_val = p_val
    def _uri_list(tag: str) -> list[str]:
        r = tags.get(tag, '')
        return [u.strip() for u in r.split(',') if u.strip()] if r else []
    pct_raw = tags.get('pct', '100')
    try:
        pct = max(0, min(100, int(pct_raw)))
    except ValueError:
        pct = 100
    return {
        'v': tags.get('v', 'DMARC1'), 'p': p_val, 'sp': sp_val,
        'adkim': tags.get('adkim', 'r').lower(),
        'aspf': tags.get('aspf', 'r').lower(),
        'pct': pct, 'rua': _uri_list('rua'), 'ruf': _uri_list('ruf'),
        'fo': tags.get('fo', '0'),
    }


def _check_dkim_alignment(
    dkim_result: dict[str, Any], from_domain: str, adkim: str
) -> dict[str, Any]:
    """DKIM alignment: pass | fail | not_checked."""
    mode = 'relaxed' if adkim == 'r' else 'strict'
    aln: dict[str, Any] = {
        'result': 'not_checked', 'mode': mode,
        'dkim_d_domain': None, 'header_from_domain': from_domain,
        'org_domain_match': None, 'reason': None,
    }
    overall = dkim_result.get('overall_result', 'none')
    if overall == 'none':
        aln['reason'] = 'No DKIM-Signature header present'
        return aln
    if overall == 'temperror':
        aln['reason'] = 'DNS temperror; DKIM key retrieval failed'
        return aln
    for sig in dkim_result.get('signatures', []):
        if sig.get('result') != 'pass':
            continue
        d = sig.get('domain') or ''
        if _domains_align(d, from_domain, mode):
            aln['result'] = 'pass'
            aln['dkim_d_domain'] = d
            aln['org_domain_match'] = _org_domain(d) == _org_domain(from_domain)
            aln['reason'] = (
                f"DKIM domain {d!r} aligns with From {from_domain!r} ({mode})")
            return aln
    aln['result'] = 'fail'
    aln['reason'] = (
        'No passing DKIM signature has an aligned d= domain'
        if overall == 'pass'
        else 'All DKIM signatures failed; alignment cannot pass')
    return aln


def _check_spf_alignment(
    spf_result: dict[str, Any], from_domain: str, aspf: str
) -> dict[str, Any]:
    """SPF alignment: always not_checked for uploaded files."""
    env = spf_result.get('envelope_domain_evidence', {}).get('extracted_domain') or ''
    mode = 'relaxed' if aspf == 'r' else 'strict'
    structural = _domains_align(env, from_domain, mode) if env else None
    return {
        'result': 'not_checked', 'mode': mode,
        'envelope_domain': env or None, 'header_from_domain': from_domain,
        'structural_domains_match': structural,
        'reason': (
            'SPF alignment requires a confirmed SPF pass, which requires the '
            'connecting IP at delivery time. Cannot determine from uploaded file.'),
    }


def _build_dmarc_result(
    parsed_result: dict[str, Any],
    spf_result: dict[str, Any],
    dkim_result: dict[str, Any],
    *,
    dns_txt_func: Callable | None = None,
) -> dict[str, Any]:
    """Build DMARC section.
    Results: pass | indeterminate | none | temperror | permerror | not_checked
    fail is NEVER emitted - SPF unverifiable without connecting IP.
    """
    out: dict[str, Any] = {
        'result': 'not_checked',
        'result_reason': 'header-From domain could not be determined',
        'domain_checked': None,
        'domain_source': 'From header (header-from domain)',
        'dns_lookup': {
            'lookup_result': 'not_checked', 'dmarc_dns_name': None,
            'raw_record': None, 'error': None,
        },
        'policy': None,
        'alignment': {'dkim': None, 'spf': None},
        'warnings': [],
        'errors': [],
    }
    meta = parsed_result.get('email_metadata') or {}
    from_domain = _extract_domain_from_address(meta.get('from'))
    if not from_domain:
        out['warnings'].append('Cannot extract From domain; DMARC skipped.')
        return out
    out['domain_checked'] = from_domain

    query_fn = dns_txt_func or _query_txt_records
    dmarc_name = f"_dmarc.{from_domain}"
    out['dns_lookup']['dmarc_dns_name'] = dmarc_name
    all_txt, status, dns_err = query_fn(dmarc_name)

    if status == 'temperror':
        out['result'] = 'temperror'
        out['result_reason'] = f"DNS temperror: {dns_err}"
        out['dns_lookup']['lookup_result'] = 'temperror'
        out['dns_lookup']['error'] = dns_err
        out['errors'].append(dns_err or 'DNS temperror')
        return out

    dmarc_recs = [r for r in all_txt if r.upper().startswith('V=DMARC1')]
    if not dmarc_recs:
        # Fallback to organizational domain if from_domain is a subdomain (RFC 7489 Section 6.6.3)
        org_dom = _org_domain(from_domain)
        if org_dom and org_dom != from_domain:
            org_dmarc_name = f"_dmarc.{org_dom}"
            out['dns_lookup']['fallback_org_dmarc_dns_name'] = org_dmarc_name
            all_txt_org, status_org, dns_err_org = query_fn(org_dmarc_name)
            if status_org == 'temperror':
                out['result'] = 'temperror'
                out['result_reason'] = f"DNS temperror at org domain: {dns_err_org}"
                out['dns_lookup']['lookup_result'] = 'temperror'
                out['dns_lookup']['error'] = dns_err_org
                out['errors'].append(dns_err_org or 'DNS temperror')
                return out
            dmarc_recs = [r for r in all_txt_org if r.upper().startswith('V=DMARC1')]
            if dmarc_recs:
                out['dns_lookup']['dmarc_dns_name'] = org_dmarc_name
                out['dns_lookup']['record_from'] = 'organizational_domain'

    if not dmarc_recs:
        out['result'] = 'none'
        out['result_reason'] = f"No DMARC record found for {from_domain!r}"
        out['dns_lookup']['lookup_result'] = 'none'
        out['dns_lookup']['error'] = dns_err
        return out

    raw_rec = dmarc_recs[0]
    out['dns_lookup']['lookup_result'] = 'retrieved'
    out['dns_lookup']['raw_record'] = raw_rec

    policy = _parse_dmarc_record(raw_rec)
    if '_error' in policy:
        out['result'] = 'permerror'
        out['result_reason'] = f"Malformed DMARC record: {policy['_error']}"
        out['errors'].append(policy['_error'])
        return out

    out['policy'] = policy
    dkim_aln = _check_dkim_alignment(dkim_result, from_domain, policy.get('adkim', 'r'))
    out['alignment']['dkim'] = dkim_aln
    spf_aln = _check_spf_alignment(spf_result, from_domain, policy.get('aspf', 'r'))
    out['alignment']['spf'] = spf_aln

    if dkim_aln['result'] == 'pass':
        out['result'] = 'pass'
        out['result_reason'] = (
            f"DMARC pass via DKIM alignment ({dkim_aln['mode']}). "
            f"DKIM {dkim_aln['dkim_d_domain']!r} aligns with From {from_domain!r}.")
    else:
        out['result'] = 'indeterminate'
        out['result_reason'] = (
            'DMARC indeterminate: DKIM did not provide a passing aligned signature '
            'and SPF cannot be evaluated without a trusted connecting IP. '
            "DMARC fail requires confirmed failure of both - not possible here.")
    return out


def _derive_overall_result(
    spf: dict[str, Any], dkim: dict[str, Any], dmarc: dict[str, Any],
) -> tuple[str, str]:
    dr = dmarc.get('result', 'not_checked')
    dk = dkim.get('overall_result', 'not_checked')
    if dr == 'pass':
        return 'pass', 'DMARC pass via verified DKIM alignment'
    if dr == 'none':
        if dk == 'pass':
            return 'indeterminate', (
                'DKIM verified but no DMARC policy published; '
                'cannot determine policy disposition')
        return 'indeterminate', 'No DMARC policy; authentication status undetermined'
    if dr == 'temperror':
        return 'indeterminate', 'DNS temperror prevented DMARC evaluation'
    if dr == 'permerror':
        return 'indeterminate', 'Malformed DMARC record; cannot evaluate policy'
    if dr == 'indeterminate':
        return 'indeterminate', (
            'DMARC found; DKIM not passing/aligned; SPF unverifiable from file')
    return 'not_checked', 'Insufficient data to determine result'


def _build_summary(
    spf: dict[str, Any], dkim: dict[str, Any],
    dmarc: dict[str, Any], overall: str,
) -> str:
    parts: list[str] = []
    dr = dkim.get('overall_result', 'not_checked')
    sigs = dkim.get('signatures', [])
    if dr == 'pass':
        n = sum(1 for s in sigs if s['result'] == 'pass')
        dom = next((s['domain'] for s in sigs if s['result'] == 'pass'), 'unknown')
        parts.append(f"DKIM: {n}/{len(sigs)} sig(s) verified (domain: {dom!r}).")
    elif dr == 'fail':
        parts.append(f"DKIM: all {len(sigs)} sig(s) failed.")
    elif dr == 'none':
        parts.append('DKIM: no DKIM-Signature; email is unsigned.')
    else:
        parts.append(f"DKIM: error ({dr}).")
    dns_r = spf.get('dns_policy', {}).get('lookup_result', 'not_checked')
    mta_v = (spf.get('mta_reported') or {}).get('parsed_verdict')
    mta_note = f"MTA reported SPF {mta_v!r} (untrusted)." if mta_v else "No Received-SPF."
    parts.append(
        f"SPF: DNS lookup={dns_r!r}; independent eval not possible (no trusted IP). {mta_note}")
    dm_r = dmarc.get('result', 'not_checked')
    pol_p = (dmarc.get('policy') or {}).get('p')
    p_note = f", policy={pol_p!r}" if pol_p else ''
    parts.append(f"DMARC: result={dm_r!r}{p_note}. {dmarc.get('result_reason', '')}")
    parts.append(f"Overall: {overall}.")
    return '  '.join(parts)


def verify_authentication(
    parsed_result: dict[str, Any],
    raw_bytes: bytes,
    *,
    dkim_dnsfunc: Callable | None = None,
    dns_txt_func: Callable | None = None,
) -> dict[str, Any]:
    """Verify SPF, DKIM, and DMARC for an email. Module 2 public entry point.

    Parameters
    ----------
    parsed_result : dict  Output of Module 1 parse_email_file(). Never modified.
    raw_bytes : bytes     Original .eml bytes (open(...,'rb')). Must be unmodified.
    dkim_dnsfunc : callable | None   Custom DNS func for DKIM (dkimpy) tests.
    dns_txt_func : callable | None   Custom DNS TXT func for SPF and DMARC tests.

    Returns
    -------
    dict  Keys: observed_evidence, spf, dkim, dmarc, overall_result,
               overall_result_reason, summary, verified_at, verifier_version, warnings
    """
    if not isinstance(parsed_result, dict):
        return {'overall_result': 'not_checked',
                'overall_result_reason': 'parsed_result must be a dict',
                'errors': ['Invalid parsed_result type']}
    if not isinstance(raw_bytes, bytes) or len(raw_bytes) == 0:
        return {'overall_result': 'not_checked',
                'overall_result_reason': 'raw_bytes must be non-empty bytes',
                'errors': ['Invalid raw_bytes']}

    auth_hdrs = parsed_result.get('authentication_headers') or {}
    meta = parsed_result.get('email_metadata') or {}
    observed: dict[str, Any] = {
        'header_from': meta.get('from'),
        'header_from_domain': _extract_domain_from_address(meta.get('from')),
        'return_path': meta.get('return_path'),
        'return_path_domain': _extract_domain_from_address(meta.get('return_path')),
        'envelope_domain_trust': (
            'UNTRUSTED - Return-Path written by sender; '
            'not verified as SMTP MAIL FROM at delivery.'),
        'dkim_signature_headers_count': len(_get_dkim_signature_headers(raw_bytes)),
        'received_spf_header': auth_hdrs.get('received_spf'),
        'received_spf_trust': (
            'UNTRUSTED - Received-SPF written by original receiving MTA.'),
        'authentication_results_headers': auth_hdrs.get('authentication_results') or [],
        'authentication_results_trust': (
            'UNTRUSTED - Written by mail servers in delivery path.'),
    }

    spf_result = _build_spf_result(parsed_result, dns_txt_func=dns_txt_func)
    dkim_result = _build_dkim_result(parsed_result, raw_bytes, dnsfunc=dkim_dnsfunc)
    dmarc_result = _build_dmarc_result(
        parsed_result, spf_result, dkim_result, dns_txt_func=dns_txt_func)

    overall, overall_reason = _derive_overall_result(spf_result, dkim_result, dmarc_result)
    summary = _build_summary(spf_result, dkim_result, dmarc_result, overall)
    all_warnings: list[str] = (
        spf_result.get('warnings', [])
        + dkim_result.get('warnings', [])
        + dmarc_result.get('warnings', []))

    return {
        'observed_evidence': observed,
        'spf': spf_result,
        'dkim': dkim_result,
        'dmarc': dmarc_result,
        'overall_result': overall,
        'overall_result_reason': overall_reason,
        'summary': summary,
        'verified_at': datetime.now(timezone.utc).isoformat(),
        'verifier_version': VERIFIER_VERSION,
        'warnings': all_warnings,
    }
