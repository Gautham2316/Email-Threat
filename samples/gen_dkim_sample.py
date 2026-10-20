from __future__ import annotations
import base64, pathlib, textwrap
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import dkim

SELECTOR = b'test2026'
DOMAIN   = b'example.com'
SAMPLE_PATH = pathlib.Path(__file__).with_name('dkim_signed.eml')

key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
private_pem = key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption())
pub_der = key.public_key().public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)
pub_b64 = base64.b64encode(pub_der).decode()
dns_txt_value = f'v=DKIM1; k=rsa; p={pub_b64}'

raw_email_no_sig = textwrap.dedent("""\
    From: Alice <alice@example.com>
    To: Bob <bob@example.com>
    Subject: DKIM signed test email (SIH 2026)
    Date: Mon, 20 Oct 2026 09:00:00 +0000
    Message-ID: <sih2026.dkim.test@example.com>
    MIME-Version: 1.0
    Content-Type: text/plain; charset=utf-8

    This is a DKIM-signed test email generated for SIH 2026 Module 2 tests.
    The signature is computed with a locally generated RSA-2048 key.
    DNS TXT records are mocked in the test suite - no network access required.
""").encode('utf-8')

d = dkim.DKIM(raw_email_no_sig)
signed_bytes = d.sign(
    selector=SELECTOR, domain=DOMAIN, privkey=private_pem,
    include_headers=[b'from', b'to', b'subject', b'date', b'message-id'],
    canonicalize=(b'relaxed', b'relaxed'))
full_signed = signed_bytes + raw_email_no_sig
SAMPLE_PATH.write_bytes(full_signed)
print(f'WROTE {len(full_signed)} bytes')
print(f'DNS_TXT={dns_txt_value[:80]}...')
print(f'SELECTOR={SELECTOR.decode()} DOMAIN={DOMAIN.decode()}')
print(f'DNS_NAME={SELECTOR.decode()}._domainkey.{DOMAIN.decode()}')
# Write the DNS value to a sidecar file so tests can load it without regenerating
pathlib.Path('samples/dkim_dns_mock.txt').write_text(dns_txt_value, encoding='utf-8')
print('DNS_MOCK_WRITTEN: samples/dkim_dns_mock.txt')
