#!/usr/bin/env python3
"""Reference checker for Merchant Verification Files (MVF 0.1).

Usage:
    pip install cryptography
    python verify_mvf.py shop.example
    python verify_mvf.py shop.example --trust https://issuer.example=https://issuer.example/.well-known/mvf-keys.json
    python verify_mvf.py shop.example --strict-revocation

It follows SPEC.md section 6 without relying on any verifier's API. A file only counts as VERIFIED when all of this holds:
  1. It sits at /.well-known/merchant-verification.json (at most one redirect, and only to the issuer's host).
  2. Its issuer is in YOUR trust policy (TRUSTED_ISSUERS or --trust). The issuer's keys are fetched from the URL in the trust
     policy, never from the URL inside the file: a file that names its own keys proves nothing about who stands behind it.
  3. The Ed25519 signature over the RFC 8785 (JCS) canonical form is valid with one of those keys.
  4. It is for this domain, has not expired, and is not a demo (`demo.fictitious`).
  5. A company file issued from 2027-01-01 carries proofs.representation (before that date it is reported as a warning).
  6. The domain is not in the issuer's signed revocation list (/.well-known/mvf-revocations.json). If the list cannot be
     fetched or checked, the result says so; with --strict-revocation that counts as NOT VERIFIED.
A shop that fails any step is unverified, not fraudulent. A valid signature alone is not an accredited identity.
"""
import base64
import datetime as dt
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# Issuers you trust, and where THEIR keys live. Edit it or pass --trust. Fidem is listed because this file comes with its spec.
TRUSTED_ISSUERS = {'https://fidemcheck.com': 'https://fidemcheck.com/.well-known/mvf-keys.json'}
REPRESENTATION_REQUIRED_FROM = '2027-01-01'
MAX_BYTES = 256 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def get(url, follow=False):
    opener = urllib.request.build_opener() if follow else urllib.request.build_opener(NoRedirect)
    req = urllib.request.Request(url, headers={'User-Agent': 'mvf-reference-checker/0.2', 'Accept': 'application/json'})
    try:
        r = opener.open(req, timeout=15)
        return r.status, dict(r.headers), r.read(MAX_BYTES + 1)[:MAX_BYTES]
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read(MAX_BYTES)


def b64u(s):
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


# ---------------------------------------------------------------- RFC 8785 (JSON Canonicalization Scheme)
def _number(x):
    if isinstance(x, bool):
        return 'true' if x else 'false'
    if isinstance(x, int):
        if abs(x) > 2 ** 53:
            raise ValueError('integer outside the exact IEEE 754 range')
        return str(x)
    if x != x or x in (float('inf'), float('-inf')):
        raise ValueError('NaN and Infinity are not JSON')
    if x == 0:
        return '0'
    from decimal import Decimal
    t = Decimal(repr(x)).as_tuple()
    digits = ''.join(map(str, t.digits)).rstrip('0') or '0'
    k = len(digits)
    n = t.exponent + len(t.digits) - len(digits) + k
    if k <= n <= 21:
        s = digits + '0' * (n - k)
    elif 0 < n <= 21:
        s = digits[:n] + '.' + digits[n:]
    elif -6 < n <= 0:
        s = '0.' + '0' * (-n) + digits
    else:
        e = n - 1
        s = digits[0] + ('.' + digits[1:] if k > 1 else '') + 'e' + ('+' if e > 0 else '-') + str(abs(e))
    return ('-' if t.sign else '') + s


def _jcs(v):
    if v is None:
        return 'null'
    if isinstance(v, (bool, int, float)):
        return _number(v)
    if isinstance(v, str):
        if any(0xD800 <= ord(c) <= 0xDFFF for c in v):
            raise ValueError('lone surrogate')
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return '[' + ','.join(_jcs(x) for x in v) + ']'
    if isinstance(v, dict):
        return '{' + ','.join(json.dumps(k, ensure_ascii=False) + ':' + _jcs(v[k]) for k in sorted(v, key=lambda k: k.encode('utf-16-be'))) + '}'
    raise TypeError(type(v).__name__)


def canonical(doc):
    return _jcs({k: v for k, v in doc.items() if k != 'signature'}).encode('utf-8')


def signature_ok(doc, keys):
    sig = doc.get('signature') or {}
    if sig.get('alg') != 'Ed25519':
        return False, 'unsupported signature algorithm'
    key = next((k for k in keys if k.get('kid') == sig.get('kid')), None)
    if not key:
        return False, 'signed with a key the issuer does not publish'
    try:
        Ed25519PublicKey.from_public_bytes(b64u(key['x'])).verify(b64u(sig['value']), canonical(doc))
        return True, ''
    except Exception:
        return False, 'invalid signature'


def revocation(issuer, keys, domain, now):
    """('revoked'|'not_revoked'|'unknown', detail) from the issuer's signed revocation list."""
    status, _, body = get(issuer.rstrip('/') + '/.well-known/mvf-revocations.json', follow=True)
    if status != 200:
        return 'unknown', f'revocation list not available (HTTP {status})'
    try:
        lst = json.loads(body)
    except ValueError:
        return 'unknown', 'revocation list is not JSON'
    ok, why = signature_ok(lst, keys)
    if not ok or lst.get('issuer', '').rstrip('/') != issuer.rstrip('/'):
        return 'unknown', f'revocation list not trustworthy ({why or "wrong issuer"})'
    if lst.get('next_update', '') < now:
        return 'unknown', f'revocation list is stale (next_update {lst.get("next_update")})'
    hit = next((r for r in lst.get('revoked', []) if r.get('domain') == domain), None)
    return ('revoked', f'revoked on {hit.get("revoked_at")}') if hit else ('not_revoked', '')


def check(domain, trusted=None, strict_revocation=False):
    trusted = {k.rstrip('/'): v for k, v in (trusted or TRUSTED_ISSUERS).items()}
    domain = domain.lower().strip().removeprefix('https://').removeprefix('http://').split('/')[0].removeprefix('www.')
    status, headers, body = get(f'https://{domain}/.well-known/merchant-verification.json')
    redirected_to = None
    if status in (301, 302, 307, 308):
        redirected_to = urllib.parse.urlparse(urllib.parse.urljoin(f'https://{domain}/', headers.get('Location', '')))
        if redirected_to.scheme != 'https' or redirected_to.netloc in (domain, 'www.' + domain):
            return False, 'no MVF file (the path redirects elsewhere on the site)'
        status, headers, body = get(redirected_to.geturl())
    if status != 200:
        return False, f'no MVF file (HTTP {status})'
    try:
        doc = json.loads(body)
    except ValueError:
        return False, 'the MVF file is not valid JSON'
    issuer_id = ((doc.get('issuer') or {}).get('id') or '').rstrip('/')
    if issuer_id not in trusted:
        return False, f'issuer {issuer_id or "(none)"} is not in your trust policy; a valid signature from it would prove nothing'
    if redirected_to and redirected_to.netloc != urllib.parse.urlparse(issuer_id).netloc:
        return False, 'the redirect does not point to the issuer'
    if doc.get('domain') != domain:
        return False, f'file is for {doc.get("domain")}, not {domain}'
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
    if doc.get('expires_at', '') < now:
        return False, f'expired on {doc.get("expires_at")}'
    _, _, kbody = get(trusted[issuer_id], follow=True)   # keys from YOUR policy, never from the file
    try:
        keys = json.loads(kbody).get('keys', [])
    except ValueError:
        return False, 'could not read the issuer keys'
    ok, why = signature_ok(doc, keys)
    if not ok:
        return False, why
    if (doc.get('demo') or {}).get('fictitious'):
        return False, 'this is a fictitious demo file: never use it to pay'
    le = doc.get('legal_entity') or {}
    warnings = []
    if le.get('kind') == 'company' and not (doc.get('proofs') or {}).get('representation'):
        if doc.get('issued_at', '') >= REPRESENTATION_REQUIRED_FROM:
            return False, 'company file without proof of representation'
        warnings.append(f'no proof of representation (allowed for files issued before {REPRESENTATION_REQUIRED_FROM})')
    rev, detail = revocation(issuer_id, keys, domain, now)
    if rev == 'revoked':
        return False, detail
    if rev == 'unknown':
        if strict_revocation:
            return False, detail
        warnings.append(detail)
    ident = le.get('identifier', {})
    host = ' (file hosted by the verifier through a redirect)' if redirected_to else ''
    extra = (' WARNING: ' + '; '.join(warnings)) if warnings else ''
    if le.get('kind') == 'sole_trader':
        return True, (f'{domain} is run by a sole trader trading as "{le.get("trade_name")}" (identity held by {doc["issuer"]["name"]}, '
                      f'checked against: {le.get("register")}), verified until {doc["expires_at"][:10]}{host}.{extra}')
    return True, (f'{domain} is run by the company {le.get("name")} ({ident.get("scheme")} {ident.get("value")}, {le.get("register")}), '
                  f'verified by {doc["issuer"]["name"]} until {doc["expires_at"][:10]}{host}.{extra}')


if __name__ == '__main__':
    args = sys.argv[1:]
    strict = '--strict-revocation' in args
    trusted = dict(TRUSTED_ISSUERS)
    while '--trust' in args:
        i = args.index('--trust')
        iss, _, keys_url = args[i + 1].partition('=')
        trusted[iss.rstrip('/')] = keys_url
        del args[i:i + 2]
    args = [a for a in args if a != '--strict-revocation']
    if len(args) != 1:
        sys.exit(__doc__)
    ok, message = check(args[0], trusted, strict)
    print(('VERIFIED: ' if ok else 'NOT VERIFIED: ') + message)
    sys.exit(0 if ok else 1)
