#!/usr/bin/env python3
"""Reference checker for Merchant Verification Files (MVF 0.1).

Usage:
    pip install cryptography
    python verify_mvf.py shop.example

It follows SPEC.md section 6 without relying on any verifier's API:
fetch /.well-known/merchant-verification.json (at most one redirect, only to the issuer's host),
check the domain and the expiry date, fetch the issuer's public keys and verify the Ed25519 signature.
A shop that fails any step is unverified, not fraudulent.
"""
import base64
import datetime as dt
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def get(url, follow=False):
    opener = urllib.request.build_opener() if follow else urllib.request.build_opener(NoRedirect)
    req = urllib.request.Request(url, headers={'User-Agent': 'mvf-reference-checker/0.1', 'Accept': 'application/json'})
    try:
        r = opener.open(req, timeout=15)
        return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def b64u(s):
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


def canonical(doc):
    body = {k: v for k, v in doc.items() if k != 'signature'}
    return json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')


def check(domain):
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
    doc = json.loads(body)
    issuer = urllib.parse.urlparse((doc.get('issuer') or {}).get('id', ''))
    if redirected_to and redirected_to.netloc != issuer.netloc:
        return False, 'the redirect does not point to the issuer'
    if doc.get('domain') != domain:
        return False, f'file is for {doc.get("domain")}, not {domain}'
    now = dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00', 'Z')
    if doc.get('expires_at', '') < now:
        return False, f'expired on {doc.get("expires_at")}'
    sig = doc.get('signature') or {}
    if sig.get('alg') != 'Ed25519':
        return False, 'unsupported signature algorithm'
    _, _, kbody = get(doc['issuer']['keys'], follow=True)
    key = next((k for k in json.loads(kbody).get('keys', []) if k.get('kid') == sig.get('kid')), None)
    if not key:
        return False, 'unknown issuer key'
    try:
        Ed25519PublicKey.from_public_bytes(b64u(key['x'])).verify(b64u(sig['value']), canonical(doc))
    except Exception:
        return False, 'invalid signature'
    le = doc['legal_entity']
    ident = le.get('identifier', {})
    if le.get('kind') == 'sole_trader':
        return True, (f'{domain} is run by a sole trader trading as "{le.get("trade_name")}" (identity held by {doc["issuer"]["name"]}, '
                      f'checked against: {le.get("register")}), verified until {doc["expires_at"][:10]}'
                      + (' (file hosted by the verifier through a redirect)' if redirected_to else ''))
    return True, (f'{domain} is run by the company {le["name"]} ({ident.get("scheme")} {ident.get("value")}, {le.get("register")}), '
                  f'verified by {doc["issuer"]["name"]} until {doc["expires_at"][:10]}'
                  + (' (file hosted by the verifier through a redirect)' if redirected_to else ''))


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit('usage: python verify_mvf.py <domain>')
    ok, message = check(sys.argv[1])
    print(('VERIFIED: ' if ok else 'NOT VERIFIED: ') + message)
    sys.exit(0 if ok else 1)
