# Merchant Verification File (MVF)

**Version 0.1, draft, 23 November 2026. Proposed by Fidem. Open specification: anyone may implement it or issue verifications under it. Licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).**

> Resumen en español: es un archivo pequeño que una tienda online publica en su propia web, en `/.well-known/merchant-verification.json`. Lo firma un verificador independiente (el primero es Fidem) y dice qué empresa ha demostrado ser la dueña de ese dominio, con qué registro oficial se ha comprobado y hasta cuándo vale. Cualquier agente de IA que visite la tienda puede leerlo y comprobar la firma sin conocer al verificador de antes.

## 1. Problem

AI agents increasingly browse the open web and buy on behalf of people. When an agent lands on an unfamiliar online shop it has no reliable, machine-readable way to answer one question: **is the company behind this domain real, and does it actually control this domain?** Copying a real company's legal notice onto a clone shop is trivial, so text on the page alone proves nothing.

MVF lets a shop publish a signed statement, issued by an independent verifier, that binds **a domain** to **a legal entity confirmed in an official register**.

## 2. Scope

MVF states facts, not opinions. It says nothing about product quality, delivery or customer service. It never contains a score.

## 3. Location and discovery

A merchant publishes the file at:

```
https://{merchant-domain}/.well-known/merchant-verification.json
```

served with `Content-Type: application/json` over HTTPS. The merchant **should** also add to every page:

```html
<link rel="merchant-verification" href="/.well-known/merchant-verification.json">
```

An agent **should** look for the file before paying on an unfamiliar domain. A missing file is not a negative signal by itself.

**Delegated hosting.** Instead of hosting the file, the merchant **may** answer that path with an HTTP redirect (301, 302, 307 or 308) to the copy the verifier keeps for its domain, for example `https://fidemcheck.com/v/{merchant-domain}/merchant-verification.json`. The verifier can then renew the file before it expires without the merchant redeploying anything. Keeping the redirect in place is itself proof that the merchant still controls the domain. Agents **must** follow at most one redirect, and only to the host named in `issuer.id`.

## 4. File format

```json
{
  "mvf": "0.1",
  "domain": "shop.example",
  "issuer": {
    "name": "Fidem",
    "id": "https://fidemcheck.com",
    "keys": "https://fidemcheck.com/.well-known/mvf-keys.json"
  },
  "legal_entity": {
    "name": "Example Shop Ltd",
    "country": "GB",
    "identifier": { "scheme": "GB-COH", "value": "00000000" },
    "register": "Companies House",
    "register_url": "https://find-and-update.company-information.service.gov.uk/company/00000000",
    "status": "active"
  },
  "proofs": {
    "domain_control": { "method": "dns-txt", "checked_at": "2026-11-23T10:00:00Z" },
    "register_match": { "checked_at": "2026-11-23T10:00:00Z", "result": "match" }
  },
  "declared_by_merchant": {
    "contact": "help@shop.example",
    "ships_to": ["GB", "IE"],
    "return_window_days": 30
  },
  "verification_url": "https://fidemcheck.com/v/shop.example",
  "issued_at": "2026-11-23T10:00:00Z",
  "expires_at": "2026-12-23T10:00:00Z",
  "signature": {
    "alg": "Ed25519",
    "kid": "fidem-2026-12",
    "value": "base64url signature"
  }
}
```

### Fields

| Field | Required | Meaning |
|---|---|---|
| `mvf` | yes | Spec version. |
| `domain` | yes | The exact host the statement covers. Agents **must** reject the file if it does not match the host it was fetched from (subdomain rules in section 6). |
| `issuer.id` | yes | Canonical URL of the verifier. |
| `issuer.keys` | yes | URL of the verifier's public key set (section 5). |
| `legal_entity` | yes | Who runs the shop. `kind` is `company` or `sole_trader` (see below). For a company: `name`, `country`, `identifier` (`scheme` uses short codes: `ES-CIF`, `EU-VAT`, `GB-COH`, `US-{STATE}-SOS`, `LEI`), `register`, `status`. |
| `proofs.domain_control` | yes | How the merchant proved control of the domain: `dns-txt` or `http-file`. |
| `proofs.register_match` | yes | Result of checking the entity in the register: `match`, `registered-name-unverified`. |
| `proofs.representation` | yes for `kind: company` | How the requester proved they represent the company, not only that the company exists: `representative-certificate` (a document signed with the company's qualified representative certificate or eIDAS seal, whose identifier matches the entity) or `payee-verified-transfer` (a code sent by bank transfer to an account in the company's name, with the payee name confirmed by the bank). Without it, a fraudster could control their own domain and copy a real company's identifier. |
| `declared_by_merchant` | no | Facts the merchant states itself. The verifier does not vouch for them. Agents must treat them as claims. |
| `verification_url` | yes | Live page and JSON endpoint where the verifier confirms the statement is still valid. |
| `issued_at`, `expires_at` | yes | ISO 8601 UTC. Validity **must not** exceed 45 days, so a lapsed or revoked merchant drops out quickly. |
| `signature` | yes | Section 5. |

**Sole traders.** If the shop is run by a natural person, `legal_entity.kind` is `sole_trader`. The file carries only `trade_name` (the name the shop already uses publicly), `country`, `register` (the official evidence the verifier checked, for example a Spanish tax census certificate verified through its secure verification code), `register_checked_on` and `identity: "held by the verifier, not published"`. The person's name and tax ID are never published, not even hashed: national ID spaces are small enough to reverse any hash. The verifier keeps the identity privately and discloses it only when legally required. Agents **must** present sole traders and companies differently: a verified sole trader proves that a registered business person controls the domain, but the agent cannot see who.

## 5. Signature

1. Remove the `signature` member.
2. Serialise the rest with the JSON Canonicalization Scheme, RFC 8785 (JCS): UTF-8, keys sorted by UTF-16 code units at every level, no insignificant whitespace, ECMAScript number formatting. MVF files only use strings, integers, booleans and null, so any JCS library gives the same bytes. The reference checker includes a JCS implementation.
3. Sign the bytes with Ed25519. Put the base64url signature, without padding, in `signature.value`, with the key id in `signature.kid`.

The verifier publishes its public keys at `issuer.keys`:

```json
{ "keys": [ { "kid": "fidem-2026-12", "alg": "Ed25519", "x": "base64url public key", "not_after": "2027-11-23" } ] }
```

## 6. How an agent checks a file

A valid signature is not, by itself, an accredited identity: anyone can sign a file with their own key. Agents **must** keep their own **trust policy**, a list of issuers they accept and, for each one, the URL of its keys. The keys are fetched from that policy, never from `issuer.keys` in the file being checked.

1. Fetch `/.well-known/merchant-verification.json` from the shop's host over HTTPS. If the answer is a redirect, follow it once and only if it points to the host in the file's `issuer.id` (delegated hosting, section 3).
2. Check that `issuer.id` is in your trust policy. If it is not, the shop is unverified.
3. Check that `domain` equals the host, or is its registrable parent when the host is `www.` of it.
4. Check that `expires_at` has not passed.
5. Fetch the issuer's keys from your trust policy (agents may cache them for 24 hours). Find `kid` and verify the signature.
6. If the file has `demo.fictitious: true`, it is an issuer's example: it **must never** count as verified for a payment.
7. A file with `legal_entity.kind` `company` issued on or after 2027-01-01 **must** carry `proofs.representation`. Earlier files may lack it during the transition, and checkers should report that as a warning.
8. Check the issuer's signed revocation list (section 7). For payments, an unavailable or stale list should count as "not verified".
9. Decide using the facts. MVF says who the company is and that it controls the domain. It does not say whether to buy.

`verify_mvf.py` in this repository implements these steps. Fidem's API and MCP tool apply the same decision and return it in the field `decision` (`verified` is the only value that means an accredited identity).

If any step fails, the agent **must** treat the shop as unverified, not as fraudulent.

## 7. Revocation

A revoked shop that hosts its own file keeps a valid signature until the file expires. To close that gap for agents that check without calling the verifier's API, the issuer **must** publish a signed revocation list at `/.well-known/mvf-revocations.json` on its `issuer.id` host:

```json
{ "mvf_revocations": "0.1", "issuer": "https://fidemcheck.com", "issued_at": "2026-11-25T14:00:00Z",
  "next_update": "2026-12-03T14:00:00Z", "revoked": [ { "domain": "shop.example", "revoked_at": "2026-11-20T10:00:00Z" } ],
  "signature": { "alg": "Ed25519", "kid": "fidem-2026-12", "value": "base64url" } }
```

It is signed like a file (section 5), with the issuer's keys. It is valid until `next_update`, at most 8 days after `issued_at`: the issuer signs it again at every revocation and at least weekly. A domain in the list is revoked whatever its file says. The reason is not published.

The verifier also marks revoked statements at `verification_url`, which returns `{"status":"revoked"}`. The short validity of files (45 days at most) limits the damage further.

## 8. Without a file: public lookup

Verifiers **should** offer a free lookup for any domain, based only on public sources (registry, domain age, certificates), clearly labelled as *not merchant-verified*. Fidem's lookup is the `check_shop` tool on its MCP server and `GET /api/v1/shop?domain=` on its API, with English field names. The original names, `consultar_tienda` and `GET /api/v1/tienda?dominio=`, keep working with Spanish field names. This lets agents get value from day one, before many merchants publish files.

## 9. Compatibility with the IETF MIA draft

Since 25 November 2026, Fidem also issues every company verification in the format of the IETF draft *Merchant Identity Assertions* (draft-anders-merchant-identity-assertions-01), with the same data and dates as the MVF file. MIA is not an alternative to MVF: it is the same signed fact in the format the draft defines, so agents that only read MIA find it too.

- **Where.** `https://{domain}/.well-known/merchant-identity.json`, served by the shop itself. MIA does not allow redirects, so the WordPress and PrestaShop plugins keep a copy and serve it directly. The same assertion is always available at `https://fidemcheck.com/v/{domain}/merchant-identity.json` (add `?subject=www.{domain}` for the www host: the `subject` must match the exact host).
- **Keys.** The same Ed25519 keys as `mvf-keys.json`, published as a JWKS at `https://fidemcheck.com/.well-known/jwks.json`.
- **Third-party issuer.** Fidem is a third-party issuer. The shop authorizes it with a Merchant Identity Delegation Document at `/.well-known/mia-delegation.json`, signed with a key that the plugin creates on the shop's own site (`/.well-known/mia-keys.json`), or with a DNS record `_mia-auth.{domain}` with the value `v=mia1; issuer=fidemcheck.com`.
- **Revocation.** `revocationUri` points to `https://fidemcheck.com/v/{domain}/revocation.json`.
- **Sole traders.** MIA would publish the person's name as `legalName`, so Fidem only issues MIA for companies. Sole traders keep their MVF file, which never publishes their name.

## 10. Open questions for v0.2

- A shared registry of verifiers (who may issue MVF).
- How to align with Visa Trusted Agent Protocol, Web Bot Auth and the agentic commerce protocols (ACP, AP2, UCP).
- More national registers (US states, Latin America).
