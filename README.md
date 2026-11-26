# Merchant Verification File (MVF)

[![Fidem MCP connector](https://glama.ai/mcp/connectors/com.fidemcheck/fidem/badges/score.svg)](https://glama.ai/mcp/connectors/com.fidemcheck/fidem)

An open format that lets an online shop prove, in a way any AI agent can check, which company runs it and that the company really controls the domain.

AI agents now browse and buy on people's behalf. Before paying, an agent cannot tell a real shop from a clone by reading the website, because anyone can copy a legal notice. MVF fixes that with a small signed file the shop publishes at:

```
https://{shop-domain}/.well-known/merchant-verification.json
```

An independent verifier signs it (Ed25519) after checking that the shop controls the domain, that its company matches an official register and, for companies, that the person asking represents the company. Any agent can verify the signature without calling the verifier, using the keys of the verifiers it chooses to trust. A valid signature from an issuer you do not trust proves nothing, so the checker takes the issuer keys from your trust policy, never from the file. Revoked verifications are listed in each issuer's signed revocation list (`/.well-known/mvf-revocations.json`).

- **Specification:** [SPEC.md](SPEC.md) (version 0.1, draft)
- **Reference checker:** [verify_mvf.py](verify_mvf.py)
- **Live example:** `python verify_mvf.py tienda-demo.fidemcheck.com`
- **First verifier:** [Fidem](https://fidemcheck.com), which also offers a free lookup for any shop through a remote MCP server (`https://fidemcheck.com/mcp`) and an [OpenAPI-described API](https://fidemcheck.com/openapi.json)

## Check a shop in one line

```
pip install cryptography
python verify_mvf.py shop.example
```

Output is either `VERIFIED: shop.example is run by ...` or `NOT VERIFIED: <reason>`. A shop that is not verified is not a fraudulent shop. It only means it has not proved it.

The checker trusts Fidem by default (`TRUSTED_ISSUERS` at the top of the file). To add another issuer, or for payments where an unavailable revocation list must count as not verified:

```
python verify_mvf.py shop.example --trust https://issuer.example=https://issuer.example/.well-known/mvf-keys.json
python verify_mvf.py shop.example --strict-revocation
```

## What a file looks like

See [examples/tienda-demo.fidemcheck.com.json](examples/tienda-demo.fidemcheck.com.json), a real file signed on 26 November 2026, and the issuer key set in [examples/fidem-keys.json](examples/fidem-keys.json). Files expire after 30 days and are renewed by the verifier, so the example will show as expired after its date; run the checker against the live domain instead.

## Design choices

- **Facts, not scores.** MVF says who runs the shop and how that was checked. It says nothing about products, deliveries or service.
- **Short validity.** At most 45 days, so a stale statement cannot live long.
- **Delegated hosting.** A shop may redirect the well-known path to its file at the verifier, so the verifier can renew it without the shop redeploying anything.
- **No personal data.** Sole traders are out of scope for v0.1.

## Contributing

Open an issue to discuss changes. Questions for v0.2 are listed at the end of the specification: a shared registry of verifiers, alignment with agentic commerce protocols, and more national registers.

## License

The specification is licensed under [Creative Commons Attribution 4.0](https://creativecommons.org/licenses/by/4.0/). The reference checker is released under the MIT License.

---

**En español:** MVF es un archivo pequeño que una tienda online publica en su web, firmado por un verificador independiente. Dice qué empresa ha demostrado ser la dueña del dominio y con qué registro oficial se ha comprobado. Cualquier agente de IA puede comprobar la firma antes de pagar. Más información en [fidemcheck.com](https://fidemcheck.com).
