# Trust Layer Integration Guide

Complete guide for integrating ArkForge Trust Layer with the EU AI Act MCP.

## What Trust Layer Does

ArkForge Trust Layer is a certifying proxy that creates a **tamper-proof, immutable audit trail** for any digital artifact — including compliance reports, evidence packages, and test results.

For EU AI Act compliance, Trust Layer directly addresses **Article 12** (Record-Keeping), which requires that high-risk AI systems automatically log events "with a level of detail sufficient to enable the identification and assessment of compliance with this Regulation."

When you certify a compliance report through Trust Layer:
1. The report content is hashed (SHA-256)
2. The hash, a timestamp, and your API key identity are submitted to the Trust Layer ledger
3. A `proof_id` and `verification_url` are returned
4. The proof is **immutable** — it cannot be modified or deleted, not even by ArkForge

An auditor visiting the `verification_url` can independently verify that your compliance report existed, in its exact form, at the certified timestamp — without contacting you or trusting your internal systems.

## Getting an API Key

1. Go to [arkforge.tech/en/pricing.html](https://arkforge.tech/en/pricing.html)
2. Choose the **Free** plan (500 proofs/month included) or a paid plan for higher volume
3. Register with your email — your API key is generated immediately
4. Save the key securely; it starts with `ak_` followed by 40 hex characters

The API key is passed as the `trust_layer_key` parameter in the MCP tools, or as the `X-Api-Key` header when calling the REST API directly.

## How `certify_compliance_report` Works

```
certify_compliance_report(report_data, trust_layer_key)
```

Step-by-step:

1. **Input validation**: The tool checks that `trust_layer_key` is non-empty. If missing, it returns `status: "missing_key"` immediately (no network call).
2. **JSON parsing**: `report_data` is parsed as JSON. If it is not valid JSON, it is wrapped as `{"report": "<raw string>"}` — no crash, no data loss.
3. **Trust Layer call**: The tool sends a POST to `https://trust.arkforge.tech/v1/proxy` with your API key in the `X-Api-Key` header and the report data in the request body.
4. **Proof returned**: On success, Trust Layer returns `proof_id`, `verification_url`, and `timestamp`.
5. **Message added**: The tool appends a human-readable `message` field: `"Compliance report certified. Proof ID: X. Share Y with your auditor as Art. 12 evidence."`
6. **Banner added**: The standard Free/Pro upgrade banner is appended to the response.

### Error States

| Status | Cause |
|--------|-------|
| `missing_key` | `trust_layer_key` was empty or whitespace |
| `auth_error` | The API key was rejected (HTTP 401) |
| `network_error` | Trust Layer was unreachable |
| `error` | Any other failure |

## How `generate_annex4_package(sign_with_trust_layer=True)` Works

When `sign_with_trust_layer=True`:

1. The tool first generates the full 8-section ZIP package (all Annex IV sections + `manifest.json`)
2. The ZIP binary is hashed with SHA-256
3. The hash + manifest + compliance score are passed to `_certify_with_trust_layer()`
4. If certification succeeds:
   - `proof_id` and `verification_url` are embedded in `manifest.json` inside the ZIP
   - `result["status"]` changes from `"generated"` to `"generated_and_certified"`
   - A `certification` object is added to the response with full proof metadata

This means the ZIP's `manifest.json` carries a self-certifying reference: anyone with the ZIP can go to the `verification_url` and verify the package's authenticity.

## Example Proof Output

```json
{
  "proof_id": "prf_a3f9c2b1e4d67890abcdef1234567890",
  "verification_url": "https://trust.arkforge.tech/verify/prf_a3f9c2b1e4d67890abcdef1234567890",
  "timestamp": "2026-04-07T12:34:56.789012+00:00",
  "status": "certified",
  "message": "Compliance report certified. Proof ID: prf_a3f9c2b1e4d67890abcdef1234567890. Share https://trust.arkforge.tech/verify/prf_a3f9c2b1e4d67890abcdef1234567890 with your auditor as Art. 12 evidence."
}
```

## What the Auditor Sees at the Verification URL

Visiting `https://trust.arkforge.tech/verify/{proof_id}` shows:

- **Proof ID**: The unique identifier
- **Certified at**: The exact ISO timestamp of certification (immutable)
- **Content hash**: The SHA-256 of the certified artifact
- **Certifier**: The API key identity (anonymized to domain/email level)
- **Verification status**: "Valid" or "Invalid" — the auditor can confirm the hash matches the document they received

The auditor does not need an account, an API key, or any special software. The page is public and accessible indefinitely.

## Why This Matters for EU AI Act Article 12

Article 12 requires that high-risk AI systems have **automatic logging** sufficient to reconstruct the sequence of events leading to any output. For compliance documentation (which is not dynamic at runtime), Trust Layer provides the equivalent assurance:

- **Timestamped**: The exact moment the compliance assessment was performed is recorded immutably
- **Tamper-evident**: Any post-hoc modification of the report would invalidate the proof
- **Verifiable by third parties**: Market surveillance authorities can verify compliance documentation without relying on the provider's internal systems

This is especially relevant for providers seeking CE marking or preparing for conformity assessment procedures under Art. 43.
