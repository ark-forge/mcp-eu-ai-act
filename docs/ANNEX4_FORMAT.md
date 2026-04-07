# Annex IV Evidence Package Format

Specification of the ZIP archive produced by `generate_annex4_package`.

## What Is Annex IV?

Annex IV is the official EU AI Act requirement for the content of technical documentation. It is referenced by Article 11 of Regulation (EU) 2024/1689 and defines the 8 mandatory sections that must be present in the technical documentation of every high-risk AI system before it is placed on the market or put into service.

The `generate_annex4_package` tool creates a ready-to-submit ZIP archive structured according to Annex IV, populated from your project's actual compliance documents and scan results.

## The 8 Mandatory Sections

| Section | Key Name in ZIP | Article Reference | Required Content |
|---------|----------------|-------------------|-----------------|
| 1 | `1_general_description.md` | Annex IV §1 / Art. 11 | General description of the AI system: intended purpose, provider identity, version, trade name, and where it is placed on the market |
| 2 | `2_development_elements.md` | Annex IV §2 | Design specifications, development methods, training and testing data, description of the system's architecture, and the algorithms and logic used |
| 3 | `3_monitoring_functioning_control.md` | Annex IV §3 / Art. 12–14 | Description of the system's expected output, performance specifications, and the monitoring and control mechanisms in place for the intended purpose |
| 4 | `4_performance_metrics.md` | Annex IV §4 / Art. 15 | Appropriateness of performance metrics selected (accuracy, recall, etc.), the test datasets used to validate them, and known limitations |
| 5 | `5_risks_and_circumstances.md` | Annex IV §5 / Art. 9 | Known and foreseeable risks to health, safety, and fundamental rights; risk mitigation measures and their effectiveness; residual risk assessment |
| 6 | `6_lifecycle_changes.md` | Annex IV §6 | Relevant changes made to the system through its lifecycle, including retraining events, significant updates, and their impact on compliance |
| 7 | `7_standards_applied.md` | Annex IV §7 / Art. 40 | List of harmonised standards (EN), common specifications, or other technical standards applied, with references and version numbers |
| 8 | `8_declaration_of_conformity.md` | Annex IV §8 / Art. 47 | EU Declaration of Conformity: the legal declaration signed by the provider's authorised representative confirming conformity with the regulation |

## The `manifest.json` File

Each ZIP also contains a `manifest.json` at its root with the following structure:

```json
{
  "generated_at": "2026-04-07T12:00:00+00:00",
  "project_path": "/absolute/path/to/project",
  "compliance_score": 83.3,
  "frameworks_detected": ["openai", "langchain"],
  "sections": [
    "1_general_description",
    "2_development_elements",
    "3_monitoring_functioning_control",
    "4_performance_metrics",
    "5_risks_and_circumstances",
    "6_lifecycle_changes",
    "7_standards_applied",
    "8_declaration_of_conformity"
  ],
  "annex_iv_version": "EU AI Act Regulation 2024/1689",
  "proof_id": "...",           // only present if certified with Trust Layer
  "verification_url": "..."   // only present if certified with Trust Layer
}
```

## Understanding the SHA-256 Hash

The `sha256` field in the tool response is the SHA-256 hash of the entire ZIP archive binary content, computed before any Trust Layer certification.

```
sha256: "a3f9c2b1e4d6..."  (64 hexadecimal characters)
```

**How to verify the hash**:
```bash
sha256sum annex4_package.zip
```

The hash serves as a tamper-evident fingerprint: if even one byte of the ZIP changes after generation, the hash will no longer match. This is what Trust Layer certifies when you use `sign_with_trust_layer=True`.

## Presenting the Package to an Auditor

When a notified body or market surveillance authority requests your technical documentation:

1. **Unzip the archive** — each section is a Markdown file named according to Annex IV structure.
2. **Point to the manifest** — `manifest.json` provides a machine-readable index of all sections and the compliance score at the time of generation.
3. **Provide the SHA-256** — the auditor can verify the package has not been modified since generation.
4. **If certified**: share the `verification_url` from the manifest — the auditor can independently verify the Trust Layer proof at that URL without contacting you.

The auditor should find that Sections 1–7 correspond to the documents your team created (populated from `TECHNICAL_DOCUMENTATION.md`, `RISK_MANAGEMENT.md`, etc.) and that Section 8 (Declaration of Conformity) has been signed by an authorised representative.

## How Trust Layer Certification Enhances the Package

When `sign_with_trust_layer=True`, the tool calls the ArkForge Trust Layer API with the package hash and manifest. Trust Layer returns:

- `proof_id`: A globally unique identifier for this certification event
- `verification_url`: A public URL (e.g. `https://trust.arkforge.tech/verify/{proof_id}`) where anyone can verify that this exact package existed and was certified at the recorded timestamp

This certification provides:

| Without Trust Layer | With Trust Layer |
|--------------------|-----------------|
| Static ZIP + SHA-256 | ZIP + SHA-256 + immutable timestamp proof |
| Auditor must trust your claim of when it was generated | Auditor can independently verify timestamp at `verification_url` |
| No chain of custody | Cryptographically signed chain of custody |
| Adequate for internal audit | Suitable for regulatory submission under Art. 12 |

The certification is recorded as a separate `certification` object in the tool response and the `proof_id` is embedded in `manifest.json` for permanent reference.
