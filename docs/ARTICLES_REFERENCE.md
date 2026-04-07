# EU AI Act Articles Reference

A human-readable guide to the 14 articles and annexes covered by the ArkForge EU AI Act MCP.

## Articles Covered

| Article | Title | Applies To | Risk Categories | Key Obligation | Effort Estimate | Template Available |
|---------|-------|------------|-----------------|----------------|-----------------|-------------------|
| Art. 5 | Prohibited AI Practices | Provider + Deployer | Unacceptable | Do not build or deploy any of the 8 prohibited system types | N/A (system must not exist) | No |
| Art. 6 | Classification of High-Risk AI Systems | Provider | High | Determine if your system falls under Annex II or Annex III classification criteria | Low (assessment) | No |
| Art. 9 | Risk Management System | Provider | High | Establish and maintain a continuous risk identification and mitigation process across the full AI lifecycle | High (10 days est.) | Yes — RISK_MANAGEMENT.md |
| Art. 10 | Data and Data Governance | Provider | High | Document training data quality, bias assessment, collection methods, and representativeness | High (7 days est.) | Yes — DATA_GOVERNANCE.md |
| Art. 11 | Technical Documentation | Provider | High | Create complete technical documentation before placing the system on the market | High (5 days est.) | Yes — TECHNICAL_DOCUMENTATION.md |
| Art. 12 | Record-Keeping | Provider + Deployer | High | Ensure the system automatically logs events sufficient to trace decisions throughout its operational lifetime | Medium (integration) | No |
| Art. 13 | Transparency and Information to Deployers | Provider | High | Provide deployers with instructions for use, including capabilities, limitations, and intended purpose | Medium (3 days est.) | No |
| Art. 14 | Human Oversight | Provider + Deployer | High | Design the system so qualified humans can monitor, understand, intervene in, and stop its operation | Medium (5 days est.) | Yes — HUMAN_OVERSIGHT.md |
| Art. 15 | Accuracy, Robustness and Cybersecurity | Provider | High | Achieve appropriate accuracy levels and protect against adversarial attacks and cybersecurity threats | High (8 days est.) | Yes — ROBUSTNESS.md |
| Art. 17 | Quality Management System | Provider | High | Implement a documented quality management system covering the entire AI lifecycle | High | No |
| Art. 25 | Responsibilities Along the AI Value Chain | Provider + Deployer | High | Clarify which obligations fall on the provider vs. deployer; document agreements | Low–Medium | No |
| Art. 50 | Transparency Obligations for GPAI-enabled Systems | Provider + Deployer | Limited | Mark AI-generated content so recipients can distinguish synthetic outputs from human ones | Low (1 day est.) | No |
| Art. 52 | Transparency Obligations | Provider + Deployer | Limited | Notify users they are interacting with an AI system before or at the moment of interaction | Low (1–2 days est.) | Yes — TRANSPARENCY.md |
| Annex III | High-Risk AI System Categories | Provider | High | Verify whether your use case is listed in any of the 8 Annex III domains | Low (assessment) | No |
| Annex IV | Technical Documentation Content | Provider | High | Structure the technical documentation package according to the 8 mandatory sections | High (varies) | No (use generate_annex4_package) |

## Key Deadlines

| Date | Event |
|------|-------|
| **August 2, 2025** | GPAI model rules apply (Art. 51–56); prohibited practices ban (Art. 5) |
| **August 2, 2026** | Full enforcement — all high-risk and limited-risk obligations apply |
| **August 2, 2027** | Extended deadline for high-risk systems that are safety components of products already subject to Union harmonisation legislation |

The MCP uses **August 2, 2026** as the default compliance deadline. With ~480 days of effort spread across multiple obligations, most teams need at least 6 months of active preparation.

## Provider vs. Deployer: What Is the Difference?

### Provider (Art. 3(3))
The entity that develops the AI system (or commissions its development) and places it on the market or puts it into service under its own name. If you train a model, build an AI-powered product, or publish an AI system as a service, you are a provider.

Provider obligations are the most extensive: they include technical documentation (Art. 11), risk management (Art. 9), data governance (Art. 10), robustness (Art. 15), quality management (Art. 17), and registration (Art. 60).

### Deployer (Art. 3(4))
The entity that uses a ready-made AI system in its own products or services, under its own control and in its own context. If you integrate a third-party model (e.g. GPT-4 via API) into your application, you are a deployer.

Deployer obligations are lighter but real: human oversight (Art. 14), record-keeping (Art. 12), transparency to users (Art. 52), and monitoring post-market.

### Practical Rule of Thumb
- Built your own model or fine-tuned a base model for a specific use case → **Provider**
- Using a third-party API (OpenAI, Anthropic, etc.) in your own product → **Deployer**
- Selling an AI-powered product that integrates a third-party model → **Both** (provider for the product, deployer for the model component)

When in doubt, treat yourself as a provider — the obligations are stricter, but the legal exposure is also higher.
