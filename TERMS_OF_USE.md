# Terms of Use - EU AI Act Compliance Checker

**Effective Date:** February 2026
**Provider:** ArkForge (https://arkforge.fr)

## 1. Service Description

The EU AI Act Compliance Checker is a Model Context Protocol (MCP) server that scans software projects to detect AI model usage and verify compliance with the European Union AI Act (Regulation EU 2024/1689).

## 2. Scope of Use

### 2.1 Permitted Use
- Scanning your own projects for AI framework detection
- Generating compliance reports for internal assessment
- Integrating into your CI/CD pipelines for automated compliance checks
- Using as a preliminary compliance screening tool

### 2.2 Limitations
- This tool provides **automated preliminary assessments only**
- Results do **not** constitute legal advice or certification
- Compliance scores are based on automated heuristic checks (file presence, pattern matching)
- A passing score does **not** guarantee regulatory compliance

## 3. No Legal Advice

This tool is **not a substitute for professional legal counsel**. The EU AI Act is a complex regulation with specific requirements that vary by use case, jurisdiction, and deployment context. Users must consult qualified legal professionals for definitive compliance guidance.

## 4. Accuracy and Reliability

### 4.1 Best Effort
The tool uses pattern matching and file analysis to detect AI usage and check documentation. Detection is based on known patterns for major frameworks (OpenAI, Anthropic, HuggingFace, TensorFlow, PyTorch, LangChain).

### 4.2 Known Limitations
- May not detect custom or proprietary AI frameworks
- File-based compliance checks (e.g., presence of RISK_MANAGEMENT.md) verify documentation existence, not content quality
- Risk categorization requires user input and is not automatically determined
- Does not verify the substance or accuracy of compliance documentation

## 5. Data and Privacy

### 5.1 Local Processing
All scanning and analysis is performed **locally** on the user's machine. No data is transmitted externally.

### 5.2 No Data Collection
The tool does not collect, store, or transmit any user data, project data, or scan results to external servers.

## 6. License

This software is distributed under the MIT License. See the LICENSE file for full terms.

## 7. Disclaimer of Warranties

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED. THE AUTHORS DO NOT WARRANT THAT THE SOFTWARE WILL MEET YOUR REQUIREMENTS, OPERATE WITHOUT INTERRUPTION, OR BE ERROR-FREE.

## 8. Limitation of Liability

IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY ARISING FROM THE USE OF THIS SOFTWARE, INCLUDING BUT NOT LIMITED TO REGULATORY PENALTIES, FINES, OR COMPLIANCE FAILURES.

## 9. Changes to Terms

These terms may be updated from time to time. The effective date at the top of this document indicates the latest revision.

## 10. Contact

For questions about these terms or the software:
- Website: https://arkforge.fr
- Email: support@arkforge.fr
- GitHub: https://github.com/ark-forge/mcp-eu-ai-act
