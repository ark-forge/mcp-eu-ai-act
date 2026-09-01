# Security Policy

## Reporting a Vulnerability

We take security seriously. If you've discovered a vulnerability in the EU AI Act Compliance Scanner MCP Server, please report it responsibly by sending an email to:

**security@arkforge.tech**

Please include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Any proof-of-concept code (if applicable)

### Responsible Disclosure

We appreciate responsible disclosure practices and will:

1. Acknowledge receipt of your report within 24 hours
2. Confirm the vulnerability within 72 hours
3. Provide a timeline for remediation
4. Credit you in the security advisory and changelog

## Recent Security Advisories

### [CVE-2026-XXXX] Unauthenticated SSRF in `/api/v1/scan-repo` (2.0.39)

**Reporter**: Syed Anas Mohiuddin, maintainer of mcp-safeguard security scanner

**Description**: The `POST /api/v1/scan-repo` endpoint accepted a `repo_url` parameter that was passed directly to `git clone` with minimal validation, allowing attackers to initiate connections to arbitrary hosts and ports (CWE-918, SSRF).

**Fixed in**: v2.0.39 (2026-09-01)

**Details**:
- `repo_url` now strictly validated: port 443 only, no credentials, public IP ranges only
- Connection errors no longer echoed to caller (service fingerprinting oracle removed)
- `git clone` invocation hardened with protocol restrictions and redirect blocking

**CVSS Score**: To be assigned by CVE authority

## Supported Versions

| Version | End of Support |
| --- | --- |
| 2.0.39+ | Current |
| < 2.0.39 | Unsupported (contains SSRF vulnerability) |

## Security Considerations

- Never expose `/api/v1/scan-repo` to untrusted networks
- Always use the latest version
- Monitor outbound network connections from the server
- Run the server with minimal privileges
