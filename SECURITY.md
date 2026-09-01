# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 2.0.x (≥ 2.0.39) | ✅ |
| < 2.0.39 | ❌ |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report security issues via GitHub's private Security Advisory channel:
[Report a vulnerability](https://github.com/ark-forge/mcp-eu-ai-act/security/advisories/new)

Include:
- Description of the vulnerability and affected component
- Steps to reproduce
- Potential impact assessment (CVSS if possible)
- Suggested fix if you have one

We aim to acknowledge reports within **48 hours** and to ship a patch within **7 days** for critical issues.

## Disclosure Policy

We follow coordinated disclosure (CVD):
1. Report received and acknowledged
2. Patch developed and tested
3. Fixed version released
4. Reporter credited in CHANGELOG (with consent)
5. Public disclosure after patch ships

## Known Fixed Vulnerabilities

### CWE-918 — SSRF in `/api/v1/scan-repo` (fixed in v2.0.39)

**Reporter**: Syed Anas Mohiuddin (independent security researcher)  
**CVSS**: 8.6 (High)  
**Details**: See [docs/CVE_REQUEST_SSRF_2026.md](docs/CVE_REQUEST_SSRF_2026.md)

The `repo_url` parameter in `POST /api/v1/scan-repo` was passed to `git clone` behind
a single `startswith("https://")` string check. Attackers could supply URLs that
resolve to private RFC 1918 ranges, loopback (127.0.0.1), or cloud metadata endpoints
(169.254.169.254) and use the server as an SSRF probe.

Fixed by strict multi-layer URL validation (urlsplit + ipaddress module), error
sanitization (git stderr no longer echoed), and git hardening (`http.followRedirects=false`,
`GIT_ALLOW_PROTOCOL=https`, `GIT_TERMINAL_PROMPT=0`).
