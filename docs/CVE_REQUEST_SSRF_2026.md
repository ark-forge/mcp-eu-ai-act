# CVE Request: Unauthenticated SSRF in `/api/v1/scan-repo`

**Date**: 2026-09-01  
**Reporter**: Syed Anas Mohiuddin (syed.anas.mohiuddin@gmail.com)  
**Maintainer attribution**: mcp-safeguard security scanner  
**Affected Component**: EU AI Act Compliance Scanner MCP Server  
**Affected Versions**: < 2.0.39  

## CVE Details

### Vulnerability Description

The EU AI Act Compliance Scanner MCP Server contains an **Unauthenticated Server-Side Request Forgery (SSRF)** vulnerability in the public REST endpoint `POST /api/v1/scan-repo`.

### Vulnerability Type
- **CWE**: CWE-918 (Server-Side Request Forgery)
- **CVSS v3.1 Preliminary Score**: 8.6 (High) — Network-accessible, no authentication required, can access internal services
- **OWASP**: A10:2021 Server-Side Request Forgery (SSRF)

### Affected Endpoint

```
POST /api/v1/scan-repo
Content-Type: application/json

{
  "repo_url": "https://attacker-controlled.com/repo.git"
}
```

### Vulnerability Details

The `repo_url` parameter was validated using only a string prefix check (`startswith("https://")`) before being passed to `git clone`. This allowed attackers to:

1. **Scan internal infrastructure** via SSRF:
   - AWS metadata endpoint: `169.254.169.254:80`
   - Private networks: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
   - Localhost: `127.0.0.1`
   
2. **Enumerate internal services** through error messages:
   - Git error responses leaked connection status (connection refused, TLS errors, auth failures)
   - This served as a service fingerprinting oracle

3. **Bypass redirects**:
   - `git clone` followed redirects AFTER URL validation, allowing protocols like `http://` to be reached via HTTPS redirects
   - Protocol restrictions were ineffective

### Impact

- **Confidentiality**: High — attackers can probe internal infrastructure and read error responses
- **Integrity**: Low — no direct write capability
- **Availability**: Medium — potential DoS via scanning expensive endpoints repeatedly

### Proof of Concept

```bash
# Scan AWS metadata (would leak credentials if misconfigured)
curl -X POST http://victim-server:8100/api/v1/scan-repo \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://169.254.169.254/latest/meta-data"}'

# Response: error messages reveal connectivity status
```

## Remediation

**Fixed in Version 2.0.39** (2026-09-01)

### Changes Made

1. **Strict URL validation**:
   ```python
   from urllib.parse import urlparse
   from ipaddress import IPv4Address, IPv6Address
   
   # Port must be 443 only (for HTTPS)
   # No credentials allowed
   # IP address must be public (reject RFC 1918, loopback, metadata, etc.)
   ```

2. **Error oracle closed**:
   - `git clone` stderr no longer echoed to caller
   - Generic error message returned instead of connection-specific details

3. **Git protocol hardening**:
   - `http.followRedirects=false` — prevent redirect bypasses
   - `GIT_ALLOW_PROTOCOL=https` — restrict to HTTPS only
   - `GIT_TERMINAL_PROMPT=0` — disable interactive prompts

4. **Installation path fix**:
   - `_INSTALL_ROOT` no longer collapses to `/`
   - Prevents exposure of application files (`api_keys.json`, `data/`)

## Timeline

| Date | Event |
|------|-------|
| 2026-08-31 | Initial vulnerability report received |
| 2026-09-01 | Patch developed and tested (8/8 test cases passing) |
| 2026-09-01 | v2.0.39 released with fix and security.md |
| 2026-09-01 | CVE requested via responsible disclosure |

## CVE ID Assignment

**Status**: Requested from CVE Numbering Authority  
**Assigned ID**: Pending (to be updated once CVE authority assigns)  
**Reference**: GitHub Security Advisory (to be created)

## References

- [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
- [OWASP: SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [RFC 1918: Private Internet Addresses](https://tools.ietf.org/html/rfc1918)

## Credits

**Discovered and Reported by**: Syed Anas Mohiuddin  
**Maintainer**: mcp-safeguard (open-source MCP security scanner)  
**Affiliation**: Independent Security Researcher

---

*This document is part of the responsible disclosure process. The vulnerability has been patched in v2.0.39. Users should upgrade immediately.*
