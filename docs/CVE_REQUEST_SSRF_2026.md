# CVE Request — SSRF in mcp-eu-ai-act `/api/v1/scan-repo`

**Date**: 2026-09-01  
**Status**: Fixed in v2.0.39 · CVE assignment pending  
**Reporter**: Syed Anas Mohiuddin (independent security researcher, maintainer of mcp-safeguard)  
**CWE**: CWE-918 (Server-Side Request Forgery)  
**CVSS 3.1 Score**: 8.6 (High) — AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N  

---

## Summary

An unauthenticated Server-Side Request Forgery vulnerability existed in the
`POST /api/v1/scan-repo` endpoint of the EU AI Act Compliance Scanner MCP Server
(package `eu-ai-act-scanner`, versions < 2.0.39).

The `repo_url` parameter was forwarded to `git clone` after only a trivial
`startswith("https://")` string check. An attacker could supply a URL whose hostname
resolved to a private IP address, causing the server to make outbound TCP connections
to arbitrary internal hosts on behalf of the attacker.

---

## Affected Versions

| Version range | Status |
|---------------|--------|
| < 2.0.39 | Vulnerable |
| ≥ 2.0.39 | Fixed |

---

## Technical Details

### Vulnerable Code (< 2.0.39)

```python
# Insufficient: only checks the scheme prefix as a string
if not repo_url.startswith("https://"):
    return 400, {"error": "Only HTTPS URLs allowed"}
subprocess.run(["git", "clone", "--depth", "1", repo_url, clone_dir], ...)
```

### Attack Scenarios

**Scenario 1 — AWS metadata endpoint**
```
POST /api/v1/scan-repo
{"repo_url": "https://169.254.169.254/"}
```
git connects to the AWS/GCP metadata service and returns content in the error message,
leaking instance credentials.

**Scenario 2 — RFC 1918 internal host**
```
POST /api/v1/scan-repo
{"repo_url": "https://192.168.1.1:443/internal-repo"}
```
Server probes internal infrastructure; git stderr (connection refused vs TLS error)
reveals host reachability — a service-fingerprinting oracle.

**Scenario 3 — IPv6 bypass (IPv4-mapped)**
```
POST /api/v1/scan-repo
{"repo_url": "https://[::ffff:127.0.0.1]/"}
```
The `startswith("https://")` check passed; the IPv4-mapped address resolves to loopback.

---

## Fix (v2.0.39)

Three independent defence layers were added:

### Layer 1 — Strict URL validation (`_validate_repo_url`)

- URL parsed with `urllib.parse.urlsplit` (not string prefix matching)
- Scheme must be `https` exactly
- No embedded credentials (`user:pass@host`)
- Port restricted to 443 (`_ALLOWED_REPO_PORTS = frozenset({443})`)
- Hostname resolved via `socket.getaddrinfo`; every resolved address validated by
  `_is_public_address` (uses `ipaddress` module)
- IPv4-mapped (`::ffff:x`), 6to4 (`2002::/16`) and Teredo (`2001::/32`) IPv6 addresses
  are unwrapped and the inner IPv4 re-validated — preventing all known IPv6 bypass forms

### Layer 2 — Error oracle closed

`git clone` stderr is **no longer returned to the caller**. The distinct error messages
for connection-refused, TLS failure and repository-not-found constituted a
service-fingerprinting oracle. The caller now receives only a generic message:
`"Cannot clone repo. Check that the URL points to a public HTTPS Git repository."`

### Layer 3 — git hardened

```python
env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ALLOW_PROTOCOL": "https"}
subprocess.run(
    ["git", "-c", "http.followRedirects=false", "clone", "--depth", "1", repo_url, clone_dir],
    ...
    env=env,
)
```

- `http.followRedirects=false`: git resolves redirects *after* our validation; a
  redirect to an internal host would have bypassed all checks.
- `GIT_ALLOW_PROTOCOL=https`: submodules and redirects cannot silently switch to
  `file://`, `ssh://`, or `git://`.
- `GIT_TERMINAL_PROMPT=0`: git never blocks waiting for interactive credentials.

---

## Test Coverage

Eight regression tests were added in `tests/test_server.py`:

| Test | Scenario |
|------|----------|
| `test_validate_repo_url_rejects_localhost` | `https://localhost/` |
| `test_validate_repo_url_rejects_127` | `https://127.0.0.1/` |
| `test_validate_repo_url_rejects_private_rfc1918` | `https://192.168.1.1/` |
| `test_validate_repo_url_rejects_metadata` | `https://169.254.169.254/` |
| `test_validate_repo_url_rejects_ipv4_mapped_ipv6` | `https://[::ffff:127.0.0.1]/` |
| `test_validate_repo_url_rejects_credentials` | `https://user:pass@github.com/` |
| `test_validate_repo_url_rejects_non_https` | `git://github.com/foo/bar` |
| `test_validate_repo_url_rejects_alt_port` | `https://github.com:8443/foo` |

---

## Acknowledgements

Thanks to **Syed Anas Mohiuddin** for responsible disclosure, a thorough technical
write-up, and for coordinating the timeline to allow a patch before any public
disclosure.

---

## References

- GitHub Issue: [ark-forge/mcp-eu-ai-act#20](https://github.com/ark-forge/mcp-eu-ai-act/issues/20)
- CHANGELOG: [v2.0.39](../CHANGELOG.md#2039---2026-09-01)
- CWE-918: https://cwe.mitre.org/data/definitions/918.html
- NVD CVE Request: https://github.com/ark-forge/mcp-eu-ai-act/security/advisories
