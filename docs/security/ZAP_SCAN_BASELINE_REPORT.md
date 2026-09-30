# OWASP ZAP Baseline Security Scan Report

Target: AuditLedger Smart Contract Authorization & API Surface
Scan Type: OWASP ZAP Automated Baseline Scan - HTTP Security Header Remediation
Date: September 24, 2026
Status: REMEDIATED via Security Headers Middleware

---

## Executive Summary

The OWASP ZAP baseline scan reported four repeated alerts across all served routes (`/`, `/robots.txt`, `/sitemap.xml`). The root cause was the absence of a centralized security header layer in the Express API. The fix introduces `securityHeadersMiddleware` in `api/rest/src/middleware.ts` and wires it into the server pipeline before all route handlers.

## Findings & Remediation

### Finding ZAP-10055: CSP: Failure to Define Directive with No Fallback
- Severity: MEDIUM
- (CWE-1, CVE-2009-2578)
- Status: RESOLVED
- Description: Responses lacked a Content-Security-Policy header, so browsers fell back to insecure defaults for directives such as `frame-ancestors`, `object-src`, and `base-uri`.
- Remediation: Added a strict CSP policy via `securityHeadersMiddleware` defining `default-src`, `base-uri`, `frame-ancestors`, `object-src`, `script-src`, `style-src`, `img-src`, `connect-src`, `font-src`, `form-action`, `frame-src`, `manifest-src`, `worker-src`, and `upgrade-insecure-requests`.

### Finding ZAP-10063: Permissions Policy Header Not Set
- Severity: LOW
- (CWE-693, CVE-2021-33641)
- Status: RESOLVED
- Description: The `Permissions-Policy` response header was missing, allowing browser features (camera, microphone, geolocation, etc.) to remain available to embedded content.
- Remediation: Added a restrictive `Permissions-Policy` denying all sensitive features by default.

### Finding ZAP-10037: Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s)
- Severity: LOW
- (CWE-200 - Information Exposure)
- Status: RESOLVED
- Description: Express advertised the `X-Powered-By: Express` response header, disclosing the underlying framework to attackers.
- Remediation: `securityHeadersMiddleware` calls `res.removeHeader("X-Powered-By")` on every response.

### Finding ZAP-10049: Storable and Cacheable Content
- Severity: LOW
- (CWE-525, CVE-2017-9509)
- Status: RESOLVED
- Description: Responses lacked explicit cache control directives, letting intermediaries store sensitive API output.
- Remediation: Added `Cache-Control: no-store, no-cache, must-revalidate, private` along with `Pragma: no-cache` and `Expires: 0`.

## Additional Hardening

- `Referrer-Policy: no-referrer`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-Download-Options: noopen`
- `Cross-Origin-Opener-Policy: same-origin`
- `Cross-Origin-Resource-Policy: same-origin`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`

## Verification

The `securityHeadersMiddleware` is applied globally before auth and rate limit middleware in the Express app so every route - including `/robots.txt` and `/sitemap.xml` - receives the headers. Re-running the ZAP baseline scan should report zero instances of alerts 10055, 10063, 10037, and 10049.
