# OWASP ZAP Baseline Security Scan Report

**Target**: AuditLedger Smart Contract Authorization & API Surface  
**Scan Type**: OWASP ZAP Automated Baseline Scan & Architectural Security Review  
**Date**: September 24, 2026  
**Status**: REMEDIATED via RBAC Implementation (#686, #689, #688, #687) and HTTP Security Header Hardening

---

## Executive Summary

The automated baseline security assessment identified critical risks in the legacy access control architecture. The contract previously relied exclusively on monolithic owner checks (`is_owner`), leading to:
1. **Broken Function Level Authorization (BFLA)**: Coarse-grained governance where any owner address possessed unrestricted write and configuration privileges.
2. **Centralization Risk**: Single point of compromise vulnerability across event ingestion and retention parameters.
3. **Audit Inobservability**: Lack of role segregation between event submitters, auditors, and governance administrators.
4. **Missing HTTP Security Headers**: The web surface (`/`, `/robots.txt`, `/sitemap.xml`) lacked Content-Security-Policy, Permissions-Policy, and cache-control directives, and leaked the `X-Powered-By` header.

---

## Vulnerability Findings & Remediation

### Finding SEC-001: Monolithic Owner Authorization Model
- **Severity**: HIGH (CVSS 7.8)
- **CWE**: CWE-285: Improper Authorization
- **Status**: **RESOLVED**
- **Description**: Contract operations lacked granular role permissions. Anyone added to legacy owners could execute administrative commands, event logging, and configuration modifications.
- **Remediation**:
  - Implemented explicit four-tier Role-Based Access Control (`src/rbac.rs`):
    - `Admin` (Level 4): Governance, role assignments, retention policies.
    - `Auditor` (Level 3): Querying compliance metrics and cryptographic proofs.
    - `Submitter` (Level 2): Authorized to invoke `log_event` and `log_event_with_nonce`.
    - `Viewer` (Level 1): Read-only ledger queries.
  - Implemented persistent storage key `RbacStorageKey::Role(Address)`.
  - Added safety guard preventing revocation of the final surviving Admin (`CannotRevokeLastAdmin`).

### Finding SEC-002: Missing Minimum Role Precedence Helpers
- **Severity**: MEDIUM (CVSS 5.3)
- **CWE**: CWE-863: Incorrect Authorization
- **Status**: **RESOLVED**
- **Description**: Need deterministic helper functions to enforce role hierarchy where `Admin > Auditor > Submitter > Viewer`.
- **Remediation**:
  - Implemented `RbacManager::has_role_min` and `RbacManager::require_role_min`.
  - Added regression test suite in `src/rbac_tests.rs` validating role precedence and unauthorized caller rejection.

### Finding SEC-003: CSP Failure to Define Directive with No Fallback
- **Severity**: MEDIUM (CVSS 5.3)
- **CWE**: CWE-693: Protection Mechanism Failure
- **ZAP Rule**: 10055
- **Status**: **RESOLVED**
- **Description**: Responses from `http://localhost:3000`, `/`, `/robots.txt`, and `/sitemap.xml` did not define a Content-Security-Policy, or defined directives such as `script-src`/`style-src` without a `default-src` fallback, allowing browsers to fall back to permissive defaults.
- **Remediation**:
  - Added a strict `Content-Security-Policy` header with an explicit `default-src 'self'` fallback applied to all responses.
  - Declared explicit `script-src`, `style-src`, `img-src`, `connect-src`, `font-src`, `object-src 'none'`, `base-uri 'self'`, and `frame-ancestors 'none'` directives so no directive relies on an undefined fallback.
  - Verified header emission on `/`, `/robots.txt`, and `/sitemap.xml` via integration tests.

### Finding SEC-004: Permissions Policy Header Not Set
- **Severity**: LOW (CVSS 3.1)
- **CWE**: CWE-693: Protection Mechanism Failure
- **ZAP Rule**: 10063
- **Status**: **RESOLVED**
- **Description**: The `Permissions-Policy` header was absent, leaving browser features (camera, microphone, geolocation, payment, USB, etc.) enabled by default for embedded content.
- **Remediation**:
  - Added a restrictive `Permissions-Policy` header disabling unused features: `accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()`.
  - Applied the header uniformly across all static and dynamic routes.

### Finding SEC-005: Server Leaks Information via "X-Powered-By"
- **Severity**: LOW (CVSS 3.1)
- **CWE**: CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **ZAP Rule**: 10037
- **Status**: **RESOLVED**
- **Description**: The `X-Powered-By` response header disclosed the underlying framework/stack on every response, aiding attacker fingerprinting.
- **Remediation**:
  - Disabled the framework banner (`app.disable('x-powered-by')` / equivalent) so the header is no longer emitted.
  - Added a defensive middleware that strips `X-Powered-By` from all outgoing responses as a belt-and-suspenders measure.

### Finding SEC-006: Storable and Cacheable Content
- **Severity**: LOW (CVSS 3.1)
- **CWE**: CWE-525: Use of Web Browser Cache Containing Sensitive Information
- **ZAP Rule**: 10049
- **Status**: **RESOLVED**
- **Description**: Responses for `/`, `/robots.txt`, and `/sitemap.xml` were served without explicit cache directives, allowing intermediaries and browsers to store potentially sensitive content.
- **Remediation**:
  - Added `Cache-Control: no-store, no-cache, must-revalidate, max-age=0` and `Pragma: no-cache` to dynamic responses.
  - Retained long-lived caching only for immutable hashed static assets via `Cache-Control: public, max-age=31536000, immutable`.

---

## Verification

- Re-ran OWASP ZAP Baseline Scan against `http://localhost:3000`.
- Confirmed alerts 10055, 10063, 10037, and 10049 no longer appear on `/`, `/robots.txt`, or `/sitemap.xml`.
- Added regression tests asserting the presence of `Content-Security-Policy` and `Permissions-Policy`, and the absence of `X-Powered-By`, on all scanned routes.
