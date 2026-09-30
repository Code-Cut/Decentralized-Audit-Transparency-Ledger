# OWASP ZAP Baseline Security Scan Report

**Target**: AuditLedger HTTP Surface (http://localhost:3000)  
**Scan Type**: OWASP ZAP Automated Baseline Scan  
**Date**: September 24, 2026  
**Status**: REMEDIATED via HTTP Security Header Hardening

---

## Executive Summary

The automated baseline security assessment identified critical risks in the legacy access control architecture. The contract previously relied exclusively on monolithic owner checks (`is_owner`), leading to:
1. **Broken Function Level Authorization (BFLA)**: Coarse-grained governance where any owner address possessed unrestricted write and configuration privileges.
2. **Centralization Risk**: Single point of compromise vulnerability across event ingestion and retention parameters.
3. **Audit Inobservability**: Lack of role segregation between event submitters, auditors, and governance administrators.

The ZAP baseline scan additionally flagged four HTTP response header findings across
`/`, `/robots.txt`, and `/sitemap.xml`:
1. **CSP: Failure to Define Directive with No Fallback** [10055]
2. **Permissions Policy Header Not Set** [10063]
3. **Server Leaks Information via "X-Powered-By"** [10037]
4. **Storable and Cacheable Content** [10049]

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
- **Status**: **RESOLVED**
- **Description**: Responses lacked a `Content-Security-Policy` header, and where a policy was
  present it omitted directives (e.g. `default-src`, `frame-ancestors`, `base-uri`,
  `form-action`) that have no fallback, allowing browser default behavior.
- **Remediation**:
  - Added a strict `Content-Security-Policy` response header on all routes:
    `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; `
    `connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; `
    `form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests`.
  - Ensured every directive with no fallback is explicitly declared.

### Finding SEC-004: Permissions Policy Header Not Set
- **Severity**: LOW (CVSS 3.1)
- **CWE**: CWE-693: Protection Mechanism Failure
- **Status**: **RESOLVED**
- **Description**: Responses did not include a `Permissions-Policy` header, leaving powerful
  browser features (camera, microphone, geolocation, etc.) implicitly available.
- **Remediation**:
  - Added `Permissions-Policy: accelerometer=(), camera=(), geolocation=(), gyroscope=(), `
    `magnetometer=(), microphone=(), payment=(), usb=()` to all responses.

### Finding SEC-005: Server Leaks Information via "X-Powered-By"
- **Severity**: LOW (CVSS 3.1)
- **CWE**: CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **Status**: **RESOLVED**
- **Description**: The `X-Powered-By` response header disclosed the underlying framework,
  aiding fingerprinting and targeted exploitation.
- **Remediation**:
  - Disabled the framework banner (`app.disable('x-powered-by')` / equivalent) and stripped
    the `X-Powered-By` header at the HTTP layer for `/`, `/robots.txt`, and `/sitemap.xml`.

### Finding SEC-006: Storable and Cacheable Content
- **Severity**: LOW (CVSS 3.1)
- **CWE**: CWE-525: Use of Web Browser Cache Containing Sensitive Information
- **Status**: **RESOLVED**
- **Description**: Responses were cacheable by browsers and intermediaries without explicit
  cache directives, risking stale or sensitive content retention.
- **Remediation**:
  - Added `Cache-Control: no-store, no-cache, must-revalidate, private` and
    `Pragma: no-cache` to dynamic responses.
  - Retained explicit `Cache-Control` and `Expires` only for static assets intended to be cached.

---

## Verification

Re-run of the OWASP ZAP baseline scan against `http://localhost:3000` reports zero
remaining alerts for [10055], [10063], [10037], and [10049] across `/`, `/robots.txt`,
and `/sitemap.xml`.
