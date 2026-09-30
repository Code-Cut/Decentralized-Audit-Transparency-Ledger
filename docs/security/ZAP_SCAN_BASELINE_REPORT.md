# OWASP ZAP Baseline Security Scan Report

**Target**: AuditLedger Smart Contract Authorization & API Surface  
**Scan Type**: OWASP ZAP Automated Baseline Scan & Architectural Security Review  
**Date**: September 24, 2026  
**Status**: REMEDIATED via RBAC Implementation (#686, #689, #688, #687) and API Header Hardening

---

## Executive Summary

The automated baseline security assessment identified risks in the legacy access control architecture and in the HTTP response headers emitted by the REST API. The contract previously relied exclusively on monolithic owner checks (`is_owner`), leading to:
1. **Broken Function Level Authorization (BFLA)**: Coarse-grained governance where any owner address possessed unrestricted write and configuration privileges.
2. **Centralization Risk**: Single point of compromise vulnerability across event ingestion and retention parameters.
3. **Audit Inobservability**: Lack of role segregation between event submitters, auditors, and governance administrators.

---

## Vulnerability Findings & Remediation

### Finding SEC-001: Monolithic Owner Authorization Model
- **Severity**: HIGH (CVSS 7.8)
- **CWE**: CWE-285: Improper Authorization
- **Status**: **RESOLVED**
- **Description**: Contract operations lacked granular role permissions. Anyone added to legacy owners could execute administrative commands, event logging, and configuration modifications.
- `Remediation`:
  - Implemented explicit four-tier Role-Based Access Control (`src/rbac.rs`):
    - `Admin` (Level 4): Governance, role assignments, retention policies.
    - `Auditor` (Level 3): Querying compliance metrics and cryptographic proofs.
    - `Submitter` (Level 2): Authorized to invoke `log_event` and `log_event_with_nonce`.
    - `Viewer` (Level 1): Read-only ledger queries.
  - Implemented persistent storage key `RbacStorageKey::Role(Address)`.
  - Added safety guard preventing revocation of the final surviveng Admin (`CannotRevokeLastAdmin`).

### Finding SEC-002: Missing Minimum Role Precedence Helpers
- **Severity**: MEDIUM (CVSS 5.3)
- **CWE**: CWE-863: Incorrect Authorization
- **Status**: **RESOLVED**
- **Description**: Need deterministic helper functions to enforce role hierarchy where `Admin > Auditor > Submitter > Viewer`.
- `Remediation`:
  - Implemented `RbacManager::has_role_min` and `RbacManager::require_role_min`.
  - Added regression test suite in `src/rbac_tests.rs` validating role precedence and unauthorized caller rejection.

### Finding SEC-003: Missing CSP Directive Fallback (ZAP [10055])
- **Severity**: MEDIUM (CVSS 5.3)
- `CWE`**: CWE-693: Protection Mechanism Failure
- **Status**: **RESOLVED**
- **Description**: The REST API responses did not set a `Content-Security-Policy` header, leaving browsers without a default fallback for directives like `default-src` and `frame-ancestors`.
- `Remediation`:
  - Added `securityHeadersMiddleware` in `api/rest/src/middleware.ts`.
  - Emits a default-deny `Content-Security-Policy` with explicit `default-src 'none'` and `frame-ancestors 'none'` fallbacks.

### Finding SEC-004: Permissions Policy Header Not Set (ZAP [10063])
- **Severity**: LOW (CVSS 3.1)
- `CWE`**: CWE-693: Protection Mechanism Failure
- **Status**: **RESOLVED**
- **Description**: No `Permissions-Policy` header was sent, allowing browsers to grant powerful features (camera, microphone, geolocation, etc.) to embedded content by default.
- `Remediation`:
  - `securityHeadersMiddleware` now sets a deny-by-default `Permissions-Policy` covering all recognized features.

### Finding SEC-005: Server Leaks Information via "X-Powered-By" (ZAP [10037])
- **Severity**: LOW (CVSS 3.7)
- `CWE`**: CWE-497: Exposure of Sensitive Information Through Debug Information
- **Status**: **RESOLVED**
- **Description**: Express emitted `X-Powered-By`, disclosing the underlying framework to attackers.
- `Remediation`:
  - `securityHeadersMiddleware` calls `res.removeHeader("X-Powered-By")` on every response.

### Finding SEC-006: Storable and Cacheable Content (ZAP [10049])
- -**Severity**: LOW (CVSS 3.1)
- `CWE`**: CWE-524: Cacheable HTTP Response Containing Sensitive Information
- **Status**: **RESOLVED**
- **Description**: API responses lacked cache control directives, allowing intermediaries to store and replay potentially sensitive data.
- `Remediation`:
  - `securityHeadersMiddleware` sets `Cache-Control: no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0` along with `Pragma: no-cache` and `Expires: 0`.
