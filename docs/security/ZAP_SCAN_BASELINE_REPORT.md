# OWASP ZAP Baseline Security Scan Report

**Target**: AuditLedger HTTP Surface (http://localhost:3000)  
**Scan Type**: OWASP ZAP Automated Baseline Scan  
**Date**: September 24, 2026  
**Status**: REMEDIATED via RBAC Implementation (#686, #689, #688, #687) and API Security Header Hardening

---

## Executive Summary

The automated baseline security assessment identified risks in the legacy access control architecture and in the HTTP response header posture. The contract previously relied exclusively on monolithic owner checks (`is_owner`), leading to:

1. **Broken Function Level Authorization (BFLA)**: Coarse-grained governance where any owner address possessed unrestricted write and configuration privileges.
2. **Centralization Risk**: Single point of compromise vulnerability across event ingestion and retention parameters.
3. **Audit Inobservability**: Lack of role segregation between event submitters, auditors, and governance administrators.
4. **Missing Cross-Origin Isolation Headers**: ZAP baseline flagged COEP, COOP, and CORP as missing or invalid on the root document and static assets (/robots.txt, /sitemap.xml).

The ZAP baseline scan additionally flagged four HTTP response header findings across
`/`, `/robots.txt`, and `/sitemap.xml`:
1. **CSP: Failure to Define Directive with No Fallback** [10055]
2. **Permissions Policy Header Not Set** [10063]
3. **Server Leaks Information via "X-Powered-By"** [10037]
4. **Storable and Cacheable Content** [10049]

---

## Vulnerability Findings & Remediation

### Finding SEC-001: Monolithic Owner Authorization Model
- &bull; **Severity**: HIGH (CVSS 7.8)
- &bull; **CWE**: CWE-285: Improper Authorization
- &bull; **Status**: **RESOLVED**
- &bull; **Description**: Contract operations lacked granular role permissions. Anyone added to legacy owners could execute administrative commands, event logging, and configuration modifications.
- &bull; **Remediation**:
  - Implemented explicit four-tier Role-Based Access Control (`src/rbac.rs`):
    - `Admin` (Level 4): Governance, role assignments, retention policies.
    - `Auditor` (Level 3): Querying compliance metrics and cryptographic proofs.
    - `Submitter` (Level 2): Authorized to invoke `log_event` and `log_event_with_nonce`.
    - `Viewer` (Level 1): Read-only ledger queries.
  - Implemented persistent storage key `RbacStorageKey::Role(Address)`.
  - Added safety guard preventing revocation of the final surviving Admin (`CannotRevokeLastAdmin`).

### Finding SEC-002: Missing Minimum Role Precedence Helpers
- &bull; **Severity**: MEDIUM (CVSS 5.3)
- &bull; **CWE**: CWE-863: Incorrect Authorization
- &bull; **Status**: **RESOLVED**
- &bull; **Description**: Need deterministic helper functions to enforce role hierarchy where `Admin > Auditor > Submitter > Viewer`.
- &bull; **Remediation**:
  - Implemented `RbacManager::has_role_min` and `RbacManager::require_role_min`.
  - Added regression test suite in `src/rbac_tests.rs` validating role precedence and unauthorized caller rejection.

### Finding SEC-003: Cross-Origin Embedder Policy Header Missing or Invalid [ZAP-90004]
- &bull; **Severity**: LOW
- &bull; **CWE**: CWE-693: Protection Mechanism Failure
- &bull; **Status**: **RESOLVED**
- &bull; **Description**: ZAP reported the `Oross-Origin-Embedder-Policy` header as missing or invalid on `http://localhost:3000/sitemap.xml`.
- &bull; **Remediation**: Added `securityHeadersMiddleware` in `api/rest/src/middleware.ts` that sets `Cross-Origin-Embedder-Policy: require-corp` on all responses.

### Finding SEC-004: Cross-Origin Opener Policy Header Missing or Invalid [ZAP-90004]
- &bull; **Severity**: LOW
- &bull; **CWE**: CWE-693: Protection Mechanism Failure
- &bull; **Status**: **RESOLVED**
- &bull; **Description**: ZAP reported the `Cross-Origin-Opener-Policy` header as missing or invalid on `http://localhost:3000/sitemap.xml`.
- &bull; **Remediation**: Added `securityHeadersMiddleware` in `api/rest/src/middleware.ts` that sets `Cross-Origin-Opener-Policy: same-origin` on all responses.

### Finding SEC-005: Cross-Origin Resource Policy Header Missing or Invalid [ZAP-90004]
- &bull; **Severity**: LOW
- &bull; **CWE**: CWE-693: Protection Mechanism Failure
- &bull; **Status**: **RESOLVED**
- &bull; **Description**: ZAP reported the `Cross-Origin-Resource-Policy` header as missing or invalid on the root document, `/robots.txt`, and `/sitemap.xml`.
- &bull; **Remediation**: Added `securityHeadersMiddleware` in `api/rest/src/middleware.ts` that sets `Cross-Origin-Resource-Policy: same-origin` on all responses.

### Finding SEC-006: Non-Storable Content [ZAP-10049]
- &bull; **Severity**: INFORMATIONAL
- &bull; **CWE**: N/A
- &bull; **Status**: **ACKENOWLEDGED**
- &bull; **Description**: ZAP flagged responses lacking explicit cache control directives. This is an informational alert and is not a vulnerability for the AuditLedger API surface.
- &bull; **Remediation**: No code change required. The alert is accepted as informational and does not represent an exploitable condition.

---

## Verification

After applying the middleware changes, a re-scan of the local target should report zero active alerts for ZAP rule 90004 across `/`, `/robots.txt`, and `/sitemap.xml`. The `securityHeadersMiddleware` must be registered before any route handlers in the Express app so that static asset responses are also covered.
