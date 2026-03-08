# Code Review: Audit Service Integration

**Date:** 2026-03-08
**Status:** Completed
**Overall Health:** Good

## Summary

The Audit Service has been successfully wired into the `UsersController` and `AuthController`. The implementation follows the project's layered architecture, uses dependency injection, and includes comprehensive tests with mocks. Non-blocking error handling for audit logs ensures that persistence failures do not impact the user experience.

---

## Findings by Severity

### ⚠️ Medium Severity

#### 1. Missing `ResourceUUID` in User Creation

- **Issue:** `UsersController.CreateUser` logs the audit entry with an empty `ResourceUUID` even on success.
- **Impact:** Difficult to filter audit logs for a specific user starting from their creation.
- **Recommendation:** Extract the UUID from the newly created user object and include it in the `auditLog` call.

#### 2. Incomplete Audit Trail for OAuth Failures

- **Issue:** Failures in the OAuth callback (e.g., during user info retrieval) are not consistently audited.
- **Impact:** Security gaps in tracking attempted/failed unauthorized access via OAuth.
- **Recommendation:** Add `auditLog` calls to all error paths in `OAuthProviderCallback`.

---

### ℹ️ Low Severity / Informational

#### 1. Context Propagation

- **Issue:** `auditLog` helper does not pass `r.Context()` to `AuditService.Log()`.
- **Impact:** Limits future capabilities for cancellation and distributed tracing (OpenTelemetry).
- **Recommendation:** Update the service interface and helper to propagate context.

#### 2. Redundant User Fetching for Updates

- **Issue:** To log "Changes" in `UpdateUser`, the service might need a "before" snapshot.
- **Impact:** Potential for race conditions or inefficient double-querying.
- **Recommendation:** Use a PostgreSQL CTE with `UPDATE ... RETURNING *` to get before/after states atomically.

#### 3. Test Verbosity

- **Issue:** Multiple tests repeat complex `mock.MatchedBy` logic.
- **Impact:** Higher maintenance burden if the audit DTO structure changes.
- **Recommendation:** Create a reusable audit matcher helper in `internal/controllers/helpers_test.go`.

---

## Next Steps Checklist

- [ ] Update `CreateUser` to include the `ResourceUUID` in the success audit log.
- [ ] Implement atomic "before/after" capture using CTEs for `UpdateUser`.
- [ ] Propagate `r.Context()` through the audit logging chain.
- [ ] Ensure all OAuth error paths generate audit entries.
