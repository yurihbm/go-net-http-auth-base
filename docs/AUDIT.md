# Audit System Documentation

## Overview

This project implements a comprehensive audit logging system designed to track all significant actions performed within the application. The audit system captures who did what, when, where, and the outcome of each action, providing a complete trail for security, compliance, and debugging purposes.

## Architecture

The audit system follows the project's layered architecture pattern and consists of these components:

### 1. Domain Layer (`internal/domain/audit.go`)

Defines the core audit data structures and interfaces:

- **`AuditLog`**: The domain model representing a single audit log entry
- **`CreateAuditLogDTO`**: Data Transfer Object for creating new audit logs
- **`ListAuditLogsDTO`** / **`AuditLogPage`**: Filters and result page for listing audit logs
- **`AuditRepository`**: Interface for persistence operations (`Create`, `List`)
- **`AuditService`**: Interface for business logic (`Log`, `List`)

### 2. Controllers (`internal/controllers/audit_helpers.go`, `audit_controller.go`)

- **Writing**: `UsersController` and `AuthController` call the unexported `auditLog` helper on both the success and failure paths of each audited action. It fills `RequestUUID` from `shared.RequestContextData` and the client IP and user agent from the request, then calls `AuditService.Log`. The IP is `RequestContextData.ClientIP`: the `r.RemoteAddr` host, or the address resolved from `X-Forwarded-For` when the connection comes from a proxy in `TRUSTED_PROXIES` (see ADR-012). `X-Real-IP` is ignored. A persistence failure is only logged (`audit log failed`) and never changes the HTTP response.
- **Reading**: `AuditController` serves `GET /audit-logs` (see [Listing Audit Logs](#listing-audit-logs)).

### 3. Service Layer (`internal/services/audit_service.go`)

`auditService` maps `CreateAuditLogDTO` to an `AuditLog` for the repository, and builds the cursor page for `List`.

### 4. Repository Layer (`internal/repositories/audit_repository.go`)

Implements data persistence through `AuditPostgresRepository`:

- Converts domain models to PostgreSQL-compatible types (`pgtype.UUID`, `pgtype.Text`)
- Marshals the `Changes` field to JSONB for flexible storage
- Uses `sqlc`-generated queries for type-safe database operations

### 5. Infrastructure Layer (`internal/infra/audit_logs_partition_manager.go`)

Manages database partitions to ensure optimal performance:

- **`AuditLogsPartitionManager`**: Automatically creates and maintains monthly partitions
- Runs maintenance on application startup and every 24 hours (stopped on shutdown)
- Uses PostgreSQL advisory locks to prevent race conditions

### 6. Database Layer (`postgres/migrations/000001_init_db.up.sql`)

Defines the partitioned table schema with appropriate indexes.

## Data Model

### AuditLog Structure

```go
type AuditLog struct {
    UUID          string  // Unique identifier for the log entry
    ActorUUID     *string // UUID of the user who performed the action (nullable for system/anonymous actions)
    IPAddress     string  // IP address of the request origin
    UserAgent     string  // Browser/client user agent string
    Action        string  // The action performed (e.g., USER_CREATE, LOGIN)
    ResourceType  string  // Type of resource affected (e.g., "user", "auth")
    ResourceUUID  string  // UUID of the specific resource affected
    RequestUUID   string  // UUID correlating this log to the HTTP request
    Changes       any     // JSONB containing old and new values
    Status        string  // SUCCESS or FAILURE
    FailureReason *string // Description of why the action failed (nullable)
    CreatedAt     string  // RFC 3339 timestamp (UTC) of when the log was created
}
```

### Constants

The domain package defines type-safe constants for common values:

**Status:**

- `AuditStatusSuccess`: Action completed successfully
- `AuditStatusFailure`: Action failed

**Actions:**

- `AuditActionSignupRequest` (`SIGNUP_REQUEST`): Sign-up started and code emailed (`POST /users`, or the OAuth callback when the provider email is not verified, with `changes.provider`; a failure with `verification_limited` when the address hit its send limit); no account exists yet, and the pending sign-up UUID is never logged because the cookie holding it is a bearer secret
- `AuditActionUserCreate` (`USER_CREATE`): User account creation, logged when the sign-up code is verified (`POST /auth/signup/verify`); on success the actor and resource are the new user
- `AuditActionUserUpdate` (`USER_UPDATE`): User account modification (`PUT /users/{uuid}`)
- `AuditActionUserDelete` (`USER_DELETE`): User account deletion (`DELETE /users/{uuid}`)
- `AuditActionUserRoleChange` (`USER_ROLE_CHANGE`): User role change by the `promote-admin` command; a system action with no actor (`actor_uuid` is null), `changes.role` holds the new role, and it is only logged when the role actually changed
- `AuditActionEmailChangeRequest` (`EMAIL_CHANGE_REQUEST`): Email change request (`POST /users/me/email`)
- `AuditActionEmailChange` (`EMAIL_CHANGE`): Email change confirmation (`POST /users/me/email/confirm`)
- `AuditActionEmailChangeRevert` (`EMAIL_CHANGE_REVERT`): Email change undone from the notice link (`POST /users/revert-email-change`)
- `AuditActionOAuthLinkRevert` (`OAUTH_LINK_REVERT`): OAuth provider link undone from the notice link (`POST /auth/oauth/revert-link`); the resource is the user
- `AuditActionLogin` (`LOGIN`): Email/password authentication (`POST /auth/login`)
- `AuditActionOAuthLogin` (`OAUTH_LOGIN`): OAuth authentication (`GET /auth/{provider}/callback`)
- `AuditActionLogout` (`LOGOUT`): User session termination (`POST /auth/logout`)
- `AuditActionLogoutOthers` (`LOGOUT_OTHERS`): Termination of the other sessions (`POST /auth/logout-others`)
- `AuditActionPasswordResetRequest` (`PASSWORD_RESET_REQUEST`): Password reset requested (`POST /auth/password/forgot`); no actor, and the resource UUID is empty because the answer must not reveal whether the address has an account
- `AuditActionPasswordReset` (`PASSWORD_RESET`): Password set with the emailed code (`POST /auth/password/reset`); on success the resource is the user and there is no actor, because the request is unauthenticated
- `AuditActionPasswordChange` (`PASSWORD_CHANGE`): Password changed by the signed-in user (`POST /users/me/password`); the actor and the resource are the user
- `AuditActionStepUpRequest` (`STEP_UP_REQUEST`): Step-up code request (`POST /auth/step-up`)
- `AuditActionStepUpVerify` (`STEP_UP_VERIFY`): Step-up code verification (`POST /auth/step-up/verify`)
- `AuditActionFeatureFlagCreate` (`FEATURE_FLAG_CREATE`): Feature flag created (`POST /feature-flags`); the resource is the new flag (empty on failure) and `changes` holds the request body
- `AuditActionFeatureFlagUpdate` (`FEATURE_FLAG_UPDATE`): Feature flag updated (`PATCH /feature-flags/{uuid}`); `changes` holds the request body
- `AuditActionFeatureFlagDelete` (`FEATURE_FLAG_DELETE`): Feature flag deleted (`DELETE /feature-flags/{uuid}`)
- `AuditActionFeatureFlagUserAdd` (`FEATURE_FLAG_USER_ADD`): User added to a flag's allow-list (`PUT /feature-flags/{uuid}/users/{userUuid}`); the resource is the flag and `changes.user_uuid` the user
- `AuditActionFeatureFlagUserRemove` (`FEATURE_FLAG_USER_REMOVE`): User removed from a flag's allow-list (`DELETE /feature-flags/{uuid}/users/{userUuid}`); the resource is the flag and `changes.user_uuid` the user

**Resources:**

- `AuditResourceUser`: User-related actions
- `AuditResourceAuth`: Authentication-related actions
- `AuditResourceFeatureFlag` (`feature_flag`): Feature flag and allow-list actions

## Listing Audit Logs

`GET /audit-logs` requires an authenticated admin (auth and admin role middlewares) and returns the newest entries first.

| Query parameter                                        | Description                                                    |
| ------------------------------------------------------ | -------------------------------------------------------------- |
| `action`, `resource_type`, `status`, `actor_uuid`      | Exact-match filters                                            |
| `start_date`, `end_date`                               | RFC 3339 timestamps bounding `created_at` (`start_date` inclusive, `end_date` exclusive) |
| `limit`                                                | Page size, 1 to 100 (default 20)                               |
| `cursor`                                               | `meta.next_cursor` from the previous page                      |

Pagination is keyset-based on the UUIDv7 `uuid` (`uuid < cursor ORDER BY uuid DESC`), so pages stay stable while new entries arrive. `meta.total` is the number of entries matching the filters (the cursor is ignored), and `meta.next_cursor` is set only when at least one more entry follows the page. Invalid `limit` or dates return `400` with `audit.list.badRequest`.

## Database Schema

### Partitioned Table Design

```sql
CREATE TABLE audit_logs (
    uuid uuid DEFAULT uuidv7() NOT NULL,
    actor_uuid UUID,
    ip_address TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_uuid TEXT NOT NULL,
    request_uuid UUID NOT NULL,
    changes JSONB,
    status TEXT NOT NULL,
    failure_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (uuid, created_at)
) PARTITION BY RANGE (created_at);
```

### Key Schema Features

1. **Composite Primary Key**: `(uuid, created_at)` is required for partitioned tables. The partition key (`created_at`) must be included in the primary key.

2. **UUIDv7 for IDs**: Uses `uuidv7()` which embeds a timestamp, providing natural time-ordering and better index performance than random UUIDs.

3. **JSONB Changes Field**: Stores arbitrary structured data about what changed, allowing flexibility without schema migrations.

4. **Nullable Actor**: `actor_uuid` is nullable to support system-initiated actions and anonymous requests.

5. **Default Partition**: A fallback partition (`audit_logs_default`) catches any data that doesn't match specific monthly partitions, ensuring no data loss if the partition manager fails.

### Indexes

Three strategic indexes optimize common query patterns:

```sql
-- Correlate all logs from a single HTTP request
CREATE INDEX idx_audit_logs_request ON audit_logs(request_uuid);

-- Find complete history of a specific resource
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource_type, resource_uuid);

-- Track all actions by a specific user
CREATE INDEX idx_audit_logs_actor ON audit_logs(actor_uuid);
```

## Partition Strategy

### Why Partitioning?

Audit logs are a classic use case for table partitioning because they:

1. **Grow indefinitely**: Every action creates a new log entry
2. **Are rarely updated**: Audit logs are write-once, read-occasionally
3. **Have time-based queries**: Most queries filter by date ranges
4. **Benefit from pruning**: Old data can be archived or dropped efficiently

### Range Partitioning by Month

The system uses **RANGE partitioning** on the `created_at` timestamp column, creating one partition per calendar month.

#### Partition Naming Convention

Partitions follow the naming pattern: `audit_logs_YYYY_MM`

Examples:

- `audit_logs_2026_02` → February 2026
- `audit_logs_2026_03` → March 2026

#### Partition Boundaries

Each partition covers exactly one calendar month:

```
audit_logs_2026_02:
  FROM '2026-02-01 00:00:00+00'
  TO   '2026-03-01 00:00:00+00'  (exclusive)
```

### Performance Benefits

#### 1. Partition Pruning

PostgreSQL's query planner automatically excludes irrelevant partitions when queries include date filters:

```sql
-- Only scans audit_logs_2026_02 partition
SELECT * FROM audit_logs
WHERE created_at >= '2026-02-01' AND created_at < '2026-03-01';
```

#### 2. Smaller Indexes

Each partition has its own set of indexes. Smaller indexes mean:

- **Faster writes**: Index updates are quicker on smaller trees
- **Better cache hit rates**: Hot partitions (current month) fit in memory
- **Reduced bloat**: Older partitions remain compact and stable

**Example**: With 12 months of data, a query on the current month only touches 1/12th of the total index size.

#### 3. Efficient Data Lifecycle Management

Old audit data can be:

- **Archived**: Detach partition and move to cold storage
- **Compressed**: Convert old partitions to read-only compressed tables
- **Purged**: Drop entire partitions in milliseconds (vs. hours for `DELETE`)

```sql
-- Drop an old partition instantly (no table scan)
DROP TABLE audit_logs_2024_01;
```

#### 4. Parallelism

PostgreSQL can scan multiple partitions in parallel when executing queries that span multiple months, leveraging multi-core CPUs.

### Why Monthly Partitions?

The choice of monthly granularity balances several factors:

| Granularity | Pros                                      | Cons                                       |
| ----------- | ----------------------------------------- | ------------------------------------------ |
| Daily       | Maximum pruning efficiency                | Too many partitions (overhead, complexity) |
| **Monthly** | **Good balance: ~12 new partitions/year** | **Ideal for most applications**            |
| Yearly      | Fewer partitions                          | Large partitions reduce pruning benefits   |

For most applications, monthly partitions provide optimal performance without excessive management overhead.

## Partition Manager

### Automatic Partition Creation

The `AuditLogsPartitionManager` ensures partitions exist before they're needed:

```go
type AuditLogsPartitionManager struct {
    db postgres.DBTX
}
```

### Initialization

On application startup (`cmd/api/main.go`):

```go
partitionManager := infra.NewAuditLogsPartitionManager(pool)
if err := partitionManager.RunMaintenance(ctx); err != nil {
    slog.Error("Failed to initialize audit log partitions", "error", err)
    os.Exit(1)
}
```

This ensures the current and next month's partitions exist immediately.

### Maintenance Schedule

A background goroutine (`runEvery` in `cmd/api/main.go`) runs maintenance every 24 hours and stops when the shutdown signal cancels `ctx`; graceful shutdown waits for it:

```go
runEvery(
    ctx, &wg, 24*time.Hour,
    func() {
        if err := partitionManager.RunMaintenance(ctx); err != nil {
            slog.Error("Failed to maintain audit log partitions", "error", err)
        }
    },
)
```

### Maintenance Operations

`RunMaintenance()` performs two operations:

1. **Ensure current month partition exists**: For incoming writes
2. **Ensure next month partition exists**: Prevents midnight month-rollover failures

### Concurrency Safety

The partition manager uses **PostgreSQL advisory locks** to prevent race conditions:

```go
// Acquire transaction-level advisory lock
_, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", auditLogsPartitionLockID)
```

**Benefits:**

- Multiple application instances can run safely
- Lock is automatically released on transaction commit/rollback
- No external coordination required (Redis, etcd, etc.)

### Partition Creation Logic

```go
func (pm *AuditLogsPartitionManager) EnsurePartition(ctx context.Context, date time.Time) error {
    // 1. Start transaction
    // 2. Acquire advisory lock (8374928374)
    // 3. Check if partition exists
    // 4. If not, create partition:
    //    CREATE TABLE audit_logs_2026_02
    //    PARTITION OF audit_logs
    //    FOR VALUES FROM ('2026-02-01') TO ('2026-03-01')
    // 5. Commit transaction (releases lock)
}
```

### Error Handling

- If partition creation fails, the transaction rolls back
- The default partition (`audit_logs_default`) catches any writes that fall through
- A failure on startup stops the application; failures of the background maintenance are logged and don't crash it

## Summary

The audit system provides:

✅ **Complete audit trail** for compliance and debugging  
✅ **Excellent query performance** via partition pruning and targeted indexes  
✅ **Automatic maintenance** with zero manual intervention  
✅ **Safe concurrency** using PostgreSQL advisory locks  
✅ **Efficient data lifecycle** through partition-level operations  
✅ **Flexible schema** using JSONB for changes  
✅ **Production-ready** with proper error handling and logging

The combination of range partitioning, strategic indexes, and automatic partition management ensures the audit system scales effortlessly.
