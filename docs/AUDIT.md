# Audit System Documentation

## Overview

This project implements a comprehensive audit logging system designed to track all significant actions performed within the application. The audit system captures who did what, when, where, and the outcome of each action, providing a complete trail for security, compliance, and debugging purposes.

## Architecture

The audit system follows the project's layered architecture pattern and consists of four main components:

### 1. Domain Layer (`internal/domain/audit.go`)

Defines the core audit data structures and interfaces:

- **`AuditLog`**: The domain model representing a single audit log entry
- **`CreateAuditLogDTO`**: Data Transfer Object for creating new audit logs
- **`AuditRepository`**: Interface for persistence operations
- **`AuditService`**: Interface for business logic (not yet implemented)

### 2. Repository Layer (`internal/repositories/audit_repository.go`)

Implements data persistence through `AuditPostgresRepository`:

- Converts domain models to PostgreSQL-compatible types (`pgtype.UUID`, `pgtype.Text`)
- Marshals the `Changes` field to JSONB for flexible storage
- Uses `sqlc`-generated queries for type-safe database operations

### 3. Infrastructure Layer (`internal/infra/audit_logs_partition_manager.go`)

Manages database partitions to ensure optimal performance:

- **`AuditLogsPartitionManager`**: Automatically creates and maintains monthly partitions
- Runs maintenance on application startup and every 24 hours
- Uses PostgreSQL advisory locks to prevent race conditions

### 4. Database Layer (`postgres/migrations/000001_init_db.up.sql`)

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
    CreatedAt     int64   // Unix timestamp of when the log was created
}
```

### Constants

The domain package defines type-safe constants for common values:

**Status:**

- `AuditStatusSuccess`: Action completed successfully
- `AuditStatusFailure`: Action failed

**Actions:**

- `AuditActionUserCreate`: User account creation
- `AuditActionUserUpdate`: User account modification
- `AuditActionUserDelete`: User account deletion
- `AuditActionLogin`: User authentication
- `AuditActionLogout`: User session termination

**Resources:**

- `AuditResourceUser`: User-related actions
- `AuditResourceAuth`: Authentication-related actions

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

On application startup (`cmd/main.go`):

```go
partitionManager := infra.NewAuditLogsPartitionManager(conn)
if err := partitionManager.RunMaintenance(ctx); err != nil {
    slog.Error("Failed to initialize audit log partitions", "error", err)
    os.Exit(1)
}
```

This ensures the current and next month's partitions exist immediately.

### Maintenance Schedule

A background goroutine runs maintenance every 24 hours:

```go
go func() {
    ticker := time.NewTicker(24 * time.Hour)
    defer ticker.Stop()
    for range ticker.C {
        if err := partitionManager.RunMaintenance(context.Background()); err != nil {
            slog.Error("Failed to maintain audit log partitions", "error", err)
        }
    }
}()
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
- Errors are logged but don't crash the application (fire-and-forget for background maintenance)

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
