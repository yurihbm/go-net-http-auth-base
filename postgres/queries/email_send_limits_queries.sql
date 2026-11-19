-- name: ReserveEmailSend :one
INSERT INTO email_send_limits (email, window_start, sends, last_sent_at)
    VALUES ($1, now(), 1, now())
ON CONFLICT (email)
    DO UPDATE SET
        sends = CASE WHEN email_send_limits.window_start < now() - sqlc.arg(send_window)::interval THEN
            1
        ELSE
            email_send_limits.sends + 1
        END,
        window_start = CASE WHEN email_send_limits.window_start < now() - sqlc.arg(send_window)::interval THEN
            now()
        ELSE
            email_send_limits.window_start
        END,
        last_sent_at = now()
    WHERE (email_send_limits.last_sent_at IS NULL
        OR email_send_limits.last_sent_at < now() - sqlc.arg(cooldown)::interval)
    AND (email_send_limits.window_start < now() - sqlc.arg(send_window)::interval
        OR email_send_limits.sends < sqlc.arg(max_sends)::int)
RETURNING
    sends;

-- name: GetEmailCodeFailures :one
SELECT
    COALESCE((
        SELECT
            l.failures
        FROM email_send_limits l
        WHERE
            l.email = $1
            AND l.failures_window_start > now() - sqlc.arg(failure_window)::interval), 0)::int AS failures;

-- name: RecordEmailCodeFailure :one
INSERT INTO email_send_limits (email, failures, failures_window_start)
    VALUES ($1, 1, now())
ON CONFLICT (email)
    DO UPDATE SET
        failures = CASE WHEN email_send_limits.failures_window_start IS NULL
            OR email_send_limits.failures_window_start < now() - sqlc.arg(failure_window)::interval THEN
            1
        ELSE
            email_send_limits.failures + 1
        END,
        failures_window_start = CASE WHEN email_send_limits.failures_window_start IS NULL
            OR email_send_limits.failures_window_start < now() - sqlc.arg(failure_window)::interval THEN
            now()
        ELSE
            email_send_limits.failures_window_start
        END
    RETURNING
        failures;

-- name: DeleteStaleEmailSendLimitsBatch :execrows
DELETE FROM
    email_send_limits
WHERE
    email IN (
        SELECT
            l.email
        FROM
            email_send_limits l
        WHERE
            l.window_start < now() - sqlc.arg(send_window)::interval
            AND (l.failures_window_start IS NULL
                OR l.failures_window_start < now() - sqlc.arg(failure_window)::interval)
        LIMIT sqlc.arg(batch_size)::int);
