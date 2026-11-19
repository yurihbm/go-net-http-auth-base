DROP TABLE IF EXISTS audit_logs;

DROP TABLE IF EXISTS email_send_limits;

DROP TABLE IF EXISTS pending_signups;

DROP TYPE IF EXISTS pending_signup_kind;

DROP TABLE IF EXISTS step_up_challenges;

DROP TABLE IF EXISTS user_sessions;

DROP TABLE IF EXISTS user_oauth_providers;

DROP TYPE IF EXISTS oauth_provider;

DROP TRIGGER IF EXISTS update_users_updated_at ON users;

DROP FUNCTION IF EXISTS update_updated_at_column;

DROP TABLE IF EXISTS users;

DROP TYPE IF EXISTS user_role;

DROP EXTENSION IF EXISTS "pgcrypto";

