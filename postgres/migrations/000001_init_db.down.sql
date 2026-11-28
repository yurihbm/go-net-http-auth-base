DROP TABLE IF EXISTS feature_flag_users;

DROP TRIGGER IF EXISTS update_feature_flags_updated_at ON feature_flags;

DROP TABLE IF EXISTS feature_flags;

DROP TABLE IF EXISTS audit_logs;

DROP TABLE IF EXISTS email_send_limits;

DROP TABLE IF EXISTS password_resets;

DROP TABLE IF EXISTS pending_signups;

DROP TYPE IF EXISTS pending_signup_kind;

DROP TABLE IF EXISTS session_challenges;

DROP TYPE IF EXISTS session_challenge_purpose;

DROP TABLE IF EXISTS user_sessions;

DROP TABLE IF EXISTS user_oauth_providers;

DROP TYPE IF EXISTS oauth_provider;

DROP TRIGGER IF EXISTS update_users_updated_at ON users;

DROP FUNCTION IF EXISTS update_updated_at_column;

DROP TABLE IF EXISTS users;

DROP TYPE IF EXISTS user_role;

DROP EXTENSION IF EXISTS "pgcrypto";

