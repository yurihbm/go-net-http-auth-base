DROP TABLE IF EXISTS audit_logs;

DROP TABLE IF EXISTS user_oauth_providers;

DROP TYPE IF EXISTS oauth_provider;

DROP TRIGGER IF EXISTS update_users_updated_at ON users;

DROP FUNCTION IF EXISTS update_updated_at_column;

DROP TABLE IF EXISTS users;

DROP EXTENSION IF EXISTS "pgcrypto";

