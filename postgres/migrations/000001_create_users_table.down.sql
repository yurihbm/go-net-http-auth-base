DROP TRIGGER IF EXISTS update_users_updated_at ON users;

DROP FUNCTION IF EXISTS update_updated_at_column ();

DROP TABLE IF EXISTS users;

DROP TYPE IF EXISTS auth_method_enum;

DROP EXTENSION IF EXISTS "pgcrypto";

