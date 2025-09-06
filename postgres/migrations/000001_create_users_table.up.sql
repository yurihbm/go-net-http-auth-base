CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TYPE auth_method_enum AS ENUM (
    'email',
    'google'
);

CREATE TABLE users (
    uuid uuid DEFAULT uuidv7() NOT NULL UNIQUE PRIMARY KEY,
    name text NOT NULL,
    email text UNIQUE NOT NULL,
    password_hash text,
    created_at timestamptz DEFAULT NOW() NOT NULL,
    updated_at timestamptz DEFAULT NOW() NOT NULL,
    auth_method auth_method_enum NOT NULL DEFAULT 'email'
);

CREATE OR REPLACE FUNCTION update_updated_at_column ()
    RETURNS TRIGGER
    AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$
LANGUAGE 'plpgsql';

CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE PROCEDURE update_updated_at_column ();

