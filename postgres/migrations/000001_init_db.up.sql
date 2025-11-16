CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE users (
    uuid uuid DEFAULT uuidv7() NOT NULL UNIQUE PRIMARY KEY,
    name text NOT NULL,
    email text UNIQUE NOT NULL,
    password_hash text,
    created_at timestamptz DEFAULT now() NOT NULL,
    updated_at timestamptz DEFAULT now() NOT NULL
);

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS trigger
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
EXECUTE PROCEDURE update_updated_at_column();

CREATE TYPE oauth_provider AS ENUM (
    'google',
    'microsoft',
    'github'
);

CREATE TABLE user_oauth_providers (
    uuid uuid DEFAULT uuidv7() NOT NULL UNIQUE PRIMARY KEY,
    user_uuid uuid REFERENCES users (uuid) ON DELETE CASCADE,
    provider oauth_provider NOT NULL,
    provider_user_id text NOT NULL,
    provider_email text NOT NULL,
    created_at timestamptz DEFAULT now() NOT NULL,
    UNIQUE (provider, provider_user_id)
);
