CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email text NOT NULL UNIQUE,
    password_hash text NOT NULL,
    is_admin boolean NOT NULL DEFAULT false,
    is_adult boolean NOT NULL DEFAULT false,
    host_access_mode text NOT NULL DEFAULT 'all',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz NULL,
    CONSTRAINT users_email_normalized_chk CHECK (email = lower(btrim(email))),
    CONSTRAINT users_host_access_mode_chk CHECK (host_access_mode IN ('all', 'deny_all', 'allow_list'))
);

CREATE TABLE IF NOT EXISTS user_allowed_hosts (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    host_pattern text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, host_pattern)
);

CREATE OR REPLACE FUNCTION set_updated_at_timestamp()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_users_updated_at ON users;
CREATE TRIGGER trg_users_updated_at
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION set_updated_at_timestamp();
