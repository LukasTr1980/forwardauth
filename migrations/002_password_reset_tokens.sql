CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash text NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz NULL,
    requested_ip text NULL,
    requested_user_agent text NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user_id
    ON password_reset_tokens (user_id);

CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_expires_at
    ON password_reset_tokens (expires_at);

CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user_active
    ON password_reset_tokens (user_id)
    WHERE consumed_at IS NULL;
