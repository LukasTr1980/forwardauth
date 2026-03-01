import { createHash, randomBytes } from 'node:crypto';
import { Pool, type PoolClient } from 'pg';

export interface PasswordResetIssueInput {
    userId: string;
    ttlSeconds: number;
    requestedIp?: string;
    requestedUserAgent?: string;
}

export interface PasswordResetIssueResult {
    token: string;
    expiresAt: Date;
}

interface PasswordResetTokenRow {
    id: string;
    user_id: string;
    expires_at: Date | string;
    consumed_at: Date | string | null;
}

export interface PasswordResetStore {
    loadInitial(): Promise<void>;
    issueTokenForUser(input: PasswordResetIssueInput): Promise<PasswordResetIssueResult>;
    consumeTokenAndUpdatePassword(token: string, passwordHash: string): Promise<string | null>;
}

export interface PostgresPasswordResetStoreOptions {
    databaseUrl: string;
    maxPoolSize?: number;
    ssl?: boolean;
}

function hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
}

function parseTimestamp(value: Date | string): number {
    const date = value instanceof Date ? value : new Date(value);
    return date.getTime();
}

export class PostgresPasswordResetStore implements PasswordResetStore {
    private readonly pool: Pool;

    constructor(options: PostgresPasswordResetStoreOptions) {
        this.pool = new Pool({
            connectionString: options.databaseUrl,
            max: options.maxPoolSize,
            ...(options.ssl ? { ssl: { rejectUnauthorized: false } } : {}),
        });
    }

    async loadInitial(): Promise<void> {
        await this.pool.query('SELECT 1');
    }

    private async withTransaction<T>(fn: (client: PoolClient) => Promise<T>): Promise<T> {
        const client = await this.pool.connect();
        try {
            await client.query('BEGIN');
            const result = await fn(client);
            await client.query('COMMIT');
            return result;
        } catch (error) {
            await client.query('ROLLBACK');
            throw error;
        } finally {
            client.release();
        }
    }

    async issueTokenForUser(input: PasswordResetIssueInput): Promise<PasswordResetIssueResult> {
        return this.withTransaction(async (client) => {
            await client.query(
                'UPDATE password_reset_tokens SET consumed_at = now() WHERE user_id = $1 AND consumed_at IS NULL',
                [input.userId],
            );

            const expiresAt = new Date(Date.now() + input.ttlSeconds * 1000);

            for (let attempt = 0; attempt < 5; attempt++) {
                const token = randomBytes(32).toString('base64url');
                const tokenDigest = hashToken(token);

                try {
                    await client.query(
                        `
                        INSERT INTO password_reset_tokens (
                            user_id,
                            token_hash,
                            expires_at,
                            requested_ip,
                            requested_user_agent
                        )
                        VALUES ($1, $2, $3, $4, $5)
                        `,
                        [
                            input.userId,
                            tokenDigest,
                            expiresAt,
                            input.requestedIp ?? null,
                            input.requestedUserAgent ?? null,
                        ],
                    );
                    return { token, expiresAt };
                } catch (error) {
                    const code = (error as { code?: string }).code;
                    if (code === '23505') {
                        continue;
                    }
                    throw error;
                }
            }

            throw new Error('Failed to generate a unique password reset token.');
        });
    }

    async consumeTokenAndUpdatePassword(token: string, passwordHash: string): Promise<string | null> {
        const tokenDigest = hashToken(token);

        return this.withTransaction(async (client) => {
            const tokenResult = await client.query<PasswordResetTokenRow>(
                `
                SELECT
                    id,
                    user_id,
                    expires_at,
                    consumed_at
                FROM password_reset_tokens
                WHERE token_hash = $1
                FOR UPDATE
                LIMIT 1
                `,
                [tokenDigest],
            );

            const row = tokenResult.rows[0];
            if (!row) {
                return null;
            }

            const consumedAtPresent = row.consumed_at !== null;
            const expiresAtMs = parseTimestamp(row.expires_at);
            const expired = !Number.isFinite(expiresAtMs) || expiresAtMs <= Date.now();

            if (consumedAtPresent || expired) {
                if (!consumedAtPresent) {
                    await client.query(
                        'UPDATE password_reset_tokens SET consumed_at = now() WHERE id = $1 AND consumed_at IS NULL',
                        [row.id],
                    );
                }
                return null;
            }

            const updatedUser = await client.query<{ id: string }>(
                'UPDATE users SET password_hash = $1 WHERE id = $2 AND disabled_at IS NULL RETURNING id',
                [passwordHash, row.user_id],
            );

            if (updatedUser.rowCount !== 1) {
                await client.query(
                    'UPDATE password_reset_tokens SET consumed_at = now() WHERE id = $1 AND consumed_at IS NULL',
                    [row.id],
                );
                return null;
            }

            await client.query(
                'UPDATE password_reset_tokens SET consumed_at = now() WHERE user_id = $1 AND consumed_at IS NULL',
                [row.user_id],
            );

            return row.user_id;
        });
    }
}
