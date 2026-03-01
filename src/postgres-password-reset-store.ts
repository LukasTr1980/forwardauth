import { createHash, createHmac, randomUUID } from 'node:crypto';
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
    reused: boolean;
}

interface PasswordResetTokenRow {
    id: string;
    user_id: string;
    token_hash: string;
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
    tokenSecret: string;
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
    private readonly tokenSecret: string;

    constructor(options: PostgresPasswordResetStoreOptions) {
        this.pool = new Pool({
            connectionString: options.databaseUrl,
            max: options.maxPoolSize,
            ...(options.ssl ? { ssl: { rejectUnauthorized: false } } : {}),
        });
        this.tokenSecret = options.tokenSecret;
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

    private buildReusableToken(tokenId: string): string {
        const idPart = tokenId.replace(/-/g, '');
        const mac = createHmac('sha256', this.tokenSecret)
            .update(tokenId)
            .digest('base64url');
        return `${idPart}${mac}`;
    }

    async issueTokenForUser(input: PasswordResetIssueInput): Promise<PasswordResetIssueResult> {
        return this.withTransaction(async (client) => {
            const existingResult = await client.query<PasswordResetTokenRow>(`
                SELECT
                    id,
                    user_id,
                    token_hash,
                    expires_at,
                    consumed_at
                FROM password_reset_tokens
                WHERE user_id = $1 AND consumed_at IS NULL
                ORDER BY created_at DESC
                LIMIT 1
                FOR UPDATE
            `, [input.userId]);

            const existing = existingResult.rows[0];
            if (existing) {
                const expiresAtMs = parseTimestamp(existing.expires_at);
                const notExpired = Number.isFinite(expiresAtMs) && expiresAtMs > Date.now();
                if (notExpired) {
                    const token = this.buildReusableToken(existing.id);
                    if (hashToken(token) === existing.token_hash) {
                        return {
                            token,
                            expiresAt: new Date(expiresAtMs),
                            reused: true,
                        };
                    }
                }

                await client.query(
                    'UPDATE password_reset_tokens SET consumed_at = now() WHERE id = $1 AND consumed_at IS NULL',
                    [existing.id],
                );
            }

            await client.query(
                'UPDATE password_reset_tokens SET consumed_at = now() WHERE user_id = $1 AND consumed_at IS NULL',
                [input.userId],
            );

            const expiresAt = new Date(Date.now() + input.ttlSeconds * 1000);

            for (let attempt = 0; attempt < 5; attempt++) {
                const tokenId = randomUUID();
                const token = this.buildReusableToken(tokenId);
                const tokenDigest = hashToken(token);

                try {
                    await client.query(
                        `
                        INSERT INTO password_reset_tokens (
                            id,
                            user_id,
                            token_hash,
                            expires_at,
                            requested_ip,
                            requested_user_agent
                        )
                        VALUES ($1, $2, $3, $4, $5, $6)
                        `,
                        [
                            tokenId,
                            input.userId,
                            tokenDigest,
                            expiresAt,
                            input.requestedIp ?? null,
                            input.requestedUserAgent ?? null,
                        ],
                    );
                    return { token, expiresAt, reused: false };
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
