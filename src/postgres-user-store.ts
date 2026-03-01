import { Pool } from 'pg';

export type HostAccessMode = 'all' | 'deny_all' | 'allow_list';

export interface UserAuthRecord {
    id: string;
    email: string;
    passwordHash: string;
    isAdmin: boolean;
    isAdult: boolean;
    hostAccessMode: HostAccessMode;
    allowedHosts: string[];
}

export interface UserStore {
    getUserByEmail(email: string): Promise<UserAuthRecord | null>;
    getUserById(id: string): Promise<UserAuthRecord | null>;
    updatePasswordHashById?(id: string, passwordHash: string): Promise<boolean>;
    loadInitial(): Promise<void>;
}

interface PostgresUserRow {
    id: string;
    email: string;
    password_hash: string;
    is_admin: boolean;
    is_adult: boolean;
    host_access_mode: HostAccessMode;
    allowed_hosts: string[] | null;
}

function mapRow(row: PostgresUserRow): UserAuthRecord {
    return {
        id: row.id,
        email: row.email,
        passwordHash: row.password_hash,
        isAdmin: row.is_admin,
        isAdult: row.is_adult,
        hostAccessMode: row.host_access_mode,
        allowedHosts: Array.isArray(row.allowed_hosts) ? row.allowed_hosts : [],
    };
}

export interface PostgresUserStoreOptions {
    databaseUrl: string;
    maxPoolSize?: number;
    ssl?: boolean;
}

export class PostgresUserStore implements UserStore {
    private readonly pool: Pool;

    constructor(options: PostgresUserStoreOptions) {
        this.pool = new Pool({
            connectionString: options.databaseUrl,
            max: options.maxPoolSize,
            ...(options.ssl ? { ssl: { rejectUnauthorized: false } } : {}),
        });
    }

    async loadInitial(): Promise<void> {
        await this.pool.query('SELECT 1');
    }

    async getUserByEmail(email: string): Promise<UserAuthRecord | null> {
        const result = await this.pool.query<PostgresUserRow>(`
            SELECT
                u.id,
                u.email,
                u.password_hash,
                u.is_admin,
                u.is_adult,
                u.host_access_mode,
                COALESCE(array_agg(h.host_pattern ORDER BY h.host_pattern) FILTER (WHERE h.host_pattern IS NOT NULL), '{}') AS allowed_hosts
            FROM users u
            LEFT JOIN user_allowed_hosts h ON h.user_id = u.id
            WHERE u.email = $1 AND u.disabled_at IS NULL
            GROUP BY u.id, u.email, u.password_hash, u.is_admin, u.is_adult, u.host_access_mode
            LIMIT 1
        `, [email]);
        const row = result.rows[0];
        return row ? mapRow(row) : null;
    }

    async getUserById(id: string): Promise<UserAuthRecord | null> {
        const result = await this.pool.query<PostgresUserRow>(`
            SELECT
                u.id,
                u.email,
                u.password_hash,
                u.is_admin,
                u.is_adult,
                u.host_access_mode,
                COALESCE(array_agg(h.host_pattern ORDER BY h.host_pattern) FILTER (WHERE h.host_pattern IS NOT NULL), '{}') AS allowed_hosts
            FROM users u
            LEFT JOIN user_allowed_hosts h ON h.user_id = u.id
            WHERE u.id = $1 AND u.disabled_at IS NULL
            GROUP BY u.id, u.email, u.password_hash, u.is_admin, u.is_adult, u.host_access_mode
            LIMIT 1
        `, [id]);
        const row = result.rows[0];
        return row ? mapRow(row) : null;
    }

    async updatePasswordHashById(id: string, passwordHash: string): Promise<boolean> {
        const result = await this.pool.query(
            'UPDATE users SET password_hash = $1 WHERE id = $2 AND disabled_at IS NULL',
            [passwordHash, id],
        );
        return (result.rowCount ?? 0) > 0;
    }
}
