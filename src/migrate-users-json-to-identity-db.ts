import fs from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { Pool } from 'pg';

interface JsonUser {
    hash: string;
    allowedHosts?: string[];
    isAdult?: boolean;
    isAdmin?: boolean;
}

type HostAccessMode = 'all' | 'deny_all' | 'allow_list';

function normalizeEmailIdentifier(value: string): string {
    return value.trim().toLowerCase();
}

function isStringArray(value: unknown): value is string[] {
    return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

function isRecordOfUser(data: unknown): data is Record<string, JsonUser> {
    return (
        typeof data === 'object' &&
        data !== null &&
        Object.values(data).every(
            (u) => typeof (u as JsonUser).hash === 'string' &&
                ((u as JsonUser).allowedHosts === undefined || isStringArray((u as JsonUser).allowedHosts)) &&
                ((u as JsonUser).isAdult === undefined || typeof (u as JsonUser).isAdult === 'boolean') &&
                ((u as JsonUser).isAdmin === undefined || typeof (u as JsonUser).isAdmin === 'boolean')
        )
    );
}

function extractTopLevelUserKeys(jsonContent: string): string[] {
    const keys: string[] = [];
    let inString = false;
    let escaped = false;
    let depth = 0;
    let current = '';
    let lastString: string | null = null;

    for (const char of jsonContent) {
        if (inString) {
            if (escaped) {
                current += char;
                escaped = false;
                continue;
            }
            if (char === '\\') {
                current += char;
                escaped = true;
                continue;
            }
            if (char === '"') {
                inString = false;
                lastString = current;
                current = '';
                continue;
            }
            current += char;
            continue;
        }

        if (char === '"') {
            inString = true;
            current = '';
            continue;
        }

        if (char === '{') {
            depth++;
            continue;
        }

        if (char === '}') {
            depth = Math.max(0, depth - 1);
            lastString = null;
            continue;
        }

        if (char === ':' && depth === 1 && lastString !== null) {
            try {
                keys.push(JSON.parse(`"${lastString}"`) as string);
            } catch {
                keys.push(lastString);
            }
            lastString = null;
            continue;
        }

        if (char === ',' || char.trim() !== '') {
            lastString = null;
        }
    }

    return keys;
}

function findDuplicateEmails(jsonContent: string): string[] {
    const keys = extractTopLevelUserKeys(jsonContent);
    const seen = new Set<string>();
    const duplicates = new Set<string>();
    for (const key of keys) {
        const normalized = normalizeEmailIdentifier(key);
        if (seen.has(normalized)) duplicates.add(normalized);
        else seen.add(normalized);
    }
    return Array.from(duplicates);
}

function findNonNormalizedEmails(jsonContent: string): string[] {
    return extractTopLevelUserKeys(jsonContent).filter((key) => normalizeEmailIdentifier(key) !== key);
}

function getHostAccessMode(user: JsonUser): HostAccessMode {
    if (user.allowedHosts === undefined) return 'all';
    if (user.allowedHosts.length === 0) return 'deny_all';
    return 'allow_list';
}

function getInputFilePath(): string {
    const cliPath = process.argv[2];
    if (cliPath) return path.resolve(process.cwd(), cliPath);
    return process.env.USER_FILE ?? path.resolve(process.cwd(), 'users.json');
}

function getEnvSecret(key: string, fileKey: string): string | undefined {
    const filePath = process.env[fileKey];
    if (filePath) {
        return readFileSync(filePath, 'utf-8').trim();
    }
    return process.env[key];
}

async function main(): Promise<void> {
    const inputFile = getInputFilePath();
    const databaseUrl = getEnvSecret('IDENTITY_DATABASE_URL', 'IDENTITY_DATABASE_URL_FILE');
    const ssl = process.env.IDENTITY_DB_SSL === '1' || process.env.IDENTITY_DB_SSL === 'true';

    if (!databaseUrl) {
        throw new Error('IDENTITY_DATABASE_URL is required.');
    }

    const rawContent = await fs.readFile(inputFile, 'utf-8');
    const duplicateEmails = findDuplicateEmails(rawContent);
    const nonNormalizedEmails = findNonNormalizedEmails(rawContent);
    if (duplicateEmails.length > 0) {
        throw new Error(`Duplicate emails detected: ${duplicateEmails.join(', ')}`);
    }
    if (nonNormalizedEmails.length > 0) {
        throw new Error(`users.json keys must be lowercase/trimmed emails: ${nonNormalizedEmails.join(', ')}`);
    }

    const parsed: unknown = JSON.parse(rawContent);
    if (!isRecordOfUser(parsed)) {
        throw new Error('Invalid users.json structure');
    }

    const users = parsed;
    const pool = new Pool({
        connectionString: databaseUrl,
        ...(ssl ? { ssl: { rejectUnauthorized: false } } : {}),
    });
    const client = await pool.connect();

    let totalUsers = 0;
    let hostRows = 0;
    let modeAll = 0;
    let modeDenyAll = 0;
    let modeAllowList = 0;

    try {
        await client.query('BEGIN');

        for (const [email, user] of Object.entries(users)) {
            const hostAccessMode = getHostAccessMode(user);
            if (hostAccessMode === 'all') modeAll++;
            if (hostAccessMode === 'deny_all') modeDenyAll++;
            if (hostAccessMode === 'allow_list') modeAllowList++;

            const userResult = await client.query<{ id: string }>(`
                INSERT INTO users (email, password_hash, is_admin, is_adult, host_access_mode)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (email) DO UPDATE SET
                    password_hash = EXCLUDED.password_hash,
                    is_admin = EXCLUDED.is_admin,
                    is_adult = EXCLUDED.is_adult,
                    host_access_mode = EXCLUDED.host_access_mode
                RETURNING id
            `, [email, user.hash, user.isAdmin === true, user.isAdult === true, hostAccessMode]);

            const userId = userResult.rows[0]?.id;
            if (!userId) {
                throw new Error(`Failed to upsert user ${email}`);
            }

            await client.query('DELETE FROM user_allowed_hosts WHERE user_id = $1', [userId]);
            const hosts = user.allowedHosts ?? [];
            for (const host of hosts) {
                await client.query(
                    'INSERT INTO user_allowed_hosts (user_id, host_pattern) VALUES ($1, $2) ON CONFLICT DO NOTHING',
                    [userId, host],
                );
                hostRows++;
            }

            totalUsers++;
        }

        await client.query('COMMIT');
    } catch (error) {
        await client.query('ROLLBACK');
        throw error;
    } finally {
        client.release();
        await pool.end();
    }

    console.log(`Imported ${totalUsers} users into identity DB.`);
    console.log(`Host rows: ${hostRows}`);
    console.log(`host_access_mode counts: all=${modeAll} deny_all=${modeDenyAll} allow_list=${modeAllowList}`);
}

void main().catch((error) => {
    console.error('[migrate-users-json-to-identity-db] ERROR:', error);
    process.exit(1);
});
