import express, { type Request, type RequestHandler } from 'express';
import { type ParamsDictionary } from 'express-serve-static-core';
import rateLimit, { type Store as RateLimitStore } from 'express-rate-limit';
import { RedisStore, type RedisReply } from 'rate-limit-redis';
import { createClient } from 'redis';
import * as cookie from 'cookie';
import { SignJWT, jwtVerify } from 'jose';
import {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse,
    type AuthenticationResponseJSON,
    type RegistrationResponseJSON,
    type AuthenticatorTransportFuture,
    type WebAuthnCredential,
} from '@simplewebauthn/server';
import argon2 from 'argon2';
import fs from 'fs/promises';
import { watchFile, readFileSync } from 'node:fs';
import path from 'path';
import helmet from 'helmet';
import he from 'he';
import validator from 'validator';
import { randomUUID } from 'node:crypto';
// CSRF cookie removed; we rely on Origin/Referer checks for POST /auth

interface User {
    hash: string;
    allowedHosts?: string[];
    isAdult?: boolean;
    isAdmin?: boolean;
}

interface LoginQuery {
    redirect_uri?: string;
    setup_passkey?: string;
}

interface LoginBody {
    email?: string;
    password?: string;
    redirect_uri?: string;
}

interface PasskeyAuthOptionsBody {
    email?: string;
    redirect_uri?: string;
}

interface PasskeyAuthVerifyBody {
    flowId?: string;
    redirect_uri?: string;
    credential?: AuthenticationResponseJSON;
}

interface PasskeyRegisterOptionsBody {
    email?: string;
}

interface PasskeyRegisterVerifyBody {
    flowId?: string;
    credential?: RegistrationResponseJSON;
}

interface PasskeyCredentialDeleteBody {
    credentialId?: string;
}

function getEnvAsNumber(key: string, defaultValue: number): number {
    const value = parseInt(process.env[key] ?? '', 10);
    return Number.isFinite(value) ? value : defaultValue;
}

function parseCsvList(value?: string): string[] {
    if (!value) return [];
    return value.split(',').map((item) => item.trim()).filter(Boolean);
}

function normalizeEmailIdentifier(value: string): string {
    return value.trim().toLowerCase();
}

function parseRequiredLoginEmail(value: unknown): string {
    if (typeof value !== 'string') {
        throw new Error('Bitte geben Sie eine E-Mail-Adresse ein.');
    }

    const normalized = normalizeEmailIdentifier(value);
    if (!normalized) {
        throw new Error('Bitte geben Sie eine E-Mail-Adresse ein.');
    }

    if (!validator.isEmail(normalized, {
        allow_utf8_local_part: false,
        require_tld: true,
        allow_ip_domain: false,
        domain_specific_validation: true,
    })) {
        throw new Error('Bitte geben Sie eine gültige E-Mail-Adresse ein.');
    }

    return normalized;
}

function normalizePathPrefix(prefix: string): string {
    if (!prefix) return '';
    if (!prefix.startsWith('/')) return `/${prefix}`;
    return prefix;
}

// Simple log level gate: LOG_LEVEL=debug|info|warn|error|silent (default: info)
type LogLevelName = 'debug' | 'info' | 'warn' | 'error' | 'silent';
const LOG_LEVEL_ENV = (process.env.LOG_LEVEL ?? 'info').toLowerCase() as LogLevelName;
const LOG_LEVELS: Record<Exclude<LogLevelName, never>, number> = { debug: 10, info: 20, warn: 30, error: 40, silent: 100 };
const CURRENT_LEVEL = LOG_LEVELS[LOG_LEVEL_ENV] ?? LOG_LEVELS.info;

const logger = {
    debug: (...args: unknown[]): void => { if (CURRENT_LEVEL <= LOG_LEVELS.debug) console.debug(...args as []); },
    info:  (...args: unknown[]): void => { if (CURRENT_LEVEL <= LOG_LEVELS.info)  console.log(...args as []); },
    warn:  (...args: unknown[]): void => { if (CURRENT_LEVEL <= LOG_LEVELS.warn)  console.warn(...args as []); },
    error: (...args: unknown[]): void => { if (CURRENT_LEVEL <= LOG_LEVELS.error) console.error(...args as []); },
} as const;

const secretEnv = process.env.JWT_SECRET;
if (!secretEnv) {
    logger.error('[config] FATAL: JWT_SECRET environment variable is not set.');
    process.exit(1);
}

const JWT_SECRET = new TextEncoder().encode(secretEnv);
// Resolve users.json relative to the working directory (ESM-safe and robust across tsx/tsc/Docker)
const USER_FILE = process.env.USER_FILE ?? path.resolve(process.cwd(), 'users.json');
const PORT = getEnvAsNumber('PORT', 3000);
const COOKIE_MAX_AGE_S = getEnvAsNumber('COOKIE_MAX_AGE_S', 3600);
const LOGIN_LIMITER_WINDOW_S = getEnvAsNumber('LOGIN_LIMITER_WINDOW_S', 15 * 60);
const VERIFY_LIMITER_WINDOW_S = getEnvAsNumber('VERIFY_LIMITER_WINDOW_S', 60);
const AUTH_PAGE_LIMITER_WINDOW_S = getEnvAsNumber('AUTH_PAGE_LIMITER_WINDOW_S', 15 * 60);
const ADMIN_LAST_SEEN_LIMITER_WINDOW_S = getEnvAsNumber('ADMIN_LAST_SEEN_LIMITER_WINDOW_S', 60);
const LOGIN_LIMITER_MAX = getEnvAsNumber('LOGIN_LIMITER_MAX', 10);
const VERIFY_LIMITER_MAX = getEnvAsNumber('VERIFY_LIMITER_MAX', 5000);
const AUTH_PAGE_LIMITER_MAX = getEnvAsNumber('AUTH_PAGE_LIMITER_MAX', 300);
const ADMIN_LAST_SEEN_LIMITER_MAX = getEnvAsNumber('ADMIN_LAST_SEEN_LIMITER_MAX', 30);
const COOKIE_NAME = process.env.COOKIE_NAME ?? 'fwd_token';
const JWT_ISSUER = process.env.JWT_ISSUER ?? 'forwardauth';
const DOMAIN = process.env.DOMAIN;
const DOMAIN_WILDCARD = DOMAIN ? `https://*.${DOMAIN}` : undefined;
const ROOT_DOMAIN = DOMAIN ? `https://${DOMAIN}` : undefined;
const LOGIN_REDIRECT_URL = process.env.LOGIN_REDIRECT_URL ?? 'http://localhost:3000/auth';
const AUTH_ORIGIN = new URL(LOGIN_REDIRECT_URL).origin;
// Brand name used in simple page layout: prefer cookie domain, else login host
const BRAND_NAME = DOMAIN ?? new URL(LOGIN_REDIRECT_URL).hostname;
const BRAND_AUTH_LABEL = process.env.BRAND_AUTH_LABEL ?? `${BRAND_NAME} Auth`;
const JUST_LOGGED_GRACE_MS = getEnvAsNumber('JUST_LOGGED_GRACE_MS', 10) * 1000;
const USER_FILE_WATCH_INTERVAL_MS = getEnvAsNumber('USER_FILE_WATCH_INTERVAL_MS', 5000);
const MAX_SESSIONS_PER_USER = getEnvAsNumber('MAX_SESSIONS_PER_USER', 3);
const ADULT_PATH_PREFIXES = parseCsvList(process.env.ADULT_PATH_PREFIXES).map(normalizePathPrefix).filter(Boolean);
const PASSKEY_ENABLED = process.env.PASSKEY_ENABLED === '1' || process.env.PASSKEY_ENABLED === 'true';
const PASSKEY_RP_ID = process.env.PASSKEY_RP_ID ?? DOMAIN;
const PASSKEY_RP_NAME = process.env.PASSKEY_RP_NAME ?? BRAND_NAME;
const PASSKEY_ORIGIN_LIST = parseCsvList(process.env.PASSKEY_ORIGIN);
const PASSKEY_ALLOWED_ORIGINS = PASSKEY_ORIGIN_LIST.length > 0 ? PASSKEY_ORIGIN_LIST : [AUTH_ORIGIN];
const PASSKEY_CHALLENGE_TTL_S = getEnvAsNumber('PASSKEY_CHALLENGE_TTL_S', 120);
const PASSKEY_LOGIN_LIMITER_WINDOW_S = getEnvAsNumber('PASSKEY_LOGIN_LIMITER_WINDOW_S', 15 * 60);
const PASSKEY_REGISTER_LIMITER_WINDOW_S = getEnvAsNumber('PASSKEY_REGISTER_LIMITER_WINDOW_S', 15 * 60);
const PASSKEY_CREDENTIALS_LIMITER_WINDOW_S = getEnvAsNumber('PASSKEY_CREDENTIALS_LIMITER_WINDOW_S', 60);
const PASSKEY_LOGIN_LIMITER_MAX = getEnvAsNumber('PASSKEY_LOGIN_LIMITER_MAX', 30);
const PASSKEY_REGISTER_LIMITER_MAX = getEnvAsNumber('PASSKEY_REGISTER_LIMITER_MAX', 20);
const PASSKEY_CREDENTIALS_LIMITER_MAX = getEnvAsNumber('PASSKEY_CREDENTIALS_LIMITER_MAX', 240);

function isAndroidApkKeyHashOrigin(origin: string): boolean {
    // Used by Android Credential Manager / WebView bridge for passkeys.
    // Pattern: android:apk-key-hash:<app-signing-hash>
    return origin.startsWith('android:apk-key-hash:') && origin.length > 'android:apk-key-hash:'.length;
}

function isRpIdAllowedForOrigin(rpId: string, origin: string): boolean {
    try {
        const host = new URL(origin).hostname.toLowerCase();
        const normalizedRpId = rpId.toLowerCase();
        return host === normalizedRpId || host.endsWith(`.${normalizedRpId}`);
    } catch {
        return false;
    }
}

if (PASSKEY_ENABLED) {
    if (!PASSKEY_RP_ID) {
        logger.error('[config] FATAL: PASSKEY_ENABLED requires PASSKEY_RP_ID or DOMAIN.');
        process.exit(1);
    }

    for (const origin of PASSKEY_ALLOWED_ORIGINS) {
        if (isAndroidApkKeyHashOrigin(origin)) {
            continue;
        }
        if (!isRpIdAllowedForOrigin(PASSKEY_RP_ID, origin)) {
            logger.error(`[config] FATAL: PASSKEY origin "${origin}" is not compatible with RP ID "${PASSKEY_RP_ID}".`);
            process.exit(1);
        }
    }
}


function getEnvSecret(key: string, fileKey: string): string | undefined {
    const filePath = process.env[fileKey];
    if (filePath) {
        try {
            return readFileSync(filePath, 'utf-8').trim();
        } catch (error) {
            logger.error(`[config] Failed reading secret file from ${filePath}:`, error);
        }
    }
    return process.env[key];
}

// Redis (or optional in-memory fallback for local development) for rate limiting and sessions
const REDIS_URL = process.env.REDIS_URL;
const REDIS_HOST = process.env.REDIS_HOST;
const REDIS_PORT = getEnvAsNumber('REDIS_PORT', 6379);
const REDIS_USERNAME = process.env.REDIS_USERNAME;
const REDIS_PASSWORD = getEnvSecret('REDIS_PASSWORD', 'REDIS_PASSWORD_FILE');
const REDIS_TLS = process.env.REDIS_TLS === '1' || process.env.REDIS_TLS === 'true';
const NODE_ENV = process.env.NODE_ENV ?? 'development';
const IS_PRODUCTION = NODE_ENV === 'production';
const INMEMORY_FALLBACK_REQUESTED = process.env.INMEMORY_FALLBACK === '1' || process.env.INMEMORY_FALLBACK === 'true';
const LAST_SEEN_REDIS_KEY = 'user:lastseen';
const USE_INMEMORY_STORE = !REDIS_URL && !REDIS_HOST && INMEMORY_FALLBACK_REQUESTED && !IS_PRODUCTION;

if (IS_PRODUCTION && INMEMORY_FALLBACK_REQUESTED) {
    logger.error('[config] FATAL: INMEMORY_FALLBACK is forbidden in production. Remove INMEMORY_FALLBACK and configure Redis.');
    process.exit(1);
}

if (!REDIS_URL && !REDIS_HOST && !USE_INMEMORY_STORE) {
    logger.error('[config] FATAL: Redis configuration is required. Provide REDIS_URL or REDIS_HOST(+REDIS_PORT). INMEMORY_FALLBACK is allowed only outside production.');
    process.exit(1);
}

interface RedisSetOptionsLike {
    EX?: number;
    NX?: boolean;
}

interface RedisZAddEntryLike {
    score: number;
    value: string;
}

interface RedisMultiLike {
    del(key: string): RedisMultiLike;
    zRem(key: string, member: string): RedisMultiLike;
    set(key: string, value: string, options?: RedisSetOptionsLike): RedisMultiLike;
    zAdd(key: string, entries: RedisZAddEntryLike[]): RedisMultiLike;
    exec(): Promise<unknown[]>;
}

interface RedisClientLike {
    connect(): Promise<void>;
    get(key: string): Promise<string | null>;
    set(key: string, value: string, options?: RedisSetOptionsLike): Promise<string | null>;
    getDel(key: string): Promise<string | null>;
    del(key: string): Promise<number>;
    mGet(keys: string[]): Promise<(string | null)[]>;
    hSet(key: string, field: string, value: string): Promise<number>;
    hGetAll(key: string): Promise<Record<string, string>>;
    hGet(key: string, field: string): Promise<string | null>;
    hDel(key: string, field: string): Promise<number>;
    zAdd(key: string, entries: RedisZAddEntryLike[]): Promise<number>;
    zRem(key: string, member: string): Promise<number>;
    zRemRangeByScore(key: string, min: string | number, max: string | number): Promise<number>;
    zCard(key: string): Promise<number>;
    zRange(key: string, start: number, stop: number): Promise<string[]>;
    sendCommand(args: string[]): Promise<unknown>;
    multi(): RedisMultiLike;
}

class InMemoryRedisClient implements RedisClientLike {
    private readonly strings = new Map<string, string>();
    private readonly hashes = new Map<string, Map<string, string>>();
    private readonly zsets = new Map<string, Map<string, number>>();
    private readonly expiries = new Map<string, number>();

    connect(): Promise<void> {
        return Promise.resolve();
    }

    private deleteKeyInternal(key: string): number {
        let removed = 0;
        if (this.strings.delete(key)) removed = 1;
        if (this.hashes.delete(key)) removed = 1;
        if (this.zsets.delete(key)) removed = 1;
        this.expiries.delete(key);
        return removed;
    }

    private clearExpiredKey(key: string): void {
        const expiry = this.expiries.get(key);
        if (typeof expiry === 'number' && expiry <= Date.now()) {
            this.deleteKeyInternal(key);
        }
    }

    private keyExists(key: string): boolean {
        this.clearExpiredKey(key);
        return this.strings.has(key) || this.hashes.has(key) || this.zsets.has(key);
    }

    private ensureType(key: string, type: 'string' | 'hash' | 'zset'): void {
        this.clearExpiredKey(key);
        if (type !== 'string') {
            this.strings.delete(key);
        }
        if (type !== 'hash') {
            this.hashes.delete(key);
        }
        if (type !== 'zset') {
            this.zsets.delete(key);
        }
        this.expiries.delete(key);
    }

    private parseBound(value: string | number, fallback: number): number {
        if (typeof value === 'number') return value;
        if (value === '-inf') return Number.NEGATIVE_INFINITY;
        if (value === '+inf') return Number.POSITIVE_INFINITY;
        const parsed = Number.parseFloat(value);
        return Number.isFinite(parsed) ? parsed : fallback;
    }

    private getSortedZsetEntries(key: string): { value: string; score: number }[] {
        this.clearExpiredKey(key);
        const set = this.zsets.get(key);
        if (!set) return [];
        return Array.from(set.entries())
            .map(([value, score]) => ({ value, score }))
            .sort((a, b) => (a.score === b.score ? a.value.localeCompare(b.value, 'en') : a.score - b.score));
    }

    private rangeSlice<T>(items: T[], start: number, stop: number): T[] {
        const len = items.length;
        if (len === 0) return [];
        let from = start < 0 ? len + start : start;
        let to = stop < 0 ? len + stop : stop;
        from = Math.max(0, from);
        to = Math.min(len - 1, to);
        if (from > to) return [];
        return items.slice(from, to + 1);
    }

    private collectAllKeys(): string[] {
        const all = new Set<string>([
            ...this.strings.keys(),
            ...this.hashes.keys(),
            ...this.zsets.keys(),
        ]);
        for (const key of all) {
            this.clearExpiredKey(key);
        }
        return Array.from(all).filter((key) => this.keyExists(key)).sort((a, b) => a.localeCompare(b, 'en'));
    }

    private static globToRegex(pattern: string): RegExp {
        const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
        return new RegExp(`^${escaped}$`);
    }

    get(key: string): Promise<string | null> {
        this.clearExpiredKey(key);
        return Promise.resolve(this.strings.get(key) ?? null);
    }

    set(key: string, value: string, options?: RedisSetOptionsLike): Promise<string | null> {
        if (options?.NX && this.keyExists(key)) {
            return Promise.resolve(null);
        }

        this.ensureType(key, 'string');
        this.strings.set(key, value);

        if (typeof options?.EX === 'number' && Number.isFinite(options.EX) && options.EX > 0) {
            this.expiries.set(key, Date.now() + options.EX * 1000);
        } else {
            this.expiries.delete(key);
        }

        return Promise.resolve('OK');
    }

    getDel(key: string): Promise<string | null> {
        this.clearExpiredKey(key);
        const value = this.strings.get(key);
        if (value === undefined) return Promise.resolve(null);
        this.deleteKeyInternal(key);
        return Promise.resolve(value);
    }

    del(key: string): Promise<number> {
        this.clearExpiredKey(key);
        return Promise.resolve(this.deleteKeyInternal(key));
    }

    mGet(keys: string[]): Promise<(string | null)[]> {
        return Promise.all(keys.map((key) => this.get(key)));
    }

    hSet(key: string, field: string, value: string): Promise<number> {
        this.ensureType(key, 'hash');
        if (!this.hashes.has(key)) {
            this.hashes.set(key, new Map());
        }
        const hash = this.hashes.get(key)!;
        const isNew = !hash.has(field);
        hash.set(field, value);
        return Promise.resolve(isNew ? 1 : 0);
    }

    hGetAll(key: string): Promise<Record<string, string>> {
        this.clearExpiredKey(key);
        const hash = this.hashes.get(key);
        if (!hash) return Promise.resolve({});
        return Promise.resolve(Object.fromEntries(hash.entries()));
    }

    hGet(key: string, field: string): Promise<string | null> {
        this.clearExpiredKey(key);
        const hash = this.hashes.get(key);
        if (!hash) return Promise.resolve(null);
        return Promise.resolve(hash.get(field) ?? null);
    }

    hDel(key: string, field: string): Promise<number> {
        this.clearExpiredKey(key);
        const hash = this.hashes.get(key);
        if (!hash) return Promise.resolve(0);
        const existed = hash.delete(field);
        if (hash.size === 0) {
            this.hashes.delete(key);
        }
        return Promise.resolve(existed ? 1 : 0);
    }

    zAdd(key: string, entries: RedisZAddEntryLike[]): Promise<number> {
        this.ensureType(key, 'zset');
        if (!this.zsets.has(key)) {
            this.zsets.set(key, new Map());
        }
        const set = this.zsets.get(key)!;
        let added = 0;
        for (const entry of entries) {
            if (!set.has(entry.value)) {
                added++;
            }
            set.set(entry.value, entry.score);
        }
        return Promise.resolve(added);
    }

    zRem(key: string, member: string): Promise<number> {
        this.clearExpiredKey(key);
        const set = this.zsets.get(key);
        if (!set) return Promise.resolve(0);
        const existed = set.delete(member);
        if (set.size === 0) {
            this.zsets.delete(key);
        }
        return Promise.resolve(existed ? 1 : 0);
    }

    zRemRangeByScore(key: string, min: string | number, max: string | number): Promise<number> {
        this.clearExpiredKey(key);
        const set = this.zsets.get(key);
        if (!set) return Promise.resolve(0);

        const minValue = this.parseBound(min, Number.NEGATIVE_INFINITY);
        const maxValue = this.parseBound(max, Number.POSITIVE_INFINITY);
        let removed = 0;

        for (const [member, score] of set.entries()) {
            if (score >= minValue && score <= maxValue) {
                set.delete(member);
                removed++;
            }
        }

        if (set.size === 0) {
            this.zsets.delete(key);
        }

        return Promise.resolve(removed);
    }

    zCard(key: string): Promise<number> {
        this.clearExpiredKey(key);
        return Promise.resolve(this.zsets.get(key)?.size ?? 0);
    }

    zRange(key: string, start: number, stop: number): Promise<string[]> {
        const entries = this.getSortedZsetEntries(key);
        return Promise.resolve(this.rangeSlice(entries, start, stop).map((entry) => entry.value));
    }

    sendCommand(args: string[]): Promise<unknown> {
        if (args.length === 0) {
            return Promise.reject(new Error('Empty command'));
        }

        const command = args[0].toUpperCase();
        if (command === 'SCAN') {
            let pattern = '*';
            for (let i = 1; i < args.length; i++) {
                const part = args[i]?.toUpperCase();
                if (part === 'MATCH') {
                    pattern = args[i + 1] ?? '*';
                    i++;
                } else if (part === 'COUNT') {
                    i++;
                }
            }
            const matcher = InMemoryRedisClient.globToRegex(pattern);
            const keys = this.collectAllKeys().filter((key) => matcher.test(key));
            return Promise.resolve(['0', keys]);
        }

        if (command === 'ZRANGE') {
            const key = args[1] ?? '';
            const start = Number.parseInt(args[2] ?? '0', 10);
            const stop = Number.parseInt(args[3] ?? '-1', 10);
            const withScores = args.slice(4).some((part) => part.toUpperCase() === 'WITHSCORES');
            const entries = this.rangeSlice(this.getSortedZsetEntries(key), start, stop);
            if (!withScores) {
                return Promise.resolve(entries.map((entry) => entry.value));
            }
            const response: string[] = [];
            for (const entry of entries) {
                response.push(entry.value, String(entry.score));
            }
            return Promise.resolve(response);
        }

        return Promise.reject(new Error(`Unsupported in-memory Redis command: ${command}`));
    }

    multi(): RedisMultiLike {
        const operations: (() => Promise<unknown>)[] = [];
        const chain: RedisMultiLike = {
            del: (key: string): RedisMultiLike => {
                operations.push(() => this.del(key));
                return chain;
            },
            zRem: (key: string, member: string): RedisMultiLike => {
                operations.push(() => this.zRem(key, member));
                return chain;
            },
            set: (key: string, value: string, options?: RedisSetOptionsLike): RedisMultiLike => {
                operations.push(() => this.set(key, value, options));
                return chain;
            },
            zAdd: (key: string, entries: RedisZAddEntryLike[]): RedisMultiLike => {
                operations.push(() => this.zAdd(key, entries));
                return chain;
            },
            exec: async (): Promise<unknown[]> => {
                const results: unknown[] = [];
                for (const op of operations) {
                    results.push(await op());
                }
                return results;
            },
        };
        return chain;
    }
}

let redisClient: RedisClientLike;
let loginStore: RateLimitStore | undefined;
let verifyStore: RateLimitStore | undefined;
let authPageStore: RateLimitStore | undefined;
let adminLastSeenStore: RateLimitStore | undefined;
let passkeyAuthStore: RateLimitStore | undefined;
let passkeyRegisterStore: RateLimitStore | undefined;
let passkeyCredentialsStore: RateLimitStore | undefined;

if (USE_INMEMORY_STORE) {
    redisClient = new InMemoryRedisClient();
} else if (REDIS_URL) {
    redisClient = createClient({ url: REDIS_URL, username: REDIS_USERNAME, password: REDIS_PASSWORD }) as unknown as RedisClientLike;
} else {
    const proto = REDIS_TLS ? 'rediss' : 'redis';
    const url = `${proto}://${REDIS_HOST}:${REDIS_PORT}`;
    redisClient = createClient({ url, username: REDIS_USERNAME, password: REDIS_PASSWORD }) as unknown as RedisClientLike;
}

function sanitizeRedisUrl(urlStr?: string): string | undefined {
    if (!urlStr) return undefined;
    try {
        const u = new URL(urlStr);
        const hostPort = u.port ? `${u.hostname}:${u.port}` : u.hostname;
        return `${u.protocol}//${hostPort}`;
    } catch {
        return undefined;
    }
}

function logStartupConfig(): void {
    const cfg = {
        port: PORT,
        domain: DOMAIN ?? '(unset)',
        cookieName: COOKIE_NAME,
        jwtIssuer: JWT_ISSUER,
        loginRedirectUrl: LOGIN_REDIRECT_URL,
        cookieMaxAgeS: COOKIE_MAX_AGE_S,
        sessionMaxPerUser: MAX_SESSIONS_PER_USER,
        windows: {
            loginLimiterWindowS: LOGIN_LIMITER_WINDOW_S,
            verifyLimiterWindowS: VERIFY_LIMITER_WINDOW_S,
            authPageLimiterWindowS: AUTH_PAGE_LIMITER_WINDOW_S,
            adminLastSeenLimiterWindowS: ADMIN_LAST_SEEN_LIMITER_WINDOW_S,
            passkeyLoginLimiterWindowS: PASSKEY_LOGIN_LIMITER_WINDOW_S,
            passkeyRegisterLimiterWindowS: PASSKEY_REGISTER_LIMITER_WINDOW_S,
            passkeyCredentialsLimiterWindowS: PASSKEY_CREDENTIALS_LIMITER_WINDOW_S,
        },
        limits: {
            loginLimiterMax: LOGIN_LIMITER_MAX,
            verifyLimiterMax: VERIFY_LIMITER_MAX,
            authPageLimiterMax: AUTH_PAGE_LIMITER_MAX,
            adminLastSeenLimiterMax: ADMIN_LAST_SEEN_LIMITER_MAX,
            passkeyLoginLimiterMax: PASSKEY_LOGIN_LIMITER_MAX,
            passkeyRegisterLimiterMax: PASSKEY_REGISTER_LIMITER_MAX,
            passkeyCredentialsLimiterMax: PASSKEY_CREDENTIALS_LIMITER_MAX,
        },
        users: {
            file: USER_FILE,
            watchIntervalMs: USER_FILE_WATCH_INTERVAL_MS,
        },
        passkey: {
            enabled: PASSKEY_ENABLED,
            rpId: PASSKEY_RP_ID ?? '(unset)',
            rpName: PASSKEY_RP_NAME,
            challengeTtlS: PASSKEY_CHALLENGE_TTL_S,
            origins: PASSKEY_ALLOWED_ORIGINS,
        },
        adult: {
            pathPrefixes: ADULT_PATH_PREFIXES,
        },
        redis: USE_INMEMORY_STORE
            ? { mode: 'inmemory' }
            : REDIS_URL
                ? { mode: 'url', url: sanitizeRedisUrl(REDIS_URL), tls: REDIS_TLS }
                : { mode: 'host', host: REDIS_HOST, port: REDIS_PORT, tls: REDIS_TLS },
        secrets: {
            jwtSecret: secretEnv ? 'set' : 'unset',
            redisPassword: REDIS_PASSWORD ? 'set' : 'unset',
            redisUsername: REDIS_USERNAME ? 'set' : 'unset',
        },
        runtime: {
            nodeEnv: NODE_ENV,
            inMemoryFallbackRequested: INMEMORY_FALLBACK_REQUESTED,
            inMemoryFallbackActive: USE_INMEMORY_STORE,
        },
    } as const;

    // Single structured log line for easier ingestion
    logger.info(`[config] ${JSON.stringify(cfg)}`);
}

function acceptsHtml(req: Request): boolean {
    const accept = req.headers.accept ?? '';
    return typeof accept === 'string' && accept.includes('text/html');
}

function isDocumentRequest(req: Request): boolean {
    const dest = req.headers['sec-fetch-dest'];
    if (dest === 'document') return true;
    return acceptsHtml(req);
}

function getHeaderString(req: Request, name: string): string {
    const value = req.headers[name.toLowerCase()];
    if (Array.isArray(value)) return value[0] ?? '';
    return typeof value === 'string' ? value : '';
}

function isAllowedAuthPost(req: Request): boolean {
    const origin = getHeaderString(req, 'origin');
    const referer = getHeaderString(req, 'referer');
    const authOrigin = AUTH_ORIGIN;

    if (origin) {
        return origin === authOrigin;
    }

    if (referer) {
        return referer.startsWith(`${authOrigin}/`);
    }

    // As a conservative fallback, accept only when browser hints same-origin
    const sfs = getHeaderString(req, 'sec-fetch-site');
    return sfs === 'same-origin';
}

// Banner feature removed to avoid redirect loops in some proxy/mobile setups

const app = express();
app.disable('x-powered-by');
// Build CSP with optional DOMAIN entries only when defined
const formActionSources = ["'self'", AUTH_ORIGIN, ROOT_DOMAIN, DOMAIN_WILDCARD].filter(Boolean) as string[];
app.use(helmet.contentSecurityPolicy({
    directives: {
        defaultSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        frameAncestors: ["'none'"],
        formAction: formActionSources,
    }
}));
// Enable HSTS in TLS-enabled deployments; harmless if behind TLS-terminating proxy
app.use(helmet.hsts({ maxAge: 15552000, includeSubDomains: true }));
app.set('trust proxy', 1);

// Rate limiters are created after Redis connect
let loginLimiter: RequestHandler;
let verifyLimiter: RequestHandler;
let authPageLimiter: RequestHandler;
let adminLastSeenLimiter: RequestHandler;
let passkeyAuthLimiter: RequestHandler;
let passkeyRegisterLimiter: RequestHandler;
let passkeyCredentialsLimiter: RequestHandler;

// Toast page removed

let users: Record<string, User> = {};

function isStringArray(value: unknown): value is string[] {
    return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

function isRecordOfUser(data: unknown): data is Record<string, User> {
    return (
        typeof data === 'object' &&
        data !== null &&
        Object.values(data).every(
            (u) => typeof (u as User).hash === 'string' &&
                (
                    (u as User).allowedHosts === undefined ||
                    isStringArray((u as User).allowedHosts)
                ) &&
                (
                    (u as User).isAdult === undefined ||
                    typeof (u as User).isAdult === 'boolean'
                ) &&
                (
                    (u as User).isAdmin === undefined ||
                    typeof (u as User).isAdmin === 'boolean'
                )
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
                const decoded = JSON.parse(`"${lastString}"`) as string;
                keys.push(decoded);
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
    const userKeys = extractTopLevelUserKeys(jsonContent);
    const seen = new Set<string>();
    const duplicates = new Set<string>();

    for (const key of userKeys) {
        const normalized = normalizeEmailIdentifier(key);
        if (seen.has(normalized)) {
            duplicates.add(normalized);
        } else {
            seen.add(normalized);
        }
    }

    return Array.from(duplicates);
}

function findNonNormalizedEmails(jsonContent: string): string[] {
    const userKeys = extractTopLevelUserKeys(jsonContent);
    return userKeys.filter((key) => normalizeEmailIdentifier(key) !== key);
}

function normalizeHost(host: string): string {
    const primaryHost = host.split(',')[0] ?? '';
    const withoutPort = primaryHost.split(':')[0] ?? '';
    const trimmed = withoutPort.trim().replace(/\.$/, '');
    return trimmed.toLowerCase();
}

function isHostAllowed(host: string, allowedHosts?: string[]): boolean {
    if (!allowedHosts) {
        return true;
    }

    if (allowedHosts.length === 0) {
        return false;
    }

    const normalizedHost = normalizeHost(host);

    return allowedHosts.some((allowedHost) => {
        const normalizedAllowed = normalizeHost(allowedHost);
        if (!normalizedAllowed) return false;

        if (normalizedAllowed.startsWith('*.')) {
            const suffix = normalizedAllowed.slice(1);
            return (
                normalizedHost.endsWith(suffix) &&
                normalizedHost.length > suffix.length
            );
        }

        return normalizedHost === normalizedAllowed;
    });
}

function getPathFromUri(uri: string): string {
    if (!uri) return '/';
    const trimmed = uri.trim();
    if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
        try {
            return new URL(trimmed).pathname || '/';
        } catch {
            // ignore parse errors and fall back below
        }
    }
    const pathOnly = trimmed.split('?')[0] ?? '/';
    if (!pathOnly.startsWith('/')) return `/${pathOnly}`;
    return pathOnly || '/';
}

function isAdultPath(uri: string): boolean {
    if (ADULT_PATH_PREFIXES.length === 0) return false;
    const path = getPathFromUri(uri);
    return ADULT_PATH_PREFIXES.some((prefix) => path.startsWith(prefix));
}

async function loadUsers(options: { fatal?: boolean } = { fatal: true }) {
    const { fatal = true } = options;
    try {
        const rawContent = await fs.readFile(USER_FILE, 'utf-8');
        const duplicateEmails = findDuplicateEmails(rawContent);
        const nonNormalizedEmails = findNonNormalizedEmails(rawContent);
        const raw: unknown = JSON.parse(rawContent);

        if (!isRecordOfUser(raw)) {
            throw new Error('Invalid users.json structure');
        }

        if (duplicateEmails.length > 0) {
            const message = `Duplicate emails detected: ${duplicateEmails.join(', ')}`;
            if (fatal) {
                logger.error(`[users] FATAL: ${message}`);
                process.exit(1);
            } else {
                logger.warn(`[users] ${message}. Reload skipped; keeping previous users.`);
                return;
            }
        }

        if (nonNormalizedEmails.length > 0) {
            const message = `users.json keys must be lowercase/trimmed emails. Invalid keys: ${nonNormalizedEmails.join(', ')}`;
            if (fatal) {
                logger.error(`[users] FATAL: ${message}`);
                process.exit(1);
            } else {
                logger.warn(`[users] ${message}. Reload skipped; keeping previous users.`);
                return;
            }
        }

        users = raw;
        logger.info(`[users] Loaded ${Object.keys(users).length} users from ${USER_FILE}`);
    } catch (error) {
        if (fatal) {
            logger.error(`[users] FATAL: Could not load or parse user file from "${USER_FILE}".`, error);
            process.exit(1);
        } else {
            logger.warn(`[users] Reloading users failed; keeping previous users. (${(error as Error).message})`);
        }
    }
}

function validateRedirectUri(uri: string): string {
    const defaultRedirect = '/';
    if (!uri) return defaultRedirect;

    const trimmed = uri.trim();

    try {
        const url = new URL(trimmed);

        if (url.protocol !== 'http:' && url.protocol !== 'https:') {
            logger.warn('[redirect] Blocked non-http(s) redirect to: %s', trimmed);
            return defaultRedirect;
        }

        if (DOMAIN && (url.hostname === DOMAIN || url.hostname.endsWith(`.${DOMAIN}`))) {
            return url.toString();
        }

        logger.warn('[redirect] Blocked potential open redirect to: %s', trimmed);
        return defaultRedirect;
    } catch (error) {
        if (trimmed.startsWith('/') && !trimmed.startsWith('//')) {
            return trimmed;
        }
        logger.warn('[redirect] Invalid redirect URI provided: %s', trimmed, error);
        return defaultRedirect;
    }
}

function getOriginalUrl(req: Request): string {
    const proto = req.header('X-Forwarded-Proto') ?? 'https';
    const host = req.hostname;
    const uri = req.header('X-Forwarded-Uri') ?? '/';
    return `${proto}://${host}${uri}`;
}

const getPageHTML = (title: string, body: string, options: { wide?: boolean } = {}): string => {
    const pageCardClass = options.wide ? 'page-card page-card--wide' : 'page-card';
    return `
    <!doctype html>
    <html lang="de">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta name="color-scheme" content="light dark">
        <title>${he.encode(title)}</title>
        <link rel="stylesheet" href="/styles.css">
    </head>
    <body>
        <main class="page-shell">
            <section class="${pageCardClass}">
                <header class="page-header">
                    <a href="/auth" class="brand">
                        <img class="brand__logo" src="/logo.png" alt="${he.encode(BRAND_AUTH_LABEL)} Logo" width="52" height="52" />
                        <span class="brand__text">
                            <span class="brand__eyebrow">${he.encode(BRAND_AUTH_LABEL)}</span>
                            <span class="brand__name">${he.encode(BRAND_NAME)}</span>
                        </span>
                    </a>
                </header>
                <div class="page-content">
                    ${body}
                </div>
            </section>
        </main>
    </body>
    </html>
    `;
};

function getSessionCookieOptions(): cookie.SerializeOptions {
    const options: cookie.SerializeOptions = { httpOnly: true, secure: true, maxAge: COOKIE_MAX_AGE_S, sameSite: 'lax', path: '/' };
    if (DOMAIN) {
        options.domain = DOMAIN;
    }
    return options;
}

function buildLoginFormBody(safeDestinationUri: string, headlineHtml: string): string {
    const passkeySection = PASSKEY_ENABLED
        ? `
            <section class="passkey-box panel panel--soft" aria-labelledby="passkey-login-heading">
                <h2 id="passkey-login-heading" class="passkey-title">Mit Passkey anmelden</h2>
                <div class="field">
                    <label for="passkey-login-email">E-Mail-Adresse <span class="optional-note">(OPTIONAL)</span></label>
                    <input id="passkey-login-email" placeholder="name@example.com" autocomplete="email webauthn" />
                </div>
                <input id="passkey-login-redirect-uri" type="hidden" value="${safeDestinationUri}" />
                <input id="passkey-allowed-domain" type="hidden" value="${he.encode(DOMAIN ?? '')}" />
                <button id="passkey-login-button" type="button">Mit Passkey anmelden</button>
                <p id="passkey-login-message" class="meta" role="status" aria-live="polite"></p>
            </section>
            <script src="/passkey.js" defer></script>
        `
        : '';

    return `
        <section class="content-stack">
            ${headlineHtml}
            <form class="form-stack" method="post" action="${AUTH_ORIGIN}/auth">
                <input type="hidden" name="redirect_uri" value="${safeDestinationUri}" />
                <div class="field">
                    <label for="login-email">E-Mail-Adresse</label>
                    <input id="login-email" name="email" type="email" placeholder="name@example.com" required autocomplete="email" />
                </div>
                <div class="field">
                    <label for="login-password">Passwort</label>
                    <input id="login-password" name="password" type="password" placeholder="Passwort eingeben" required autocomplete="current-password" />
                </div>
                <button type="submit">Anmelden</button>
            </form>
            ${passkeySection}
        </section>
    `;
}

interface LoggedInBodyOptions {
    setupPasskeyPrompt?: boolean;
    autoRedirectAfterPasskeySetup?: boolean;
}

function buildLoggedInBody(safeDestinationUri: string, options: LoggedInBodyOptions = {}): string {
    const setupPrompt = options.setupPasskeyPrompt === true;
    const autoRedirectAfterSetup = options.autoRedirectAfterPasskeySetup === true;
    const setupPromptHtml = setupPrompt ? `
        <div class="setup-callout panel">
            <h2>Bitte jetzt Passkey einrichten</h2>
            <p>Damit melden Sie sich beim nächsten Mal schnell und ohne Passwort an.</p>
            <p><strong>Nach der Einrichtung geht es automatisch weiter.</strong></p>
        </div>
    ` : '';
    const passkeyIntro = setupPrompt
        ? 'Einmal auf den Button tippen und den Schritten folgen.'
        : 'Hier können Sie Ihre Passkey-Anmeldung einrichten oder verwalten.';
    const passkeySection = PASSKEY_ENABLED
        ? `
            <section class="passkey-box panel panel--soft" aria-labelledby="passkey-register-heading">
                <h2 id="passkey-register-heading" class="passkey-title">Passkey-Verwaltung</h2>
                <p class="meta">${passkeyIntro}</p>
                <button id="passkey-register-button" type="button">Passkey einrichten</button>
                <input id="passkey-post-register-redirect-uri" type="hidden" value="${safeDestinationUri}" />
                <input id="passkey-auto-redirect-after-register" type="hidden" value="${autoRedirectAfterSetup ? '1' : '0'}" />
                <input id="passkey-allowed-domain" type="hidden" value="${he.encode(DOMAIN ?? '')}" />
                <p id="passkey-register-message" class="meta" role="status" aria-live="polite"></p>
                <div id="passkey-credential-list" class="passkey-list"></div>
            </section>
            <script src="/passkey.js" defer></script>
        `
        : '';

    if (setupPrompt) {
        return `
            <section class="content-stack">
                <h1>Fast geschafft</h1>
                ${setupPromptHtml}
                ${passkeySection}
                <p class="meta login-actions">
                    Falls es gerade nicht möglich ist:
                    <a class="inline-link" href="${safeDestinationUri}">Passkey später einrichten</a>
                </p>
                <div class="login-actions login-actions--bottom">
                    <a class="button button--ghost" href="/logout">Abmelden</a>
                </div>
            </section>
        `;
    }

    return `
        <section class="content-stack">
            <h1>Angemeldet</h1>
            <p>Sie sind erfolgreich angemeldet und können andere geschützte Dienste aufrufen.</p>
            <div class="action-row">
                <a class="button button--primary" href="${safeDestinationUri}">Zur geschützten Seite</a>
            </div>
            ${passkeySection}
            <div class="login-actions login-actions--bottom">
                <a class="button button--ghost" href="/logout">Abmelden</a>
            </div>
        </section>
    `;
}

function buildAdminNav(activePage: 'sessions' | 'last-seen'): string {
    const sessionsClass = activePage === 'sessions' ? 'subnav-link is-active' : 'subnav-link';
    const lastSeenClass = activePage === 'last-seen' ? 'subnav-link is-active' : 'subnav-link';
    return `
        <nav class="subnav" aria-label="Admin-Navigation">
            <a href="/admin/sessions" class="${sessionsClass}">Aktive Sitzungen</a>
            <a href="/admin/last-seen" class="${lastSeenClass}">Letzte Aktivität</a>
        </nav>
    `;
}

app.use(express.urlencoded({ extended: false }));
app.use(express.json({ limit: '100kb' }));
app.use(express.static('public'));

// -----------------------------
// Session limiting infrastructure
// -----------------------------

interface SessionStore {
    addSession(user: string, jti: string, ttlSeconds: number, maxSessions: number): Promise<boolean>;
    isActive(user: string, jti: string): Promise<boolean>;
    removeSession(user: string, jti: string): Promise<void>;
}

class RedisSessionStore implements SessionStore {
    private readonly client: RedisClientLike;
    private readonly keySessionPrefix = 'sess:token:'; // sess:token:<jti> -> email
    private readonly keyUserZsetPrefix = 'sess:user:'; // sess:user:<user> -> ZSET of jti scored by expiry (ms epoch)

    constructor(client: RedisClientLike) {
        this.client = client;
    }

    private keySession(jti: string): string { return `${this.keySessionPrefix}${jti}`; }
    private keyUser(user: string): string { return `${this.keyUserZsetPrefix}${user}`; }

    async addSession(user: string, jti: string, ttlSeconds: number, maxSessions: number): Promise<boolean> {
        const userKey = this.keyUser(user);
        const nowMs = Date.now();
        const expiryMs = nowMs + ttlSeconds * 1000;

        // 1) Remove expired sessions from index (by expiry score)
        await this.client.zRemRangeByScore(userKey, '-inf', nowMs);

        // 2) Count active sessions
        const count = await this.client.zCard(userKey);

        // 3) If limit reached, evict oldest active session (Last-Login-Wins)
        if (count >= maxSessions) {
            const oldest = await this.client.zRange(userKey, 0, 0);
            if (oldest.length > 0) {
                const oldestJti = oldest[0];
                await this.client.multi()
                    .del(this.keySession(oldestJti))
                    .zRem(userKey, oldestJti)
                    .exec();
                logger.info(`[sessions] Evicted oldest session for user "${user}" (jti=${oldestJti}) to respect maxSessions=${maxSessions}`);
            }
        }

        // 4) Add new session
        await this.client.multi()
            .set(this.keySession(jti), user, { EX: ttlSeconds })
            .zAdd(userKey, [{ score: expiryMs, value: jti }])
            .exec();

        return true;
    }

    async isActive(user: string, jti: string): Promise<boolean> {
        if (!jti) return false;
        const key = this.keySession(jti);
        const val = await this.client.get(key);
        if (val === user) return true;
        // Housekeeping: remove stale ZSET member if present (e.g., TTL already expired)
        await this.client.zRem(this.keyUser(user), jti);
        return false;
    }

    async removeSession(user: string, jti: string): Promise<void> {
        if (!jti) return;
        await this.client.multi()
            .del(this.keySession(jti))
            .zRem(this.keyUser(user), jti)
            .exec();
    }
}

// Session persistence is provided via Redis or an optional in-memory fallback.

let sessionStore: SessionStore;

// -----------------------------
// Last-seen tracking (Redis-backed)
// -----------------------------

type LastSeenSource = 'login' | 'verify';

interface LastSeenPayload {
    at: number;
    ip: string;
    host: string;
    uri?: string;
    userAgent: string;
    platform?: string;
    via: LastSeenSource;
    jti?: string;
}

interface LastSeenRecord extends LastSeenPayload {
    user: string;
}

interface SessionEntry {
    jti: string;
    expiryMs: number;
    active: boolean;
}

interface UserSessionOverview {
    user: string;
    sessions: SessionEntry[];
    activeCount: number;
    totalCount: number;
    lastSeen?: LastSeenRecord;
}

function formatTimestamp(ms: number): string {
    const date = new Date(ms);
    if (Number.isNaN(date.getTime())) return '–';
    return new Intl.DateTimeFormat('de-DE', {
        dateStyle: 'medium',
        timeStyle: 'medium',
    }).format(date);
}

function parseLastSeenPayload(raw: string): LastSeenPayload | null {
    try {
        const parsed = JSON.parse(raw) as Partial<LastSeenPayload>;
        if (
            typeof parsed.at === 'number' &&
            typeof parsed.ip === 'string' &&
            typeof parsed.host === 'string' &&
            typeof parsed.userAgent === 'string' &&
            (parsed.via === 'login' || parsed.via === 'verify')
        ) {
            return {
                at: parsed.at,
                ip: parsed.ip,
                host: parsed.host,
                uri: typeof parsed.uri === 'string' ? parsed.uri : undefined,
                userAgent: parsed.userAgent,
                platform: typeof parsed.platform === 'string' ? parsed.platform : undefined,
                via: parsed.via,
                jti: typeof parsed.jti === 'string' ? parsed.jti : undefined,
            };
        }
    } catch {
        // ignore invalid JSON
    }
    return null;
}

async function recordLastSeen(user: string, payload: Omit<LastSeenPayload, 'at'>): Promise<void> {
    const entry: LastSeenPayload = {
        ...payload,
        at: Date.now(),
    };
    try {
        await redisClient.hSet(LAST_SEEN_REDIS_KEY, user, JSON.stringify(entry));
    } catch (error) {
        logger.warn(`[lastseen] Failed to store last-seen for "${user}":`, error);
    }
}

async function fetchLastSeen(): Promise<LastSeenRecord[]> {
    try {
        const rawMap = await redisClient.hGetAll(LAST_SEEN_REDIS_KEY);
        const records = Object.entries(rawMap)
            .map(([user, raw]) => {
                const parsed = parseLastSeenPayload(raw);
                if (!parsed) return null;
                return { user, ...parsed };
            })
            .filter((entry): entry is LastSeenRecord => entry !== null)
            .sort((a, b) => b.at - a.at);
        return records;
    } catch (error) {
        logger.error('[lastseen] Failed to fetch last-seen data from Redis', error);
        return [];
    }
}

const SESSION_USER_PREFIX = 'sess:user:';
const SESSION_TOKEN_PREFIX = 'sess:token:';

function isUnknownArray(value: unknown): value is unknown[] {
    return Array.isArray(value);
}

async function scanKeys(pattern: string, count = 200): Promise<string[]> {
    const keys: string[] = [];
    let cursor = '0';
    do {
        const reply: unknown = await redisClient.sendCommand(['SCAN', cursor, 'MATCH', pattern, 'COUNT', String(count)]);
        if (isUnknownArray(reply) && reply.length >= 2) {
            const nextCursor = typeof reply[0] === 'string' ? reply[0] : String(reply[0]);
            const batchRaw = reply[1];
            if (Array.isArray(batchRaw)) {
                const batch = batchRaw.filter((item): item is string => typeof item === 'string');
                keys.push(...batch);
            }
            cursor = nextCursor;
        } else {
            cursor = '0';
        }
    } while (cursor !== '0');
    return keys;
}

function parseZsetWithScores(raw: unknown): { value: string; score: number }[] {
    if (!isUnknownArray(raw)) return [];
    const results: { value: string; score: number }[] = [];
    for (let i = 0; i < raw.length; i += 2) {
        const value = raw[i];
        const scoreRaw = raw[i + 1];
        if (typeof value !== 'string') continue;
        const score = Number.parseInt(String(scoreRaw), 10);
        results.push({ value, score: Number.isFinite(score) ? score : 0 });
    }
    return results;
}

async function fetchUserSessions(user: string): Promise<SessionEntry[]> {
    const userKey = `${SESSION_USER_PREFIX}${user}`;
    const raw = await redisClient.sendCommand(['ZRANGE', userKey, '0', '-1', 'WITHSCORES']);
    const entries = parseZsetWithScores(raw)
        .map(({ value, score }) => ({
            jti: value,
            expiryMs: score,
            active: false,
        }));
    if (entries.length === 0) return [];

    const tokenKeys = entries.map((entry) => `${SESSION_TOKEN_PREFIX}${entry.jti}`);
    const tokenValues = await redisClient.mGet(tokenKeys);
    entries.forEach((entry, index) => {
        entry.active = tokenValues[index] === user;
    });
    entries.sort((a, b) => b.expiryMs - a.expiryMs);
    return entries;
}

async function fetchSessionOverview(): Promise<UserSessionOverview[]> {
    const userKeys = await scanKeys(`${SESSION_USER_PREFIX}*`);
    const users = userKeys
        .map((key) => key.slice(SESSION_USER_PREFIX.length))
        .filter((user) => user.length > 0)
        .sort((a, b) => a.localeCompare(b, 'de'));
    const lastSeenEntries = await fetchLastSeen();
    const lastSeenMap = new Map(lastSeenEntries.map((entry) => [entry.user, entry]));

    const results: UserSessionOverview[] = [];
    for (const user of users) {
        const sessions = await fetchUserSessions(user);
        const activeCount = sessions.filter((entry) => entry.active).length;
        results.push({
            user,
            sessions,
            activeCount,
            totalCount: sessions.length,
            lastSeen: lastSeenMap.get(user),
        });
    }
    results.sort((a, b) => {
        const aSeen = a.lastSeen?.at ?? 0;
        const bSeen = b.lastSeen?.at ?? 0;
        if (aSeen === bSeen) {
            return a.user.localeCompare(b.user, 'de');
        }
        return bSeen - aSeen;
    });
    return results;
}

async function cleanupOrphanedSessions(): Promise<{ users: number; scanned: number; removed: number }> {
    const userKeys = await scanKeys(`${SESSION_USER_PREFIX}*`);
    let scanned = 0;
    let removed = 0;
    let usersTouched = 0;

    for (const userKey of userKeys) {
        const user = userKey.slice(SESSION_USER_PREFIX.length);
        if (!user) continue;
        const jtis = await redisClient.zRange(userKey, 0, -1);
        if (jtis.length === 0) {
            await redisClient.del(userKey);
            continue;
        }
        scanned += jtis.length;
        const tokenKeys = jtis.map((jti) => `${SESSION_TOKEN_PREFIX}${jti}`);
        const tokenValues = await redisClient.mGet(tokenKeys);
        const toRemove: string[] = [];
        tokenValues.forEach((val, index) => {
            if (val !== user) {
                toRemove.push(jtis[index]);
            }
        });
        if (toRemove.length > 0) {
            const multi = redisClient.multi();
            for (const jti of toRemove) {
                multi.zRem(userKey, jti);
            }
            await multi.exec();
            removed += toRemove.length;
            usersTouched++;
        }
    }

    return { users: usersTouched, scanned, removed };
}

const PASSKEY_USER_PREFIX = 'passkey:user:';
const PASSKEY_CRED_PREFIX = 'passkey:cred:';
const PASSKEY_CHALLENGE_REG_PREFIX = 'passkey:challenge:reg:';
const PASSKEY_CHALLENGE_AUTH_PREFIX = 'passkey:challenge:auth:';

type PasskeyChallengeKind = 'reg' | 'auth';

interface StoredPasskeyCredential {
    credentialId: string;
    publicKey: string;
    counter: number;
    transports?: AuthenticatorTransportFuture[];
    createdAt: number;
    lastUsedAt: number;
    deviceType?: string;
    backedUp?: boolean;
}

interface StoredPasskeyChallenge {
    flowId: string;
    challenge: string;
    email?: string;
    redirectUri?: string;
    createdAt: number;
}

interface AuthenticatedSession {
    email: string;
    jti: string;
}

function passkeyUserKey(email: string): string {
    return `${PASSKEY_USER_PREFIX}${email}`;
}

function passkeyCredentialKey(credentialId: string): string {
    return `${PASSKEY_CRED_PREFIX}${credentialId}`;
}

function passkeyChallengeKey(kind: PasskeyChallengeKind, flowId: string): string {
    return kind === 'reg'
        ? `${PASSKEY_CHALLENGE_REG_PREFIX}${flowId}`
        : `${PASSKEY_CHALLENGE_AUTH_PREFIX}${flowId}`;
}

function redactedCredentialId(credentialId: string): string {
    if (credentialId.length <= 12) return credentialId;
    return `${credentialId.slice(0, 12)}...`;
}

function bytesToBase64Url(bytes: Uint8Array): string {
    return Buffer.from(bytes).toString('base64url');
}

function base64UrlToBytes(value: string): ReturnType<Uint8Array['slice']> {
    const bytes = Uint8Array.from(Buffer.from(value, 'base64url'));
    return bytes.slice();
}

function getWebAuthnClientOrigin(clientDataJSON: string | undefined): string | undefined {
    // Only used for logging; do not log `challenge` or other sensitive fields.
    if (!clientDataJSON) return undefined;
    try {
        const raw = Buffer.from(base64UrlToBytes(clientDataJSON)).toString('utf-8');
        const parsed = JSON.parse(raw) as { origin?: unknown };
        return typeof parsed.origin === 'string' ? parsed.origin : undefined;
    } catch {
        return undefined;
    }
}

function isTransport(value: string): value is AuthenticatorTransportFuture {
    return (
        value === 'ble' ||
        value === 'cable' ||
        value === 'hybrid' ||
        value === 'internal' ||
        value === 'nfc' ||
        value === 'smart-card' ||
        value === 'usb'
    );
}

function parseStoredPasskeyCredential(raw: string): StoredPasskeyCredential | null {
    try {
        const parsed = JSON.parse(raw) as Partial<StoredPasskeyCredential>;
        if (
            typeof parsed.credentialId !== 'string' ||
            typeof parsed.publicKey !== 'string' ||
            typeof parsed.counter !== 'number' ||
            typeof parsed.createdAt !== 'number' ||
            typeof parsed.lastUsedAt !== 'number'
        ) {
            return null;
        }

        const transports = Array.isArray(parsed.transports)
            ? parsed.transports.filter((item): item is AuthenticatorTransportFuture => typeof item === 'string' && isTransport(item))
            : undefined;

        return {
            credentialId: parsed.credentialId,
            publicKey: parsed.publicKey,
            counter: parsed.counter,
            createdAt: parsed.createdAt,
            lastUsedAt: parsed.lastUsedAt,
            transports,
            deviceType: typeof parsed.deviceType === 'string' ? parsed.deviceType : undefined,
            backedUp: typeof parsed.backedUp === 'boolean' ? parsed.backedUp : undefined,
        };
    } catch {
        return null;
    }
}

function parseStoredPasskeyChallenge(raw: string): StoredPasskeyChallenge | null {
    try {
        const parsed = JSON.parse(raw) as Partial<StoredPasskeyChallenge>;
        if (
            typeof parsed.flowId !== 'string' ||
            typeof parsed.challenge !== 'string' ||
            typeof parsed.createdAt !== 'number'
        ) {
            return null;
        }

        return {
            flowId: parsed.flowId,
            challenge: parsed.challenge,
            email: typeof parsed.email === 'string' ? parsed.email : undefined,
            redirectUri: typeof parsed.redirectUri === 'string' ? parsed.redirectUri : undefined,
            createdAt: parsed.createdAt,
        };
    } catch {
        return null;
    }
}

function getPasskeyExpectedOrigins(): string | string[] {
    return PASSKEY_ALLOWED_ORIGINS.length === 1 ? PASSKEY_ALLOWED_ORIGINS[0] : PASSKEY_ALLOWED_ORIGINS;
}

async function getPasskeyCredentialsForUser(email: string): Promise<StoredPasskeyCredential[]> {
    const rawMap = await redisClient.hGetAll(passkeyUserKey(email));
    const parsed = Object.values(rawMap)
        .map((raw) => parseStoredPasskeyCredential(raw))
        .filter((item): item is StoredPasskeyCredential => item !== null);
    parsed.sort((a, b) => b.lastUsedAt - a.lastUsedAt);
    return parsed;
}

async function getPasskeyCredentialForUser(email: string, credentialId: string): Promise<StoredPasskeyCredential | null> {
    const raw = await redisClient.hGet(passkeyUserKey(email), credentialId);
    if (!raw) return null;
    return parseStoredPasskeyCredential(raw);
}

async function getPasskeyCredentialOwner(credentialId: string): Promise<string | null> {
    const owner = await redisClient.get(passkeyCredentialKey(credentialId));
    if (!owner || owner.trim() === '') return null;
    return owner;
}

async function savePasskeyCredentialForUser(email: string, credential: StoredPasskeyCredential): Promise<boolean> {
    const credentialKey = passkeyCredentialKey(credential.credentialId);
    const existingOwner = await redisClient.get(credentialKey);
    if (existingOwner && existingOwner !== email) {
        return false;
    }

    if (!existingOwner) {
        const reserved = await redisClient.set(credentialKey, email, { NX: true });
        if (reserved !== 'OK') {
            return false;
        }
    }

    await redisClient.hSet(passkeyUserKey(email), credential.credentialId, JSON.stringify(credential));
    return true;
}

async function deletePasskeyCredentialForUser(email: string, credentialId: string): Promise<boolean> {
    const removed = await redisClient.hDel(passkeyUserKey(email), credentialId);
    if (removed === 0) return false;

    const credentialKey = passkeyCredentialKey(credentialId);
    const owner = await redisClient.get(credentialKey);
    if (owner === email) {
        await redisClient.del(credentialKey);
    }
    return true;
}

async function storePasskeyChallenge(kind: PasskeyChallengeKind, challenge: StoredPasskeyChallenge): Promise<void> {
    await redisClient.set(
        passkeyChallengeKey(kind, challenge.flowId),
        JSON.stringify(challenge),
        { EX: PASSKEY_CHALLENGE_TTL_S, NX: true },
    );
}

async function consumePasskeyChallenge(kind: PasskeyChallengeKind, flowId: string): Promise<StoredPasskeyChallenge | null> {
    const raw = await redisClient.getDel(passkeyChallengeKey(kind, flowId));
    if (!raw) return null;
    return parseStoredPasskeyChallenge(raw);
}

async function authenticateSession(req: Request): Promise<AuthenticatedSession | null> {
    const cookies = cookie.parse(req.headers.cookie ?? '');
    const sessionToken = cookies[COOKIE_NAME];
    if (!sessionToken) return null;

    try {
        const { payload } = await jwtVerify(sessionToken, JWT_SECRET, { issuer: JWT_ISSUER, algorithms: ['HS256'] });
        if (typeof payload.sub !== 'string' || typeof payload.jti !== 'string') {
            return null;
        }

        if (!users[payload.sub]) {
            return null;
        }

        const active = await sessionStore.isActive(payload.sub, payload.jti);
        if (!active) {
            return null;
        }

        return { email: payload.sub, jti: payload.jti };
    } catch {
        return null;
    }
}

async function authenticateAdmin(req: Request): Promise<string | null> {
    const auth = await authenticateSession(req);
    if (!auth) return null;
    return users[auth.email]?.isAdmin ? auth.email : null;
}

const verifyHandler: RequestHandler = async (req, res) => {
    const sourceIp = req.ip ?? 'unknown';
    const userAgent = getHeaderString(req, 'user-agent') || 'unknown';
    const platformHeader = getHeaderString(req, 'sec-ch-ua-platform');
    const platform = platformHeader || undefined;
    logger.debug(`[verify] Verifying request from IP: ${sourceIp}`);

    try {
        const parsedCookies = cookie.parse(req.headers.cookie ?? '');
        let token: string | undefined;

        const authHeader = getHeaderString(req, 'authorization');
        if (authHeader?.toLowerCase().startsWith('bearer ')) {
            token = authHeader.slice('bearer '.length).trim();
        } else {
            token = parsedCookies[COOKIE_NAME];
        }

        if (!token) throw new Error('No token found');

        const { payload } = await jwtVerify(token, JWT_SECRET, { issuer: JWT_ISSUER, algorithms: ['HS256'] });

        if (typeof payload.sub !== 'string') {
            throw new Error('Token subject missing');
        }

        const userRecord = users[payload.sub];
        if (!userRecord) {
            throw new Error('User not found');
        }

        const requestedHost = req.hostname;
        if (!requestedHost) {
            throw new Error('Host header missing');
        }

        if (!isHostAllowed(requestedHost, userRecord.allowedHosts)) {
            logger.warn(`[verify] Host access denied for user "${payload.sub}" from IP ${sourceIp} on host ${requestedHost}`);
            if (isDocumentRequest(req)) {
                const body = '<div class="alert alert--error">Zugriff auf diesen Host ist für Ihr Konto nicht erlaubt.</div>';
                res.status(403).set('Cache-Control', 'no-store').send(getPageHTML('Zugriff verweigert', body));
            } else {
                res.status(403).set('Cache-Control', 'no-store').end('Forbidden');
            }
            return;
        }

        const requestedUri = req.header('X-Forwarded-Uri') ?? req.originalUrl ?? '/';
        const adultContentRequested = isAdultPath(requestedUri);
        // Trust primary flag from users.json; allow a signed token claim as additive truthy signal
        const userIsAdult = userRecord.isAdult === true || payload.isAdult === true;

        if (adultContentRequested && !userIsAdult) {
            logger.warn(`[verify] Adult content blocked for user "${payload.sub}" from IP ${sourceIp} on uri ${requestedUri}`);
            if (isDocumentRequest(req)) {
                const body = '<div class="alert alert--error">Dieser Inhalt ist nur für volljährige Nutzerinnen und Nutzer freigeschaltet.</div>';
                res.status(403).set('Cache-Control', 'no-store').send(getPageHTML('Zugriff verweigert', body));
            } else {
                res.status(403).set('Cache-Control', 'no-store').end('Forbidden');
            }
            return;
        }

        if (typeof payload.jti !== 'string' || payload.jti.trim() === '') {
            throw new Error('Token jti missing');
        }

        // Require active session for all tokens (including bearer tokens).
        const active = await sessionStore.isActive(payload.sub, payload.jti);
        if (!active) {
            throw new Error('Session not active');
        }

        logger.debug(`[verify] Verification successful for IP: ${sourceIp} (user: "${payload.sub}", host: ${requestedHost})`);

        void recordLastSeen(payload.sub, {
            ip: sourceIp,
            host: requestedHost,
            uri: requestedUri,
            userAgent,
            platform,
            via: 'verify',
            jti: typeof payload.jti === 'string' ? payload.jti : undefined,
        });

        if (typeof payload.iat === 'number' && (Date.now() - payload.iat * 1000) < JUST_LOGGED_GRACE_MS) {
            res.set('X-Forwarded-User', payload.sub);
            res.set('X-Forwarded-Is-Adult', userIsAdult ? '1' : '0');
            res.sendStatus(200);
            return;
        }

        // Removed banner redirect logic to prevent redirect loops

        res.set('X-Forwarded-User', payload.sub);
        res.set('X-Forwarded-Is-Adult', userIsAdult ? '1' : '0');
        res.sendStatus(200);
        return;
    } catch (error) {
        const reason = (error as Error).message.includes('No token') ? 'No token' : 'Invalid, expired, or inactive session token';
        logger.warn(`[verify] Verification failed for IP ${sourceIp}: ${reason}`);

        const originalUrl = getOriginalUrl(req);

        const loginUrl = new URL(LOGIN_REDIRECT_URL);
        loginUrl.searchParams.set('redirect_uri', originalUrl);
        if (isDocumentRequest(req)) {
            res.redirect(loginUrl.toString());
        } else {
            res.status(401).set('Cache-Control', 'no-store').end('Unauthorized');
        }
    }
};

const statusHandler: RequestHandler = async (req, res) => {
    const sourceIp = req.ip ?? 'unknown';
    logger.debug(`[status] Status check from IP: ${sourceIp}`);

    try {
        const parsedCookies = cookie.parse(req.headers.cookie ?? '');
        let token: string | undefined;

        const authHeader = getHeaderString(req, 'authorization');
        if (authHeader?.toLowerCase().startsWith('bearer ')) {
            token = authHeader.slice('bearer '.length).trim();
        } else {
            token = parsedCookies[COOKIE_NAME];
        }

        if (!token) throw new Error('No token found');

        const { payload } = await jwtVerify(token, JWT_SECRET, { issuer: JWT_ISSUER, algorithms: ['HS256'] });

        if (typeof payload.sub !== 'string') {
            throw new Error('Token subject missing');
        }

        const userRecord = users[payload.sub];
        if (!userRecord) {
            throw new Error('User not found');
        }

        if (typeof payload.jti !== 'string' || payload.jti.trim() === '') {
            throw new Error('Token jti missing');
        }

        // Require active session for all tokens (including bearer tokens).
        const active = await sessionStore.isActive(payload.sub, payload.jti);
        if (!active) {
            throw new Error('Session not active');
        }

        const userIsAdult = userRecord.isAdult === true || payload.isAdult === true;

        res.set('Cache-Control', 'no-store');
        res.set('Vary', 'Cookie');
        res.status(200).json({ loggedIn: true, user: payload.sub, isAdult: userIsAdult });
        return;
    } catch (error) {
        const reason = (error as Error).message.includes('No token') ? 'No token' : 'Invalid, expired, or inactive session token';
        logger.debug(`[status] Status check failed for IP ${sourceIp}: ${reason}`);
        res.set('Cache-Control', 'no-store');
        res.set('Vary', 'Cookie');
        res.status(401).json({ loggedIn: false });
    }
};

function isObjectRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null;
}

function getRequiredTrimmedString(value: unknown): string | null {
    if (typeof value !== 'string') return null;
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : null;
}

function isRegistrationResponseJson(value: unknown): value is RegistrationResponseJSON {
    if (!isObjectRecord(value)) return false;
    if (typeof value.id !== 'string' || typeof value.rawId !== 'string' || value.type !== 'public-key') return false;
    if (!isObjectRecord(value.response)) return false;

    const response = value.response;
    return (
        typeof response.clientDataJSON === 'string' &&
        typeof response.attestationObject === 'string'
    );
}

function isAuthenticationResponseJson(value: unknown): value is AuthenticationResponseJSON {
    if (!isObjectRecord(value)) return false;
    if (typeof value.id !== 'string' || typeof value.rawId !== 'string' || value.type !== 'public-key') return false;
    if (!isObjectRecord(value.response)) return false;

    const response = value.response;
    return (
        typeof response.clientDataJSON === 'string' &&
        typeof response.authenticatorData === 'string' &&
        typeof response.signature === 'string'
    );
}

const passkeyRegisterOptionsHandler: RequestHandler<ParamsDictionary, unknown, PasskeyRegisterOptionsBody> = async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');

    if (!PASSKEY_ENABLED) {
        res.status(404).json({ error: 'Not found' });
        return;
    }

    if (!isAllowedAuthPost(req as Request)) {
        logger.warn(`[passkey] Cross-site register/options blocked from IP ${req.ip}`);
        res.status(403).json({ error: 'Ungültige Anfrageherkunft.' });
        return;
    }

    const auth = await authenticateSession(req as Request);
    if (!auth) {
        res.status(401).json({ error: 'Nicht angemeldet.' });
        return;
    }

    const providedEmail = getRequiredTrimmedString(req.body?.email);
    if (providedEmail && normalizeEmailIdentifier(providedEmail) !== auth.email) {
        res.status(403).json({ error: 'E-Mail stimmt nicht mit aktiver Sitzung überein.' });
        return;
    }

    const existingCredentials = await getPasskeyCredentialsForUser(auth.email);
    const options = await generateRegistrationOptions({
        rpName: PASSKEY_RP_NAME,
        rpID: PASSKEY_RP_ID ?? '',
        userName: auth.email,
        userID: new TextEncoder().encode(auth.email),
        userDisplayName: auth.email,
        attestationType: 'none',
        authenticatorSelection: {
            residentKey: 'preferred',
            userVerification: 'required',
        },
        excludeCredentials: existingCredentials.map((credential) => ({
            id: credential.credentialId,
            transports: credential.transports,
        })),
    });

    const flowId = randomUUID();
    await storePasskeyChallenge('reg', {
        flowId,
        challenge: options.challenge,
        email: auth.email,
        createdAt: Date.now(),
    });

    logger.info(`[passkey] registration options issued for user "${auth.email}"`);
    res.status(200).json({ flowId, options });
};

const passkeyRegisterVerifyHandler: RequestHandler<ParamsDictionary, unknown, PasskeyRegisterVerifyBody> = async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');

    if (!PASSKEY_ENABLED) {
        res.status(404).json({ error: 'Not found' });
        return;
    }

    if (!isAllowedAuthPost(req as Request)) {
        logger.warn(`[passkey] Cross-site register/verify blocked from IP ${req.ip}`);
        res.status(403).json({ error: 'Ungültige Anfrageherkunft.' });
        return;
    }

    const auth = await authenticateSession(req as Request);
    if (!auth) {
        res.status(401).json({ error: 'Nicht angemeldet.' });
        return;
    }

    const flowId = getRequiredTrimmedString(req.body?.flowId);
    if (!flowId) {
        res.status(400).json({ error: 'flowId fehlt.' });
        return;
    }

    if (!isRegistrationResponseJson(req.body?.credential)) {
        res.status(400).json({ error: 'Ungültige Registrierung-Antwort.' });
        return;
    }

    const challengeState = await consumePasskeyChallenge('reg', flowId);
    if (!challengeState) {
        res.status(400).json({ error: 'Challenge abgelaufen oder bereits verwendet.' });
        return;
    }

    if (challengeState.email !== auth.email) {
        res.status(403).json({ error: 'Challenge passt nicht zum aktiven Benutzer.' });
        return;
    }

    try {
        const verification = await verifyRegistrationResponse({
            response: req.body.credential,
            expectedChallenge: challengeState.challenge,
            expectedOrigin: getPasskeyExpectedOrigins(),
            expectedRPID: PASSKEY_RP_ID ?? '',
            requireUserVerification: true,
        });

        if (!verification.verified || !verification.registrationInfo) {
            res.status(400).json({ error: 'Passkey-Verifizierung fehlgeschlagen.' });
            return;
        }

        const now = Date.now();
        const registrationInfo = verification.registrationInfo;
        const credential: StoredPasskeyCredential = {
            credentialId: registrationInfo.credential.id,
            publicKey: bytesToBase64Url(registrationInfo.credential.publicKey),
            counter: registrationInfo.credential.counter,
            transports: req.body.credential.response.transports?.filter(isTransport),
            createdAt: now,
            lastUsedAt: now,
            deviceType: registrationInfo.credentialDeviceType,
            backedUp: registrationInfo.credentialBackedUp,
        };

        const saved = await savePasskeyCredentialForUser(auth.email, credential);
        if (!saved) {
            logger.warn(`[passkey] Credential collision on registration for user "${auth.email}" (${redactedCredentialId(credential.credentialId)})`);
            res.status(409).json({ error: 'Passkey ist bereits für einen anderen Benutzer registriert.' });
            return;
        }

        logger.info(`[passkey] registration success for user "${auth.email}" (${redactedCredentialId(credential.credentialId)})`);
        res.status(200).json({ ok: true });
    } catch (error) {
        const clientOrigin = getWebAuthnClientOrigin(req.body?.credential?.response?.clientDataJSON);
        logger.warn(
            `[passkey] registration verify failed for user "${auth.email}": ${(error as Error).message}` +
            (clientOrigin ? ` (clientOrigin=${clientOrigin})` : '')
        );
        res.status(400).json({ error: 'Passkey-Verifizierung fehlgeschlagen.' });
    }
};

const passkeyAuthOptionsHandler: RequestHandler<ParamsDictionary, unknown, PasskeyAuthOptionsBody> = async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');

    if (!PASSKEY_ENABLED) {
        res.status(404).json({ error: 'Not found' });
        return;
    }

    if (!isAllowedAuthPost(req as Request)) {
        logger.warn(`[passkey] Cross-site auth/options blocked from IP ${req.ip}`);
        res.status(403).json({ error: 'Ungültige Anfrageherkunft.' });
        return;
    }

    const emailInput = getRequiredTrimmedString(req.body?.email);
    const requestedEmail = emailInput ? normalizeEmailIdentifier(emailInput) : undefined;
    let allowCredentials: { id: string; transports?: AuthenticatorTransportFuture[] }[] | undefined;
    let challengeEmail: string | undefined;

    if (requestedEmail) {
        // Avoid account/passkey enumeration: fall back to discovery when no matching
        // user/passkey exists instead of returning an error.
        const storedCredentials = await getPasskeyCredentialsForUser(requestedEmail);
        if (users[requestedEmail] && storedCredentials.length > 0) {
            allowCredentials = storedCredentials.map((credential) => ({
                id: credential.credentialId,
                transports: credential.transports,
            }));
            challengeEmail = requestedEmail;
        }
    }

    const options = await generateAuthenticationOptions({
        rpID: PASSKEY_RP_ID ?? '',
        userVerification: 'required',
        ...(allowCredentials ? { allowCredentials } : {}),
    });

    const flowId = randomUUID();
    const redirectUri = validateRedirectUri(req.body?.redirect_uri ?? '/');
    await storePasskeyChallenge('auth', {
        flowId,
        challenge: options.challenge,
        email: challengeEmail,
        redirectUri,
        createdAt: Date.now(),
    });

    logger.info(`[passkey] authentication options issued (${challengeEmail ? `user "${challengeEmail}"` : 'discovery'})`);
    res.status(200).json({ flowId, options });
};

const passkeyAuthVerifyHandler: RequestHandler<ParamsDictionary, unknown, PasskeyAuthVerifyBody> = async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');

    if (!PASSKEY_ENABLED) {
        res.status(404).json({ error: 'Not found' });
        return;
    }

    if (!isAllowedAuthPost(req as Request)) {
        logger.warn(`[passkey] Cross-site auth/verify blocked from IP ${req.ip}`);
        res.status(403).json({ error: 'Ungültige Anfrageherkunft.' });
        return;
    }

    const flowId = getRequiredTrimmedString(req.body?.flowId);
    if (!flowId) {
        res.status(400).json({ error: 'flowId fehlt.' });
        return;
    }

    if (!isAuthenticationResponseJson(req.body?.credential)) {
        res.status(400).json({ error: 'Ungültige Anmelde-Antwort.' });
        return;
    }

    const challengeState = await consumePasskeyChallenge('auth', flowId);
    if (!challengeState) {
        res.status(400).json({ error: 'Challenge abgelaufen oder bereits verwendet.' });
        return;
    }

    let email = challengeState.email;
    const credentialId = req.body.credential.id;
    const mappedOwner = await getPasskeyCredentialOwner(credentialId);
    email ??= mappedOwner ?? undefined;

    if (!email || !users[email]) {
        res.status(401).json({ error: 'Passkey-Anmeldung fehlgeschlagen.' });
        return;
    }

    if (mappedOwner && mappedOwner !== email) {
        logger.warn(`[passkey] auth verify owner mismatch for credential ${redactedCredentialId(credentialId)}`);
        res.status(401).json({ error: 'Passkey-Anmeldung fehlgeschlagen.' });
        return;
    }

    const storedCredential = await getPasskeyCredentialForUser(email, credentialId);
    if (!storedCredential) {
        logger.warn(`[passkey] auth verify failed: unknown credential for "${email}"`);
        res.status(401).json({ error: 'Passkey-Anmeldung fehlgeschlagen.' });
        return;
    }

    const credential: WebAuthnCredential = {
        id: storedCredential.credentialId,
        publicKey: base64UrlToBytes(storedCredential.publicKey),
        counter: storedCredential.counter,
        transports: storedCredential.transports,
    };

    try {
        const verification = await verifyAuthenticationResponse({
            response: req.body.credential,
            expectedChallenge: challengeState.challenge,
            expectedOrigin: getPasskeyExpectedOrigins(),
            expectedRPID: PASSKEY_RP_ID ?? '',
            credential,
            requireUserVerification: true,
        });

        if (!verification.verified) {
            res.status(401).json({ error: 'Passkey-Anmeldung fehlgeschlagen.' });
            return;
        }

        const now = Date.now();
        const updatedCredential: StoredPasskeyCredential = {
            ...storedCredential,
            counter: verification.authenticationInfo.newCounter,
            lastUsedAt: now,
            deviceType: verification.authenticationInfo.credentialDeviceType,
            backedUp: verification.authenticationInfo.credentialBackedUp,
        };
        const saved = await savePasskeyCredentialForUser(email, updatedCredential);
        if (!saved) {
            res.status(409).json({ error: 'Credential-Zuordnung ist nicht mehr gültig.' });
            return;
        }

        const jti = randomUUID();
        await sessionStore.addSession(email, jti, COOKIE_MAX_AGE_S, MAX_SESSIONS_PER_USER);

        const jwt = await new SignJWT({})
            .setProtectedHeader({ alg: 'HS256' })
            .setIssuer(JWT_ISSUER)
            .setSubject(email)
            .setJti(jti)
            .setIssuedAt()
            .setExpirationTime(`${COOKIE_MAX_AGE_S}s`)
            .sign(JWT_SECRET);

        res.setHeader('Set-Cookie', [
            cookie.serialize(COOKIE_NAME, jwt, getSessionCookieOptions()),
        ]);

        void recordLastSeen(email, {
            ip: req.ip ?? 'unknown',
            host: req.hostname || 'unknown',
            uri: challengeState.redirectUri ?? '/',
            userAgent: getHeaderString(req as Request, 'user-agent') || 'unknown',
            platform: getHeaderString(req as Request, 'sec-ch-ua-platform') || undefined,
            via: 'login',
            jti,
        });

        logger.info(`[passkey] authentication success for user "${email}" (${redactedCredentialId(storedCredential.credentialId)})`);
        res.status(200).json({
            ok: true,
            redirectTo: validateRedirectUri(req.body?.redirect_uri ?? challengeState.redirectUri ?? '/'),
        });
    } catch (error) {
        const clientOrigin = getWebAuthnClientOrigin(req.body?.credential?.response?.clientDataJSON);
        logger.warn(
            `[passkey] auth verify failed for "${email}": ${(error as Error).message}` +
            (clientOrigin ? ` (clientOrigin=${clientOrigin})` : '')
        );
        res.status(401).json({ error: 'Passkey-Anmeldung fehlgeschlagen.' });
    }
};

const passkeyCredentialsHandler: RequestHandler = async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');

    if (!PASSKEY_ENABLED) {
        res.status(404).json({ error: 'Not found' });
        return;
    }

    const auth = await authenticateSession(req as Request);
    if (!auth) {
        res.status(401).json({ error: 'Nicht angemeldet.' });
        return;
    }

    const credentials = await getPasskeyCredentialsForUser(auth.email);
    res.status(200).json({
        credentials: credentials.map((credential) => ({
            credentialId: credential.credentialId,
            createdAt: credential.createdAt,
            lastUsedAt: credential.lastUsedAt,
            transports: credential.transports ?? [],
            deviceType: credential.deviceType ?? 'unknown',
            backedUp: credential.backedUp ?? false,
        })),
    });
};

const passkeyCredentialDeleteHandler: RequestHandler<ParamsDictionary, unknown, PasskeyCredentialDeleteBody> = async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');

    if (!PASSKEY_ENABLED) {
        res.status(404).json({ error: 'Not found' });
        return;
    }

    if (!isAllowedAuthPost(req as Request)) {
        logger.warn(`[passkey] Cross-site credential/delete blocked from IP ${req.ip}`);
        res.status(403).json({ error: 'Ungültige Anfrageherkunft.' });
        return;
    }

    const auth = await authenticateSession(req as Request);
    if (!auth) {
        res.status(401).json({ error: 'Nicht angemeldet.' });
        return;
    }

    const credentialId = getRequiredTrimmedString(req.body?.credentialId);
    if (!credentialId) {
        res.status(400).json({ error: 'credentialId fehlt.' });
        return;
    }

    const removed = await deletePasskeyCredentialForUser(auth.email, credentialId);
    if (!removed) {
        res.status(404).json({ error: 'Passkey nicht gefunden.' });
        return;
    }

    logger.info(`[passkey] credential deleted for "${auth.email}" (${redactedCredentialId(credentialId)})`);
    res.status(200).json({ ok: true });
};

const loginPageHandler: RequestHandler<ParamsDictionary | Record<string, never>, string, LoginBody, LoginQuery> = async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');

    const cookies = cookie.parse(req.headers.cookie ?? '');
    const userAgent = getHeaderString(req as Request, 'user-agent') || 'unknown';
    const platformHeader = getHeaderString(req as Request, 'sec-ch-ua-platform');
    const platform = platformHeader || undefined;
    const requestHost = req.hostname;

    const rawRedirectUri = req.query.redirect_uri ?? req.body?.redirect_uri;
    const validatedDestinationUri = validateRedirectUri(rawRedirectUri ?? getOriginalUrl(req as Request));
    const safeDestinationUri = he.encode(validatedDestinationUri);
    const setupPasskeyRequested = req.query.setup_passkey === '1';

    const sourceIp = req.ip ?? 'unknown';

    if (req.method === 'POST') {
        if (!isAllowedAuthPost(req as Request)) {
            logger.warn(`[auth] Cross-site POST blocked from IP: ${sourceIp} (origin=${req.headers.origin ?? ''}, referer=${req.headers.referer ?? ''})`);
            const backLink = `${AUTH_ORIGIN}/auth?redirect_uri=${encodeURIComponent(validatedDestinationUri)}`;
            const body = `
                <div class="alert alert--error">Ungültige Anfrageherkunft. Bitte verwenden Sie die offizielle Anmeldeseite.</div>
                <p><a href="${backLink}">Zur Anmeldeseite</a></p>
            `;
            res.status(403).send(getPageHTML('Zugriff verweigert', body));
            return;
        }

        let email: string;
        try {
            email = parseRequiredLoginEmail(req.body?.email);
        } catch (error) {
            logger.warn(`[auth] Rejected login with invalid email input from IP: ${sourceIp}`);
            const message = `<div class="alert alert--error">${he.encode((error as Error).message)}</div><h1>Bitte anmelden</h1>`;
            const loginFormBody = buildLoginFormBody(safeDestinationUri, message);
            res.status(400).send(getPageHTML('Anmeldung', loginFormBody));
            return;
        }
        if (typeof req.body?.password !== 'string') {
            logger.warn(`[auth] Rejected login with invalid password type from IP: ${sourceIp}`);
            const message = '<div class="alert alert--error">Ungültige Anfrage.</div><h1>Bitte anmelden</h1>';
            const loginFormBody = buildLoginFormBody(safeDestinationUri, message);
            res.status(400).send(getPageHTML('Anmeldung', loginFormBody));
            return;
        }
        const pass = req.body.password;
        logger.info(`[auth] Login attempt for user "${email}" from IP: ${sourceIp}`);

        if (email && pass) {
            const userObject = users[email];
            const hash = userObject?.hash;
            const DUMMY_HASH = '$argon2id$v=19$m=65536,t=3,p=4$WXl3a2tCbjVYcHpGNEoyRw$g5bC13aXAa/U0KprDD9P7x0BvJ2T1jcsjpQj5Ym+kIM';
            const hashToVerify = hash || DUMMY_HASH;

            try {
                const isMatch = await argon2.verify(hashToVerify, pass);
                if (isMatch && hash) {
                    logger.info(`[auth] SUCCESS: User "${email}" authenticated from IP: ${sourceIp}`);

                    const jti = randomUUID();
                    // Register session before issuing the cookie, enforcing max active sessions
                    const allowed = await sessionStore.addSession(email, jti, COOKIE_MAX_AGE_S, MAX_SESSIONS_PER_USER);
                    if (!allowed) {
                        logger.warn(`[auth] BLOCKED: User "${email}" at session limit (${MAX_SESSIONS_PER_USER})`);
                        const message = '<div class="alert alert--error">Zu viele aktive Sitzungen für dieses Konto. Bitte melden Sie sich auf einem anderen Gerät ab und versuchen Sie es erneut.</div>';
                        const loginFormBody = buildLoginFormBody(safeDestinationUri, `${message}<h1>Bitte anmelden</h1>`);
                        res.status(429).send(getPageHTML('Zu viele Sitzungen', loginFormBody));
                        return;
                    }

                    const jwt = await new SignJWT({})
                        .setProtectedHeader({ alg: 'HS256' })
                        .setIssuer(JWT_ISSUER)
                        .setSubject(email)
                        .setJti(jti)
                        .setIssuedAt()
                        .setExpirationTime(`${COOKIE_MAX_AGE_S}s`)
                        .sign(JWT_SECRET);

                    res.setHeader('Set-Cookie', [
                        cookie.serialize(COOKIE_NAME, jwt, getSessionCookieOptions())
                    ]);

                    const lastSeenHost = requestHost || req.hostname || 'unknown';
                    void recordLastSeen(email, {
                        ip: sourceIp,
                        host: lastSeenHost,
                        uri: validatedDestinationUri,
                        userAgent,
                        platform,
                        via: 'login',
                        jti,
                    });

                    if (PASSKEY_ENABLED) {
                        try {
                            const existingPasskeys = await getPasskeyCredentialsForUser(email);
                            if (existingPasskeys.length === 0) {
                                const setupPasskeyUrl = new URL(`${AUTH_ORIGIN}/auth`);
                                setupPasskeyUrl.searchParams.set('redirect_uri', validatedDestinationUri);
                                setupPasskeyUrl.searchParams.set('setup_passkey', '1');
                                res.redirect(setupPasskeyUrl.toString());
                                return;
                            }
                        } catch (error) {
                            logger.warn(`[passkey] Could not check existing passkeys for "${email}", continuing with normal redirect.`, error);
                        }
                    }

                    res.redirect(validatedDestinationUri);
                    return;
                }
            } catch (error) {
                logger.error('[auth] Internal error during argon2 verification', error);
                const body = '<div class="alert alert--error"><strong>Es ist ein Fehler aufgetreten.</strong> Bitte versuchen Sie es später erneut.</div>';
                res.status(500).send(getPageHTML('Fehler', body));
                return;
            }
        }
        logger.warn(`[auth] FAILED: Authentication attempt from IP: ${sourceIp}`);
    }

    try {
        const token = cookies[COOKIE_NAME];
        if (!token) throw new Error('Not logged in');
        const { payload } = await jwtVerify(token, JWT_SECRET, { issuer: JWT_ISSUER, algorithms: ['HS256'] });

        // If token carries JTI but session is not active anymore, treat as logged out.
        if (typeof payload.sub === 'string' && typeof payload.jti === 'string') {
            const stillActive = await sessionStore.isActive(payload.sub, payload.jti);
            if (!stillActive) {
                logger.warn('[auth] Inactive session token detected on /auth; clearing cookie and showing login form.');

                const clearCookieOptions: cookie.SerializeOptions = { maxAge: 0, domain: DOMAIN, httpOnly: true, secure: true, sameSite: 'strict', path: '/' };
                if (!DOMAIN) delete clearCookieOptions.domain;
                res.setHeader('Set-Cookie', [
                    cookie.serialize(COOKIE_NAME, '', clearCookieOptions)
                ]);

                const message = '<div class="alert alert--error">Sie wurden auf diesem Gerät abgemeldet, weil Sie sich an einem anderen Ort angemeldet haben. Bitte melden Sie sich erneut an.</div>';
                const loginFormBody = buildLoginFormBody(safeDestinationUri, `${message}<h1>Bitte anmelden</h1>`);
                res.status(401).send(getPageHTML('Anmeldung', loginFormBody));
                return;
            }
        }

        let hasPasskey = false;
        if (PASSKEY_ENABLED && typeof payload.sub === 'string') {
            try {
                hasPasskey = (await getPasskeyCredentialsForUser(payload.sub)).length > 0;
            } catch (error) {
                logger.warn(`[passkey] Could not load passkey list for "${payload.sub}"`, error);
            }
        }

        const promptPasskeySetup = PASSKEY_ENABLED && setupPasskeyRequested && !hasPasskey;
        const loggedInBody = buildLoggedInBody(safeDestinationUri, {
            setupPasskeyPrompt: promptPasskeySetup,
            autoRedirectAfterPasskeySetup: promptPasskeySetup,
        });
        res.status(200).send(getPageHTML('Angemeldet', loggedInBody));
        return;
    } catch {
        logger.warn('[auth] JWT verification not present/failed (likely not logged in).');

        const loginMessage = req.method === 'POST'
            ? '<div class="alert alert--error">Ungültige E-Mail oder Passwort.</div><h1>Bitte anmelden</h1>'
            : '<h1>Bitte anmelden</h1>';

        const loginFormBody = buildLoginFormBody(safeDestinationUri, loginMessage);

        res.status(401).send(getPageHTML('Anmeldung', loginFormBody));
    }
};

const logoutHandler: RequestHandler = async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');

    logger.info(`[logout] User logged out from IP: ${req.ip}`);

    const sessionCookieOptions: cookie.SerializeOptions = { maxAge: 0, domain: DOMAIN, httpOnly: true, secure: true, sameSite: 'strict', path: '/' };
    if (!DOMAIN) delete sessionCookieOptions.domain;

    // Best-effort revoke of current session
    try {
        const parsedCookies = cookie.parse(req.headers.cookie ?? '');
        const token = parsedCookies[COOKIE_NAME];
        if (token) {
            const { payload } = await jwtVerify(token, JWT_SECRET, { issuer: JWT_ISSUER, algorithms: ['HS256'] });
            if (typeof payload.sub === 'string' && typeof payload.jti === 'string') {
                await sessionStore.removeSession(payload.sub, payload.jti);
            }
        }
    } catch {
        // ignore errors; still clear cookie
    }

    res.setHeader('Set-Cookie', [
        cookie.serialize(COOKIE_NAME, '', sessionCookieOptions)
    ]);

    const logoutBody = `
        <section class="content-stack">
            <h1>Abgemeldet</h1>
            <p>Sie wurden erfolgreich abgemeldet.</p>
            <div class="action-row">
                <a class="button button--primary" href="/">Erneut anmelden</a>
            </div>
        </section>
    `;
    res.status(200).send(getPageHTML('Abgemeldet', logoutBody));
};

const adminLastSeenHandler: RequestHandler = async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');

    const adminUser = await authenticateAdmin(req);
    if (!adminUser) {
        logger.warn(`[admin] Unauthorized last-seen access attempt from IP: ${req.ip}`);
        const body = '<div class="alert alert--error">Zugriff verweigert. Bitte als Admin anmelden.</div>';
        res.status(401).send(getPageHTML('Zugriff verweigert', body));
        return;
    }

    const entries = await fetchLastSeen();
    logger.info(`[admin] Last-seen report requested by "${adminUser}" from IP ${req.ip}; ${entries.length} entries returned`);

    const tableRows = entries.map((entry) => {
        const platform = entry.platform ? entry.platform.replace(/^"+|"+$/g, '') : '–';
        const uri = entry.uri ? he.encode(entry.uri) : '–';
        const jti = entry.jti ? he.encode(entry.jti) : '–';
        const viaLabel = entry.via === 'login' ? 'Login' : 'Verify';
        return `
            <tr>
                <td>${he.encode(entry.user)}</td>
                <td><span title="${new Date(entry.at).toISOString()}">${he.encode(formatTimestamp(entry.at))}</span></td>
                <td>${he.encode(entry.ip)}</td>
                <td>${he.encode(entry.host)}</td>
                <td>${uri}</td>
                <td>${he.encode(platform)}</td>
                <td><span class="pill pill--muted">${he.encode(viaLabel)}</span></td>
                <td><span class="code">${jti}</span></td>
                <td><span class="meta">${he.encode(entry.userAgent)}</span></td>
            </tr>
        `;
    }).join('') || `
        <tr>
            <td colspan="9" class="table__empty">Keine Einträge vorhanden.</td>
        </tr>
    `;

    const body = `
        <section class="content-stack">
            ${buildAdminNav('last-seen')}
            <h1>Letzte Aktivität</h1>
            <p class="meta">Anzeige des letzten Logins/Verifies pro Nutzer (aus Redis gespeichert).</p>
            <div class="table-wrapper">
                <table class="table">
                    <thead>
                        <tr>
                            <th>Nutzer</th>
                            <th>Wann</th>
                            <th>IP</th>
                            <th>Host</th>
                            <th>URI</th>
                            <th>Gerät</th>
                            <th>Quelle</th>
                            <th>JTI</th>
                            <th>User Agent</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${tableRows}
                    </tbody>
                </table>
            </div>
        </section>
    `;

    res.status(200).send(getPageHTML('Letzte Aktivität', body, { wide: true }));
};

interface AdminRevokeBody {
    user?: string;
}

const adminSessionsHandler: RequestHandler = async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');

    const adminUser = await authenticateAdmin(req);
    if (!adminUser) {
        logger.warn(`[admin] Unauthorized sessions access attempt from IP: ${req.ip}`);
        const body = '<div class="alert alert--error">Zugriff verweigert. Bitte als Admin anmelden.</div>';
        res.status(401).send(getPageHTML('Zugriff verweigert', body));
        return;
    }

    const notice = typeof req.query.notice === 'string' ? req.query.notice : undefined;
    const noticeText = notice ?? '';
    const entries = await fetchSessionOverview();
    const totalActive = entries.reduce((acc, entry) => acc + entry.activeCount, 0);
    const totalSessions = entries.reduce((acc, entry) => acc + entry.totalCount, 0);
    logger.info(`[admin] Session overview requested by "${adminUser}" from IP ${req.ip}; users=${entries.length} active=${totalActive}`);

    const tableRows = entries.map((entry) => {
        const lastSeen = entry.lastSeen;
        const lastSeenWhen = lastSeen ? formatTimestamp(lastSeen.at) : '–';
        const lastSeenTitle = lastSeen ? new Date(lastSeen.at).toISOString() : '';
        const lastSeenMeta = lastSeen ? `${lastSeen.ip} • ${lastSeen.host}` : '';
        const lastSeenUri = lastSeen?.uri ?? '';
        const lastSeenHtml = lastSeen
            ? `
                <div><span title="${he.encode(lastSeenTitle)}">${he.encode(lastSeenWhen)}</span></div>
                <div class="meta">${he.encode(lastSeenMeta)}</div>
                ${lastSeenUri ? `<div class="meta">${he.encode(lastSeenUri)}</div>` : ''}
            `
            : '–';

        const sessionItems = entry.sessions.map((session) => {
            const expLabel = session.expiryMs ? formatTimestamp(session.expiryMs) : '–';
            const expTitle = session.expiryMs ? new Date(session.expiryMs).toISOString() : '';
            const statusClass = session.active ? 'pill' : 'pill pill--muted';
            const statusLabel = session.active ? 'Gültig' : 'Ungültig';
            return `
                <div class="session-entry">
                    <span class="${statusClass}">${he.encode(statusLabel)}</span>
                    <span title="${he.encode(expTitle)}" class="code">${he.encode(expLabel)}</span>
                    <span class="code">${he.encode(session.jti)}</span>
                </div>
            `;
        }).join('') || '<div class="meta">Keine Sessions gefunden.</div>';

        const action = entry.totalCount > 0
            ? `
                <form class="inline-form" method="post" action="/admin/sessions/revoke">
                    <input type="hidden" name="user" value="${he.encode(entry.user)}" />
                    <button class="button--small button--danger" type="submit" onclick="return confirm('Alle Sessions löschen?')">Sessions löschen</button>
                </form>
            `
            : '<span class="meta">–</span>';

        return `
            <tr>
                <td>${he.encode(entry.user)}</td>
                <td>${lastSeenHtml}</td>
                <td><span class="stat">${he.encode(`${entry.activeCount} / ${entry.totalCount}`)}</span></td>
                <td><div class="session-list">${sessionItems}</div></td>
                <td>${action}</td>
            </tr>
        `;
    }).join('') || `
        <tr>
            <td colspan="5" class="table__empty">Keine Sessions gefunden.</td>
        </tr>
    `;

    const body = `
        <section class="content-stack">
            ${buildAdminNav('sessions')}
            <h1>Aktive Sitzungen</h1>
            <p class="meta">Direkt aus Redis geladen. Nur Admin-Zugriff. Sessions gelten als gültig, wenn ein passender sess:token-Eintrag existiert.</p>
            ${noticeText ? `<div class="alert">${he.encode(noticeText)}</div>` : ''}
            <div class="stat">
                <span class="pill">Nutzer: ${he.encode(String(entries.length))}</span>
                <span class="pill pill--muted">Gültig: ${he.encode(String(totalActive))} / ${he.encode(String(totalSessions))}</span>
                <form class="inline-form" method="post" action="/admin/sessions/cleanup">
                    <button class="button--small button--danger" type="submit" onclick="return confirm('Ungültige Sessions aus Redis entfernen?')">Cleanup</button>
                </form>
            </div>
            <div class="table-wrapper">
                <table class="table">
                    <thead>
                        <tr>
                            <th>Nutzer</th>
                            <th>Letzte Aktivität</th>
                            <th>Gültig/Gesamt</th>
                            <th>Sessions</th>
                            <th>Aktion</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${tableRows}
                    </tbody>
                </table>
            </div>
        </section>
    `;

    res.status(200).send(getPageHTML('Aktive Sitzungen', body, { wide: true }));
};

const adminSessionsRevokeHandler: RequestHandler<ParamsDictionary, string, AdminRevokeBody> = async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');

    const adminUser = await authenticateAdmin(req);
    if (!adminUser) {
        logger.warn(`[admin] Unauthorized session revoke attempt from IP: ${req.ip}`);
        const body = '<div class="alert alert--error">Zugriff verweigert. Bitte als Admin anmelden.</div>';
        res.status(401).send(getPageHTML('Zugriff verweigert', body));
        return;
    }

    if (!isAllowedAuthPost(req as Request)) {
        logger.warn(`[admin] Cross-site revoke blocked from IP: ${req.ip} (origin=${req.headers.origin ?? ''}, referer=${req.headers.referer ?? ''})`);
        const body = '<div class="alert alert--error">Ungültige Anfrageherkunft.</div>';
        res.status(403).send(getPageHTML('Zugriff verweigert', body));
        return;
    }

    const user = typeof req.body.user === 'string' ? req.body.user.trim() : '';
    if (!user) {
        res.redirect('/admin/sessions?notice=Ungültiger Nutzer.');
        return;
    }

    const userKey = `${SESSION_USER_PREFIX}${user}`;
    let jtis: string[] = [];
    try {
        jtis = await redisClient.zRange(userKey, 0, -1);
    } catch (error) {
        logger.error(`[admin] Failed to fetch sessions for "${user}"`, error);
    }

    if (jtis.length > 0) {
        const multi = redisClient.multi();
        for (const jti of jtis) {
            multi.del(`${SESSION_TOKEN_PREFIX}${jti}`);
        }
        multi.del(userKey);
        await multi.exec();
    } else {
        await redisClient.del(userKey);
    }

    logger.info(`[admin] Sessions revoked for user "${user}" by "${adminUser}" (jtis=${jtis.length})`);
    const notice = encodeURIComponent(`Sitzungen für "${user}" gelöscht (${jtis.length}).`);
    res.redirect(`/admin/sessions?notice=${notice}`);
};

const adminSessionsCleanupHandler: RequestHandler = async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');

    const adminUser = await authenticateAdmin(req);
    if (!adminUser) {
        logger.warn(`[admin] Unauthorized session cleanup attempt from IP: ${req.ip}`);
        const body = '<div class="alert alert--error">Zugriff verweigert. Bitte als Admin anmelden.</div>';
        res.status(401).send(getPageHTML('Zugriff verweigert', body));
        return;
    }

    if (!isAllowedAuthPost(req as Request)) {
        logger.warn(`[admin] Cross-site cleanup blocked from IP: ${req.ip} (origin=${req.headers.origin ?? ''}, referer=${req.headers.referer ?? ''})`);
        const body = '<div class="alert alert--error">Ungültige Anfrageherkunft.</div>';
        res.status(403).send(getPageHTML('Zugriff verweigert', body));
        return;
    }

    const result = await cleanupOrphanedSessions();
    logger.info(
        `[admin] Session cleanup by "${adminUser}" removed=${result.removed} scanned=${result.scanned} users=${result.users}`
    );
    const notice = encodeURIComponent(
        `Cleanup: ${result.removed} ungültige Sessions entfernt (gescannt ${result.scanned}, Nutzer ${result.users}).`
    );
    res.redirect(`/admin/sessions?notice=${notice}`);
};

void (async () => {
    await loadUsers();

    // Log effective configuration once at startup (secrets masked)
    logStartupConfig();

    try {
        if (USE_INMEMORY_STORE) {
            await redisClient.connect();
            logger.warn('[redis] INMEMORY_FALLBACK enabled: using process-local in-memory store (development only).');
        } else {
            try {
                await redisClient.connect();
                logger.info('[redis] Connected to Redis');
            } catch (error) {
                logger.error('[redis] FATAL: Failed to connect to Redis.', error);
                process.exit(1);
            }

            // Create Redis-backed stores once connected
            const sendCommand = (...args: string[]): Promise<RedisReply> => redisClient.sendCommand(args) as Promise<RedisReply>;
            loginStore = new RedisStore({ sendCommand, prefix: 'rl:login:' });
            verifyStore = new RedisStore({ sendCommand, prefix: 'rl:verify:' });
            authPageStore = new RedisStore({ sendCommand, prefix: 'rl:authpage:' });
            adminLastSeenStore = new RedisStore({ sendCommand, prefix: 'rl:admin-lastseen:' });
            passkeyAuthStore = new RedisStore({ sendCommand, prefix: 'rl:passkey-auth:' });
            passkeyRegisterStore = new RedisStore({ sendCommand, prefix: 'rl:passkey-register:' });
            passkeyCredentialsStore = new RedisStore({ sendCommand, prefix: 'rl:passkey-credentials:' });
        }

        // Initialize rate limiters with Redis stores when available
        loginLimiter = rateLimit({
            windowMs: LOGIN_LIMITER_WINDOW_S * 1000,
            limit: LOGIN_LIMITER_MAX,
            standardHeaders: true,
            legacyHeaders: false,
            message: 'Zu viele Anmeldeversuche von dieser IP. Bitte versuchen Sie es in 15 Minuten erneut.',
            ...(loginStore ? { store: loginStore } : {}),
        });
        verifyLimiter = rateLimit({
            windowMs: VERIFY_LIMITER_WINDOW_S * 1000,
            limit: VERIFY_LIMITER_MAX,
            standardHeaders: true,
            legacyHeaders: false,
            message: 'Zu viele Anfragen von dieser IP. Bitte versuchen Sie es später erneut.',
            ...(verifyStore ? { store: verifyStore } : {}),
        });
        authPageLimiter = rateLimit({
            windowMs: AUTH_PAGE_LIMITER_WINDOW_S * 1000,
            limit: AUTH_PAGE_LIMITER_MAX,
            standardHeaders: true,
            legacyHeaders: false,
            message: 'Zu viele Anfragen von dieser IP. Bitte versuchen Sie es später erneut.',
            ...(authPageStore ? { store: authPageStore } : {}),
        });
        adminLastSeenLimiter = rateLimit({
            windowMs: ADMIN_LAST_SEEN_LIMITER_WINDOW_S * 1000,
            limit: ADMIN_LAST_SEEN_LIMITER_MAX,
            standardHeaders: true,
            legacyHeaders: false,
            message: 'Zu viele Admin-Anfragen von dieser IP. Bitte versuchen Sie es später erneut.',
            ...(adminLastSeenStore ? { store: adminLastSeenStore } : {}),
        });
        passkeyAuthLimiter = rateLimit({
            windowMs: PASSKEY_LOGIN_LIMITER_WINDOW_S * 1000,
            limit: PASSKEY_LOGIN_LIMITER_MAX,
            standardHeaders: true,
            legacyHeaders: false,
            message: 'Zu viele Passkey-Anfragen von dieser IP. Bitte versuchen Sie es später erneut.',
            ...(passkeyAuthStore ? { store: passkeyAuthStore } : {}),
        });
        passkeyRegisterLimiter = rateLimit({
            windowMs: PASSKEY_REGISTER_LIMITER_WINDOW_S * 1000,
            limit: PASSKEY_REGISTER_LIMITER_MAX,
            standardHeaders: true,
            legacyHeaders: false,
            message: 'Zu viele Passkey-Registrierungsanfragen von dieser IP. Bitte versuchen Sie es später erneut.',
            ...(passkeyRegisterStore ? { store: passkeyRegisterStore } : {}),
        });
        passkeyCredentialsLimiter = rateLimit({
            windowMs: PASSKEY_CREDENTIALS_LIMITER_WINDOW_S * 1000,
            limit: PASSKEY_CREDENTIALS_LIMITER_MAX,
            standardHeaders: true,
            legacyHeaders: false,
            message: 'Zu viele Passkey-Abfragen von dieser IP. Bitte versuchen Sie es später erneut.',
            ...(passkeyCredentialsStore ? { store: passkeyCredentialsStore } : {}),
        });

        // Initialize session store (Redis or in-memory fallback)
        sessionStore = new RedisSessionStore(redisClient);
        logger.info(
            `[sessions] Using ${USE_INMEMORY_STORE ? 'in-memory' : 'Redis-backed'} session store; max per user: ${MAX_SESSIONS_PER_USER}; strategy: last-login-wins`
        );

        // Register routes after limiters are ready
        app.get('/', (req, res) => {
            res.redirect('/auth');
        });
        app.post('/auth', loginLimiter, loginPageHandler);
        app.get('/auth', authPageLimiter, loginPageHandler);
        app.get('/auth/status', verifyLimiter, statusHandler);
        app.post('/passkey/register/options', passkeyRegisterLimiter, passkeyRegisterOptionsHandler);
        app.post('/passkey/register/verify', passkeyRegisterLimiter, passkeyRegisterVerifyHandler);
        app.post('/passkey/auth/options', passkeyAuthLimiter, passkeyAuthOptionsHandler);
        app.post('/passkey/auth/verify', passkeyAuthLimiter, passkeyAuthVerifyHandler);
        app.get('/passkey/credentials', passkeyCredentialsLimiter, passkeyCredentialsHandler);
        app.post('/passkey/credentials/delete', passkeyRegisterLimiter, passkeyCredentialDeleteHandler);
        app.get('/logout', logoutHandler);
        app.get('/verify', verifyLimiter, verifyHandler);
        app.get('/admin/last-seen', adminLastSeenLimiter, adminLastSeenHandler);
        app.get('/admin/sessions', adminLastSeenLimiter, adminSessionsHandler);
        app.post('/admin/sessions/revoke', adminLastSeenLimiter, adminSessionsRevokeHandler);
        app.post('/admin/sessions/cleanup', adminLastSeenLimiter, adminSessionsCleanupHandler);
        logger.info(`[passkey] endpoints ${PASSKEY_ENABLED ? 'enabled' : 'disabled'} (feature flag PASSKEY_ENABLED)`);
        logger.info('[admin] /admin/last-seen enabled (admin session required)');
        logger.info('[admin] /admin/sessions enabled (admin session required)');

        // Removed /still-logged route

        // Poll for changes in users.json and reload on modifications
        watchFile(USER_FILE, { interval: USER_FILE_WATCH_INTERVAL_MS }, (curr, prev) => {
            if (curr.mtimeMs !== prev.mtimeMs) {
                logger.info(`[users] Change detected (mtime). Reloading users from ${USER_FILE}...`);
                void loadUsers({ fatal: false });
            }
        });

        process.on('SIGHUP', () => {
            logger.info('[users] SIGHUP received. Reloading users...');
            void loadUsers({ fatal: false });
        });
    } catch (error) {
        logger.warn('[users] Failed to initialize watch/polling for users file.', error);
    }

    app.listen(PORT, () => {
        logger.info(`[server] ForwardAuth listening on port ${PORT}`);
        if (!DOMAIN) {
            logger.warn('[config] DOMAIN is not set. Cookies may not work across subdomains.');
        } else {
            logger.info(`[config] Cookies will be set for domain: ${DOMAIN}`);
        }
    })
})();
