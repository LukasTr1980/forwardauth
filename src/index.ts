import express, { type Request, type RequestHandler } from 'express';
import { type ParamsDictionary } from 'express-serve-static-core';
import rateLimit, { type Store as RateLimitStore } from 'express-rate-limit';
import { RedisStore, type RedisReply } from 'rate-limit-redis';
import { createClient, type RedisClientType } from 'redis';
import * as cookie from 'cookie';
import { SignJWT, jwtVerify } from 'jose';
import argon2 from 'argon2';
import fs from 'fs/promises';
import { watchFile, readFileSync } from 'node:fs';
import path from 'path';
import helmet from 'helmet';
import he from 'he';
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
}

interface LoginBody {
    username?: string;
    password?: string;
    redirect_uri?: string;
}

function getEnvAsNumber(key: string, defaultValue: number): number {
    const value = parseInt(process.env[key] ?? '', 10);
    return Number.isFinite(value) ? value : defaultValue;
}

function parseCsvList(value?: string): string[] {
    if (!value) return [];
    return value.split(',').map((item) => item.trim()).filter(Boolean);
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
const JUST_LOGGED_GRACE_MS = getEnvAsNumber('JUST_LOGGED_GRACE_MS', 10) * 1000;
const USER_FILE_WATCH_INTERVAL_MS = getEnvAsNumber('USER_FILE_WATCH_INTERVAL_MS', 5000);
const MAX_SESSIONS_PER_USER = getEnvAsNumber('MAX_SESSIONS_PER_USER', 3);
const ADULT_PATH_PREFIXES = parseCsvList(process.env.ADULT_PATH_PREFIXES).map(normalizePathPrefix).filter(Boolean);


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

// Redis (REQUIRED) for rate limiting and sessions
const REDIS_URL = process.env.REDIS_URL;
const REDIS_HOST = process.env.REDIS_HOST;
const REDIS_PORT = getEnvAsNumber('REDIS_PORT', 6379);
const REDIS_USERNAME = process.env.REDIS_USERNAME;
const REDIS_PASSWORD = getEnvSecret('REDIS_PASSWORD', 'REDIS_PASSWORD_FILE');
const REDIS_TLS = process.env.REDIS_TLS === '1' || process.env.REDIS_TLS === 'true';
const LAST_SEEN_REDIS_KEY = 'user:lastseen';

if (!REDIS_URL && !REDIS_HOST) {
    logger.error('[config] FATAL: Redis configuration is required. Provide REDIS_URL or REDIS_HOST(+REDIS_PORT).');
    process.exit(1);
}

let redisClient: RedisClientType;
let loginStore: RateLimitStore;
let verifyStore: RateLimitStore;
let authPageStore: RateLimitStore;
let adminLastSeenStore: RateLimitStore;

if (REDIS_URL) {
    redisClient = createClient({ url: REDIS_URL, username: REDIS_USERNAME, password: REDIS_PASSWORD });
} else {
    const proto = REDIS_TLS ? 'rediss' : 'redis';
    const url = `${proto}://${REDIS_HOST}:${REDIS_PORT}`;
    redisClient = createClient({ url, username: REDIS_USERNAME, password: REDIS_PASSWORD });
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
        },
        limits: {
            loginLimiterMax: LOGIN_LIMITER_MAX,
            verifyLimiterMax: VERIFY_LIMITER_MAX,
            authPageLimiterMax: AUTH_PAGE_LIMITER_MAX,
            adminLastSeenLimiterMax: ADMIN_LAST_SEEN_LIMITER_MAX,
        },
        users: {
            file: USER_FILE,
            watchIntervalMs: USER_FILE_WATCH_INTERVAL_MS,
        },
        adult: {
            pathPrefixes: ADULT_PATH_PREFIXES,
        },
        redis: REDIS_URL
            ? { mode: 'url', url: sanitizeRedisUrl(REDIS_URL), tls: REDIS_TLS }
            : { mode: 'host', host: REDIS_HOST, port: REDIS_PORT, tls: REDIS_TLS },
        secrets: {
            jwtSecret: secretEnv ? 'set' : 'unset',
            redisPassword: REDIS_PASSWORD ? 'set' : 'unset',
            redisUsername: REDIS_USERNAME ? 'set' : 'unset',
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

function extractTopLevelUsernames(jsonContent: string): string[] {
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

function findDuplicateUsernames(jsonContent: string): string[] {
    const usernames = extractTopLevelUsernames(jsonContent);
    const seen = new Set<string>();
    const duplicates = new Set<string>();

    for (const name of usernames) {
        if (seen.has(name)) {
            duplicates.add(name);
        } else {
            seen.add(name);
        }
    }

    return Array.from(duplicates);
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
        const duplicateUsernames = findDuplicateUsernames(rawContent);
        const raw: unknown = JSON.parse(rawContent);

        if (!isRecordOfUser(raw)) {
            throw new Error('Invalid users.json structure');
        }

        if (duplicateUsernames.length > 0) {
            const message = `Duplicate usernames detected: ${duplicateUsernames.join(', ')}`;
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

const getPageHTML = (title: string, body: string, options: { containerClass?: string } = {}): string => {
    const containerClass = options.containerClass ? `container ${options.containerClass}` : 'container';
    return `
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>${title}</title>
        <link rel="stylesheet" href="/styles.css">
    </head>
    <body>
        <div class="${containerClass}">
            <div class="brand">${he.encode(BRAND_NAME)}</div>
            ${body}
        </div>
    </body>
    </html>
    `;
};

app.use(express.urlencoded({ extended: false }));
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
    private readonly client: RedisClientType;
    private readonly keySessionPrefix = 'sess:token:'; // sess:token:<jti> -> username
    private readonly keyUserZsetPrefix = 'sess:user:'; // sess:user:<user> -> ZSET of jti scored by expiry (ms epoch)

    constructor(client: RedisClientType) {
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
        let count = await this.client.zCard(userKey);

        // 3) If limit reached, evict oldest active session (Last-Login-Wins)
        if (count >= maxSessions) {
            const oldest = await this.client.zRange(userKey, 0, 0);
            if (oldest.length > 0) {
                const oldestJti = oldest[0];
                await this.client.multi()
                    .del(this.keySession(oldestJti))
                    .zRem(userKey, oldestJti)
                    .exec();
                count--;
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

// In-memory session store removed; Redis is mandatory.

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

async function authenticateAdmin(req: Request): Promise<string | null> {
    const cookies = cookie.parse(req.headers.cookie ?? '');
    const sessionToken = cookies[COOKIE_NAME];
    if (sessionToken) {
        try {
            const { payload } = await jwtVerify(sessionToken, JWT_SECRET, { issuer: JWT_ISSUER, algorithms: ['HS256'] });
            if (typeof payload.sub === 'string') {
                const user = users[payload.sub];
                if (user?.isAdmin) {
                    if (typeof payload.jti === 'string') {
                        const active = await sessionStore.isActive(payload.sub, payload.jti);
                        if (!active) return null;
                    }
                    return payload.sub;
                }
            }
        } catch {
            // fall through to token-based auth
        }
    }
    return null;
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

        const user = req.body.username!;
        const pass = req.body.password!;
        logger.info(`[auth] Login attempt for user "${user}" from IP: ${sourceIp}`);

        if (user && pass) {
            const userObject = users[user];
            const hash = userObject?.hash;
            const DUMMY_HASH = '$argon2id$v=19$m=65536,t=3,p=4$WXl3a2tCbjVYcHpGNEoyRw$g5bC13aXAa/U0KprDD9P7x0BvJ2T1jcsjpQj5Ym+kIM';
            const hashToVerify = hash || DUMMY_HASH;

            try {
                const isMatch = await argon2.verify(hashToVerify, pass);
                if (isMatch && hash) {
                    logger.info(`[auth] SUCCESS: User "${user}" authenticated from IP: ${sourceIp}`);

                    const jti = randomUUID();
                    // Register session before issuing the cookie, enforcing max active sessions
                    const allowed = await sessionStore.addSession(user, jti, COOKIE_MAX_AGE_S, MAX_SESSIONS_PER_USER);
                    if (!allowed) {
                        logger.warn(`[auth] BLOCKED: User "${user}" at session limit (${MAX_SESSIONS_PER_USER})`);
                        const message = '<div class="alert alert--error">Zu viele aktive Sitzungen für dieses Konto. Bitte melden Sie sich auf einem anderen Gerät ab und versuchen Sie es erneut.</div>';
                        const loginFormBody = `
                            ${message}
                            <form method="post" action="${AUTH_ORIGIN}/auth">
                                <input type="hidden" name="redirect_uri" value="${safeDestinationUri}" />
                                <input name="username" placeholder="Benutzername" required autocomplete="username" />
                                <input name="password" type="password" placeholder="Passwort" required autocomplete="current-password" />
                                <button type="submit">Anmelden</button>
                            </form>
                        `;
                        res.status(429).send(getPageHTML('Zu viele Sitzungen', loginFormBody));
                        return;
                    }

                    const jwt = await new SignJWT({})
                        .setProtectedHeader({ alg: 'HS256' })
                        .setIssuer(JWT_ISSUER)
                        .setSubject(user)
                        .setJti(jti)
                        .setIssuedAt()
                        .setExpirationTime(`${COOKIE_MAX_AGE_S}s`)
                        .sign(JWT_SECRET);

                    // Use SameSite Lax to maximize compatibility across subdomain navigations
                    const sessionCookieOptions: cookie.SerializeOptions = { httpOnly: true, secure: true, maxAge: COOKIE_MAX_AGE_S, sameSite: 'lax', path: '/' };
                    if (DOMAIN) sessionCookieOptions.domain = DOMAIN;

                    res.setHeader('Set-Cookie', [
                        cookie.serialize(COOKIE_NAME, jwt, sessionCookieOptions)
                    ]);

                    const lastSeenHost = requestHost || req.hostname || 'unknown';
                    void recordLastSeen(user, {
                        ip: sourceIp,
                        host: lastSeenHost,
                        uri: validatedDestinationUri,
                        userAgent,
                        platform,
                        via: 'login',
                        jti,
                    });

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
                const loginFormBody = `
                    ${message}
                    <form method="post" action="${AUTH_ORIGIN}/auth">
                        <input type="hidden" name="redirect_uri" value="${safeDestinationUri}" />
                        <input name="username" placeholder="Benutzername" required autocomplete="username" />
                        <input name="password" type="password" placeholder="Passwort" required autocomplete="current-password" />
                        <button type="submit">Anmelden</button>
                    </form>
                `;
                res.status(401).send(getPageHTML('Anmeldung', loginFormBody));
                return;
            }
        }

        const loggedInBody = `
            <h1>Angemeldet</h1>
            <p>Sie sind erfolgreich angemeldet und können andere geschützte Dienste aufrufen.</p>
            <p><a href="${safeDestinationUri}">Zur ursprünglichen Seite</a> oder <a href="/logout">Abmelden</a></p>
        `;
        res.status(200).send(getPageHTML('Angemeldet', loggedInBody));
        return;
    } catch {
        logger.warn('[auth] JWT verification not present/failed (likely not logged in).');

        const loginMessage = req.method === 'POST'
            ? '<div class="alert alert--error">Ungültiger Benutzername oder Passwort.</div><h1>Bitte anmelden</h1>'
            : '<h1>Bitte anmelden</h1>';

        const loginFormBody = `
            ${loginMessage}
            <form method="post" action="${AUTH_ORIGIN}/auth">
                <input type="hidden" name="redirect_uri" value="${safeDestinationUri}" />
                <input name="username" placeholder="Benutzername" required autocomplete="username" />
                <input name="password" type="password" placeholder="Passwort" required autocomplete="current-password" />
                <button type="submit">Anmelden</button>
            </form>
        `;

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
        <h1>Abgemeldet</h1>
        <p>Sie wurden erfolgreich abgemeldet.</p>
        <a href="/">Erneut anmelden</a>
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
    `;

    res.status(200).send(getPageHTML('Letzte Aktivität', body, { containerClass: 'container--wide' }));
};

void (async () => {
    await loadUsers();

    // Log effective configuration once at startup (secrets masked)
    logStartupConfig();

    try {
        // Connect to Redis (required)
        try {
            await redisClient.connect();
            logger.info('[redis] Connected to Redis');
        } catch (error) {
            logger.error('[redis] FATAL: Failed to connect to Redis.', error);
            process.exit(1);
        }

        // Create Redis-backed stores once connected
        const sendCommand = (...args: string[]): Promise<RedisReply> => redisClient.sendCommand(args);
        loginStore = new RedisStore({ sendCommand, prefix: 'rl:login:' });
        verifyStore = new RedisStore({ sendCommand, prefix: 'rl:verify:' });
        authPageStore = new RedisStore({ sendCommand, prefix: 'rl:authpage:' });
        adminLastSeenStore = new RedisStore({ sendCommand, prefix: 'rl:admin-lastseen:' });

        // Initialize rate limiters with Redis store
        loginLimiter = rateLimit({
            windowMs: LOGIN_LIMITER_WINDOW_S * 1000,
            limit: LOGIN_LIMITER_MAX,
            standardHeaders: true,
            legacyHeaders: false,
            message: 'Zu viele Anmeldeversuche von dieser IP. Bitte versuchen Sie es in 15 Minuten erneut.',
            store: loginStore,
        });
        verifyLimiter = rateLimit({
            windowMs: VERIFY_LIMITER_WINDOW_S * 1000,
            limit: VERIFY_LIMITER_MAX,
            standardHeaders: true,
            legacyHeaders: false,
            message: 'Zu viele Anfragen von dieser IP. Bitte versuchen Sie es später erneut.',
            store: verifyStore,
        });
        authPageLimiter = rateLimit({
            windowMs: AUTH_PAGE_LIMITER_WINDOW_S * 1000,
            limit: AUTH_PAGE_LIMITER_MAX,
            standardHeaders: true,
            legacyHeaders: false,
            message: 'Zu viele Anfragen von dieser IP. Bitte versuchen Sie es später erneut.',
            store: authPageStore,
        });
        adminLastSeenLimiter = rateLimit({
            windowMs: ADMIN_LAST_SEEN_LIMITER_WINDOW_S * 1000,
            limit: ADMIN_LAST_SEEN_LIMITER_MAX,
            standardHeaders: true,
            legacyHeaders: false,
            message: 'Zu viele Admin-Anfragen von dieser IP. Bitte versuchen Sie es später erneut.',
            store: adminLastSeenStore,
        });

        // Initialize session store (Redis only)
        sessionStore = new RedisSessionStore(redisClient);
        logger.info(`[sessions] Using Redis-backed session store; max per user: ${MAX_SESSIONS_PER_USER}; strategy: last-login-wins`);

        // Register routes after limiters are ready
        app.get('/', (req, res) => {
            res.redirect('/auth');
        });
        app.post('/auth', loginLimiter, loginPageHandler);
        app.get('/auth', authPageLimiter, loginPageHandler);
        app.get('/auth/status', verifyLimiter, statusHandler);
        app.get('/logout', logoutHandler);
        app.get('/verify', verifyLimiter, verifyHandler);
        app.get('/admin/last-seen', adminLastSeenLimiter, adminLastSeenHandler);
        logger.info('[admin] /admin/last-seen enabled (admin session required)');

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
