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

const secretEnv = process.env.JWT_SECRET;
if (!secretEnv) {
    console.error('FATAL: JWT_SECRET environment variable is not set.');
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
const LOGIN_LIMITER_MAX = getEnvAsNumber('LOGIN_LIMITER_MAX', 10);
const VERIFY_LIMITER_MAX = getEnvAsNumber('VERIFY_LIMITER_MAX', 5000);
const AUTH_PAGE_LIMITER_MAX = getEnvAsNumber('AUTH_PAGE_LIMITER_MAX', 300);
const COOKIE_NAME = process.env.COOKIE_NAME ?? 'fwd_token';
const JWT_ISSUER = process.env.JWT_ISSUER ?? 'forwardauth';
const DOMAIN = process.env.DOMAIN;
const DOMAIN_WILDCARD = DOMAIN ? `https://*.${DOMAIN}` : undefined;
const ROOT_DOMAIN = DOMAIN ? `https://${DOMAIN}` : undefined;
const LOGIN_REDIRECT_URL = process.env.LOGIN_REDIRECT_URL ?? 'http://localhost:3000/auth';
const AUTH_ORIGIN = new URL(LOGIN_REDIRECT_URL).origin;
const JUST_LOGGED_GRACE_MS = getEnvAsNumber('JUST_LOGGED_GRACE_MS', 10) * 1000;
const USER_FILE_WATCH_INTERVAL_MS = getEnvAsNumber('USER_FILE_WATCH_INTERVAL_MS', 5000);
const MAX_SESSIONS_PER_USER = getEnvAsNumber('MAX_SESSIONS_PER_USER', 3);

function getEnvSecret(key: string, fileKey: string): string | undefined {
    const filePath = process.env[fileKey];
    if (filePath) {
        try {
            return readFileSync(filePath, 'utf-8').trim();
        } catch (error) {
            console.error(`[rate-limit] Failed reading secret file from ${filePath}:`, error);
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

if (!REDIS_URL && !REDIS_HOST) {
    console.error('FATAL: Redis configuration is required. Provide REDIS_URL or REDIS_HOST(+REDIS_PORT).');
    process.exit(1);
}

let redisClient: RedisClientType;
let loginStore: RateLimitStore;
let verifyStore: RateLimitStore;
let authPageStore: RateLimitStore;

if (REDIS_URL) {
    redisClient = createClient({ url: REDIS_URL, username: REDIS_USERNAME, password: REDIS_PASSWORD });
} else {
    const proto = REDIS_TLS ? 'rediss' : 'redis';
    const url = `${proto}://${REDIS_HOST}:${REDIS_PORT}`;
    redisClient = createClient({ url, username: REDIS_USERNAME, password: REDIS_PASSWORD });
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

// Rate limiters will be created after optional Redis connect
let loginLimiter: RequestHandler;
let verifyLimiter: RequestHandler;
let authPageLimiter: RequestHandler;

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
                )
        )
    );
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

async function loadUsers(options: { fatal?: boolean } = { fatal: true }) {
    const { fatal = true } = options;
    try {
        const rawContent = await fs.readFile(USER_FILE, 'utf-8');
        const raw: unknown = JSON.parse(rawContent);

        if (!isRecordOfUser(raw)) {
            throw new Error('Invalid users.json structure');
        }

        users = raw;
        console.log(`Loaded ${Object.keys(users).length} users from ${USER_FILE}`);
    } catch (error) {
        if (fatal) {
            console.error(`FATAL: Could not load or parse user file from "${USER_FILE}".`, error);
            process.exit(1);
        } else {
            console.warn(`WARN: Reloading users failed; keeping previous users. (${(error as Error).message})`);
        }
    }
}

function validateRedirectUri(uri: string): string {
    const defaultRedirect = '/';
    if (!uri) return defaultRedirect;

    try {
        const url = new URL(uri);
        if (DOMAIN && (url.hostname === DOMAIN || url.hostname.endsWith(`.${DOMAIN}`))) {
            return uri;
        }

        console.warn(`[validateRedirectUri] Blocked potential open redirect to: ${uri}`);
        return defaultRedirect;
    } catch (error) {
        if (uri.startsWith('/') && !uri.startsWith('//')) {
            return uri;
        }
        console.warn('[validateRedirectUri] Invalid redirect URI provided: %s', uri, error);
        return defaultRedirect;
    }
}

function getOriginalUrl(req: Request): string {
    const proto = req.header('X-Forwarded-Proto') ?? 'https';
    const host = req.header('X-Forwarded-Host') ?? req.hostname;
    const uri = req.header('X-Forwarded-Uri') ?? '/';
    return `${proto}://${host}${uri}`;
}

const getPageHTML = (title: string, body: string): string => `
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>${title}</title>
        <link rel="stylesheet" href="/styles.css">
    </head>
    <body>
        <div class="container">
            ${body}
        </div>
    </body>
    </html>
`;

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

        // Robust prune: drop expired JTIs from the index before counting
        await this.client.zRemRangeByScore(userKey, '-inf', nowMs);

        // Reject when limit reached (only active JTIs remain)
        const count = await this.client.zCard(userKey);
        if (count >= maxSessions) return false;

        // Add new session atomically
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

const verifyHandler: RequestHandler = async (req, res) => {
    const sourceIp = req.ip;
    console.log(`[verifyHandler] Verifying request from IP: ${sourceIp}`);

    try {
        const parsedCookies = cookie.parse(req.headers.cookie ?? '');
        const token = parsedCookies[COOKIE_NAME];
        if (!token) throw new Error('No token found');

        const { payload } = await jwtVerify(token, JWT_SECRET, { issuer: JWT_ISSUER, algorithms: ['HS256'] });

        if (typeof payload.sub !== 'string') {
            throw new Error('Token subject missing');
        }

        const userRecord = users[payload.sub];
        if (!userRecord) {
            throw new Error('User not found');
        }

        const requestedHost = req.header('X-Forwarded-Host') ?? req.hostname;
        if (!requestedHost) {
            throw new Error('Host header missing');
        }

        if (!isHostAllowed(requestedHost, userRecord.allowedHosts)) {
            console.warn(`[verifyHandler] Host access denied for user "${payload.sub}" from IP ${sourceIp} on host ${requestedHost}`);
            res.status(403).set('Cache-Control', 'no-store').end('Forbidden');
            return;
        }

        // Enforce active session check when token carries a JTI
        if (typeof payload.jti === 'string') {
            const active = await sessionStore.isActive(payload.sub, payload.jti);
            if (!active) {
                throw new Error('Session not active');
            }
        }

        console.log(`[verifyHandler] Verification successful for IP: ${sourceIp} (user: "${payload.sub}", host: ${requestedHost})`);

        if (typeof payload.iat === 'number' && (Date.now() - payload.iat * 1000) < JUST_LOGGED_GRACE_MS) {
            res.set('X-Forwarded-User', payload.sub);
            res.sendStatus(200);
            return;
        }

        // Removed banner redirect logic to prevent redirect loops

        res.set('X-Forwarded-User', payload.sub);
        res.sendStatus(200);
        return;
    } catch (error) {
        const reason = (error as Error).message.includes('No token') ? 'No token' : 'Invalid, expired, or inactive session token';
        console.warn(`[verifyHandler] Verification failed for IP ${sourceIp}: ${reason}`);

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

const loginPageHandler: RequestHandler<ParamsDictionary | Record<string, never>, string, LoginBody, LoginQuery> = async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');

    const cookies = cookie.parse(req.headers.cookie ?? '');

    const rawRedirectUri = req.query.redirect_uri ?? req.body?.redirect_uri;
    const validatedDestinationUri = validateRedirectUri(rawRedirectUri ?? getOriginalUrl(req as Request));
    const safeDestinationUri = he.encode(validatedDestinationUri);

    const sourceIp = req.ip;

    if (req.method === 'POST') {
        if (!isAllowedAuthPost(req as Request)) {
            console.warn(`[loginPageHandler] FAILED: Cross-site POST blocked from IP: ${sourceIp} (origin=${req.headers.origin ?? ''}, referer=${req.headers.referer ?? ''})`);
            res.status(403).send(getPageHTML('Error', '<h1>Forbidden</h1><p>Invalid request origin.</p>'));
            return;
        }

        const user = req.body.username!;
        const pass = req.body.password!;
        console.log(`[loginPageHandler] Login attempt for user "${user}" from IP: ${sourceIp}`);

        if (user && pass) {
            const userObject = users[user];
            const hash = userObject?.hash;
            const DUMMY_HASH = '$argon2id$v=19$m=65536,t=3,p=4$WXl3a2tCbjVYcHpGNEoyRw$g5bC13aXAa/U0KprDD9P7x0BvJ2T1jcsjpQj5Ym+kIM';
            const hashToVerify = hash || DUMMY_HASH;

            try {
                const isMatch = await argon2.verify(hashToVerify, pass);
                if (isMatch && hash) {
                    console.log(`[loginPageHandler] SUCCESS: User "${user}" authenticated from IP: ${sourceIp}`);

                    const jti = randomUUID();
                    // Register session before issuing the cookie, enforcing max active sessions
                    const allowed = await sessionStore.addSession(user, jti, COOKIE_MAX_AGE_S, MAX_SESSIONS_PER_USER);
                    if (!allowed) {
                        console.warn(`[loginPageHandler] BLOCKED: User "${user}" at session limit (${MAX_SESSIONS_PER_USER})`);
                        const message = '<h1 class="login-error">Too many active sessions for this account. Please log out on another device and try again.</h1>';
                        const loginFormBody = `
                            ${message}
                            <form method="post" action="${AUTH_ORIGIN}/auth">
                                <input type="hidden" name="redirect_uri" value="${safeDestinationUri}" />
                                <input name="username" placeholder="Username" required autocomplete="username" />
                                <input name="password" type="password" placeholder="Password" required autocomplete="current-password" />
                                <button type="submit">Login</button>
                            </form>
                        `;
                        res.status(429).send(getPageHTML('Too many sessions', loginFormBody));
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

                    res.redirect(validatedDestinationUri);
                    return;
                }
            } catch (error) {
                console.error('Internal error during argon2 verification', error);
                res.status(500).send(getPageHTML('Error', '<h1>Internal Server Error</h1><p>An unexpected error occurred. Please try again later.</p>'));
                return;
            }
        }
        console.warn(`[loginPageHandler] FAILED: Authentication attempt from IP: ${sourceIp}`);
    }

    try {
        const token = cookies[COOKIE_NAME];
        if (!token) throw new Error('Not logged in');
        const { payload } = await jwtVerify(token, JWT_SECRET, { issuer: JWT_ISSUER, algorithms: ['HS256'] });

        // If token carries JTI but session is not active anymore, treat as logged out.
        if (typeof payload.sub === 'string' && typeof payload.jti === 'string') {
            const stillActive = await sessionStore.isActive(payload.sub, payload.jti);
            if (!stillActive) {
                console.warn('[loginPageHandler] Inactive session token detected on /auth; clearing cookie and showing login form.');

                const clearCookieOptions: cookie.SerializeOptions = { maxAge: 0, domain: DOMAIN, httpOnly: true, secure: true, sameSite: 'strict', path: '/' };
                if (!DOMAIN) delete clearCookieOptions.domain;
                res.setHeader('Set-Cookie', [
                    cookie.serialize(COOKIE_NAME, '', clearCookieOptions)
                ]);

                const message = '<h1 class="login-error">You have been signed out on this device because you logged in elsewhere. Please login again.</h1>';
                const loginFormBody = `
                    ${message}
                    <form method="post" action="${AUTH_ORIGIN}/auth">
                        <input type="hidden" name="redirect_uri" value="${safeDestinationUri}" />
                        <input name="username" placeholder="Username" required autocomplete="username" />
                        <input name="password" type="password" placeholder="Password" required autocomplete="current-password" />
                        <button type="submit">Login</button>
                    </form>
                `;
                res.status(401).send(getPageHTML('Login', loginFormBody));
                return;
            }
        }

        const loggedInBody = `
            <h1>Authenticated</h1>
            <p>You are successfully authenticated and can access other protected services.</p>
            <p><a href="${safeDestinationUri}">Go back to original destination</a> or <a href="/logout">Logout</a></p>
        `;
        res.status(200).send(getPageHTML('Authenticated', loggedInBody));
        return;
    } catch {
        console.warn('[loginPageHandler] JWT verification not present/failed (likely not logged in).');

        const loginMessage = req.method === 'POST'
            ? '<h1 class="login-error">Invalid username or password!</h1>'
            : '<h1>Please Login</h1>';

        const loginFormBody = `
            ${loginMessage}
            <form method="post" action="${AUTH_ORIGIN}/auth">
                <input type="hidden" name="redirect_uri" value="${safeDestinationUri}" />
                <input name="username" placeholder="Username" required autocomplete="username" />
                <input name="password" type="password" placeholder="Password" required autocomplete="current-password" />
                <button type="submit">Login</button>
            </form>
        `;

        res.status(401).send(getPageHTML('Login', loginFormBody));
    }
};

const logoutHandler: RequestHandler = async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');

    console.log(`[logoutHandler] User logged out from IP :${req.ip}`);

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
        <h1>Logged Out</h1>
        <p>You have been successfully logged out.</p>
        <a href="/">Login again</a>
    `;
    res.status(200).send(getPageHTML('Logged Out', logoutBody));
};

void (async () => {
    await loadUsers();

    try {
        // Connect to Redis (required)
        try {
            await redisClient.connect();
            console.log('[redis] Connected to Redis');
        } catch (error) {
            console.error('[redis] FATAL: Failed to connect to Redis.', error);
            process.exit(1);
        }

        // Create Redis-backed stores once connected
        const sendCommand = (...args: string[]): Promise<RedisReply> => redisClient.sendCommand(args);
        loginStore = new RedisStore({ sendCommand, prefix: 'rl:login:' });
        verifyStore = new RedisStore({ sendCommand, prefix: 'rl:verify:' });
        authPageStore = new RedisStore({ sendCommand, prefix: 'rl:authpage:' });

        // Initialize rate limiters with Redis store
        loginLimiter = rateLimit({
            windowMs: LOGIN_LIMITER_WINDOW_S * 1000,
            limit: LOGIN_LIMITER_MAX,
            standardHeaders: true,
            legacyHeaders: false,
            message: 'Too many login attempts from this IP, please try again after 15 minutes',
            store: loginStore,
        });
        verifyLimiter = rateLimit({
            windowMs: VERIFY_LIMITER_WINDOW_S * 1000,
            limit: VERIFY_LIMITER_MAX,
            standardHeaders: true,
            legacyHeaders: false,
            message: 'Too many requests from this IP, please try again later',
            store: verifyStore,
        });
        authPageLimiter = rateLimit({
            windowMs: AUTH_PAGE_LIMITER_WINDOW_S * 1000,
            limit: AUTH_PAGE_LIMITER_MAX,
            standardHeaders: true,
            legacyHeaders: false,
            message: 'Too many requests from this IP, please try again later',
            store: authPageStore,
        });

        // Initialize session store (Redis only)
        sessionStore = new RedisSessionStore(redisClient);
        console.log(`[sessions] Using Redis-backed session store; max per user: ${MAX_SESSIONS_PER_USER}; strategy: reject`);

        // Register routes after limiters are ready
        app.get('/', (req, res) => {
            res.redirect('/auth');
        });
        app.post('/auth', loginLimiter, loginPageHandler);
        app.get('/auth', authPageLimiter, loginPageHandler);
        app.get('/logout', logoutHandler);
        app.get('/verify', verifyLimiter, verifyHandler);

        // Removed /still-logged route

        // Poll for changes in users.json and reload on modifications
        watchFile(USER_FILE, { interval: USER_FILE_WATCH_INTERVAL_MS }, (curr, prev) => {
            if (curr.mtimeMs !== prev.mtimeMs) {
                console.log(`[users.json] Change detected (mtime). Reloading users from ${USER_FILE}...`);
                void loadUsers({ fatal: false });
            }
        });

        process.on('SIGHUP', () => {
            console.log('[users.json] SIGHUP received. Reloading users...');
            void loadUsers({ fatal: false });
        });
    } catch (error) {
        console.warn('[users.json] Failed to initialize watch/polling for users file.', error);
    }

    app.listen(PORT, () => {
        console.log(`ForwardAuth-Server running on port: ${PORT}`);
        if (!DOMAIN) {
            console.warn('WARN: DOMAIN environment variable is not set. Cookies may not work across subdomains.');
        } else {
            console.log(`Cookies will be set for domain: ${DOMAIN}`);
        }
    })
})();
