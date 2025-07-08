import express, { Request, RequestHandler } from 'express';
import rateLimit from 'express-rate-limit';
import * as cookie from 'cookie';
import { SignJWT, jwtVerify } from 'jose';
import argon2 from 'argon2';
import fs from 'fs/promises';
import path from 'path';
import helmet from 'helmet';
import he from 'he';
import { randomBytes } from 'crypto';

interface User {
    hash: string;
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
const USER_FILE = process.env.USER_FILE ?? path.resolve(__dirname, '../users.json');
const PORT = getEnvAsNumber('PORT', 3000);
const COOKIE_MAX_AGE_S = getEnvAsNumber('COOKIE_MAX_AGE_S', 3600);
const LOGIN_LIMITER_WINDOW_S = getEnvAsNumber('LOGIN_LIMITER_WINDOW_S', 15 * 60);
const LOGIN_LIMITER_MAX = getEnvAsNumber('LOGIN_LIMITER_MAX', 10);
const COOKIE_NAME = process.env.COOKIE_NAME ?? 'fwd_token';
const CSRF_COOKIE_NAME = '__Host-csrf-token';
const JWT_ISSUER = process.env.JWT_ISSUER ?? 'forwardauth';
const DOMAIN = process.env.DOMAIN;
const LOGIN_REDIRECT_URL = process.env.LOGIN_REDIRECT_URL || 'http://localhost:3000/auth';

const app = express();
app.disable('x-powered-by');
app.use(helmet());
app.use(helmet.contentSecurityPolicy({
    directives: {
        defaultSrc: ["'self'"],
    }
}));
app.set('trust proxy', 1);

const loginLimiter = rateLimit({
    windowMs: LOGIN_LIMITER_WINDOW_S * 1000,
    max: LOGIN_LIMITER_MAX,
    standardHeaders: true,
    legacyHeaders: false,
    message: 'Too many login attempts from this IP, please try again after 15 minutes',
});

let users: Record<string, User> = {};

async function loadUsers() {
    try {
        users = JSON.parse(await fs.readFile(USER_FILE, 'utf-8'));
        console.log(`Successfully loaded ${Object.keys(users).length} users from ${USER_FILE}`);
    } catch (error) {
        console.error(`FATAL: Could not load or parse user file from "${USER_FILE}".`, error);
        process.exit(1);
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
        console.warn(`[validateRedirectUri] Invalid redirect URI provided: ${uri}`);
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
        <!-- Verlinke zur externen CSS-Datei -->
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

const verifyHandler: RequestHandler = async (req, res) => {
    const sourceIp = req.ip;
    console.log(`[verifyHandler] Verifying request from IP: ${sourceIp}`);

    try {
        const cookies = cookie.parse(req.headers.cookie || '');
        const token = cookies[COOKIE_NAME];
        if (!token) throw new Error('No token found');

        await jwtVerify(token, JWT_SECRET, { issuer: JWT_ISSUER, algorithms: ['HS256'] });
        console.log(`[verifyHandler] Verification successful for IP: ${sourceIp}`);
        res.sendStatus(200);
        return;
    } catch (error) {
        const reason = (error as Error).message.includes('No token') ? 'No token' : 'Invalid or expired token';
        console.warn(`[verifyHandler] Verification failed for IP ${sourceIp}: ${reason}`);

        const originalUrl = getOriginalUrl(req);

        const loginUrl = new URL(LOGIN_REDIRECT_URL, `${req.protocol}://${req.get('host')}`);
        loginUrl.searchParams.set('redirect_uri', originalUrl);
        res.redirect(loginUrl.toString());
    }
};

const loginPageHandler: RequestHandler = async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');

    const rawRedirectUri = (req.query.redirect_uri || (req.body && req.body.redirect_uri)) as string;
    const validatedDestinationUri = validateRedirectUri(rawRedirectUri || getOriginalUrl(req));
    const safeDestinationUri = he.encode(validatedDestinationUri);

    const sourceIp = req.ip;
    const cookies = cookie.parse(req.headers.cookie || '');

    if (req.method === 'POST') {
        const sentCsrfToken = req.body.csrf_token as string;
        const cookieCsrfToken = cookies[CSRF_COOKIE_NAME];

        if (!sentCsrfToken || !cookieCsrfToken || sentCsrfToken !== cookieCsrfToken) {
            console.warn(`[loginPageHandler] FAILED: Invalid CSRF token from IP: ${sourceIp}`);
            res.status(403).send(getPageHTML('Error', '<h1>Invalid Request</h1><p>Your session is invalid. Please return to the login page and try again.</p>'));
            return;
        }

        const user = req.body.username as string;
        const pass = req.body.password as string;
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

                    const jwt = await new SignJWT({ sub: user })
                        .setProtectedHeader({ alg: 'HS256' })
                        .setIssuer(JWT_ISSUER)
                        .setExpirationTime(`${COOKIE_MAX_AGE_S}s`)
                        .sign(JWT_SECRET);

                    const sessionCookieOptions: cookie.SerializeOptions = { httpOnly: true, secure: true, maxAge: COOKIE_MAX_AGE_S, sameSite: 'strict' };
                    if (DOMAIN) sessionCookieOptions.domain = DOMAIN;

                    const csrfCookieOptions: cookie.SerializeOptions = { secure: true, httpOnly: true, sameSite: 'strict', path: '/' };

                    res.setHeader('Set-Cookie', [
                        cookie.serialize(COOKIE_NAME, jwt, sessionCookieOptions),
                        cookie.serialize(CSRF_COOKIE_NAME, '', { ...csrfCookieOptions, maxAge: 0 })
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
        await jwtVerify(token, JWT_SECRET, { issuer: JWT_ISSUER, algorithms: ['HS256'] });

        const loggedInBody = `
            <h1>Authenticated</h1>
            <p>You are successfully authenticated and can access other protected services.</p>
            <p><a href="${safeDestinationUri}">Go back to original destination</a> or <a href="/logout">Logout</a></p>
        `;
        res.status(200).send(getPageHTML('Authenticated', loggedInBody));
        return;
    } catch (error) {
        const csrfToken = randomBytes(32).toString('hex');
        const csrfCookieOptions: cookie.SerializeOptions = { secure: true, httpOnly: true, sameSite: 'strict', path: '/' };

        res.setHeader('Set-Cookie', cookie.serialize(CSRF_COOKIE_NAME, csrfToken, csrfCookieOptions));

        const loginMessage = req.method === 'POST'
            ? '<h1 class="login-error">Invalid username or password!</h1>'
            : '<h1>Please Login</h1>';

        const loginFormBody = `
            ${loginMessage}
            <form method="post" action="/auth">
                <input type="hidden" name="redirect_uri" value="${safeDestinationUri}" />
                <input type="hidden" name="csrf_token" value="${csrfToken}" />
                <input name="username" placeholder="Username" required autocomplete="username" />
                <input name="password" type="password" placeholder="Password" required autocomplete="current-password" />
                <button type="submit">Login</button>
            </form>
        `;

        res.status(401).send(getPageHTML('Login', loginFormBody));
    }
};

const logoutHandler: RequestHandler = (req, res) => {
    res.setHeader('Cache-Control', 'no-store');

    console.log(`[logoutHandler] User logged out from IP :${req.ip}`);

    const sessionCookieOptions: cookie.SerializeOptions = { maxAge: 0, domain: DOMAIN, httpOnly: true, secure: true, sameSite: 'strict' };
    if (!DOMAIN) delete sessionCookieOptions.domain;

    const csrfCookieOptions: cookie.SerializeOptions = { maxAge: 0, secure: true, httpOnly: true, sameSite: 'strict', path: '/' };

    res.setHeader('Set-Cookie', [
        cookie.serialize(COOKIE_NAME, '', sessionCookieOptions),
        cookie.serialize(CSRF_COOKIE_NAME, '', csrfCookieOptions)
    ]);

    const logoutBody = `
        <h1>Logged Out</h1>
        <p>You have been successfully logged out.</p>
        <a href="/">Login again</a>
    `;
    res.status(200).send(getPageHTML('Logged Out', logoutBody));
};

app.get('/', (req, res) => {
    res.redirect('/auth');
})

app.post('/auth', loginLimiter, loginPageHandler);
app.get('/auth', loginPageHandler);
app.get('/logout', logoutHandler);
app.get('/verify', verifyHandler);

(async () => {
    await loadUsers();

    app.listen(PORT, () => {
        console.log(`ForwardAuth-Server running on port: ${PORT}`);
        if (!DOMAIN) {
            console.warn('WARN: DOMAIN environment variable is not set. Cookies may not work across subdomains.');
        } else {
            console.log(`Cookies will be set for domain: ${DOMAIN}`);
        }
    })
})