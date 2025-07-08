import express, { Request, RequestHandler } from 'express';
import rateLimit from 'express-rate-limit';
import * as cookie from 'cookie';
import { SignJWT, jwtVerify } from 'jose';
import argon2 from 'argon2';
import fs from 'fs/promises';
import path from 'path';

const app = express();
app.set('trust proxy', 1);

const PORT = +(process.env.PORT ?? 3000);
const COOKIE_NAME = process.env.COOKIE_NAME ?? 'fwd_token';
const JWT_SECRET = new TextEncoder().encode(process.env.JWT_SECRET);
const JWT_ISSUER = process.env.JWT_ISSUER ?? 'forwardauth';
const COOKIE_MAX_AGE = +(process.env.COOKIE_MAX_AGE ?? 3600) * 1000;
const USER_FILE = process.env.USER_FILE ?? path.resolve(__dirname, '../users.json');
const DOMAIN = process.env.DOMAIN;
const LOGIN_REDIRECT_URL = process.env.LOGIN_REDIRECT_URL || 'example.com';
const LOGIN_LIMITER_WINDOW_S = +(process.env.LOGIN_LIMITER_WINDOW_S ?? 15 * 60);
const LOGIN_LIMITER_MAX = +(process.env.LOGIN_LIMITER_MAX ?? 10);

const loginLimiter = rateLimit({
    windowMs: LOGIN_LIMITER_WINDOW_S * 1000,
    max: LOGIN_LIMITER_MAX,
    standardHeaders: true,
    legacyHeaders: false,
    message: 'Too many login attempts from this IP, please try again after 15 minutes',
});

let users: Record<string, string> = {};

async function loadUsers() {
    try {
        if (!USER_FILE) {
            throw new Error('USER_FILE environment variable is not set.');
        }
        users = JSON.parse(await fs.readFile(USER_FILE, 'utf-8'));
        console.log(`Successfully loaded ${Object.keys(users).length} users from ${USER_FILE}`);
    } catch (error) {
        console.error(`FATAL: Could not load or parse user file from "${USER_FILE}".`, error);
        process.exit(1);
    }
}
loadUsers();

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

app.get('/', (req, res) => {
    res.redirect('/auth');
});

const verifyHandler: RequestHandler = async (req, res) => {
    const sourceIp = req.ip;
    console.log(`[verifyHandler] Verifying request from IP: ${sourceIp}`);

    try {
        const cookies = cookie.parse(req.headers.cookie || '');
        const token = cookies[COOKIE_NAME];
        if (!token) throw new Error('No token found');

        await jwtVerify(token, JWT_SECRET, { issuer: JWT_ISSUER });
        console.log(`[verifyHandler] Verification successfull for IP: ${sourceIp}`);
        res.sendStatus(200);
        return;
    } catch (error) {
        const reason = (error as Error).message.includes('No token') ? 'No token' : 'Invalid or expired token';
        console.warn(`[verifyHandler] Verification failed for IP ${sourceIp}: ${reason}`);
        
        const originalUrl = getOriginalUrl(req);
        const loginRedirectUrl = new URL(LOGIN_REDIRECT_URL);

        loginRedirectUrl.searchParams.set('redirect_uri', originalUrl);

        res.redirect(loginRedirectUrl.toString());
    }
};

const loginPageHandler: RequestHandler = async (req, res) => {
    const redirectUri = (req.query.redirect_uri || (req.body && req.body.redirect_uri)) as string || undefined;
    const destinationUri = redirectUri || getOriginalUrl(req);

    const sourceIp = req.ip;

    if (req.method === 'POST') {
        const user = req.body.username as string;
        const pass = req.body.password as string;

        console.log(`[loginPageHandler] Login attempt for user "${user}" from IP: ${sourceIp}`);

        if (user && pass) {
            const hash = users[user];
            const DUMMY_HASH = '$argon2id$v=19$m=65536,t=3,p=4$WXl3a2tCbjVYcHpGNEoyRw$g5bC13aXAa/U0KprDD9P7x0BvJ2T1jcsjpQj5Ym+kIM';
            const hashToVerify = hash || DUMMY_HASH;

            try {
                const isMatch = await argon2.verify(hashToVerify, pass);
                if (isMatch && hash) {
                    console.log(`[loginPageHandler] SUCCESS: User "${user}" authenticated successfully from IP: ${sourceIp}`);

                    const jwt = await new SignJWT({ sub: user })
                        .setProtectedHeader({ alg: 'HS256' })
                        .setIssuer(JWT_ISSUER)
                        .setExpirationTime(`${COOKIE_MAX_AGE / 1000}s`)
                        .sign(JWT_SECRET)
                    const sc = cookie.serialize(COOKIE_NAME, jwt, { httpOnly: true, secure: true, maxAge: COOKIE_MAX_AGE / 1000, sameSite: 'strict', domain: DOMAIN});
                    res.setHeader('Set-Cookie', sc);
                    res.redirect(destinationUri);
                    return;
                }
            } catch (error) {
                console.error('Internal error during argon2 verification', error);
            }
        }
        console.warn(`[loginPageHandler] FAILED: Invalid login attempt for user "${user}" from IP: ${sourceIp}`);
    }

    try {
        const cookies = cookie.parse(req.headers.cookie || '');
        const token = cookies[COOKIE_NAME];
        if (!token) throw new Error();
        await jwtVerify(token, JWT_SECRET, { issuer: JWT_ISSUER });

        const loggedInBody = `
            <h1>Authenticated</h1>
            <p>You are successfully authenticated and can access other protected services.</p>
            <p><a href="${destinationUri}">Go back to original destination</a> or <a href="/logout">Logout</a></p>
        `;
        res.status(200).send(getPageHTML('Authenticated', loggedInBody));
        return;
    } catch (error) {
        let loginMessage = '<h1>Please Login</h1>';
        if (req.method === 'POST') {
            loginMessage = '<h1 style="color: #d93025;">Invalid username or password!</h1>';
        }
        const loginFormBody = `
            ${loginMessage}
            <form method="post" action="/auth">
                <input type="hidden" name="redirect_uri" value="${destinationUri}" />
                <input name="username" placeholder="Username" required autocomplete="username" />
                <input name="password" type="password" placeholder="Password" required autocomplete="current-password" />
                <button type="submit">Login</button>
            </form>
        `;
        res.status(200).send(getPageHTML('Login', loginFormBody));
    }
};

const logoutHandler: RequestHandler = (req, res) => {
    console.log(`[logoutHandler] User logged out from IP :${req.ip}`);
    res.setHeader('Set-Cookie', cookie.serialize(COOKIE_NAME, '', { maxAge: 0, domain: DOMAIN, httpOnly: true, secure: true, sameSite: 'strict' }));

    const logoutBody = `
        <h1>Logged Out</h1>
        <p>You have been successfully logged out.</p>
        <a href="/">Login again</a>
    `;
    res.status(200).send(getPageHTML('Logged Out', logoutBody));
};

app.use('/auth', loginLimiter);
app.all('/auth', loginPageHandler);
app.get('/logout', logoutHandler);
app.get('/verify', verifyHandler);

app.listen(PORT, () => {
    console.log(`ForwardAuth-Server running on port: ${PORT}`);
    if (!DOMAIN) {
        console.warn('WARN: DOMAIN environment variable is not set. Cookies may not work across subdomains.');
    } else {
        console.log(`Cookies will be set for domain: ${DOMAIN}`);
    }
});