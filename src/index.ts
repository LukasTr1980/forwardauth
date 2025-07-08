import express, { Request, RequestHandler } from 'express';
import rateLimit from 'express-rate-limit';
import * as cookie from 'cookie';
import { SignJWT, jwtVerify } from 'jose';
import argon2 from 'argon2';
import fs from 'fs/promises';
import path from 'path';

const app = express();
const PORT = +(process.env.PORT ?? 3000);
const COOKIE_NAME = process.env.COOKIE_NAME ?? 'fwd_token';
const JWT_SECRET = new TextEncoder().encode(process.env.JWT_SECRET);
const JWT_ISSUER = process.env.JWT_ISSUER ?? 'forwardauth';
const COOKIE_MAX_AGE = +(process.env.COOKIE_MAX_AGE ?? 3600) * 1000;
const USER_FILE = process.env.USER_FILE ?? path.resolve(__dirname, '../users.json');
const DOMAIN = process.env.DOMAIN;

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
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
    try {
        const cookies = cookie.parse(req.headers.cookie || '');
        const token = cookies[COOKIE_NAME];
        if (!token) {
            throw new Error('No token found');
        }
        await jwtVerify(token, JWT_SECRET, { issuer: JWT_ISSUER });
        res.sendStatus(200);
    } catch (error) {
        res.sendStatus(401);
    }
};

const loginPageHandler: RequestHandler = async (req, res) => {
    const originalUrl = getOriginalUrl(req);

    if (req.method === 'POST') {
        const user = req.body.username as string;
        const pass = req.body.password as string;

        if (user && pass) {
            const hash = users[user];
            const DUMMY_HASH = '$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWvVIm_societ';
            const hashToVerify = hash || DUMMY_HASH;

            try {
                const isMatch = await argon2.verify(hashToVerify, pass);
                if (isMatch && hash) {
                    const jwt = await new SignJWT({ sub: user })
                        .setProtectedHeader({ alg: 'HS256' })
                        .setIssuer(JWT_ISSUER)
                        .setExpirationTime(`${COOKIE_MAX_AGE / 1000}s`)
                        .sign(JWT_SECRET)
                    const sc = cookie.serialize(COOKIE_NAME, jwt, { httpOnly: true, secure: true, maxAge: COOKIE_MAX_AGE / 1000, sameSite: 'strict', domain: DOMAIN});
                    res.setHeader('Set-Cookie', sc);
                    res.redirect(originalUrl);
                    return;
                }
            } catch (error) {
                console.error('Internal error during argon2 verification', error);
            }
        }
    }

    try {
        const cookies = cookie.parse(req.headers.cookie || '');
        const token = cookies[COOKIE_NAME];
        if (!token) throw new Error();
        await jwtVerify(token, JWT_SECRET, { issuer: JWT_ISSUER });

        const loggedInBody = `
            <h1>Authenticated</h1>
            <p>You are successfully authenticated and can access other protected services.</p>
            <p><a href="${originalUrl}">Go back to original destination</a> or <a href="/logout">Logout</a></p>
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
                <input name="username" placeholder="Username" required autocomplete="username" />
                <input name="password" type="password" placeholder="Password" required autocomplete="current-password" />
                <button type="submit">Login</button>
            </form>
        `;
        res.status(200).send(getPageHTML('Login', loginFormBody));
    }
};

const logoutHandler: RequestHandler = (req, res) => {
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