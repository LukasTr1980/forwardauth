export interface EmailLogger {
    debug(...args: unknown[]): void;
    info(...args: unknown[]): void;
    warn(...args: unknown[]): void;
    error(...args: unknown[]): void;
}

export interface PasswordResetEmailInput {
    to: string;
    resetUrl: string;
    expiresInMinutes: number;
    brandLabel: string;
}

export interface EmailService {
    sendPasswordResetEmail(input: PasswordResetEmailInput): Promise<void>;
}

export type EmailProvider = 'noop' | 'resend';

export interface CreateEmailServiceOptions {
    provider: EmailProvider;
    logger: EmailLogger;
    resendApiKey?: string;
    emailFrom?: string;
    requestTimeoutMs?: number;
}

interface ResendErrorPayload {
    error?: {
        message?: string;
    };
}

function maskEmail(email: string): string {
    const [localPart, domain] = email.split('@');
    if (!domain) return '<invalid-email>';
    if (!localPart) return `***@${domain}`;
    if (localPart.length <= 2) return `${localPart[0] ?? '*'}***@${domain}`;
    return `${localPart.slice(0, 2)}***@${domain}`;
}

function escapeHtml(value: string): string {
    return value
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function getBrandForPasswordResetEmail(label: string): string {
    const trimmed = label.trim();
    if (!trimmed) return 'Ihr Konto';
    const withoutAuthSuffix = trimmed.replace(/\s+auth$/i, '').trim();
    return withoutAuthSuffix || trimmed;
}

function buildPasswordResetSubject(input: PasswordResetEmailInput): string {
    const brand = getBrandForPasswordResetEmail(input.brandLabel);
    return `Passwort zurücksetzen für ${brand}`;
}

function buildPasswordResetText(input: PasswordResetEmailInput): string {
    const brand = getBrandForPasswordResetEmail(input.brandLabel);
    return [
        `Es wurde eine Anfrage zum Zurücksetzen des Passworts für ${brand} gestellt.`,
        '',
        `Link zum Zurücksetzen (gültig für ${input.expiresInMinutes} Minuten):`,
        input.resetUrl,
        '',
        'WICHTIGER SICHERHEITSHINWEIS:',
        'Wenn Sie diese Anfrage nicht selbst gestellt haben, ignorieren Sie diese E-Mail.',
        'Ihr Passwort bleibt unverändert, solange Sie den Link nicht verwenden.',
    ].join('\n');
}

function buildPasswordResetHtml(input: PasswordResetEmailInput): string {
    const escapedUrl = escapeHtml(input.resetUrl);
    const escapedLabel = escapeHtml(getBrandForPasswordResetEmail(input.brandLabel));
    return `
<!doctype html>
<html lang="de">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Passwort zurücksetzen</title>
</head>
<body>
    <p>Es wurde eine Anfrage zum Zurücksetzen des Passworts für <strong>${escapedLabel}</strong> gestellt.</p>
    <p>Der Link ist für <strong>${input.expiresInMinutes} Minuten</strong> gültig:</p>
    <p><a href="${escapedUrl}">Passwort zurücksetzen</a></p>
    <p><strong>Wichtiger Sicherheitshinweis:</strong></p>
    <p><strong>Wenn Sie diese Anfrage nicht selbst gestellt haben, ignorieren Sie diese E-Mail.</strong></p>
    <p>Ihr Passwort bleibt unverändert, solange Sie den Link nicht verwenden.</p>
</body>
</html>
`;
}

class NoopEmailService implements EmailService {
    private readonly logger: EmailLogger;

    constructor(logger: EmailLogger) {
        this.logger = logger;
    }

    sendPasswordResetEmail(input: PasswordResetEmailInput): Promise<void> {
        this.logger.info(
            `[email] EMAIL_PROVIDER=noop: reset email simulated for ${maskEmail(input.to)} (expiresInMin=${input.expiresInMinutes})`
        );
        return Promise.resolve();
    }
}

interface ResendEmailServiceOptions {
    apiKey: string;
    from: string;
    logger: EmailLogger;
    requestTimeoutMs: number;
}

class ResendEmailService implements EmailService {
    private readonly apiKey: string;
    private readonly from: string;
    private readonly logger: EmailLogger;
    private readonly requestTimeoutMs: number;

    constructor(options: ResendEmailServiceOptions) {
        this.apiKey = options.apiKey;
        this.from = options.from;
        this.logger = options.logger;
        this.requestTimeoutMs = options.requestTimeoutMs;
    }

    async sendPasswordResetEmail(input: PasswordResetEmailInput): Promise<void> {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), this.requestTimeoutMs);

        try {
            const response = await fetch('https://api.resend.com/emails', {
                method: 'POST',
                headers: {
                    Authorization: `Bearer ${this.apiKey}`,
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    from: this.from,
                    to: [input.to],
                    subject: buildPasswordResetSubject(input),
                    text: buildPasswordResetText(input),
                    html: buildPasswordResetHtml(input),
                }),
                signal: controller.signal,
            });

            const rawBody = await response.text();
            let payload: ResendErrorPayload | null = null;
            try {
                payload = JSON.parse(rawBody) as ResendErrorPayload;
            } catch {
                payload = null;
            }

            if (!response.ok) {
                const remoteMessage = payload?.error?.message?.trim();
                const fallbackMessage = rawBody.trim().slice(0, 160);
                const message = remoteMessage ?? fallbackMessage ?? `HTTP ${response.status}`;
                throw new Error(`Resend request failed (${response.status}): ${message}`);
            }

            this.logger.info(`[email] Password reset email sent via Resend to ${maskEmail(input.to)}`);
        } finally {
            clearTimeout(timeout);
        }
    }
}

export function createEmailService(options: CreateEmailServiceOptions): EmailService {
    if (options.provider === 'resend') {
        if (!options.resendApiKey) {
            throw new Error('EMAIL_PROVIDER=resend requires RESEND_API_KEY or RESEND_API_KEY_FILE.');
        }

        if (!options.emailFrom) {
            throw new Error('EMAIL_PROVIDER=resend requires EMAIL_FROM.');
        }

        return new ResendEmailService({
            apiKey: options.resendApiKey,
            from: options.emailFrom,
            logger: options.logger,
            requestTimeoutMs: options.requestTimeoutMs ?? 10000,
        });
    }

    return new NoopEmailService(options.logger);
}
