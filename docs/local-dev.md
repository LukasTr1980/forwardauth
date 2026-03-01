# Local Dev (Postgres Identity, ohne Redis)

ForwardAuth nutzt lokal und in Produktion nur noch den Postgres-Identity-Store.

## 1) Postgres starten

```bash
docker run --name forwardauth-postgres \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=forwardauth \
  -p 5432:5432 \
  -d postgres:16
```

## 2) Schema migrieren

```bash
psql "postgres://postgres:postgres@localhost:5432/forwardauth" -f migrations/001_identity_users.sql
psql "postgres://postgres:postgres@localhost:5432/forwardauth" -f migrations/002_password_reset_tokens.sql
```

## 3) Test-User anlegen

Argon2-Hash lokal erzeugen:

```bash
node -e 'import("argon2").then(async ({ default: argon2 }) => { console.log(await argon2.hash("dev-password")); process.exit(0); })'
```

Danach mit dem erzeugten Hash einen Benutzer schreiben:

```bash
psql "postgres://postgres:postgres@localhost:5432/forwardauth" <<'SQL'
INSERT INTO users (email, password_hash, is_admin, is_adult, host_access_mode)
VALUES ('admin@example.com', '<ARGON2_HASH>', true, true, 'all')
ON CONFLICT (email) DO UPDATE SET
  password_hash = EXCLUDED.password_hash,
  is_admin = EXCLUDED.is_admin,
  is_adult = EXCLUDED.is_adult,
  host_access_mode = EXCLUDED.host_access_mode;
SQL
```

## 4) Service starten

```bash
npm run dev:postgres
```

Der Befehl setzt automatisch:

- `NODE_ENV=development`
- `INMEMORY_FALLBACK=1`
- `JWT_SECRET=dev-secret`
- `IDENTITY_DATABASE_URL=postgres://postgres:postgres@localhost:5432/forwardauth`
- `PASSKEY_ENABLED=1`
- `PASSKEY_RP_ID=localhost`
- `PASSKEY_RP_NAME=ForwardAuth-Dev`
- `PASSKEY_ORIGIN=http://localhost:3000`

Test-Login:

- E-Mail: `admin@example.com`
- Passwort: `dev-password` (oder dein eigenes Passwort aus Schritt 3)

Hinweise:

- In-Memory-Redis-Fallback ist nur fuer Development gedacht und in Production blockiert.
- Password-Reset ist im Postgres-Setup verfuegbar.
- Legacy-Variablen (`USER_STORE_BACKEND`, `USER_FILE`, `USER_FILE_WATCH_INTERVAL_MS`) fuehren jetzt zu einem Startup-Fehler.
- Fuer lokale Mail-Tests ohne Versand kann `EMAIL_PROVIDER=noop` verwendet werden (Default).

## Optional: Turnstile fuer `forgot-password`

Wenn du Bot-Schutz im lokalen oder Staging-Test pruefen willst:

- `TURNSTILE_FORGOT_PASSWORD_ENABLED=1`
- `TURNSTILE_SITE_KEY=<site-key>`
- `TURNSTILE_SECRET_KEY_FILE=/run/secrets/turnstile_secret_key` (empfohlen)
- alternativ nur lokal: `TURNSTILE_SECRET_KEY=<secret-key>`
- optional: `TURNSTILE_VERIFY_TIMEOUT_MS=3000`

Hinweis:

- In Docker Swarm sollte das Secret ueber `TURNSTILE_SECRET_KEY_FILE` kommen, nicht als Klartext-Env.
- Bei aktivem Feature wird `POST /auth/forgot-password` ohne gueltiges Turnstile-Token mit `400` abgewiesen.
