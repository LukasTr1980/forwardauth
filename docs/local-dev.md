# Local Dev (Postgres Identity, ohne Redis)

ForwardAuth nutzt lokal und in Produktion nur noch den Postgres-Identity-Store.
Redis kann lokal ueber `INMEMORY_FALLBACK=1` ersetzt werden.

## Schnellstart (empfohlen)

1) `.env` setzen (Beispiel mit Supabase Pooler oder lokalem Postgres)

```env
IDENTITY_DATABASE_URL=postgresql://<USER>:<PASSWORD>@<HOST>:<PORT>/postgres
IDENTITY_DB_SSL=1
```

Wichtig:

- Verwende `KEY=VALUE`-Syntax. Eine nackte URL-Zeile in `.env` wird ignoriert.
- Bei Sonderzeichen im Passwort URL-encoding verwenden (z. B. `%` als `%25`).

2) Service starten

```bash
npm run dev
```

`npm run dev` setzt automatisch:

- `JWT_SECRET=dev-secret`
- `NODE_ENV=development`
- `INMEMORY_FALLBACK=1`

Und laedt `.env` automatisch.

## Option A: Supabase (kein Docker in WSL)

1) In Supabase SQL Editor ausfuehren:

- `migrations/001_identity_users.sql`
- `migrations/002_password_reset_tokens.sql`

2) Test-User anlegen (optional, falls noch kein User existiert)

Argon2-Hash lokal erzeugen:

```bash
node -e 'import("argon2").then(async ({ default: argon2 }) => { console.log(await argon2.hash("dev-password")); process.exit(0); })'
```

Dann in Supabase SQL Editor:

```sql
INSERT INTO users (email, password_hash, is_admin, is_adult, host_access_mode)
VALUES ('admin@example.com', '<ARGON2_HASH>', true, true, 'all')
ON CONFLICT (email) DO UPDATE SET
  password_hash = EXCLUDED.password_hash,
  is_admin = EXCLUDED.is_admin,
  is_adult = EXCLUDED.is_adult,
  host_access_mode = EXCLUDED.host_access_mode,
  disabled_at = NULL;
```

## Option B: Lokaler Postgres (Docker)

1) Postgres starten:

```bash
docker run --name forwardauth-postgres \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=forwardauth \
  -p 5432:5432 \
  -d postgres:16
```

2) `.env` fuer lokal setzen:

```env
IDENTITY_DATABASE_URL=postgres://postgres:postgres@localhost:5432/forwardauth
IDENTITY_DB_SSL=0
```

3) Schema migrieren:

```bash
psql "postgres://postgres:postgres@localhost:5432/forwardauth" -f migrations/001_identity_users.sql
psql "postgres://postgres:postgres@localhost:5432/forwardauth" -f migrations/002_password_reset_tokens.sql
```

4) Optionaler Test-User wie oben.

## Test-Login

- E-Mail: `admin@example.com`
- Passwort: `dev-password` (wenn du den Beispiel-User angelegt hast)

## Troubleshooting

- Fehler `password authentication failed for user`:
  - Meist ist noch eine alte Shell-Variable gesetzt, die `.env` uebersteuert.
  - Loesung:

```bash
unset IDENTITY_DATABASE_URL IDENTITY_DB_SSL
npm run dev
```

- Fehler `IDENTITY_DATABASE_URL ... required`:
  - Pruefen, ob `.env` wirklich `IDENTITY_DATABASE_URL=<...>` enthaelt.

Hinweise:

- In-Memory-Redis-Fallback ist nur fuer Development gedacht und in Production blockiert.
- Password-Reset ist im Postgres-Setup verfuegbar.
- Legacy-Variablen (`USER_STORE_BACKEND`, `USER_FILE`, `USER_FILE_WATCH_INTERVAL_MS`) fuehren zu einem Startup-Fehler.
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
