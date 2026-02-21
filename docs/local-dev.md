# Local Dev (ohne Redis)

Für reines lokales UI-Testing kannst du den In-Memory-Fallback nutzen:

Zuerst eine lokale `users.dev.json` anlegen (wird nicht versioniert):

```bash
cat > users.dev.json <<'EOF'
{
    "admin@example.com": {
        "hash": "<ARGON2_HASH_FROM_NPM_RUN_GENERATE_HASH>",
        "isAdmin": true
    }
}
EOF
```

Den Hash kannst du lokal mit `npm run generate-hash` erzeugen.

Dann starten:

```bash
npm run dev:inmemory
```

Der Befehl setzt automatisch:

- `NODE_ENV=development`
- `INMEMORY_FALLBACK=1`
- `JWT_SECRET=dev-secret`
- `USER_FILE=./users.dev.json`
- `PASSKEY_ENABLED=1`
- `PASSKEY_RP_ID=localhost`
- `PASSKEY_RP_NAME=ForwardAuth-Dev`
- `PASSKEY_ORIGIN=http://localhost:3000`

Test-Login aus `users.dev.json`:

- E-Mail: `admin@example.com`
- Passwort: das Passwort, das du beim Hash-Generieren verwendet hast

Hinweis:

- In-Memory-Daten gehen beim Neustart verloren (gewollt für Dev).
- Passkey-UI ist in diesem Dev-Start standardmäßig aktiv.
- In Production ist `INMEMORY_FALLBACK` blockiert.
