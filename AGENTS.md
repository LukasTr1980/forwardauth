# Repository Guidelines

## Project Structure & Modules
- `src/`: TypeScript source. Entry is `src/index.ts`; helper CLI `src/generate-hash.ts`.
- `public/`: Static assets served by Express (styles).
- `users.json`: Credentials store (Argon2 hashes). Default path is repo root; override with `USER_FILE`.
- `.github/`, `.pre-commit-config.yaml`, `eslint.config.mjs`: CI and linting configuration.

## Build, Run, and Dev
- `npm run dev`: Start local server with hot‐reload via `tsx`.
- `npm start`: Run the server (TypeScript executed via `tsx`).
- `npm run lint`: Type‑checked ESLint over TS/JS.
- `npm run generate-hash`: Interactive Argon2 hash generator for `users.json`.
- Docker: `docker build -t forwardauth .` then run with a secret for `JWT_SECRET`; entrypoint reads `/run/secrets/jwt_secret`.

## Coding Style & Conventions
- Language: TypeScript (strict). Modules: NodeNext.
- Indentation: 4 spaces; trailing spaces discouraged.
- Imports: Prefer type‑only imports where applicable (`@typescript-eslint/consistent-type-imports`).
- Promises: No floating promises (`@typescript-eslint/no-floating-promises`).
- Lint before pushing: `npm run lint` (also enforced in pre‑commit if enabled).

## Testing Guidelines
- Current: `npm test` is a placeholder (no tests yet).
- Add unit tests under `src/__tests__/` or `src/**/*.spec.ts` using your preferred runner (e.g., Vitest/Jest). Keep fast and isolated.
- Aim for meaningful coverage on auth flows (JWT creation/verify, redirect validation, rate limits).

## Commit & Pull Requests
- Commits: Use clear, imperative subjects (e.g., "fix: correct redirect validation"). Keep changes focused.
- PRs: Include summary, rationale, and testing notes (env vars used, manual steps). Link issues where relevant. Screenshots only if UI output changed.
- CI/Lint must pass before merge.

### Agent Commit Policy
- The Codex agent must never commit, push, or rewrite history autonomously.
- Only commit or push when explicitly instructed by the user (e.g., "commit", "push").
- No force-push or history rewrites unless the user requests it explicitly.

## Security & Configuration
- This GitHub repository is public. Treat all tracked files, PRs, issues, and comments as publicly visible.
- Required env: `JWT_SECRET` (must be set); recommended: `DOMAIN`, optional: `COOKIE_NAME`, `USER_FILE`, rate‑limit windows and maxima.
- Never commit secrets or sensitive data. This includes real passwords, API keys, tokens, private hostnames/internal IPs, customer/user PII, and production config values. `gitleaks` runs via pre‑commit and CI; fix or mark intentional.
- Keep all examples sanitized with placeholders (e.g., `<DOMAIN>`, `<PASSWORD>`, `<TOKEN>`), especially in docs and deployment manifests.
- Use HTTPS and set proper `X-Forwarded-*` headers when running behind a proxy.
- `users.json` format: `{ "username": { "hash": "<argon2id hash>" } }`. Generate with `npm run generate-hash`.

## Docker Swarm (Sanitized)
- Masked examples only. Replace placeholders outside this repo. Do not commit real domains, host paths, passwords, or resolver names.

```yaml
services:
  forwardauth:
    image: registry.example.com/forwardauth:<version>
    deploy:
      replicas: 1
      restart_policy:
        condition: any
    environment:
      TZ: "<TZ>"
      COOKIE_NAME: "<COOKIE_NAME>"
      JWT_ISSUER: "<JWT_ISSUER>"
      DOMAIN: "<DOMAIN>"
      USER_FILE: "/app/data/users.json"
      COOKIE_MAX_AGE_S: "<SECONDS>"
      LOGIN_LIMITER_WINDOW_S: "<SECONDS>"
      LOGIN_REDIRECT_URL: "https://<AUTH_HOST>/auth"
      LOGIN_LIMITER_MAX: "<N>"
      SHOW_LOGIN_BANNER: "<0|1>"
      TOAST_INTERVAL_S: "<SECONDS>"
      # Redis-backed rate limiting (choose one of the two blocks)
      # REDIS_URL: "redis://<host>:<port>"        # or rediss:// for TLS
      # -- OR --
      # REDIS_HOST: "<redis-service-name>"
      # REDIS_PORT: "6379"
      # REDIS_USERNAME: "<optional-username>"     # only if ACL is used
      # REDIS_TLS: "<0|1>"
      # forwardauth reads the password via a secret file
      # REDIS_PASSWORD_FILE: "/run/secrets/redis_password"
    labels:
      traefik.enable: "true"
      traefik.http.routers.forwardauth-server.rule: "Host(`<AUTH_HOST>`)"
      traefik.http.routers.forwardauth-server.entrypoints: "websecure"
      traefik.http.routers.forwardauth-server.tls.certresolver: "<resolver>"
      traefik.http.services.forwardauth-server.loadbalancer.server.port: "3000"

      traefik.http.middlewares.forwardauth.forwardauth.address: "http://forwardauth:3000/verify"
      traefik.http.middlewares.forwardauth.forwardauth.trustForwardHeader: "true"
      traefik.http.middlewares.forwardauth.forwardauth.authResponseHeaders: "X-Forwarded-User"
    volumes:
      - /HOST/PATH/forwardauth/users.json:/app/data/users.json:ro
    networks:
      overlay-a:
        aliases: [forwardauth_server_container]
      overlay-b:
        aliases: [forwardauth_server_container]
    secrets:
      - jwt_secret
      - redis_password   # forwardauth only; Redis itself reads via its conf file

  redis:
    image: redis:<tag>
    deploy:
      replicas: 1
      restart_policy:
        condition: any
    # Prefer not to publish Redis publicly; if required, secure appropriately
    # ports:
    #   - target: 6379
    #     published: 6379
    #     protocol: tcp
    #     mode: host
    volumes:
      - redis-data:/data
      - /HOST/PATH/redis/redis.conf:/usr/local/etc/redis/redis.conf:ro
    command: redis-server /usr/local/etc/redis/redis.conf
    networks:
      overlay-a:
        aliases: [redis]

volumes:
  redis-data:

secrets:
  jwt_secret:
    external: true
  redis_password:
    external: true
```

Notes
- forwardauth reads `JWT_SECRET` from the `jwt_secret` secret (`/run/secrets/jwt_secret`).
- Redis password: Redis may load its password from its mounted `redis.conf` (e.g., `requirepass ...`). forwardauth must read the same password via `REDIS_PASSWORD_FILE` pointing to `/run/secrets/redis_password`.
- Choose one Redis config path: either `REDIS_URL` or `REDIS_HOST`+`REDIS_PORT`. For TLS, use `rediss://` in `REDIS_URL` or set `REDIS_TLS=1`.
- Env keys used by the app (values masked here): `COOKIE_NAME`, `JWT_ISSUER`, `DOMAIN`, `USER_FILE`, `COOKIE_MAX_AGE_S`, `LOGIN_LIMITER_WINDOW_S`, `LOGIN_LIMITER_MAX`, `LOGIN_REDIRECT_URL`, `TOAST_INTERVAL_S`, `REDIS_URL`/`REDIS_HOST`/`REDIS_PORT`, `REDIS_USERNAME`, `REDIS_PASSWORD_FILE`, `REDIS_TLS`.
