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

## Security & Configuration
- Required env: `JWT_SECRET` (must be set); recommended: `DOMAIN`, optional: `COOKIE_NAME`, `USER_FILE`, rate‑limit windows and maxima.
- Never commit secrets. `gitleaks` runs via pre‑commit and CI; fix or mark intentional.
- Use HTTPS and set proper `X-Forwarded-*` headers when running behind a proxy.
- `users.json` format: `{ "username": { "hash": "<argon2id hash>" } }`. Generate with `npm run generate-hash`.
