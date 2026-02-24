# Downstream Integration Guide: ForwardAuth Identity Migration (Email -> UUID)

## Document Purpose

This document describes the **breaking identity contract changes** introduced in `forwardauth` when migrating from `users.json` to a PostgreSQL-backed identity store.

It is intended for **downstream service teams** that consume:

- `X-Forwarded-*` headers from ForwardAuth / Traefik `forwardAuth`
- ForwardAuth-issued JWTs (if any service validates or inspects them)
- `/auth/status` response payloads (if used by internal tools/UIs)

This guide is designed to be handed directly to service owners for implementation.

## Executive Summary (What Changes)

### Breaking Changes

1. `X-Forwarded-User` changes from **email address** to **UUID** (when ForwardAuth runs in PostgreSQL identity mode)
2. JWT `sub` changes from **email address** to **UUID**
3. Session identity in ForwardAuth backend is now **UUID-based** (internal, but relevant if you inspect tokens)

### New Compatibility Signal

- New header: `X-Forwarded-User-Email`
  - Contains the current normalized email address
  - Intended to help downstream services during migration and for display/logging

### Unchanged

- `X-Forwarded-Is-Adult` remains unchanged (`"1"` or `"0"`)
- Passkeys remain stored in Redis (no downstream impact)
- Login UX and auth redirect flow remain functionally the same

### Deployment Mode Caveat (Important)

- The UUID-based identity contract in this document applies when ForwardAuth is running with:
  - `USER_STORE_BACKEND=postgres`
- In `USER_STORE_BACKEND=json` compatibility mode:
  - `X-Forwarded-User` remains the normalized email (legacy behavior)

## Change Scope

This migration affects downstreams that:

- use `X-Forwarded-User` as a username/email
- store user records keyed by email derived from ForwardAuth
- use the JWT `sub` claim as email
- log or authorize based on email-only assumptions

This migration does **not** directly affect downstreams that:

- only check whether a request is authenticated (HTTP 200 vs 401/403)
- only use `X-Forwarded-Is-Adult`
- do not inspect user identity values

## New Identity Contract (Post-Migration)

### Response Headers from `/verify`

For **successful authenticated `/verify` responses (HTTP 200)** in PostgreSQL identity mode (`USER_STORE_BACKEND=postgres`), ForwardAuth will set:

- `X-Forwarded-User`: `<uuid>`
- `X-Forwarded-User-Email`: `<normalized-email>`
- `X-Forwarded-Is-Adult`: `1` or `0`

### Example (after migration, postgres identity mode)

```http
X-Forwarded-User: <user-uuid>
X-Forwarded-User-Email: user@example.com
X-Forwarded-Is-Adult: 0
```

### JWT Claims (if consumed downstream)

ForwardAuth-issued JWTs now contain:

- `sub` = UUID
- `email` = normalized email (additional claim)
- `jti` = session token ID (unchanged semantics)
- `iss` = configured issuer (unchanged)
- expiry / issue time = unchanged pattern

### Example JWT payload (conceptual)

```json
{
  "iss": "forwardauth",
  "sub": "<user-uuid>",
  "email": "user@example.com",
  "jti": "<session-jti>",
  "iat": 1730000000,
  "exp": 1730003600
}
```

## Why This Change Was Made

Email addresses are mutable. Using email as the primary identity causes problems when users:

- change their email address
- have aliases normalized differently
- require stable references across systems

UUID-based identity provides:

- stable user IDs
- safer long-term references in downstream databases
- support for email changes without breaking identity linkage

## Migration Requirements for Downstream Services

## 1. Stop Treating `X-Forwarded-User` as Email

### Before

Many services currently assume:

- `X-Forwarded-User` is an email
- it can be used directly as display name
- it can be used as a lookup key in local tables keyed by email

### After

Treat `X-Forwarded-User` as:

- a **stable opaque user ID** (UUID)
- suitable for primary keys / foreign keys / ownership references
- **not** suitable as a display label

## 2. Use `X-Forwarded-User-Email` for Display/Contact Logic

If your service needs email for:

- UI display
- audit logs (human-readable)
- email-based business rules
- backward-compatible API payloads

Use:

- `X-Forwarded-User-Email`

Important:

- Email can change over time
- Do not use email as the only durable identifier going forward

## 3. Update Database Schemas (if Needed)

If your downstream service stores authenticated users, update schemas to support UUID identity.

### Recommended pattern

- Add `forwardauth_user_id` (`uuid` or string UUID)
- Keep `email` as mutable, non-primary attribute

### Recommended table shape (example)

```sql
ALTER TABLE app_users
ADD COLUMN forwardauth_user_id uuid;

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS app_users_forwardauth_user_id_uidx
ON app_users(forwardauth_user_id);
```

Then backfill from observed traffic or controlled migration logic.

If the table is currently keyed by email:

- keep the email column
- add UUID column
- migrate references gradually
- avoid immediate destructive schema changes until rollout is complete

## 4. Update Authorization/Ownership Logic

If ownership checks currently compare email values, change them to compare UUIDs.

### Before (example)

```ts
const userEmail = req.get("X-Forwarded-User");
if (record.ownerEmail !== userEmail) {
  return res.status(403).end();
}
```

### After (recommended)

```ts
const userId = req.get("X-Forwarded-User");
const userEmail = req.get("X-Forwarded-User-Email"); // optional display/logging

if (!userId) {
  return res.status(401).end();
}

if (record.ownerUserId !== userId) {
  return res.status(403).end();
}
```

## 5. Update Logging and Monitoring

### Recommended logging fields

Log both during transition:

- `forwardauth_user_id` (UUID)
- `forwardauth_user_email` (if present)

This improves:

- incident investigation
- migration debugging
- support workflows

### Example log payload

```json
{
  "forwardauth_user_id": "<user-uuid>",
  "forwardauth_user_email": "user@example.com",
  "path": "/api/orders/123",
  "status": 200
}
```

## Backward Compatibility Strategy for Downstreams

In PostgreSQL identity mode, ForwardAuth will send both:

- `X-Forwarded-User` (UUID)
- `X-Forwarded-User-Email` (email)

Downstream services should implement a **two-step migration**:

1. **Read both headers**
2. **Switch internal identity keying to UUID**

### Transitional parsing rule (recommended)

- Identity key = `X-Forwarded-User` (required)
- Human-readable label = `X-Forwarded-User-Email` (optional)

Do **not** try to infer whether `X-Forwarded-User` is an email or UUID based on format in production code. After rollout, it should be treated as UUID only.

## `/auth/status` Response Change (if used)

If you use ForwardAuth `/auth/status`, note that the payload now includes:

- `user`: UUID (was email before)
- `email`: normalized email (new)
- `isAdult`: unchanged

### Example

```json
{
  "loggedIn": true,
  "user": "<user-uuid>",
  "email": "user@example.com",
  "isAdult": false
}
```

## JWT Consumer Guidance (if applicable)

If your service validates ForwardAuth JWTs directly:

### Required changes

- treat `sub` as UUID
- read `email` claim for display/logging if needed
- stop assuming `sub` contains `@`

### Validation checklist

- issuer (`iss`) validation remains unchanged
- signature verification remains unchanged
- expiration (`exp`) validation remains unchanged
- session semantics remain unchanged from a consumer perspective

## Common Breaking Patterns to Search For

Teams should search their codebase for:

- `X-Forwarded-User` used as email
- regex checks like `includes("@")`
- local DB columns named `owner_email`, `created_by_email`, etc.
- JWT logic expecting `sub` to be email
- analytics pipelines joining on email from auth headers

Search examples:

```bash
rg "X-Forwarded-User|ownerEmail|createdByEmail|sub.*email|email.*sub"
```

## Recommended Implementation Patterns by Service Type

## API Services

- Use `X-Forwarded-User` as authenticated principal ID
- Persist UUID for ownership and audit references
- Optionally persist latest email as metadata

## Web Applications / UIs

- Display `X-Forwarded-User-Email`
- Do not display raw UUID unless needed for admin/debug
- Use UUID in API calls and server-side session context

## Batch Jobs / Workers

- Update job payload schemas if they currently carry auth email as identity reference
- Prefer UUID as canonical user reference

## Analytics / Event Pipelines

- Add `user_id` (UUID) dimension
- Keep `user_email` only as non-canonical attribute
- Expect email changes over time for the same UUID

## Testing Checklist for Downstream Teams

Each downstream service should test the following after implementation:

1. Authenticated `/verify` success response (HTTP 200) contains `X-Forwarded-User` as UUID
2. Service accepts UUID identity without parsing errors
3. Service uses `X-Forwarded-User-Email` for display/logging where needed
4. Ownership/authorization checks work with UUID-based records
5. Existing email-based records are either migrated or handled safely
6. Logs and metrics include UUID (and optional email)
7. No code path rejects identity because it is not an email format

## Rollout and Operational Recommendations

### Recommended rollout order

1. Update downstream services to support new headers/UUID identity
2. Deploy downstream changes
3. Deploy ForwardAuth identity migration
4. Monitor authorization errors, parsing errors, and 5xx spikes

### Suggested monitoring signals

- increase in 401/403 rates per service
- parsing/validation exceptions involving UUID or headers
- missing `X-Forwarded-User-Email` handling bugs
- ownership mismatches after migration

## FAQ

### Is `X-Forwarded-User-Email` guaranteed to be present?

In PostgreSQL identity mode, it is expected to be present for authenticated `/verify` responses after migration. Downstreams should still code defensively and treat it as optional metadata.

### Can the email change for the same UUID?

Yes. This is the key reason UUID is now the primary identity.

### Should we store both UUID and email?

Yes, in most services:

- UUID as canonical identity
- Email as mutable profile attribute / display field

### Should we continue authorizing by email?

No. Authorization and ownership should use UUID.

## Contact / Coordination Notes (Fill In Before Sending)

Before distributing this document, add:

- target rollout window/date
- affected environments (dev/staging/prod)
- contact person/team for migration support
- exact ForwardAuth release/tag being deployed

## ForwardAuth Implementation Reference (for maintainers)

Relevant implementation changes in this repository:

- `src/index.ts` (user store backend switch, JWT/header identity changes, `/auth/status`)
- `src/postgres-user-store.ts` (PostgreSQL user lookup)
- `migrations/001_identity_users.sql` (identity schema)
- `src/migrate-users-json-to-identity-db.ts` (one-time JSON import)
