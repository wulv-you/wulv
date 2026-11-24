# Secure authentication example

A compact, auditable reference implementation of email/password authentication using Express and TypeScript. It demonstrates short-lived JWT access tokens plus opaque, rotating refresh tokens.

> This repository uses an in-memory store so the security flow is easy to inspect. Replace `InMemoryStore` with a transactional database adapter before production use; restarting the process intentionally removes all users and sessions.

## Components

| Component | Responsibility |
| --- | --- |
| `src/app.ts` | HTTP routes, input validation, bearer middleware, safe error responses |
| `src/auth-service.ts` | Registration, login, refresh rotation, reuse detection, logout |
| `src/crypto.ts` | Password hashing with scrypt, random refresh-token generation, token hashing |
| `src/tokens.ts` | JWT signing and strict verification of algorithm, issuer, audience, expiry |
| `src/store.ts` | Replaceable user and refresh-session persistence boundary |
| `src/config.ts` | Environment parsing and secret/TTL validation |

## Request flow

```text
Register / Login
client -- email + password --> API
API -- scrypt verify/hash --> user store
API -- signed short JWT + random refresh token --> client
API -- SHA-256(refresh token) --> session store

Authenticated request
client -- Authorization: Bearer <JWT> --> middleware
middleware -- verify signature + exp + iss + aud --> protected route

Refresh
client -- opaque refresh token --> API
API -- hash and lookup --> session store
API -- revoke old token; store new token hash --> session store
API -- new JWT + new refresh token --> client
```

If an already-rotated refresh token is presented, the service treats it as possible theft and revokes the entire token family. Logout does the same intentionally.

## Credential and token handling

- Passwords are never stored. Each password is hashed with Node's `scrypt`, a fresh 128-bit salt, and a 64-byte output; verification uses a timing-safe comparison.
- Access tokens are signed JWTs with `sub`, `scope`, `iat`, `exp`, `iss`, and `aud`. The verifier pins `HS256` and validates issuer and audience.
- Refresh tokens are 256-bit cryptographically random opaque values. Only their SHA-256 hashes are stored, so a store leak does not immediately expose usable refresh tokens.
- Refresh tokens rotate on every use. A token family records the chain and enables reuse detection and family-wide revocation.
- `JWT_SECRET` is loaded from the environment, validated to at least 32 characters, excluded by `.gitignore`, and never returned or logged.
- Authentication failures use generic responses. Request bodies and `Authorization` headers are not logged.

For a browser application, keep the access token in memory and prefer placing the refresh token in a `Secure`, `HttpOnly`, `SameSite` cookie. This JSON API returns the refresh token in the response so native clients and API tools can exercise the flow; production browser deployments should adapt the transport and add CSRF protection.

## Run locally

Requires Node.js 18 or newer.

```bash
npm install
cp .env.example .env
# Replace JWT_SECRET in .env with a high-entropy secret.
npm run dev
```

Example:

```bash
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"person@example.com","password":"a-long-unique-password"}'
```

Use the returned access token as `Authorization: Bearer <accessToken>` with `GET /me`. Send the refresh token to `POST /auth/refresh` or `POST /auth/logout` as `{ "refreshToken": "..." }`.

## Verify

```bash
npm test
npm run typecheck
npm run build
```

## Production checklist

- Replace the in-memory store with a transactional database and enforce unique email/token-hash constraints.
- Use a managed secrets service and rotate signing keys; prefer asymmetric signing when multiple services verify tokens.
- Add TLS, rate limiting, account verification/recovery, audit events, and monitoring without logging secrets.
- Define session/device management and revocation retention policies.
- Add CSRF protection when refresh tokens are carried in cookies.
- Review password policy, privacy obligations, and abuse controls for the product's threat model.
