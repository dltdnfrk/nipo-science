# ADR-0002: Same-origin authentication

- Status: Accepted
- Owner: Identity Platform

## Context

Browser tokens must not be exposed to JavaScript or to a cross-origin API
integration, and tenant identity must never come from request content.

## Decision

The Web App exposes `/api/v1` on the application origin and proxies to the
private Application API. Authentication uses a host-only `Secure`, `HttpOnly`,
`SameSite=Lax` session cookie. Every state-changing authenticated request also
passes CSRF token, Origin, and Fetch Metadata checks. The server derives
`user_id` and `org_id`; cross-tenant lookup returns 404.

Artifact preview uses a separate origin that receives no application cookie.
Magic-link exchange additionally binds one-use state to its strict intent
cookie and rotates the authenticated session and CSRF token.

## Verification and consequences

Auth contract tests cover forged tenant IDs, missing CSRF/Origin, cross-site
requests, session rotation, and cookie absence on the artifact origin. Browser
code never stores bearer, OAuth, or connector tokens.

