# Artifact service operation

The production Artifact process uses PostgreSQL for metadata and session
authority, an owner-private filesystem root for immutable bytes, and a separate
owner-private recovery root for crash reconciliation. It does not create test
principals, issue browser sessions, or accept organization/requester identity in
headers or JSON.

Run the current schema migration with deployment migration authority. The
migration creates `science_workbench_app`, the non-login
`science_workbench_session_authenticator`, and the narrow
`resolve_auth_session(bytea)`/`revoke_auth_session(bytea)` security-definer
functions. Grant only `science_workbench_app` membership to the login named by
`ARTIFACT_DATABASE_URL`:

```sql
GRANT science_workbench_app TO artifact_runtime_login;
```

The runtime login does not need membership in the authenticator role and must
not have `BYPASSRLS`. Session issuance is owned by the identity service. The
Artifact process consumes the SHA-256 digest of the opaque host-only session
cookie and compares the SHA-256 digest of `X-CSRF-Token` with `csrf_hash` for
every mutation. It rechecks expiry, revocation, and active membership on every
request.

Set every environment key explicitly:

- `ARTIFACT_DATABASE_URL`: `postgresql+asyncpg` URL for the runtime login.
- `ARTIFACT_PRIVATE_BLOB_ROOT`: absolute persistent volume path for bytes.
- `ARTIFACT_RECOVERY_ROOT`: separate, non-overlapping absolute persistent path.
- `ARTIFACT_RECOVERY_INTEGRITY_KEY_B64`: base64 of at least 32 random bytes.
- `ARTIFACT_DOWNLOAD_SIGNING_KEY_B64`: base64 of a distinct 32-byte-or-longer key.
- `ARTIFACT_TRUSTED_EXECUTIONS_JSON`: non-empty JSON array of exact execution
  bindings with `org_id`, `project_id`, `requester_id`, `execution_id`,
  `runtime_adapter_id`, and `runtime_connection_id`.
- `ARTIFACT_BIND_HOST`: canonical IP address on which to listen.
- `ARTIFACT_BIND_PORT`: integer from 1 through 65535.
- `ARTIFACT_PUBLIC_ORIGIN`: canonical HTTPS origin. Plain HTTP is accepted only
  for a loopback hostname or address.
- `PROVIDER_RUN_DISPATCH_SOCKET`: absolute path to the protected dispatcher
  Unix socket described in `provider-qualification.md`.

Start the dedicated provider Run dispatcher and verify its socket before
starting this HTTP process. Mount only the dispatcher socket directory into the
HTTP container; do not give the HTTP process the dispatcher database credential.
The socket path and every ancestor must satisfy the owner-protected requirements
in the provider qualification runbook. Missing configuration rejects startup,
and a missing, replaced, or unavailable dispatcher socket makes provider Run
creation fail closed without direct database fallback.

After the deployment secret manager has populated the environment, start it
from the repository root:

```sh
PYTHONPATH=. .venv/bin/python -m services.api.artifact_production_app
```

Terminate TLS at a trusted reverse proxy, preserve the configured Host and
Origin exactly, and do not forward a client-selected host. HTTPS uses the
`__Host-swb_session` cookie; explicit loopback HTTP uses `product_session`.
Authenticated reads reject an absent, duplicate, or mismatched Host. Mutations
also require the exact Origin, `Sec-Fetch-Site: same-origin`, an accepted
same-origin fetch mode, and the persisted CSRF capability.

The listener admits at most 16 concurrent request handlers and gives incomplete
requests two seconds to finish. Keep stricter connection and body limits at the
reverse proxy when exposed outside a private network. Excess sockets are closed
before a handler or database operation is allocated.

Keep both filesystem roots and both keys stable across process replacement.
Mount roots on durable storage with a single operating-system owner; the process
creates and verifies private `0700` directories. Rotating or deleting the
recovery key prevents reconciliation, and changing either root loses access to
the corresponding durable state. Database backups alone do not contain Artifact
bytes.

`build_artifact_production_application()` returns the exact composed
`ArtifactProductionStack`. A co-resident trusted runtime adapter registers output
through that stack's `OutputWatcher`; browser HTTP never registers sandbox bytes
or supplies object keys. The HTTP surface creates Artifact identities, commits
Versions from watcher references, reads metadata, and downloads verified bytes.
Watcher registration accepts only the passive media-type allowlist enforced by
the service; active HTML, SVG, MIME parameters, control characters, and unknown
types fail closed. Downloads always use `application/octet-stream`, attachment
disposition, a deny-all sandbox CSP, and `nosniff`, while the authenticated JSON
metadata retains the registered passive media type. Metadata and bytes recheck
the active Project under the same PostgreSQL row-lock boundary used for the
read, so an archive racing after scope discovery cannot release content.
Fixture helpers in `artifact_ui_app.py`, `product_artifacts.py`, and
`run_product_server()` are not used by this entrypoint.
