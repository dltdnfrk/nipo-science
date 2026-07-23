# Provider qualification operations

This runbook covers the external receipt authority, public verification, database
adoption, qualified Run dispatch, cleanup, key rotation, incidents, migration,
and rollback.

## Deployment boundaries

Run the signing authority outside the evaluator and application runtime. Its RSA
private key must not be mounted, injected, logged, or otherwise readable by the
capture CLI, API, worker, provider runtime, or PostgreSQL adopter. The authority
receives no database credential. The qualification authority, adopter, Run
dispatcher, and cleanup worker are four separately deployed processes. Do not
reuse their credentials or make one process a fallback for another. In
particular, the cleanup credential must never be resident in the ordinary
application or provider runtime.

Production supplies an exact runtime policy for its deployed platform through
the deployment configuration boundary. The Darwin arm64 entry checked into
`config/provider-runtime-policies.json` is only a reproducible development and
test example. It is not production admission evidence and must not be copied
into a non-Darwin deployment.

The authority listens on an absolute Unix socket owned by root or by the numeric
dedicated provider-service UID shared with its intended capture client. The
client rejects symlinks, non-sockets, and group/world-writable sockets. Restrict
the parent directory and socket volume to that server/client pair.

Provision the authority's private key as an exact six-field JSON document:

```json
{
  "schema_version": 1,
  "key_id": "deployment-key-id",
  "algorithm": "RSASSA-PKCS1-v1_5/SHA-256",
  "modulus_hex": "768 lowercase hexadecimal characters",
  "public_exponent": 65537,
  "private_exponent_hex": "lowercase hexadecimal private exponent"
}
```

Generate or import this material only inside the deployment key-management
boundary. The modulus must be an odd 3072-bit value, the public exponent must be
exactly 65537, and the private exponent must be greater than 1 and less than the
modulus. Validate the resulting document by starting the authority against it
and completing a public-key verification check before enabling issuance. Mount
the file only into the authority container at an absolute path, with no symlink,
mode `0600`, and a root- or authority-UID-owned protected ancestor chain. Never
put `private_exponent_hex` in the public key ring or any other process's mount.
The descriptive hexadecimal values above are templates, not valid key material.

Provision an exact public-key file to the evaluator, runtime, adopter, and
dispatcher. Its only accepted shape is:

```json
{
  "schema_version": 1,
  "keys": [
    {
      "key_id": "deployment-key-id",
      "algorithm": "RSASSA-PKCS1-v1_5/SHA-256",
      "modulus_hex": "768 lowercase hexadecimal characters",
      "exponent": 65537
    }
  ]
}
```

The descriptive modulus above is a template, not a valid configuration. Deploy
the actual 3072-bit public modulus. The loader rejects unknown fields, duplicate
JSON keys, private-key fields, an empty ring, an oversized document, wrong
modulus length, uppercase/non-hex modulus text, and any other exponent or
algorithm.

The public ring contains both the one active admission key and historical
verification keys. Pin the active key ID separately: capture requires
`--authority-active-key-id`, and the adopter requires
`PROVIDER_QUALIFICATION_ACTIVE_KEY_ID`. The value must identify exactly one key
in the SHA-pinned ring. Capture and adoption reject a newly issued receipt whose
key ID is not that active value; public verification and dispatch of receipts
adopted while an older key was active remain valid.

The authority protocol is one canonical JSON line with schema version 1,
operation `issue_provider_qualification`, and the exact claim. It returns one
canonical JSON line containing the same claim and a signed receipt. Requests or
responses over 64 KiB and responses with a different claim fail closed.

## Database credentials and process identities

Remediation migration `0004_provider_security` replaces the 0003
`science_workbench_qualification` role and creates
`science_workbench_dispatcher` and `science_workbench_provider_cleanup` as
`NOLOGIN`, `NOINHERIT`, `NOSUPERUSER`, `NOBYPASSRLS` capability roles. Cleanup
has no direct `SELECT`, `INSERT`, `UPDATE`, or `DELETE` privilege on provider
tables. It may execute only four fixed `SECURITY DEFINER` functions: the
database-time-clamped 100-row due-candidate list, exact advisory-locked due-work
validation, the outbox/superseded completion, and revoked-connection completion.
Deployment separately creates three dedicated LOGIN roles with `NOINHERIT` and
no administrative attributes. Each LOGIN may be a member only of its matching
capability role. Store their passwords separately in the deployment secret
manager. Give each database URL and expected login name only to its matching
adopter, dispatcher, or cleanup process. Do not reuse the owner, migration,
application, worker, session-authenticator, or other provider capability
credential.

The migration removes every existing membership from the replaced qualification
role, so provision all three dedicated memberships only after revision 0004 has
committed. An existing dispatcher or cleanup role name makes the migration fail
closed; do not pre-create those capability roles.

On PostgreSQL 18, grant each membership with the exact options below, replacing
the placeholders independently for adopter, dispatcher, and cleanup:

```sql
GRANT provider_capability_role TO dedicated_provider_login
  WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
```

The capability must have exactly that one direct member. Any additional member,
grant option, inherited authority, owned database object, or direct/effective
privilege outside its documented allowlist makes service startup fail closed.
Migration 0004 also removes `PUBLIC` execution from every existing routine in
the `public` schema and from both the global and `public`-schema routine defaults
owned by the migration role. An explicit PUBLIC routine default owned outside
that boundary makes the migration fail closed. Every future migration-created
routine therefore needs an explicit, reviewed role grant.

The adopter checks the exact expected `session_user`, role membership, LOGIN,
`NOINHERIT`, and absence of superuser, bypass-RLS, create-role, create-database,
and replication attributes before `SET LOCAL ROLE`. Its API owns fixed receipt
append and connection CAS SQL; it has no arbitrary callback or general query
surface. The dispatcher performs the same confinement check for its dedicated
LOGIN before assuming `science_workbench_dispatcher`; that capability alone
reads the exact current receipt and inserts the bound Run in one transaction.
The ordinary application role has receipt read access only, cannot change a
current receipt pointer, and has no `INSERT` privilege on `runs`.

Provision the cleanup worker with the dedicated LOGIN that may assume only
`science_workbench_provider_cleanup`, scoped to fixed due-work selection,
validation, runtime-home destruction, and cleanup-receipt duties through those
four functions. The credential cannot query provider tables directly. It is not
the application, authority, adopter, dispatcher, provider runtime, owner, or
migration credential.

## Process startup

The non-test authority, adopter, dispatcher, and cleanup entrypoints are separate
modules. Run them in separate containers or equivalent process sandboxes with
separate credentials and secret mounts. A mode-`0600` service socket is usable
only when its server and intended client have the same numeric dedicated
provider-service UID (or the client is root), and the client additionally
requires that UID or root to own every protected socket-path component. The
supported non-root deployment therefore uses the same numeric dedicated UID on
each server/client pair while preserving capability separation with distinct
containers and pair-specific socket-volume mounts. Mount an authority socket
only to the capture client, an adopter socket only to capture, a dispatcher
socket only to the product API, and the cleanup vault socket only to cleanup.
Do not mount the authority private key outside the authority or expose any
process's database credential to another process. Using one numeric UID is not
permission to share a filesystem, container, database credential, or secret
volume.

- Authority: set `PROVIDER_QUALIFICATION_AUTHORITY_SOCKET` and
  `PROVIDER_QUALIFICATION_PRIVATE_KEY_FILE`, then run
  `uv run python -m services.api.provider_qualification_authority_server`.
- Adopter: set `PROVIDER_QUALIFICATION_ADOPTER_SOCKET`,
  `PROVIDER_QUALIFICATION_ADOPTER_DATABASE_URL`,
  `PROVIDER_QUALIFICATION_ADOPTER_LOGIN_ROLE`,
  `PROVIDER_QUALIFICATION_ACTIVE_KEY_ID`,
  `PROVIDER_QUALIFICATION_AUTHORITY_PUBLIC_KEYS_FILE`, and
  `PROVIDER_QUALIFICATION_AUTHORITY_PUBLIC_KEYS_SHA256`, then run
  `uv run python -m services.api.provider_qualification_adopter`.
- Dispatcher: set `PROVIDER_RUN_DISPATCH_SOCKET`,
  `PROVIDER_RUN_DISPATCH_DATABASE_URL`,
  `PROVIDER_RUN_DISPATCH_LOGIN_ROLE`, the same public-key file and
  digest variables, and the exact `PROVIDER_RUNTIME_ADAPTER_ID`,
  `PROVIDER_RUNTIME_VERSION`, and `PROVIDER_RUNTIME_EXECUTABLE_SHA256`,
  then run `uv run python -m services.api.provider_run_dispatch_service`.
- Cleanup: set `PROVIDER_CLEANUP_DATABASE_URL`,
  `PROVIDER_CLEANUP_EXPECTED_LOGIN_ROLE`, and the protected
  `PROVIDER_CLEANUP_VAULT_SOCKET`, then run the one-shot
  `uv run python -m services.api.provider_cleanup_cli` on the deployment
  scheduler. A nonzero result remains queued for the next bounded sweep.

Expected LOGIN variables name the separately provisioned LOGIN, never the
`NOLOGIN` capability role. Keep authority, adopter, dispatcher, and cleanup
sockets in pair-specific owner-private directories. Give each intended client
only the socket volume it needs, and do not mount one process's secret or
database credential into another process.

After the dispatcher is ready, set the same protected
`PROVIDER_RUN_DISPATCH_SOCKET` path on the production HTTP process. The HTTP
process receives only the socket path, not the dispatcher database credential.
Missing socket configuration rejects production HTTP startup. With a configured
socket, dispatcher outage makes provider Run creation fail closed with the stable
unavailable response; it never falls back to direct application-role Run
insertion.

## Capture and adoption

Run capture only after the provider connection preflight identifies the exact
requester, connection, current revision, approved runtime version, and executable
digest. `--connection-revision` is the new revision to which the receipt binds.
The command below is the checked-in Darwin development/test example. Production
must use the policy ID from its deployment-supplied exact-platform policy and its
matching approved executable.

```sh
uv run python -m services.api.provider_live_capture \
  --cases tests/g004/fixtures/golden_session_cases.json \
  --output-root /var/lib/science-workbench/provider-qualification \
  --scratch-root /var/lib/science-workbench/provider-qualification-scratch \
  --output /var/lib/science-workbench/provider-qualification/profile.json \
  --receipt-output /var/lib/science-workbench/provider-qualification/receipt.json \
  --codex-executable /absolute/path/to/approved/codex \
  --approved-runtime-policy openai-codex-0.144.4-darwin-arm64 \
  --approved-runtime-policy-file /absolute/protected/path/provider-runtime-policies.json \
  --approved-runtime-policy-sha256 64-lowercase-hex-policy-file-digest \
  --operator-account-ref acct_deployment_correlation_reference \
  --authority-public-keys /etc/science-workbench/qualification-public-keys.json \
  --authority-public-keys-sha256 64-lowercase-hex-public-key-file-digest \
  --authority-active-key-id deployment-key-id \
  --authority-socket /run/science-workbench/qualification-authority.sock \
  --org-id 00000000-0000-7000-8000-000000000001 \
  --user-id 00000000-0000-7000-8000-000000000002 \
  --connection-id 00000000-0000-7000-8000-000000000003 \
  --connection-revision 2 \
  --qualification-adopter-socket /run/science-workbench/qualification-adopter.sock \
  --runtime-home-ref vault://runtime/provider-home/opaque-deployment-id \
  --provider-account-id acct_deployment_provider_subject \
  --eligible-model gpt-5.4 \
  --selected-model gpt-5.4 \
  --connection-health healthy \
  --connection-created-at 2026-07-16T00:00:00+00:00
```

Replace both digest placeholders and every example path with the exact protected
file digest and deployment path before running the command.

Create the output and scratch roots before capture as two distinct, canonical
absolute directories owned by the capture process UID with exact mode `0700`.
Neither root may be a symlink. Both are required deployment inputs; the command
has no source-checkout, current-directory, home-directory, or system-temporary
fallback. `--output` and `--receipt-output` must be absolute paths below the
configured output root. The operator account reference has the single accepted
grammar `acct_[A-Za-z0-9_-]{1,128}`; it remains correlation metadata, not OAuth
account identity evidence.

Repeat `--eligible-model` for every exact model in the existing connection
snapshot; `--selected-model` must name one of them. Supply the connection's
actual timezone-aware creation time and exact current health.

The CLI publishes the profile first, publishes the signed receipt sidecar
second, and requests adoption over the protected adopter socket third. Each
individual file replacement and the adopter transaction are atomic, but the
ordered sequence is not one atomic triple. The adopter compare-and-swap rechecks
the exact requester, connection, prior revision, connection creation time,
runtime-home reference, account, eligible models, selected model, health,
adapter, and receipt/runtime binding.
Any mismatch rolls the receipt insert and current-pointer change back together.
An adoption failure may leave profile and receipt sidecars, but they remain
non-authoritative and no database receipt or current pointer is committed. A
profile without an adopted exact valid receipt grants no dispatch authority. A
model-backed Run must be created by the
dedicated provider dispatcher process, which atomically persists the exact
current receipt, selected model, and runtime binding under the dispatcher
capability role.

## Rotation, revocation, and outage

To rotate a signer, generate and validate a new private-key document inside the
key-management boundary without replacing the active authority mount. First
publish its public key alongside every historical verification key, then roll
out the updated protected public-key file and exact SHA-256 pin to every capture
environment, adopter, and dispatcher while all admission configuration still
names the old active key. Restart the adopter and dispatcher and prove that each
continues to verify historical receipts. Pause new capture and adoption, then
atomically replace the authority-only private-key mount and restart the
authority, which loads exactly one signer at startup. Change the capture
`--authority-active-key-id` and adopter
`PROVIDER_QUALIFICATION_ACTIVE_KEY_ID` to the new key, restart the adopter, and
verify a newly issued receipt through capture, adoption, and dispatch before
resuming admission. This pause prevents either signer from being accepted under
the wrong active-key policy. Never remove the old public key from verification.
Receipt
history is immutable, so every old verification key must remain available
permanently in the active set or a permanently available archive verifier.
Rotation never deletes a key needed to verify a stored receipt. If a required key
is unavailable, restart verification and dispatch fail closed.

For suspected private-key compromise, stop the authority, block new qualification
adoption, preserve receipt and Run history, publish the incident key decision,
rotate the signer, and requalify affected connections. Do not rewrite or delete
old receipts. An authority or adopter outage prevents new qualification and
refresh; a dispatcher outage prevents new Runs; a cleanup outage leaves work
queued for the dedicated worker and blocks any dependent safety gate. None of
these outages may demote, replace, or fabricate history. Existing dispatch is
still subject to current public verification and operational revocation policy.

## Upgrade, recovery, and rollback

Upgrade through provider-qualification remediation revision
`0004_provider_security`. On a fresh path, current revision 0003 archives every
observable legacy unsigned signal as immutable `legacy_unverified` evidence,
including a bare `healthy` connection with no qualification metadata or
timestamp, before changing unsigned `healthy` connections to `pending`. Revision
0004 then converges the capability roles, privileges, and guards.

For a deployment already stamped with an older 0003, first inspect its pre-0003
backup. If that older migration already demoted a bare `healthy` row without
archiving it, 0004 deliberately preserves `pending` with zero history instead of
inventing `legacy_unverified` evidence. Recover the historical fact only from
the backup under an approved remediation, or treat the connection as new and
requalify it. Never label inferred or reconstructed state as signed or current.

Back up PostgreSQL before migration and validate migration on a restored copy.
After restart, load each current receipt through the public verifier and exercise
an exact-bound queued Run through the dedicated dispatcher. Rollback from 0004 is
allowed only when both signed and legacy qualification history are empty. The
migration deliberately refuses a downgrade that would destroy history;
archive-and-delete is not an implicit
rollback procedure and requires a separately approved retention operation.
Before an approved downgrade, revoke and deprovision every deployment LOGIN
membership in `science_workbench_qualification` and
`science_workbench_dispatcher` and `science_workbench_provider_cleanup`, and
deprovision all three dedicated LOGIN credentials. The migration will not delete
externally managed credentials or memberships on the operator's behalf.

## Evidence status

Repository tests and local PostgreSQL exercises verify the authority client,
public verifier, adopter, dispatcher, cleanup, migration, and privilege code
paths. They do not constitute external live qualification. The current external
attempt is blocked by the provider subscription usage limit. No deployment-signed
receipt or adopted live qualification is claimed; release remains blocked until
a fresh external attempt succeeds and its evidence is retained.
