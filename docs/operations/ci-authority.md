# External CI authority

The repository CI runner intentionally has no production publication authority. Pull requests and checked-out code run only `make ci-validate` in a job without `id-token: write`. That job can prove tests passed but cannot mint release evidence.

After an unprivileged validation succeeds on a push to protected `main`, a separate `ci-attestation` environment job receives OIDC permission. It performs no checkout and runs no repository script. It asks the external authority to clone the exact commit, derive the source identity and governed catalogs independently, execute every command in an authority-owned runner, and publish the resulting manifest. A caller-supplied `GateResult` is never release evidence.

## GitHub configuration

Configure these repository or environment variables:

- `CI_AUTHORITY_URL`: HTTPS endpoint for the authority protocol.
- `CI_AUTHORITY_AUDIENCE`: audience accepted by that service for GitHub OIDC tokens.

The validation job grants only `contents: read` and disables checkout credential persistence. The attestation job grants `id-token: write`, has `contents: none`, uses the protected `ci-attestation` environment, and contains no checkout step. Missing variables, missing GitHub OIDC inputs, a non-HTTPS endpoint, malformed responses, or an authority rejection fail closed.

The `id-token: write` permission only permits requesting a short-lived GitHub OIDC token. It does not grant repository or external-resource write access. The authority service must validate the token signature and issuer, then enforce the expected repository, workflow, ref/environment, commit SHA, run ID, run attempt, and configured audience claims.

## Release wire contract

The client sends canonical JSON by `POST` with `Authorization: Bearer <GitHub OIDC JWT>`, `Content-Type: application/json`, and `X-CI-Authority-Protocol: 2`.

```json
{
  "operation": "execute_and_publish",
  "payload": {
    "repository": "owner/science-workbench",
    "commit_sha": "0123456789abcdef0123456789abcdef01234567",
    "run_id": "1234",
    "run_attempt": "1"
  }
}
```

The successful response is exactly `{"manifest_sha256":"<lowercase sha256>","ok":true}`. Protocol version 2 does not accept commands, counts, output hashes, `GateResult` objects, or a manifest from the caller.

The older lease client in `tools/platform_policy/ci_remote_authority.py` remains a fail-closed protocol test adapter for local contract tests. It is not selected by the release workflow and must not be exposed to OIDC credentials from a checked-out job.

The service is authoritative for source checkout, command execution, atomic run supersession, the source/run-bound control catalog, the High-threat catalog, signed execution receipts, and manifest finalization. It must never translate caller assertions into successful execution receipts.

Each High-threat catalog entry must bind one `threat_id` to the exact pytest `case_id`, whole source-file SHA-256, test-function AST SHA-256, denial-observation AST SHA-256, and postcondition-observation AST SHA-256. The service must treat this catalog as independently reviewed policy, not derive it from the requesting checkout. The runner rederives every binding before and after the selected child process; the evidence parser rejects relabeling, case swaps, omitted observations, stale catalog replay, and recomputed roots for altered bindings.

The checked-in command catalog is deliberately not semantic release evidence. Its
27 commands carry no `requirement_ids`; all normative IDs are listed under
`unverified_requirement_ids`. A local pass therefore cannot claim requirement
coverage, and release finalization rejects that catalog. A success-capable catalog
must come from the independent authority, bind every mapped requirement to exact
requirements-document, source, and test identities, and include the authority-observed
`CI_REQUIREMENT_CASE` record in the signed raw log. A copied requirement ID, a
static attachment, or an aggregate `1 passed` line is insufficient.

## Source and evidence lifecycle

`make ci-source-identity` remains available for local diagnostics. For release publication the authority derives the source-tree digest from its own clean checkout of `commit_sha`, rederives it before publication, and rejects any repository/ref/SHA claim mismatch. Mutable CI evidence directories are excluded from that digest.

Older checkouts contain a directory at `.ci/evidence/latest`. Before the first generation publication, the runner atomically preserves that directory under `.ci/evidence/.legacy-latest-*`; it does not delete its contents. Subsequent successful publications use `latest` only as an atomically replaced symlink to an externally finalized generation.
