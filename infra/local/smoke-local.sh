#!/bin/sh
set -eu

compose() {
  docker compose -f compose.yaml "$@"
}

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
api_port=${SWB_API_PORT:-58000}
worker_port=${SWB_WORKER_PORT:-58001}
web_port=${SWB_WEB_PORT:-53000}
minio_port=${SWB_MINIO_PORT:-59000}
mailpit_port=${SWB_MAILPIT_PORT:-58025}

# Given: every long-running local service reports healthy.
for service in postgres redis minio clamav mailpit api worker web; do
  test "$(compose ps --format json "$service" | jq -r '.Health')" = "healthy"
done
curl --fail --silent "http://localhost:$api_port/health" | jq -e '.status == "ok"' >/dev/null
curl --fail --silent "http://localhost:$worker_port/health" | jq -e '.status == "ok"' >/dev/null
curl --fail --silent "http://localhost:$web_port/health" | jq -e '.status == "ok"' >/dev/null

# When: an object is created, read, and deleted through the S3-compatible interface.
printf 'deterministic-artifact' | compose --profile tools run --rm -T \
  --entrypoint /bin/sh minio-client -ec '
    mc alias set local http://minio:9000 local-minio local-minio-secret >/dev/null
    mc mb --ignore-existing local/smoke >/dev/null
    mc pipe local/smoke/object.txt >/dev/null
    test "$(mc cat local/smoke/object.txt)" = "deterministic-artifact"
    mc rm local/smoke/object.txt >/dev/null
    mc rb local/smoke >/dev/null
  '

# Then: a Magic Link arrives and the artifact host receives no application cookie.
curl --fail --silent --request POST "http://localhost:$api_port/magic-links" >/dev/null
message_id="$(curl --fail --silent "http://localhost:$mailpit_port/api/v1/messages" | jq -er '.messages[0].ID')"
curl --fail --silent "http://localhost:$mailpit_port/api/v1/message/$message_id" | \
  grep -q 'local-smoke-token'
curl --silent --cookie-jar "$tmpdir/cookies" "http://localhost:$web_port/session-cookie" >/dev/null
curl --fail --silent --verbose --cookie "$tmpdir/cookies" \
  "http://127.0.0.1:$minio_port/minio/health/live" \
  2>"$tmpdir/artifact.trace" >/dev/null
test -z "$(grep -i '^> Cookie:' "$tmpdir/artifact.trace" || true)"

clean_status="$(curl --silent --output "$tmpdir/clean-upload.json" --write-out '%{http_code}' --request POST --data-binary 'clean scientific input' "http://localhost:$api_port/uploads")"
eicar='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
threat_status="$(curl --silent --output "$tmpdir/threat-upload.json" --write-out '%{http_code}' --request POST --data-binary "$eicar" "http://localhost:$api_port/uploads")"
long_filename="$(awk 'BEGIN { for (i = 0; i < 1025; i++) printf "x" }')"
invalid_status="$(curl --silent --output "$tmpdir/invalid-upload.json" --write-out '%{http_code}' --request POST --header "X-Upload-Filename: $long_filename" --data-binary 'x' "http://localhost:$api_port/uploads")"
test "$clean_status" = "202"
jq -e '.status == "scan_accepted"' "$tmpdir/clean-upload.json" >/dev/null
test "$threat_status" = "422"
jq -e '.status == "quarantined" and .error == "malware_detected"' "$tmpdir/threat-upload.json" >/dev/null
test "$invalid_status" = "422"
jq -e '.error == "upload_body_invalid"' "$tmpdir/invalid-upload.json" >/dev/null

# Given: the malware scanner becomes unavailable after healthy startup.
compose stop clamav >/dev/null

# When: health and upload boundaries are exercised while scanning is unavailable.
health_status="$(curl --silent --output "$tmpdir/health.json" --write-out '%{http_code}' "http://localhost:$api_port/health")"
upload_status="$(curl --silent --output "$tmpdir/upload.json" --write-out '%{http_code}' --request POST --data-binary 'clean scientific input' "http://localhost:$api_port/uploads")"

# Then: health degrades and uploads fail closed with no accepted artifact.
test "$health_status" = "503"
test "$upload_status" = "503"
jq -e '.status == "degraded"' "$tmpdir/health.json" >/dev/null
jq -e '.error == "upload_scan_unavailable"' "$tmpdir/upload.json" >/dev/null
compose up -d --wait --wait-timeout 180 clamav >/dev/null

echo "smoke-local: all service, object, mail, origin, and scanner checks passed"
