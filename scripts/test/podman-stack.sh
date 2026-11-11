#!/usr/bin/env bash
# Local test of the FreeSynergy server stack in ONE rootless Podman pod (shared loopback, like on the real server):
#   Zentinel (gate, first) -> Kanidm (behind it) -> OIDC login (code flow with PKCE, password + TOTP) -> Tuwunel (SSO with Kanidm)
# Rules (project decisions):
#  * SELinux stays Enforcing. Every bind mount is labelled :Z (all containers share one label because they sit in one pod);
#    only files copied into a private RAM directory are mounted, never repo paths. Sockets/data live in --tmpfs or the container layer.
#  * Every container: --restart=no and a memory limit <= 1 GiB. A crashed container stays down and the test is red.
#  * Only one run at a time (lock + pod check). Nothing is started if a pod "fs-test" exists.
#  * At the end the test fails if setroubleshoot logged any SELinux denial since the start (scripts/test/avc_check.sh, no root).
#  * Secrets (ADR 0054): TLS key, Kanidm admin password, test person's password and TOTP secret, OAuth2 client secret are created at run
#    time inside the containers; files only in a RAM-backed directory under /dev/shm, removed at the end; never printed, never read.
#    Output is PASS/FAIL lines only.
# The configs under test are the templates of the three repos, rendered with NON-secret test values (render.py prints each override).
# Containers are the makers' official images, used ONLY for this local test (never mirrored). Override with KANIDM_IMAGE etc.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
kanidm_repo=$(cd "$here/../.." && pwd)
zentinel_repo=${FS_ZENTINEL_DIR:-$kanidm_repo/../fs-zentinel}
tuwunel_repo=${FS_TUWUNEL_DIR:-$kanidm_repo/../fs-tuwunel}
KANIDM_IMAGE=${KANIDM_IMAGE:-docker.io/kanidm/server:1.12.0}
ZENTINEL_IMAGE=${ZENTINEL_IMAGE:-ghcr.io/zentinelproxy/zentinel:26.11_1}
TUWUNEL_IMAGE=${TUWUNEL_IMAGE:-ghcr.io/matrix-construct/tuwunel:latest}
RUNNER_IMAGE=${RUNNER_IMAGE:-docker.io/library/python:3.13-slim}
CERT_IMAGE=${CERT_IMAGE:-docker.io/library/alpine:3}
pod=fs-test
. "$here/avc_check.sh"

exec 9>/tmp/fs-test.lock
flock -n 9 || { echo "REFUSED: another test run is active"; exit 3; }
if podman pod exists "$pod" 2>/dev/null; then echo "REFUSED: pod $pod already exists (remove it by hand if it is a leftover)"; exit 3; fi
start=$(date '+%Y-%m-%d %H:%M:%S'); t0=$(date +%s)
work=$(mktemp -d -p /dev/shm fs-test.XXXXXX)   # RAM only
tls=$work/tls
say() { printf '== %s\n' "$*"; }
say "secret scan (ADR 0054): selftest, then every file of the three repos"
"$here/scan_secrets.sh" --selftest >/dev/null && echo "PASS secret scan selftest (prepared example secrets are detected)" || { echo "FAIL secret scan selftest"; exit 1; }
for r in "$kanidm_repo" "$zentinel_repo" "$tuwunel_repo"; do
  "$here/scan_secrets.sh" --repo "$r" && echo "PASS no secret pattern in $(basename "$r")" || { echo "FAIL secret pattern found (file:line above, text not shown)"; exit 1; }
done
exec > >(tee -a "$work/run.log") 2>&1   # everything below is also scanned at the end
cleanup() { set +e; podman pod rm -f "$pod" >/dev/null 2>&1; podman unshare rm -rf "$work" 2>/dev/null; rm -rf "$work"; }
trap cleanup EXIT
quiet_logs() { podman logs "$1" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -E -i 'error|panic|fatal' | grep -v -i -E 'token|secret|password' | cut -c1-240 | tail -n 8 || true; }
R="--restart=no"

say "render configs from the repo templates (non-secret test values)"
D=idm.test.local; IDM=https://$D:9443
python3 -I "$here/render.py" "$kanidm_repo/config/server.toml" "$work/server.toml" \
  fs/kanidm/domain=$D 'fs/kanidm/tls-key#file=/tls/key.pem' \
  --sub 'origin = "https://idm.test.local" => origin = "https://idm.test.local:9443"' \
  --sub '/etc/kanidmd/tls/chain.pem => /tls/chain.pem' --sub '/srv/freesynergy/kanidm/kanidm.db => /data/kanidm.db' \
  --sub '/srv/freesynergy/kanidm/backups/ => /data/backups/'
python3 -I "$here/render.py" "$zentinel_repo/config/zentinel.kdl" "$work/zentinel.kdl" \
  fs/kanidm/domain=$D 'fs/zentinel/tls-key#file=/etc/zentinel/tls/key.pem' \
  --sub '0.0.0.0:443 => 0.0.0.0:9443' --sub '/etc/zentinel/tls/fullchain.pem => /etc/zentinel/tls/chain.pem'
python3 -I "$here/render.py" "$tuwunel_repo/config/tuwunel.toml" "$work/tuwunel.toml" \
  fs/tuwunel/server-name=matrix.test.local fs/tuwunel/domain=localhost:8008 fs/kanidm/domain=$D:9443 \
  'fs/tuwunel/oidc-client-secret#file=/tls/oidc-secret' \
  --sub 'https://localhost:8008 => http://localhost:8008' --sub '/srv/freesynergy/tuwunel/db => /data/db'
cp "$here/oidc_flow.py" "$work/oidc_flow.py"
mkdir -m 755 "$tls"; chmod 755 "$work"; chmod 644 "$work"/*.toml "$work"/*.kdl "$work"/*.py

say "pod and run-time TLS material (created inside a container, RAM directory only)"
podman pod create --name "$pod" --add-host "$D:127.0.0.1" --add-host matrix.test.local:127.0.0.1 >/dev/null
podman run --rm --pod "$pod" --memory=128m "$R" -v "$tls:/tls:Z" "$CERT_IMAGE" sh -c '
  set -e; apk add -q openssl >/dev/null
  cd /tls
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 -subj "/CN=fs-test-ca" -keyout ca.key -out ca.pem -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -addext "subjectKeyIdentifier=hash" 2>/dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=idm.test.local" -keyout key.pem -out s.csr 2>/dev/null
  printf "subjectAltName=DNS:idm.test.local,DNS:matrix.test.local,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nauthorityKeyIdentifier=keyid\nsubjectKeyIdentifier=hash\n" > ext
  openssl x509 -req -in s.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 1 -extfile ext -out chain.pem 2>/dev/null
  rm -f ca.key s.csr ext ca.srl; chmod 644 ca.pem chain.pem key.pem' >/dev/null

say "1/4 Zentinel (the gate) validates its configuration and starts"
if out=$(podman run --rm --pod "$pod" --memory=256m "$R" -v "$work/zentinel.kdl:/etc/zentinel/zentinel.kdl:ro,Z" -v "$tls:/etc/zentinel/tls:ro,Z" "$ZENTINEL_IMAGE" test -c /etc/zentinel/zentinel.kdl 2>&1); then
  echo "PASS zentinel test -c (our template, rendered)"
else
  echo "FAIL zentinel test -c"; printf '%s\n' "$out" | sed 's/\x1b\[[0-9;]*m//g' | tail -n 8; exit 1
fi
# SSL_CERT_FILE: Zentinel 26.11_1 did not apply `ca-cert` for the upstream here, so the test CA is given through the environment.
podman run -d --name fs-test-zentinel --pod "$pod" "$R" -e SSL_CERT_FILE=/etc/zentinel/tls/ca.pem --memory=256m --memory-swap=256m --read-only --cap-drop=all \
  -v "$work/zentinel.kdl:/etc/zentinel/zentinel.kdl:ro,Z" -v "$tls:/etc/zentinel/tls:ro,Z" "$ZENTINEL_IMAGE" >/dev/null

say "2/4 Kanidm behind it"
# The admin socket goes into its own tmpfs (labelled for the container) instead of a host volume.
podman run -d --name fs-test-kanidm --pod "$pod" "$R" --memory=1g --memory-swap=1g --tmpfs /run/kanidmd -e KANIDM_ADMIN_BIND_PATH=/run/kanidmd/sock \
  -v "$work/server.toml:/cfg/server.toml:ro,Z" -v "$tls:/tls:ro,Z" "$KANIDM_IMAGE" /sbin/kanidmd server -c /cfg/server.toml >/dev/null
ready() { podman logs fs-test-kanidm 2>&1 | grep -q "Ready to rock"; }
for i in $(seq 1 90); do ready && break; [ "$(podman inspect -f '{{.State.Running}}' fs-test-kanidm)" = true ] || break; sleep 2; done
if ready; then echo "PASS kanidm is up (behind Zentinel, no restart policy)"; else echo "FAIL kanidm did not start"; quiet_logs fs-test-kanidm; exit 1; fi

say "3/4 OIDC login through Zentinel"
# The admin password is captured in a shell variable and handed to the runner through the environment; it is never printed.
KANIDM_ADMIN_PW=$(podman exec fs-test-kanidm /sbin/kanidmd recover-account idm_admin -c /cfg/server.toml 2>&1 | sed -n 's/.*new_password: "\(.*\)".*/\1/p' | tail -n 1)
[ -n "$KANIDM_ADMIN_PW" ] || { echo "FAIL could not recover idm_admin"; exit 1; }
export KANIDM_ADMIN_PW
run_runner() { podman run --rm --pod "$pod" "$R" --memory=256m -e KANIDM_ADMIN_PW -e IDM_URL="$IDM" -v "$tls:/tls:Z" -v "$work/oidc_flow.py:/oidc_flow.py:ro,Z" "$RUNNER_IMAGE" python3 -I /oidc_flow.py "$1"; }
rc=0; run_runner selftest || rc=1
run_runner kanidm || rc=1
unset KANIDM_ADMIN_PW

if [ "$rc" = 0 ]; then
  say "4/4 Tuwunel signs in with Kanidm"
  podman run -d --name fs-test-tuwunel --pod "$pod" "$R" --memory=1g --memory-swap=1g --cap-drop=all --tmpfs /data \
    -e SSL_CERT_FILE=/tls/ca.pem -e TUWUNEL_CONFIG=/etc/tuwunel/tuwunel.toml \
    -v "$work/tuwunel.toml:/etc/tuwunel/tuwunel.toml:ro,Z" -v "$tls:/tls:ro,Z" "$TUWUNEL_IMAGE" >/dev/null
  for i in $(seq 1 60); do podman run --rm --pod "$pod" "$R" --memory=64m "$RUNNER_IMAGE" python3 -I -c 'import urllib.request;urllib.request.urlopen("http://localhost:8008/_matrix/client/versions",timeout=3)' >/dev/null 2>&1 && break
    [ "$(podman inspect -f '{{.State.Running}}' fs-test-tuwunel)" = true ] || break; sleep 2; done
  run_runner tuwunel || rc=1
  [ "$rc" = 0 ] || quiet_logs fs-test-tuwunel
fi
[ "$rc" = 0 ] || { quiet_logs fs-test-zentinel; quiet_logs fs-test-kanidm; }
for c in fs-test-zentinel fs-test-kanidm fs-test-tuwunel; do
  if podman container exists "$c" 2>/dev/null && [ "$(podman inspect -f '{{.State.Running}}' "$c")" != true ]; then echo "FAIL container $c is not running (no restart policy: it stays down)"; rc=1; fi
done
say "memory in use (limits: zentinel 256m, kanidm 1g, tuwunel 1g)"; podman stats --no-stream --format '{{.Name}} {{.MemUsage}}' 2>/dev/null | grep fs-test || true

sleep 1
"$here/scan_secrets.sh" "$work/run.log" && echo "PASS no secret pattern in this run's output" || { echo "FAIL secret pattern in the run output"; rc=1; }

say "SELinux check (setroubleshoot since $start, no root)"
sleep 3
if alarms=$(avc_alarms "$start"); then echo "PASS no SELinux denial since the start of the run"; else echo "FAIL SELinux denials (or journal unreadable):"; printf '%s\n' "$alarms"; rc=1; fi
echo "run time: $(( $(date +%s) - t0 )) s"
[ "$rc" = 0 ] && echo "ALL PASS" || echo "SOME FAILED"
exit "$rc"
