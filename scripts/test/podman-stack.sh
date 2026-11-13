#!/usr/bin/env bash
# Local test of the FreeSynergy server stack in ONE rootless Podman pod (shared loopback, like on the real server):
#   Zentinel (gate, first) -> Kanidm (behind it) -> OIDC login (code flow with PKCE, password + TOTP) -> Tuwunel (SSO with Kanidm)
#
# Rules (project decisions):
#  * SELinux stays Enforcing. Bind mounts are labelled :Z and hold only NON-secret rendered configs (/dev/shm/..., mode 0755).
#  * Test secrets are never written to host files of ours, never put into the host environment or into command-line arguments, and
#    never visible in `podman inspect`. They live in containers (a container's own tmpfs, mode 0700) or in Podman secrets created
#    from stdin. HONEST NOTE: Podman's default secret driver (`file`) keeps Podman secrets as base64 in the user's own store
#    (~/.local/share/containers/storage/secrets/filedriver/secretsdata.json, mode 0600) until `podman secret rm`, which deletes the
#    entry but does not overwrite the disk. Everything stored there is throw-away (the CA lives 1 day, the passwords belong to a
#    test server that is removed at the end). We do not change host configuration to move that store to a tmpfs.
#      - TLS keys/CA: generated inside container fs-test-pki (tmpfs), piped by `podman exec ... cat | podman secret create`.
#      - Kanidm admin password: `kanidmd recover-account` output is piped through sed into `podman secret create` (never printed).
#      - Test person's password + TOTP secret, OAuth2 client secret: created and kept inside the runner container (tmpfs /state).
#        The client secret is handed to Tuwunel the same way (runner stdout -> podman secret create).
#  * Every container: --restart=no, --pids-limit, --cap-drop=all (no cap-add was needed), --security-opt no-new-privileges, a memory
#    limit <= 1 GiB. A crashed container stays down and the test is red.
#  * One run at a time (lock in $XDG_RUNTIME_DIR + pod check). The cleanup trap is set before anything is created.
#  * First the secret scan (selftest + all three repos), at the end also over this run's output; at the end the SELinux check
#    (journalctl, no root; unreadable journal = red).
# The configs under test are the templates of the three repos, rendered with NON-secret test values (render.py prints each override).
# Containers are the makers' official images (python: Docker official image), ALL pinned by digest, used ONLY for this local test (never
# mirrored). The Tuwunel image's revision label must equal the commit pinned in fs-tuwunel/mirror.toml.
#
# pids limits: zentinel 256 (one worker per core, 32 here, plus runtime threads), kanidm 512 (tokio + database threads), tuwunel 1024
# (database pool capped by config at 256 workers plus tokio and RocksDB threads; upstream's default needs more than 2048),
# runner/pki 64.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
kanidm_repo=$(cd "$here/../.." && pwd)
zentinel_repo=${FS_ZENTINEL_DIR:-$kanidm_repo/../fs-zentinel}
tuwunel_repo=${FS_TUWUNEL_DIR:-$kanidm_repo/../fs-tuwunel}
KANIDM_IMAGE=${KANIDM_IMAGE:-docker.io/kanidm/server@sha256:71b6ff5a9c9c32b632894d8acef5a2afc77941b35a0aa95dcee959fe688d5ce9}   # tag 1.12.0 (digest of 1.12.1 not yet looked up; local tests only, never mirrored; to be raised with the next registry check)
ZENTINEL_IMAGE=${ZENTINEL_IMAGE:-ghcr.io/zentinelproxy/zentinel@sha256:4718b2ea97276d11fd327bafce92bbd095fd2db86d013f6600c3b3663513d197}   # tag 26.11_1
TUWUNEL_IMAGE=${TUWUNEL_IMAGE:-ghcr.io/matrix-construct/tuwunel@sha256:43e55dd2eb36c9b6604b68cbd2a7aeace1899143eeda87c6c8f5cbf508d8ab7e}
RUNNER_IMAGE=${RUNNER_IMAGE:-docker.io/library/python@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90}   # 3.13-slim
PKI_IMAGE=${PKI_IMAGE:-docker.io/library/python@sha256:ecbe213fb818d557fd19db4078244339e2e2e52874f9c81052d3094ea114d797}   # python:3.13 (full image: contains the openssl CLI)
pod=fs-test
secrets=(fs-ca fs-kanidm-chain fs-kanidm-key fs-zentinel-chain fs-zentinel-key fs-admin-pw fs-oidc)
. "$here/avc_check.sh"

lockfile=${XDG_RUNTIME_DIR:-/tmp}/fs-test.lock
exec 9>"$lockfile"
flock -n 9 || { echo "REFUSED: another test run is active"; exit 3; }
if podman pod exists "$pod" 2>/dev/null; then echo "REFUSED: pod $pod already exists (remove it by hand if it is a leftover)"; exit 3; fi
for s in "${secrets[@]}"; do podman secret exists "$s" 2>/dev/null && { echo "REFUSED: podman secret $s exists (leftover?)"; exit 3; }; done

start=$(date '+%Y-%m-%d %H:%M:%S'); t0=$(date +%s)
work=$(mktemp -d -p /dev/shm fs-test.XXXXXX)   # NON-secret rendered configs and the output log only (RAM)
cleanup() { set +e; podman pod rm -f "$pod" >/dev/null 2>&1; for s in "${secrets[@]}"; do podman secret rm "$s" >/dev/null 2>&1; done; rm -rf "$work"; }
trap cleanup EXIT
say() { printf '== %s\n' "$*"; }

say "secret scan (ADR 0054): selftest, then every file of the three repos"
"$here/scan_secrets.sh" --selftest >/dev/null && echo "PASS secret scan selftest (every pattern detects its prepared example)" || { echo "FAIL secret scan selftest"; exit 1; }
for r in "$kanidm_repo" "$zentinel_repo" "$tuwunel_repo"; do
  "$here/scan_secrets.sh" --repo "$r" && echo "PASS no secret pattern in $(basename "$r")" || { echo "FAIL secret pattern found (file:line above, text not shown)"; exit 1; }
done
exec > >(tee -a "$work/run.log") 2>&1   # everything below is also scanned at the end
avc_prepare

# Common hardening for every container.
H=(--restart=no --cap-drop=all --security-opt no-new-privileges)
quiet_logs() { podman logs "$1" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -E -i 'error|warn|panic|fatal' | grep -v -i -E 'token|secret|password|code=' | cut -c1-300 | tail -n 12 || true; }
secret_from() { podman secret create "$1" - >/dev/null; }   # reads stdin

say "render configs from the repo templates (non-secret test values)"
D=idm.test.local; IDM=https://$D:9443
python3 -I "$here/render.py" "$kanidm_repo/config/server.toml" "$work/server.toml" \
  fs/kanidm/domain=$D 'fs/kanidm/tls-key#file=/run/secrets/fs-kanidm-key' \
  --sub 'origin = "https://idm.test.local" => origin = "https://idm.test.local:9443"' \
  --sub '/etc/kanidmd/tls/chain.pem => /run/secrets/fs-kanidm-chain' --sub '/srv/freesynergy/kanidm/kanidm.db => /data/kanidm.db' \
  --sub '/srv/freesynergy/kanidm/backups/ => /data/backups/'
python3 -I "$here/render.py" "$zentinel_repo/config/zentinel.kdl" "$work/zentinel.kdl" \
  fs/kanidm/domain=$D 'fs/zentinel/tls-key#file=/run/secrets/fs-zentinel-key' \
  --sub '0.0.0.0:443 => 0.0.0.0:9443' --sub '/etc/zentinel/tls/fullchain.pem => /run/secrets/fs-zentinel-chain'
python3 -I "$here/render.py" "$tuwunel_repo/config/tuwunel.toml" "$work/tuwunel.toml" \
  fs/tuwunel/server-name=matrix.test.local fs/tuwunel/domain=localhost:8008 fs/kanidm/domain=$D:9443 \
  'fs/tuwunel/oidc-client-secret#file=/run/secrets/fs-oidc' \
  --sub 'https://localhost:8008 => http://localhost:8008' --sub '/srv/freesynergy/tuwunel/db => /data/db'
cp "$here/oidc_flow.py" "$work/oidc_flow.py"
chmod 755 "$work"; chmod 644 "$work"/*.toml "$work"/*.kdl "$work"/*.py

say "pinned Tuwunel image must be the commit pinned in fs-tuwunel/mirror.toml"
want=$(python3 -I -c 'import sys,tomllib; print(tomllib.load(open(sys.argv[1],"rb"))["source"]["commit"])' "$tuwunel_repo/mirror.toml")
got=$(podman image inspect "$TUWUNEL_IMAGE" --format '{{index .Labels "org.opencontainers.image.revision"}}' 2>/dev/null || echo none)
if [ "$got" = "$want" ]; then echo "PASS Tuwunel image revision equals the pinned commit"; else echo "FAIL Tuwunel image revision ($got) differs from the pin ($want)"; exit 1; fi

say "pod; TLS material is generated inside a container (tmpfs) and handed over as Podman secrets"
podman pod create --name "$pod" --add-host "$D:127.0.0.1" --add-host matrix.test.local:127.0.0.1 >/dev/null
podman run -d --name fs-test-pki --pod "$pod" "${H[@]}" --pids-limit=64 --memory=128m --tmpfs /tls:rw,mode=0700 "$PKI_IMAGE" sh -c '
  set -e; cd /tls; umask 077
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 -subj "/CN=fs-test-ca" -keyout ca.key -out ca.pem -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -addext "subjectKeyIdentifier=hash" 2>/dev/null
  printf "subjectAltName=DNS:idm.test.local,DNS:matrix.test.local,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nauthorityKeyIdentifier=keyid\nsubjectKeyIdentifier=hash\n" > ext
  for n in kanidm zentinel; do
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=idm.test.local" -keyout $n.key -out $n.csr 2>/dev/null
    openssl x509 -req -in $n.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 1 -extfile ext -out $n.chain 2>/dev/null
  done
  rm -f ca.key *.csr ext ca.srl; touch done; sleep 300' >/dev/null
for _ in $(seq 1 30); do podman exec fs-test-pki test -f /tls/done 2>/dev/null && break; sleep 1; done
podman exec fs-test-pki test -f /tls/done || { echo "FAIL TLS material was not generated"; exit 1; }
podman exec fs-test-pki cat /tls/ca.pem        | secret_from fs-ca
podman exec fs-test-pki cat /tls/kanidm.chain  | secret_from fs-kanidm-chain
podman exec fs-test-pki cat /tls/kanidm.key    | secret_from fs-kanidm-key
podman exec fs-test-pki cat /tls/zentinel.chain | secret_from fs-zentinel-chain
podman exec fs-test-pki cat /tls/zentinel.key  | secret_from fs-zentinel-key
podman rm -f fs-test-pki >/dev/null

say "1/4 Zentinel (the gate) validates its configuration and starts"
# --secret ...,uid=65532: the image runs as nonroot (65532); SSL_CERT_FILE: Zentinel 26.11_1 did not apply `ca-cert` for the upstream.
# shellcheck disable=SC2054  # commas belong to the podman --secret option syntax
ZS=(--secret fs-ca,uid=65532,mode=0400 --secret fs-zentinel-chain,uid=65532,mode=0400 --secret fs-zentinel-key,uid=65532,mode=0400)
if out=$(podman run --rm --pod "$pod" "${H[@]}" --pids-limit=256 --memory=256m "${ZS[@]}" -v "$work/zentinel.kdl:/etc/zentinel/zentinel.kdl:ro,Z" "$ZENTINEL_IMAGE" test -c /etc/zentinel/zentinel.kdl 2>&1); then
  echo "PASS zentinel test -c (our template, rendered)"
else
  echo "FAIL zentinel test -c"; printf '%s\n' "$out" | sed 's/\x1b\[[0-9;]*m//g' | tail -n 8; exit 1
fi
podman run -d --name fs-test-zentinel --pod "$pod" "${H[@]}" --pids-limit=256 --memory=256m --memory-swap=256m --read-only \
  -e SSL_CERT_FILE=/run/secrets/fs-ca "${ZS[@]}" -v "$work/zentinel.kdl:/etc/zentinel/zentinel.kdl:ro,Z" "$ZENTINEL_IMAGE" >/dev/null

say "2/4 Kanidm behind it"
# The admin socket goes into its own tmpfs (labelled for the container) instead of a host volume.
podman run -d --name fs-test-kanidm --pod "$pod" "${H[@]}" --pids-limit=512 --memory=1g --memory-swap=1g --tmpfs /run/kanidmd -e KANIDM_ADMIN_BIND_PATH=/run/kanidmd/sock \
  --secret fs-kanidm-chain,mode=0400 --secret fs-kanidm-key,mode=0400 -v "$work/server.toml:/cfg/server.toml:ro,Z" \
  "$KANIDM_IMAGE" /sbin/kanidmd server -c /cfg/server.toml >/dev/null
ready() { podman logs fs-test-kanidm 2>&1 | grep -q "Ready to rock"; }
for _ in $(seq 1 90); do ready && break; [ "$(podman inspect -f '{{.State.Running}}' fs-test-kanidm)" = true ] || break; sleep 2; done
if ready; then echo "PASS kanidm is up (behind Zentinel, no restart policy)"; else echo "FAIL kanidm did not start"; quiet_logs fs-test-kanidm; exit 1; fi

say "3/4 OIDC login through Zentinel"
# The admin password goes from the recovery output through sed straight into a Podman secret; it is never printed or stored in a file.
# (only the NUMBER of bytes is counted, to prove that something was captured)
n=$(podman exec fs-test-kanidm /sbin/kanidmd recover-account idm_admin -c /cfg/server.toml 2>&1 | sed -n 's/.*new_password: "\(.*\)".*/\1/p' | tail -n 1 | tee >(secret_from fs-admin-pw) | wc -c)
for _ in $(seq 1 20); do podman secret exists fs-admin-pw && break; sleep 0.5; done   # the process substitution creates the secret asynchronously
{ [ "$n" -gt 8 ] && podman secret exists fs-admin-pw; } || { echo "FAIL could not recover idm_admin"; exit 1; }
podman run -d --name fs-test-runner --pod "$pod" "${H[@]}" --pids-limit=64 --memory=256m --read-only --tmpfs /state:rw,mode=0700 --tmpfs /tmp \
  -e PYTHONDONTWRITEBYTECODE=1 -e IDM_URL="$IDM" --secret fs-ca,mode=0400 --secret fs-admin-pw,mode=0400 \
  -v "$work/oidc_flow.py:/oidc_flow.py:ro,Z" "$RUNNER_IMAGE" sleep infinity >/dev/null
run_flow() { podman exec fs-test-runner python3 -I /oidc_flow.py "$1"; }
rc=0; run_flow selftest || rc=1
run_flow kanidm || rc=1

if [ "$rc" = 0 ]; then
  say "4/4 Tuwunel signs in with Kanidm"
  run_flow export-oidc | secret_from fs-oidc
  podman run -d --name fs-test-tuwunel --pod "$pod" "${H[@]}" --pids-limit=1024 --memory=1g --memory-swap=1g --tmpfs /data \
    -e SSL_CERT_FILE=/run/secrets/fs-ca -e TUWUNEL_CONFIG=/etc/tuwunel/tuwunel.toml --secret fs-ca,mode=0400 --secret fs-oidc,mode=0400 \
    -v "$work/tuwunel.toml:/etc/tuwunel/tuwunel.toml:ro,Z" "$TUWUNEL_IMAGE" >/dev/null
  for _ in $(seq 1 60); do podman exec fs-test-runner python3 -I -c 'import urllib.request;urllib.request.urlopen("http://localhost:8008/_matrix/client/versions",timeout=3)' >/dev/null 2>&1 && break
    [ "$(podman inspect -f '{{.State.Running}}' fs-test-tuwunel)" = true ] || break; sleep 2; done
  run_flow tuwunel || rc=1
  if podman logs fs-test-tuwunel 2>&1 | grep -q "Username invalid"; then echo "FAIL Tuwunel had to fall back to another claim for the user name (\"Username invalid\")"; rc=1; else echo "PASS the Matrix user name came from the chosen claim (no \"Username invalid\" fallback)"; fi
  [ "$rc" = 0 ] || quiet_logs fs-test-tuwunel
fi
[ "$rc" = 0 ] || { quiet_logs fs-test-zentinel; quiet_logs fs-test-kanidm; }
for c in fs-test-zentinel fs-test-kanidm fs-test-runner fs-test-tuwunel; do
  if podman container exists "$c" 2>/dev/null && [ "$(podman inspect -f '{{.State.Running}}' "$c")" != true ]; then echo "FAIL container $c is not running (no restart policy: it stays down)"; rc=1; fi
done
say "memory in use (limits: zentinel 256m, kanidm 1g, tuwunel 1g, runner 256m)"; podman stats --no-stream --format '{{.Name}} {{.MemUsage}}' 2>/dev/null | grep fs-test || true

for _ in $(seq 1 20); do grep -q "memory in use" "$work/run.log" && break; sleep 0.5; done   # wait until tee has written the log
"$here/scan_secrets.sh" "$work/run.log" && echo "PASS no secret pattern in this run's output" || { echo "FAIL secret pattern in the run output"; rc=1; }
say "SELinux check (setroubleshoot since $start, no root; journal readability proven by a marker line)"
sleep 8
if alarms=$(avc_alarms "$start"); then echo "PASS no SELinux denial since the start of the run"; else echo "FAIL SELinux denials or journal unreadable:"; printf '%s\n' "$alarms"; rc=1; fi
echo "run time: $(( $(date +%s) - t0 )) s"
[ "$rc" = 0 ] && echo "ALL PASS" || echo "SOME FAILED"
exit "$rc"
