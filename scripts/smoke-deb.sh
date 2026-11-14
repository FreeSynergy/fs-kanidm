#!/usr/bin/env bash
# Smoke test of the .deb on the platforms named in mirror.toml ([platform] smoke_images, each pinned by digest). No secrets, nothing is signed here.
#   smoke-deb.sh <dist-dir>          on the runner: starts one container per image (docker, or CONTAINER_TOOL=podman) and runs this script inside it
# Inside the container (INSIDE=1) it does what a person does: installs the package the way apt does, then checks it:
#   dpkg-deb -I / -c (metadata, file list), the version from mirror.toml, systemd unit and sysusers file present and unchanged in the
#   points that matter (DynamicUser + group kanidmd), group kanidmd created by the package's own postinst via systemd-sysusers,
#   `kanidmd version` (the subcommand; kanidmd has no --version flag) as a plain user, no missing shared library (checked on the unpacked binary
#   BEFORE anything else is installed, so a missing library is not hidden by a package apt pulled in), removal leaves no binary.
#   systemd itself is NOT started. Our package revision adds `systemd` to Depends (upstream's postinst calls `systemd-sysusers`): the
#   container starts without systemd, so apt installing it through that dependency is part of what is tested.
set -euo pipefail
die() { echo "::error::$*" >&2; exit 1; }

if [ -z "${INSIDE:-}" ]; then
  dist=$(cd "${1:?usage: smoke-deb.sh <dist-dir>}" && pwd)
  root=$(cd "$(dirname "$0")/.." && pwd)
  mapfile -t images < <(python3 -I -c 'import sys,tomllib; print("\n".join(tomllib.load(open(sys.argv[1],"rb"))["platform"]["smoke_images"]))' "$root/mirror.toml")
  want=$(python3 -I -c 'import sys,tomllib; m=tomllib.load(open(sys.argv[1],"rb")); print(m["upstream"]["version"]+"-"+str(m["build"]["deb_revision"]))' "$root/mirror.toml")
  [ "${#images[@]}" -gt 0 ] || die "mirror.toml lists no smoke_images"
  for i in "${images[@]}"; do
    case $i in *@sha256:*) ;; *) die "image $i is not pinned by digest" ;; esac
    echo "=== $i"
    # shellcheck disable=SC2086  # CONTAINER_ARGS is a word list on purpose
    ${CONTAINER_TOOL:-docker} run --rm ${CONTAINER_ARGS:-} -e INSIDE=1 -e WANT_VERSION="$want" -v "$dist:/dist:ro" -v "$root/scripts/smoke-deb.sh:/smoke-deb.sh:ro" \
      "$i" bash /smoke-deb.sh
  done
  echo "smoke ok on ${#images[@]} platform(s)"
  exit 0
fi

# ---- inside the container -----------------------------------------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
debs=(/dist/kanidmd_*_amd64.deb)
[ "${#debs[@]}" = 1 ] && [ -f "${debs[0]}" ] || die "expected exactly one /dist/kanidmd_*_amd64.deb, found: ${debs[*]}"
deb=${debs[0]}
# shellcheck disable=SC1091
. /etc/os-release; echo "platform: $PRETTY_NAME, glibc $(ldd --version | head -n1 | awk '{print $NF}')"

dpkg-deb -I "$deb"
dpkg-deb -c "$deb"
[ "$(dpkg-deb -f "$deb" Package)" = kanidmd ] || die "package name is not kanidmd"
[ "$(dpkg-deb -f "$deb" Architecture)" = amd64 ] || die "architecture is not amd64"
[ "$(dpkg-deb -f "$deb" Version)" = "$WANT_VERSION" ] || die "version is $(dpkg-deb -f "$deb" Version), mirror.toml says $WANT_VERSION"
list=$(dpkg-deb -c "$deb" | awk '{print $NF}' | sed 's|^\./||')   # names without a leading ./ (cargo-deb writes none, dpkg-deb --build writes one)
for p in usr/bin/kanidmd usr/lib/sysusers.d/kanidmd.conf etc/kanidmd/server.toml usr/share/kanidmd/static/; do
  grep -q -x -F "$p" <<<"$list" || die "$p is not in the package"
done
grep -q -E '^(usr/)?lib/systemd/system/kanidmd\.service$' <<<"$list" || die "kanidmd.service is not in the package"

# shared libraries of the binary as shipped, in the bare image (before apt installs anything)
tmp=$(mktemp -d); dpkg-deb -x "$deb" "$tmp"
ldd "$tmp/usr/bin/kanidmd"
if ldd "$tmp/usr/bin/kanidmd" | grep 'not found'; then die "kanidmd needs shared libraries this platform lacks (see above); add them to Depends"; fi
rm -rf "$tmp"
dpkg-deb -f "$deb" Depends | grep -q -w systemd || die "Depends of the package does not name systemd"
apt-get update -qq >/dev/null
apt-get install -y --no-install-recommends "$deb" >/dev/null           # apt resolves the dependencies (libc6, tpm-udev), like a person would

getent group kanidmd >/dev/null || die "group kanidmd does not exist: the sysusers file was not applied by the postinst"
unit=$(dpkg -L kanidmd | grep -E '/systemd/system/kanidmd\.service$' | head -n1)
[ -f "$unit" ] || die "unit file $unit missing after install"
grep -q '^DynamicUser=yes' "$unit" || die "unit file lost DynamicUser=yes"
grep -q '^Group=kanidmd' "$unit" || die "unit file lost Group=kanidmd"
grep -q '^g kanidmd' /usr/lib/sysusers.d/kanidmd.conf || die "sysusers file does not declare group kanidmd"

useradd --create-home smoke
out=$(runuser -u smoke -- timeout 30 /usr/bin/kanidmd version </dev/null 2>&1) || die "kanidmd version failed: $out"
echo "started: $out"
grep -q -F "${WANT_VERSION%-*}" <<<"$out" || die "kanidmd version does not say ${WANT_VERSION%-*}: $out"

apt-get remove -y kanidmd >/dev/null
! command -v kanidmd >/dev/null || die "kanidmd is still there after removal"
echo "deb ok on $PRETTY_NAME"
