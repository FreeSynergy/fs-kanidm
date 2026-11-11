#!/usr/bin/env bash
# Verify a downloaded mirror release: OpenPGP signatures (.asc) against the FreeSynergy release key and SHA256SUMS.txt.
# Usage: verify-mirror.sh <release-dir> [public-key.asc]
# The expected fingerprint is read from mirror.toml; the key file defaults to FreeSynergy-release-key.pgp from the release.
set -euo pipefail
dir=${1:?usage: verify-mirror.sh <release-dir> [public-key.asc]}
root=$(cd "$(dirname "$0")/.." && pwd)
want=$(python3 -I -c 'import sys,tomllib; print(tomllib.load(open(sys.argv[1],"rb"))["signing"]["key_fingerprint"])' "$root/mirror.toml")
key=${2:-$dir/FreeSynergy-release-key.pgp}
[[ -f $key ]] || { echo "error: public key $key not found (pass it as 2nd argument)" >&2; exit 2; }
export GNUPGHOME; GNUPGHOME=$(mktemp -d); trap 'rm -rf "$GNUPGHOME"' EXIT
gpg --batch -q --import "$key"
gpg --batch --list-keys --with-colons | awk -F: '/^fpr:/{print $10}' | grep -qx "$want" || {
  # the signing subkey may be listed instead of the primary: accept if the primary fingerprint is listed anywhere
  gpg --batch --list-keys --with-colons --fingerprint | grep -q "$want" || { echo "error: key fingerprint $want not in the key file" >&2; exit 1; }; }
fail=0
shopt -s nullglob
for sig in "$dir"/*.asc; do
  f=${sig%.asc}; [[ -f $f ]] || continue
  if gpg --batch --verify "$sig" "$f" 2>/dev/null; then echo "signature ok: $(basename "$f")"; else echo "SIGNATURE BAD: $(basename "$f")"; fail=1; fi
done
(cd "$dir" && sha256sum --check --strict SHA256SUMS.txt) || fail=1
exit $fail
