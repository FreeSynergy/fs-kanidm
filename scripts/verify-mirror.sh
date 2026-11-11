#!/usr/bin/env bash
# Verify a mirror release directory: EVERY file must carry a detached OpenPGP signature (<file>.asc) made by the project key, and
# SHA256SUMS.txt must match and list every file.
#   verify-mirror.sh [--fingerprint <primary-fpr>] <release-dir> <public-key.asc>
# The expected PRIMARY fingerprint comes from mirror.toml ([signing] key_fingerprint) unless --fingerprint is given (used by the selftest).
# GREEN only if gpg reports GOODSIG and VALIDSIG whose primary-key fingerprint equals the expected one (a signing subkey of that
# primary key is fine). RED on any other status line: EXPKEYSIG, EXPSIG, REVKEYSIG, BADSIG, ERRSIG, NO_PUBKEY, or
# no GOODSIG/VALIDSIG at all; EVERY VALIDSIG line of a signature must carry the expected primary fingerprint. No .asc at all, a file without signature, or an empty directory is a failure. Nothing secret is read or printed.
set -euo pipefail
want=""
if [ "${1:-}" = "--fingerprint" ]; then want=${2:?}; shift 2; fi
dir=${1:?usage: verify-mirror.sh [--fingerprint F] <release-dir> <public-key.asc>}
key=${2:?usage: verify-mirror.sh [--fingerprint F] <release-dir> <public-key.asc>}
root=$(cd "$(dirname "$0")/.." && pwd)
[ -n "$want" ] || want=$(python3 -I -c 'import sys,tomllib; print(tomllib.load(open(sys.argv[1],"rb"))["signing"]["key_fingerprint"])' "$root/mirror.toml")
want=${want^^}; want=${want// /}
[ -f "$key" ] || { echo "error: public key $key not found" >&2; exit 2; }
[ -d "$dir" ] || { echo "error: $dir is not a directory" >&2; exit 2; }

export GNUPGHOME; GNUPGHOME=$(mktemp -d); chmod 700 "$GNUPGHOME"; trap 'rm -rf "$GNUPGHOME"' EXIT
gpg --batch -q --import "$key" 2>/dev/null
# the primary fingerprint of an imported key must be the expected one
gpg --batch --list-keys --with-colons 2>/dev/null | awk -F: '/^pub:/{p=1;next} p&&/^fpr:/{print $10; p=0}' | grep -qx "$want" \
  || { echo "FAIL key file does not contain the expected primary key $want"; exit 1; }

# KEYEXPIRED / KEYREVOKED are NOT in this list on purpose: gpg prints them for ANY expired or revoked (sub)key it merely considers in the key
# file (e.g. an old rotated signing subkey), also when the signature itself is good. A signature made BY an expired or revoked key never gets
# GOODSIG (gpg says EXPKEYSIG / REVKEYSIG instead), and GOODSIG is required below, so nothing bad slips through.
BAD='EXPKEYSIG|EXPSIG|REVKEYSIG|BADSIG|ERRSIG|NO_PUBKEY'
fail=0; n=0
while IFS= read -r -d '' f; do
  case $f in *.asc) continue ;; esac
  n=$((n+1)); name=$(basename "$f")
  if [ ! -f "$f.asc" ]; then echo "FAIL no signature for $name"; fail=1; continue; fi
  status=$(gpg --batch --status-fd=1 --verify "$f.asc" "$f" 2>/dev/null || true)
  if printf '%s\n' "$status" | grep -q -E "^\[GNUPG:\] ($BAD)( |$)"; then
    echo "FAIL $name: $(printf '%s\n' "$status" | grep -o -E "^\[GNUPG:\] ($BAD)" | cut -d' ' -f2 | sort -u | paste -sd, -)"; fail=1; continue
  fi
  mapfile -t primaries < <(printf '%s\n' "$status" | awk '$1=="[GNUPG:]" && $2=="VALIDSIG" {print toupper($12)}')
  allok=1; [ "${#primaries[@]}" -gt 0 ] || allok=0
  for p in "${primaries[@]}"; do [ "$p" = "$want" ] || allok=0; done
  if printf '%s\n' "$status" | grep -q '^\[GNUPG:\] GOODSIG ' && [ "$allok" = 1 ]; then
    echo "signature ok: $name"
  else
    echo "FAIL $name: no good signature by primary key $want"; fail=1
  fi
done < <(find "$dir" -maxdepth 1 -type f -print0 | sort -z)
[ "$n" -gt 0 ] || { echo "FAIL no files to verify in $dir"; exit 1; }

[ -f "$dir/SHA256SUMS.txt" ] || { echo "FAIL SHA256SUMS.txt missing"; exit 1; }
(cd "$dir" && sha256sum --check --strict SHA256SUMS.txt) || fail=1
while IFS= read -r -d '' f; do
  name=$(basename "$f"); case $name in *.asc|SHA256SUMS.txt) continue ;; esac
  grep -q -F "  $name" "$dir/SHA256SUMS.txt" || { echo "FAIL $name is not listed in SHA256SUMS.txt"; fail=1; }
done < <(find "$dir" -maxdepth 1 -type f -print0)
exit $fail
