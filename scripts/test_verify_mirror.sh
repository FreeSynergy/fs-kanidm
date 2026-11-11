#!/usr/bin/env bash
# Selftest of verify-mirror.sh with throw-away keys (no secret of ours is involved): right key = green; a VALID signature by another key,
# no signatures at all, a file without signature, a missing SUMS entry and an empty directory = red.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
v="$here/verify-mirror.sh"
t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
export GNUPGHOME="$t/gh"; mkdir -m 700 "$GNUPGHOME"
gpg --batch -q --passphrase '' --quick-gen-key "project test <p@test.invalid>" ed25519 sign never 2>/dev/null
gpg --batch -q --passphrase '' --quick-gen-key "other test <o@test.invalid>" ed25519 sign never 2>/dev/null
fa=$(gpg --batch --list-keys --with-colons "p@test.invalid" | awk -F: '/^fpr:/{print $10; exit}')
fb=$(gpg --batch --list-keys --with-colons "o@test.invalid" | awk -F: '/^fpr:/{print $10; exit}')
gpg --batch --armor --export "p@test.invalid" > "$t/a.asc"; gpg --batch --armor --export "o@test.invalid" > "$t/b.asc"
mk() {  # dir signing-fpr
  rm -rf "$1"; mkdir "$1"; echo one > "$1/one.bin"; echo two > "$1/two.bin"
  (cd "$1" && sha256sum one.bin two.bin > SHA256SUMS.txt)
  for f in "$1"/*; do gpg --batch --armor --detach-sign -u "$2" -o "$f.asc" "$f" 2>/dev/null; done
}
fail=0
expect() {  # name wantedrc dir key fpr
  "$v" --fingerprint "$5" "$3" "$4" >/dev/null 2>&1; local rc=$?
  if { [ "$2" = 0 ] && [ $rc = 0 ]; } || { [ "$2" != 0 ] && [ $rc != 0 ]; }; then echo "PASS $1"; else echo "FAIL $1 (rc $rc)"; fail=1; fi
}
mk "$t/ok" "$fa";               expect "right key signs everything = green" 0 "$t/ok" "$t/a.asc" "$fa"
mk "$t/wrong" "$fb";            cat "$t/a.asc" "$t/b.asc" > "$t/ab.asc"
                                expect "valid signature by ANOTHER imported key = red" 1 "$t/wrong" "$t/ab.asc" "$fa"
mk "$t/nosig" "$fa"; rm -f "$t/nosig"/*.asc; expect "no .asc files at all = red" 1 "$t/nosig" "$t/a.asc" "$fa"
mk "$t/partial" "$fa"; rm -f "$t/partial/two.bin.asc"; expect "one file without signature = red" 1 "$t/partial" "$t/a.asc" "$fa"
mk "$t/unlisted" "$fa"; echo three > "$t/unlisted/three.bin"; gpg --batch --armor --detach-sign -u "$fa" -o "$t/unlisted/three.bin.asc" "$t/unlisted/three.bin" 2>/dev/null
                                expect "signed file missing from SHA256SUMS.txt = red" 1 "$t/unlisted" "$t/a.asc" "$fa"
mkdir "$t/empty";               expect "empty directory = red" 1 "$t/empty" "$t/a.asc" "$fa"
mk "$t/ok2" "$fa";              expect "key file without the expected primary key = red" 1 "$t/ok2" "$t/b.asc" "$fa"
exit $fail
