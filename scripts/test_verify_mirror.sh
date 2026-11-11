#!/usr/bin/env bash
# Selftest of verify-mirror.sh. Throw-away keys are generated at run time inside a temporary GNUPGHOME (mktemp -d, mode 0700, removed at
# the end); no real key and no secret of ours is involved, nothing is printed from the keys.
# green: primary key; signing SUBkey of the expected primary.  red: other key (also its subkey), expired subkey, expired primary,
# revoked key, tampered file, no signatures, one unsigned file, file missing from SHA256SUMS.txt, empty directory, wrong key file.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
v="$here/verify-mirror.sh"
t=$(mktemp -d); chmod 700 "$t"; trap 'rm -rf "$t"' EXIT
export GNUPGHOME="$t/gh"; mkdir -m 700 "$GNUPGHOME"
G=(gpg --batch -q --yes --passphrase '' --pinentry-mode loopback)
fpr()  { gpg --batch --list-keys --with-colons "$1" 2>/dev/null | awk -F: '/^fpr:/{print $10; exit}'; }
subf() { gpg --batch --list-keys --with-colons "$1" 2>/dev/null | awk -F: '/^sub:/{s=1;next} s&&/^fpr:/{print $10; exit}'; }
"${G[@]}" --quick-gen-key "project <p@test.invalid>" ed25519 sign never 2>/dev/null; A=$(fpr p@test.invalid)
"${G[@]}" --quick-add-key "$A" ed25519 sign never 2>/dev/null; ASUB=$(subf p@test.invalid)
"${G[@]}" --quick-gen-key "other <o@test.invalid>" ed25519 sign never 2>/dev/null; B=$(fpr o@test.invalid)
"${G[@]}" --quick-add-key "$B" ed25519 sign never 2>/dev/null; BSUB=$(subf o@test.invalid)
"${G[@]}" --quick-add-key "$A" ed25519 sign seconds=3 2>/dev/null          # a second subkey of the project key, expires in 3 s
ASUB_EXP=$(gpg --batch --list-keys --with-colons p@test.invalid | awk -F: '/^sub:/{n++; id=$0} /^fpr:/&&n==2{print $10; exit}')
"${G[@]}" --quick-gen-key "shortlived <s@test.invalid>" ed25519 sign seconds=3 2>/dev/null; S=$(fpr s@test.invalid)
"${G[@]}" --quick-gen-key "revoked <r@test.invalid>" ed25519 sign never 2>/dev/null; R=$(fpr r@test.invalid)
sign() { gpg --batch -q --armor --detach-sign -u "$1" -o "$2.asc" "$2" 2>/dev/null; }
mk() {  # dir signing-key-spec ; signs every file with that key spec
  rm -rf "$1"; mkdir "$1"; echo one > "$1/one.bin"; echo two > "$1/two.bin"
  (cd "$1" && sha256sum one.bin two.bin > SHA256SUMS.txt)
  for f in "$1"/*; do sign "$2" "$f"; done
}
pub() { gpg --batch --armor --export "$@" 2>/dev/null; }
pub p@test.invalid > "$t/a.asc"; pub o@test.invalid > "$t/b.asc"; cat "$t/a.asc" "$t/b.asc" > "$t/ab.asc"
fail=0
expect() {  # name want(0|1) dir key fpr [reason that must appear in the output, e.g. EXPKEYSIG]
  local out rc
  out=$("$v" --fingerprint "$5" "$3" "$4" 2>&1); rc=$?
  if [ "$2" = 0 ] && [ $rc = 0 ]; then echo "PASS $1"
  elif [ "$2" != 0 ] && [ $rc != 0 ] && { [ -z "${6:-}" ] || printf '%s' "$out" | grep -q "$6"; }; then echo "PASS $1"
  else echo "FAIL $1 (rc $rc${6:+, wanted reason $6})"; fail=1; fi
}
mk "$t/ok" "$A";                 expect "primary key signs everything = green" 0 "$t/ok" "$t/a.asc" "$A"
mk "$t/sub" "${ASUB}!";          expect "signing SUBkey of the expected primary = green" 0 "$t/sub" "$t/a.asc" "$A"
mk "$t/wrong" "$B";              expect "valid signature by ANOTHER primary key = red" 1 "$t/wrong" "$t/ab.asc" "$A"
mk "$t/wsub" "${BSUB}!";         expect "SUBkey of ANOTHER primary key (both keys imported) = red" 1 "$t/wsub" "$t/ab.asc" "$A"
mk "$t/wsub2" "${BSUB}!";        expect "SUBkey of another primary, its key not imported (NO_PUBKEY) = red" 1 "$t/wsub2" "$t/a.asc" "$A" NO_PUBKEY
mk "$t/tamper" "$A"; echo evil >> "$t/tamper/one.bin"; (cd "$t/tamper" && sha256sum one.bin two.bin > SHA256SUMS.txt); sign "$A" "$t/tamper/SHA256SUMS.txt"
                                 expect "tampered file (BADSIG) = red" 1 "$t/tamper" "$t/a.asc" "$A" BADSIG
mk "$t/nosig" "$A"; rm -f "$t/nosig"/*.asc; expect "no .asc files at all = red" 1 "$t/nosig" "$t/a.asc" "$A"
mk "$t/partial" "$A"; rm -f "$t/partial/two.bin.asc"; expect "one file without signature = red" 1 "$t/partial" "$t/a.asc" "$A"
mk "$t/unlisted" "$A"; echo three > "$t/unlisted/three.bin"; sign "$A" "$t/unlisted/three.bin"
                                 expect "signed file missing from SHA256SUMS.txt = red" 1 "$t/unlisted" "$t/a.asc" "$A"
mkdir "$t/empty";                expect "empty directory = red" 1 "$t/empty" "$t/a.asc" "$A"
mk "$t/ok2" "$A";                expect "key file without the expected primary key = red" 1 "$t/ok2" "$t/b.asc" "$A"
# expiry: sign while the key is still valid, then wait until it has expired
mk "$t/expsub" "${ASUB_EXP}!"; mk "$t/expprim" "$S"; pub s@test.invalid > "$t/s.asc"
# revocation: sign, then revoke the key and export the public key with the revocation certificate
mk "$t/revoked" "$R"
printf 'y\n0\n\ny\n' | gpg --yes --no-tty --pinentry-mode loopback --command-fd 0 --output "$t/rev.asc" --gen-revoke "$R" >/dev/null 2>&1
gpg --batch -q --import "$t/rev.asc" 2>/dev/null; pub r@test.invalid > "$t/r.asc"
sleep 5
pub p@test.invalid > "$t/a2.asc"
                                 expect "signature by an EXPIRED subkey = red" 1 "$t/expsub" "$t/a2.asc" "$A" EXPKEYSIG
                                 expect "signature by an EXPIRED primary key = red" 1 "$t/expprim" "$t/s.asc" "$S" EXPKEYSIG
                                 expect "signature by a REVOKED key = red" 1 "$t/revoked" "$t/r.asc" "$R" REVKEYSIG
exit $fail
