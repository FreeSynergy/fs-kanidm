#!/usr/bin/env bash
# Selftest of verify-mirror.sh. Throw-away keys are generated at run time inside a temporary GNUPGHOME (mktemp -d, mode 0700, removed at
# the end); no real key and no secret of ours is involved, nothing is printed from the keys.
# green: primary key; signing SUBkey of the expected primary.  red: other key (also its subkey), expired subkey, expired primary,
# revoked key, expired signature, tampered file, no signatures, one unsigned file, file missing from SHA256SUMS.txt, empty directory,
# wrong key file. Expiry uses --faked-system-time (keys created and used in 2020 with a one-day life): no sleeping, no dependence on the
# speed of the runner. Each single status word of the reject list is also tested ALONE with a canned gpg output (FS_VERIFY_GPG), so
# removing one word from verify-mirror.sh is noticed. Two VALIDSIG lines with different primaries are red.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
v="$here/verify-mirror.sh"
t=$(mktemp -d); chmod 700 "$t"; trap 'rm -rf "$t"' EXIT
export GNUPGHOME="$t/gh"; mkdir -m 700 "$GNUPGHOME"
G=(gpg --batch -q --yes --passphrase '' --pinentry-mode loopback)
fpr()  { gpg --batch --list-keys --with-colons "$1" 2>/dev/null | awk -F: '/^fpr:/{print $10; exit}'; }
subf() { gpg --batch --list-keys --with-colons "$1" 2>/dev/null | awk -F: '/^sub:/{s=1;next} s&&/^fpr:/{print $10; exit}'; }
PAST=(--faked-system-time 20200101T000000)      # keys that must be expired today are created on 2020-01-01 with a life of one day
"${G[@]}" "${PAST[@]}" --quick-gen-key "project <p@test.invalid>" ed25519 sign never 2>/dev/null; A=$(fpr p@test.invalid)
"${G[@]}" "${PAST[@]}" --quick-add-key "$A" ed25519 sign never 2>/dev/null; ASUB=$(subf p@test.invalid)
"${G[@]}" "${PAST[@]}" --quick-gen-key "other <o@test.invalid>" ed25519 sign never 2>/dev/null; B=$(fpr o@test.invalid)
"${G[@]}" "${PAST[@]}" --quick-add-key "$B" ed25519 sign never 2>/dev/null; BSUB=$(subf o@test.invalid)
"${G[@]}" "${PAST[@]}" --quick-add-key "$A" ed25519 sign 1d 2>/dev/null     # a second subkey of the project key, valid only on 2020-01-01
ASUB_EXP=$(gpg --batch --list-keys --with-colons p@test.invalid | awk -F: '/^sub:/{n++} /^fpr:/&&n==2{print $10; exit}')
"${G[@]}" "${PAST[@]}" --quick-gen-key "shortlived <s@test.invalid>" ed25519 sign 1d 2>/dev/null; S=$(fpr s@test.invalid)
"${G[@]}" "${PAST[@]}" --quick-gen-key "revoked <r@test.invalid>" ed25519 sign never 2>/dev/null; R=$(fpr r@test.invalid)
"${G[@]}" "${PAST[@]}" --quick-gen-key "sigexp <x@test.invalid>" ed25519 sign never 2>/dev/null; X=$(fpr x@test.invalid)
sign() { gpg --batch -q --armor --detach-sign "${SIGNOPTS[@]}" -u "$1" -o "$2.asc" "$2" 2>/dev/null; }
SIGNOPTS=()
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
# expiry: signed on 2020-01-01 12:00 while the key was valid; today the key is expired (no sleeping)
SIGNOPTS=(--faked-system-time 20200101T120000)
mk "$t/expsub" "${ASUB_EXP}!"; mk "$t/expprim" "$S"; pub s@test.invalid > "$t/s.asc"
# expired SIGNATURE (key valid for ever, signature valid for one day)
SIGNOPTS=(--faked-system-time 20200101T120000 --default-sig-expire 1d); mk "$t/expsig" "$X"; pub x@test.invalid > "$t/x.asc"
SIGNOPTS=()
# revocation: sign, then revoke the key and export the public key with the revocation certificate
mk "$t/revoked" "$R"
printf 'y\n0\n\ny\n' | gpg --yes --no-tty --pinentry-mode loopback --command-fd 0 --output "$t/rev.asc" --gen-revoke "$R" >/dev/null 2>&1
gpg --batch -q --import "$t/rev.asc" 2>/dev/null; pub r@test.invalid > "$t/r.asc"
pub p@test.invalid > "$t/a2.asc"
                                 expect "signature by an EXPIRED subkey = red" 1 "$t/expsub" "$t/a2.asc" "$A" EXPKEYSIG
                                 expect "signature by an EXPIRED primary key = red" 1 "$t/expprim" "$t/s.asc" "$S" EXPKEYSIG
                                 expect "EXPIRED signature = red" 1 "$t/expsig" "$t/x.asc" "$X" EXPSIG
                                 expect "signature by a REVOKED key = red" 1 "$t/revoked" "$t/r.asc" "$R" REVKEYSIG
# each status word ALONE: canned gpg output = good signature by the right primary key plus exactly one bad status line
mkdir "$t/mock"; cat > "$t/mock/gpg" <<'MOCK'
#!/usr/bin/env bash
[ -n "${MOCK_NOGOOD:-}" ] || echo "[GNUPG:] GOODSIG 0123456789ABCDEF mock"
echo "[GNUPG:] VALIDSIG $MOCK_FPR 2026-01-01 1 0 4 0 22 10 00 $MOCK_FPR"
[ -n "${MOCK_EXTRA:-}" ] && echo "[GNUPG:] $MOCK_EXTRA"
[ -n "${MOCK_VALID2:-}" ] && echo "[GNUPG:] VALIDSIG $MOCK_VALID2 2026-01-01 1 0 4 0 22 10 00 $MOCK_VALID2"
exit 0
MOCK
chmod +x "$t/mock/gpg"; export MOCK_FPR="$A"
mk "$t/mk" "$A"
mockcase() {  # name want extra valid2
  local rc; MOCK_EXTRA="$3" MOCK_VALID2="${4:-}" FS_VERIFY_GPG="$t/mock/gpg" "$v" --fingerprint "$A" "$t/mk" "$t/a.asc" >/dev/null 2>&1; rc=$?
  if { [ "$2" = 0 ] && [ $rc = 0 ]; } || { [ "$2" = 1 ] && [ $rc != 0 ]; }; then echo "PASS $1"; else echo "FAIL $1 (rc $rc)"; fail=1; fi
}
mockcase "canned GOODSIG+VALIDSIG alone = green (control)" 0 ""
for w in EXPKEYSIG EXPSIG REVKEYSIG BADSIG ERRSIG NO_PUBKEY; do mockcase "status $w alone = red" 1 "$w 0123456789ABCDEF"; done
# KEYEXPIRED / KEYREVOKED only say that gpg considered an expired or revoked (sub)key in the key file, e.g. an old rotated signing
# subkey; with GOODSIG + VALIDSIG of the right primary they must stay green, without GOODSIG (the signing key itself is bad) red.
for w in KEYEXPIRED KEYREVOKED; do
  mockcase "status $w next to a good signature (rotated old subkey) = green" 0 "$w 1794429991"
  MOCK_NOGOOD=1 mockcase "status $w WITHOUT GOODSIG = red" 1 "$w 1794429991"
done
mockcase "a second VALIDSIG with another primary = red" 1 "" "$B"
exit $fail
