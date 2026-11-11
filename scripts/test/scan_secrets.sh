#!/usr/bin/env bash
# Secret pattern scan (ADR 0054): no tokens, passwords, secrets, private keys or bearer strings in anything we commit, log or report.
#   scan_secrets.sh <file>...        scan files; exit 1 on any hit, 0 if clean
#   scan_secrets.sh --repo <dir>     scan every tracked or untracked-not-ignored file of a git repository
#   scan_secrets.sh --selftest       a prepared example secret MUST be detected, a clean file MUST pass
# It prints file:line and the name of the pattern, NEVER the matching text. Placeholders ${vault:...} are fine.
set -uo pipefail

declare -A PAT=(
  [private-key-block]='-----BEGIN [A-Z ]*PRIVATE KEY-----'
  [client-secret-literal]='client_secret[a-z_]*[[:space:]]*[=:][[:space:]]*["'"'"'][^"'"'"'$]{8,}["'"'"']'
  [password-literal]='(password|passwd|new_password)[a-z_]*[[:space:]]*[=:][[:space:]]*["'"'"'][^"'"'"'$\\(]{6,}["'"'"']'
  [token-literal]='(token|api_key|apikey|secret)[a-z_]*[[:space:]]*[=:][[:space:]]*["'"'"'][A-Za-z0-9+/_=.-]{16,}["'"'"']'
  [bearer-string]='[Bb]earer[[:space:]]+[A-Za-z0-9._~+/-]{20,}'
  [jwt]='eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}'
  [github-token]='(ghp|gho|ghs|ghu|github_pat)_[A-Za-z0-9_]{20,}'
  [aws-key]='AKIA[0-9A-Z]{16}'
  [totp-uri]='otpauth://totp/[^ ]*secret=[A-Z2-7]{16,}'
)

scan_files() {
  local hits=0 f name line
  for f in "$@"; do
    [ -f "$f" ] || continue
    for name in "${!PAT[@]}"; do
      while IFS= read -r line; do
        [ -n "$line" ] && { echo "SECRET-PATTERN $name: $f:$line"; hits=1; }
      done < <(grep -n -I -E -i -e "${PAT[$name]}" "$f" 2>/dev/null | cut -d: -f1)
    done
  done
  return $hits
}

selftest() {
  local d; d=$(mktemp -d); trap 'rm -rf "$d"' RETURN
  # The example secrets are assembled here at run time so this file itself stays clean.
  local pw="correct""horse""battery9"
  printf 'client_secret = "%s"\n' "$pw$pw" > "$d/a.toml"
  printf 'password: "%s"\n' "$pw" > "$d/b.txt"
  printf -- '-----BEGIN %s KEY-----\n' "EC PRIVATE" > "$d/c.pem"
  printf 'Authorization: Bearer %s\n' "abcdefghijklmnopqrstuvwxyz0123456789" > "$d/d.log"
  printf 'secret = "${vault:fs/x/y#file}"\npassword = "${vault:fs/x/z}"\n' > "$d/clean.toml"
  local ok=0 f
  for f in a.toml b.txt c.pem d.log; do
    if scan_files "$d/$f" >/dev/null; then echo "FAIL selftest: example in $f not detected"; ok=1; else echo "PASS selftest: example in $f detected"; fi
  done
  if scan_files "$d/clean.toml" >/dev/null; then echo "PASS selftest: placeholders pass"; else echo "FAIL selftest: placeholders flagged"; ok=1; fi
  return $ok
}

case "${1:-}" in
  --selftest) selftest ;;
  --repo) shift; mapfile -t files < <(cd "$1" && git ls-files -co --exclude-standard | sed "s#^#$1/#"); scan_files "${files[@]}" ;;
  "") echo "usage: scan_secrets.sh <file>... | --repo <dir> | --selftest" >&2; exit 2 ;;
  *) scan_files "$@" ;;
esac
