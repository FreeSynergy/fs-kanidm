#!/usr/bin/env bash
# Secret pattern scan (ADR 0054): no tokens, passwords, secrets, private keys or bearer strings in anything we commit, log or report.
#   scan_secrets.sh <file>...        scan files; exit 1 on any hit, 0 if clean
#   scan_secrets.sh --repo <dir>     scan every tracked or untracked-not-ignored file of a git repository
#   scan_secrets.sh --selftest       EVERY pattern must detect a prepared example (reported under its own name); a clean file must pass
# It prints file:line and the NAME of the pattern, never the matching text. Placeholders ${vault:...} are fine.
# CI additionally runs gitleaks (.github/workflows/secrets-scan.yml); this script is the offline, dependency-free check inside the test.
set -uo pipefail

declare -A PAT=(
  [private-key-block]='-----BEGIN [A-Z ]*PRIVATE KEY( BLOCK)?-----'
  [client-secret-quoted]='client_secret[a-z_]*[[:space:]]*[=:][[:space:]]*["'"'"'][^"'"'"'$]{8,}["'"'"']'
  [assignment-unquoted]='(client_secret|password|passwd|token|api_key|apikey|secret)[a-z_]*=[^"'"'"'$({[:space:]][^[:space:]]{7,}'
  [password-quoted]='(password|passwd|new_password)[a-z_]*[[:space:]]*[=:][[:space:]]*["'"'"'][^"'"'"'$\\(]{6,}["'"'"']'
  [token-quoted]='(token|api_key|apikey|secret)[a-z_]*[[:space:]]*[=:][[:space:]]*["'"'"'][A-Za-z0-9+/_=.-]{16,}["'"'"']'
  [bearer-string]='[Bb]earer[[:space:]]+[A-Za-z0-9._~+/-]{20,}'
  [jwt]='eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}'
  [github-token]='(ghp|gho|ghs|ghu|github_pat)_[A-Za-z0-9_]{20,}'
  [aws-access-key]='(AKIA|ASIA)[0-9A-Z]{16}'
  [aws-secret-key]='aws_secret_access_key[[:space:]]*[=:][[:space:]]*["'"'"']?[A-Za-z0-9/+=]{40}'
  [totp-uri]='otpauth://totp/[^ ]*secret=[A-Z2-7]{16,}'
)

scan_files() {
  local hits=0 f name line
  for f in "$@"; do
    [ -f "$f" ] || continue
    # The scanner holds the patterns and the (assembled) examples; it is covered by its own selftest and by gitleaks in CI.
    case "$f" in */scan_secrets.sh) continue ;; esac
    for name in "${!PAT[@]}"; do
      while IFS= read -r line; do
        [ -n "$line" ] && { echo "SECRET-PATTERN $name: $f:$line"; hits=1; }
      done < <(grep -n -I -E -i -e "${PAT[$name]}" "$f" 2>/dev/null | cut -d: -f1)
    done
  done
  return $hits
}

selftest() {
  local d name ok=0 out
  d=$(mktemp -d); trap 'rm -rf "$d"' RETURN
  # Example secrets are assembled at run time so this file itself stays clean.
  local w="correct""horse""battery""staple" a40; a40=$(printf 'A%.0s' $(seq 1 40))
  declare -A EX=(
    [private-key-block]="-----BEGIN ""PGP PRIVATE KEY BLOCK-----"
    [client-secret-quoted]="client_secret = \"$w\""
    [assignment-unquoted]="TOKEN=$w"
    [password-quoted]="password: \"$w\""
    [token-quoted]="api_key = \"$w$w\""
    [bearer-string]="Authorization: Bearer ${w}0123456789"
    [jwt]="eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4eHh4eHh4eCJ9.c2lnbmF0dXJl"
    [github-token]="ghp_${w}ABCDEFG"
    [aws-access-key]="ASIA""ABCDEFGHIJKLMNOP"
    [aws-secret-key]="aws_secret_access_key = $a40"
    [totp-uri]="otpauth://totp/x:y?secret=ABCDEFGHIJKLMNOP&issuer=x"
  )
  for name in "${!PAT[@]}"; do
    if [ -z "${EX[$name]:-}" ]; then echo "FAIL selftest: no example for pattern $name"; ok=1; continue; fi
    printf '%s\n' "${EX[$name]}" > "$d/x"
    out=$(scan_files "$d/x")
    if printf '%s' "$out" | grep -q "SECRET-PATTERN $name:"; then echo "PASS selftest: pattern $name detects its example"; else echo "FAIL selftest: pattern $name did not detect its example"; ok=1; fi
  done
  printf 'secret = "${vault:fs/x/y#file}"\npassword = "${vault:fs/x/z}"\nTOKEN=$(cat /run/x)\nclient_secret=${X}\n' > "$d/clean"
  if scan_files "$d/clean" >/dev/null; then echo "PASS selftest: placeholders and substitutions pass"; else echo "FAIL selftest: placeholders flagged"; ok=1; fi
  return $ok
}

case "${1:-}" in
  --selftest) selftest ;;
  --repo) shift; mapfile -t files < <(cd "$1" && git ls-files -co --exclude-standard | sed "s#^#$1/#"); scan_files "${files[@]}" ;;
  "") echo "usage: scan_secrets.sh <file>... | --repo <dir> | --selftest" >&2; exit 2 ;;
  *) scan_files "$@" ;;
esac
