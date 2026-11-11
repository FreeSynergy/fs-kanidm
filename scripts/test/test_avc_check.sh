#!/usr/bin/env bash
# Unit test of the AVC check with a MOCK journalctl (no real alarm is raised, no container). The alarm texts are the real ones seen
# on 2026-11-11 when a bind mount lacked its SELinux label (German and English wording).
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
. "$here/avc_check.sh"
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
cat > "$d/journalctl" <<'MOCK'
#!/usr/bin/env bash
# MOCK_MODE: clean | de | en | hint | nomarker | fail
args="$*"
if [[ $args == *fs-test-marker* ]]; then
  [ "$MOCK_MODE" = nomarker ] && exit 0
  echo "$MOCK_MARKER"; exit 0
fi
case $MOCK_MODE in
  clean|nomarker) echo "-- No entries --" ;;
  de) echo 'Nov 11 21:10:43 host setroubleshoot[1]: SELinux hindert zentinel daran, open Zugriff auf Datei zentinel.kdl zuzulassen.' ;;
  en) echo 'Nov 11 21:10:43 host setroubleshoot[1]: SELinux is preventing kanidmd from create access on the sock_file kanidmd.sock.' ;;
  hint) echo "Hint: You are currently not seeing messages from other users and the system."; echo "-- No entries --" ;;
  fail) echo "boom" >&2; exit 1 ;;
esac
MOCK
chmod +x "$d/journalctl"; export AVC_JOURNAL="$d/journalctl" MOCK_MARKER="fs-test-0123456789abcdef" AVC_MARKER="fs-test-0123456789abcdef"
fail=0
expect() {  # name mode wanted-return
  MOCK_MODE=$2 avc_alarms "now" >/dev/null; local rc=$?
  if [ "$rc" = "$3" ]; then echo "PASS $1 (return $rc)"; else echo "FAIL $1: return $rc, wanted $3"; fail=1; fi
}
sleep() { :; }   # the marker poll must not slow the unit test
expect "clean journal is green" clean 0
expect "german alarm line is RED" de 1
expect "english alarm line is RED" en 1
expect "unreadable journal (hint) is RED, never silently green" hint 2
expect "own marker not found is RED" nomarker 2
expect "journalctl failure is RED" fail 2
exit $fail
