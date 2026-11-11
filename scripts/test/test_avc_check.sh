#!/usr/bin/env bash
# Unit test of the AVC check with RECORDED lines (no real alarm is raised). The recorded lines are the real alarms
# seen on 2026-11-11 when a bind mount lacked the :Z label (German and English wording).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
. "$here/avc_check.sh"
t=$(mktemp); trap 'rm -f "$t"' EXIT
export AVC_SAMPLE_FILE=$t
fail=0
printf '%s\n' "-- No entries --" > "$t"
avc_alarms "now" >/dev/null && echo "PASS clean journal is green" || { echo "FAIL clean journal"; fail=1; }
printf '%s\n' 'Nov 11 21:10:43 host setroubleshoot[1]: SELinux hindert zentinel daran, open Zugriff auf Datei zentinel.kdl zuzulassen. For complete SELinux messages run: sealert -l 0000' > "$t"
if avc_alarms "now" >/dev/null; then echo "FAIL german alarm not detected"; fail=1; else echo "PASS german alarm line makes it RED"; fi
printf '%s\n' 'Nov 11 21:10:43 host setroubleshoot[1]: SELinux is preventing kanidmd from create access on the sock_file kanidmd.sock.' > "$t"
if avc_alarms "now" >/dev/null; then echo "FAIL english alarm not detected"; fail=1; else echo "PASS english alarm line makes it RED"; fi
unset AVC_SAMPLE_FILE
exit $fail
