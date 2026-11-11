#!/usr/bin/env bash
# SELinux must stay Enforcing and the stack must run without denials (our rpm packages must work under Enforcing).
#   avc_prepare          writes a random marker line into the journal (logger -t fs-test-marker); sets AVC_MARKER
#   avc_alarms <since>   ("YYYY-MM-DD HH:MM:SS") first proves the journal is readable by finding the marker again, then prints
#                        setroubleshoot alarms since <since>. Return: 0 = none, 1 = alarm (RED), 2 = journal not readable (RED).
# No root needed. NOTE: the marker is written by the user and lands in the user's own journal (journald SplitMode=uid), so finding it
# only proves that journalctl runs; whether the SYSTEM journal (where setroubleshoot writes) is readable is proven by the hint-text
# check below ("not seeing messages ...", tested in test_avc_check.sh), not by the marker. A journal that cannot be read must never look like "no alarms": journalctl then prints a hint and exits 0,
# so the marker round trip and the hint text are checked explicitly.
# For the unit test (test_avc_check.sh) AVC_JOURNAL replaces the journalctl command.
avc_journal() { "${AVC_JOURNAL:-journalctl}" "$@"; }

avc_prepare() {
  AVC_MARKER="fs-test-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
  logger -t fs-test-marker "$AVC_MARKER" 2>/dev/null || true
}

avc_alarms() {
  local since=$1 out hits found=1
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if avc_journal -t fs-test-marker --since "$since" --no-pager -o cat 2>/dev/null | grep -q -F "${AVC_MARKER:-no-marker}"; then found=0; break; fi
    sleep 1
  done
  [ "$found" = 0 ] || { echo "AVC check impossible: my own marker line is not readable from the journal"; return 2; }
  out=$(avc_journal -b -t setroubleshoot --since "$since" --no-pager 2>&1) || { echo "AVC check impossible: journalctl failed"; return 2; }
  if printf '%s\n' "$out" | grep -q -E 'not seeing messages|No journal files|Permission denied'; then
    echo "AVC check impossible: the journal hides the setroubleshoot messages (not enough rights)"; return 2
  fi
  hits=$(printf '%s\n' "$out" | grep -E 'SELinux hindert|SELinux is preventing' || true)
  [ -z "$hits" ] && return 0
  printf '%s\n' "$hits" | cut -c1-240
  return 1
}
