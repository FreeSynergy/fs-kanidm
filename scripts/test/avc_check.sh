#!/usr/bin/env bash
# SELinux must stay Enforcing and the stack must run without denials (our rpm packages must work under Enforcing).
# avc_alarms <since>   prints setroubleshoot alarms since <since> ("YYYY-MM-DD HH:MM:SS") and returns
#   0 = none, 1 = at least one alarm (test is RED), 2 = the journal could not be read (test is RED: no silent pass).
# No root needed: `journalctl -b -t setroubleshoot` is readable by the user. For the unit test, AVC_SAMPLE_FILE replaces the journal.
avc_alarms() {
  local since=$1 out
  if [ -n "${AVC_SAMPLE_FILE:-}" ]; then
    out=$(cat "$AVC_SAMPLE_FILE")
  else
    out=$(journalctl -b -t setroubleshoot --since "$since" --no-pager 2>&1) || { echo "AVC check unavailable: journalctl failed"; return 2; }
  fi
  local hits
  hits=$(printf '%s\n' "$out" | grep -E 'SELinux hindert|SELinux is preventing' || true)
  [ -z "$hits" ] && return 0
  printf '%s\n' "$hits" | cut -c1-240
  return 1
}
