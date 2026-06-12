#!/usr/bin/env bash
# test-run-on-target.sh — prove engine-based routing for run-on-target.sh using
# FUZZAH_DRYRUN (no command is actually executed).
#
#   jackalope engine -> route=local
#   afl / default    -> route=vm
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROT="$HERE/run-on-target.sh"
fail=0

check() {  # desc, expected, actual
  if [[ "$3" == "$2" ]]; then
    echo "ok   - $1"
  else
    echo "FAIL - $1"
    echo "       expected: $2"
    echo "       actual:   $3"
    fail=1
  fi
}

# 1. jackalope engine via env override -> local
out="$(FUZZAH_ENGINE_testtgt=jackalope FUZZAH_DRYRUN=1 bash "$ROT" testtgt 'echo hi')"
check "jackalope engine (env) routes local" "route=local engine=jackalope" "$out"

# 2. no engine override, no engine file -> default afl -> vm
out="$(FUZZAH_DRYRUN=1 bash "$ROT" __no_such_target__ 'echo hi')"
check "default engine routes vm" "route=vm engine=afl" "$out"

# 3. explicit afl override -> vm
out="$(FUZZAH_ENGINE_testtgt=afl FUZZAH_DRYRUN=1 bash "$ROT" testtgt 'echo hi')"
check "afl engine (env) routes vm" "route=vm engine=afl" "$out"

# 4. engine FILE resolution via a temp host-targets root -> local
tmproot="$(mktemp -d "${TMPDIR:-/tmp}/rot-test.XXXXXX")"
mkdir -p "$tmproot/imageio"
printf 'jackalope\n' > "$tmproot/imageio/engine"
out="$(FUZZAH_HOST_TARGETS_ROOT="$tmproot" FUZZAH_DRYRUN=1 bash "$ROT" imageio 'echo hi')"
check "engine file routes local" "route=local engine=jackalope" "$out"
rm -rf "$tmproot"

if [[ "$fail" == "0" ]]; then
  echo "ALL PASS"
else
  echo "FAILURES"
fi
exit "$fail"
