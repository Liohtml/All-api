#!/usr/bin/env bash
# Runs the README demo commands for real and records their output and timing as JSON, for render.mjs.
# Usage: docs/media/src/capture.sh <commands.txt> <out.json>   (needs the release binary, jq and Chrome; state goes to a temp home)
set -euo pipefail
cd "$(dirname "$0")/../../.."
cmdfile="${1:?commands.txt}"
out="${2:?out.json}"
export PATH="$PWD/rust/target/release:$PATH"
export API_ANYTHING_HOME="$(mktemp -d)"
export JQ_COLORS="1;30:0;39:0;39:0;39:0;32:1;39:1;39:34;1"
# one command per line
mapfile -t cmds < "$cmdfile"
exec > "$out"
echo '['
first=1
for c in "${cmds[@]}"; do
  start=$(date +%s%3N)
  output=$(bash -c "$c" 2>&1 || true)
  ms=$(( $(date +%s%3N) - start ))
  [ $first = 1 ] || echo ','
  first=0
  jq -n --arg cmd "$c" --arg out "$output" --argjson ms "$ms" '{cmd: $cmd, out: $out, ms: $ms}'
done
echo ']'
