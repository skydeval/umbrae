#!/bin/sh
# The full CI run. Builds and tests everything; any failure fails the run.
#
# Run it on the build machine from the repo root, never on a workstation:
#   sh scripts/ci.sh
set -eu

cargo="${CARGO:-cargo}"

echo "== fmt"
"$cargo" fmt --all --check

echo "== clippy"
"$cargo" clippy --locked --all-targets -- -D warnings

echo "== tests"
"$cargo" test --locked

echo "ci: all steps passed"
