#!/usr/bin/env bash
set -euo pipefail

NATPMC_PATH=""
restore_natpmpc() {
  [[ -n "$NATPMC_PATH" && -f "${NATPMC_PATH}.real" ]] && mv "${NATPMC_PATH}.real" "$NATPMC_PATH"
}
trap restore_natpmpc EXIT

if command -v natpmpc >/dev/null 2>&1; then
  NATPMC_PATH=$(command -v natpmpc)
  mv "$NATPMC_PATH" "${NATPMC_PATH}.real"
fi

bats tests/unit

restore_natpmpc
trap - EXIT

if [ -d tests/integration ]; then
  sudo bats tests/integration
fi
