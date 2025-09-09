#!/usr/bin/env bash
set -euo pipefail

NATPMC_PATH=""
restore_natpmpc() {
  [[ -n "$NATPMC_PATH" && -f "${NATPMC_PATH}.real" ]] && mv "${NATPMC_PATH}.real" "$NATPMC_PATH"
}
trap restore_natpmpc EXIT

if command -v natpmpc >/dev/null 2>&1; then
  NATPMC_PATH=$(command -v natpmpc)
  if [ -w "$NATPMC_PATH" ]; then
    mv "$NATPMC_PATH" "${NATPMC_PATH}.real"
  else
    echo "Skipping natpmpc relocation: insufficient permissions for $NATPMC_PATH"
    NATPMC_PATH=""
  fi
fi

bats tests/unit

restore_natpmpc
trap - EXIT

if [ -d tests/integration ]; then
  sudo bats tests/integration
fi
