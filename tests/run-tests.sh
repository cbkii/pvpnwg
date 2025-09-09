#!/usr/bin/env bash
set -euo pipefail

NATPMC_PATH=""
RESTORE_CMD=""
restore_natpmpc() {
  if [[ -n "$RESTORE_CMD" ]]; then
    eval "$RESTORE_CMD"
  fi
}
trap restore_natpmpc EXIT

if command -v natpmpc >/dev/null 2>&1; then
  NATPMC_PATH=$(command -v natpmpc)
  if [ -w "$NATPMC_PATH" ]; then
    mv "$NATPMC_PATH" "${NATPMC_PATH}.real"
    RESTORE_CMD="mv \"${NATPMC_PATH}.real\" \"$NATPMC_PATH\""
  elif command -v sudo >/dev/null 2>&1 && sudo -n test -w "$NATPMC_PATH" 2>/dev/null; then
    sudo mv "$NATPMC_PATH" "${NATPMC_PATH}.real"
    RESTORE_CMD="sudo mv \"${NATPMC_PATH}.real\" \"$NATPMC_PATH\""
  else
    echo "Skipping natpmpc relocation: insufficient permissions for $NATPMC_PATH"
  fi
fi

bats tests/unit

restore_natpmpc
trap - EXIT

if [ -d tests/integration ]; then
  sudo bats tests/integration
fi
