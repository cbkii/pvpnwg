#!/usr/bin/env bats
# tests/unit/test_user_paths.bats — verify user detection and ownership

load ../test_helper.bats

SCRIPT="$BATS_TEST_DIRNAME/../../pvpnwg.sh"

setup() {
    require_root
    export PATH="$BATS_TEST_DIRNAME/../mock/bin:$PATH"
}

run_as() {
    local user="$1"
    shift
    if command -v sudo >/dev/null 2>&1; then
        sudo -n -u "$user" "$@"
    elif command -v su >/dev/null 2>&1; then
        su - "$user" -c "$(printf '%q ' "$@")"
    elif [[ "$(id -un)" == "$user" ]]; then
        "$@"
    else
        echo "missing sudo and su" >&2
        return 127
    fi
}

@test "SUDO_USER determines run user and ownership" {
    user="pvuser1"
    userdel -r "$user" 2>/dev/null || true
    useradd -m "$user"
    run env -i PATH="$PATH" SUDO_USER="$user" HOME="/root" bash "$SCRIPT" init
    [ "$status" -eq 0 ]
    conf="/home/$user/.pvpnwg/pvpnwg.conf"
    log="/home/$user/.pvpnwg/pvpn.log"
    [ -f "$conf" ]
    [ "$(stat -c '%U' "$conf")" = "$user" ]
    [ "$(stat -c '%U' "$log")" = "$user" ]
    userdel -r "$user"
}

@test "ignores inherited PHOME outside user home" {
    user="pvuser1b"
    userdel -r "$user" 2>/dev/null || true
    useradd -m "$user"
    run env -i PATH="$PATH" SUDO_USER="$user" HOME="/root" PHOME="/root/.pvpnwg" bash "$SCRIPT" init
    [ "$status" -eq 0 ]
    conf="/home/$user/.pvpnwg/pvpnwg.conf"
    [ -f "$conf" ]
    grep -Fq "PHOME=\"/home/$user/.pvpnwg\"" "$conf"
    grep -Fq "CONFIG_DIR=\"/home/$user/.pvpnwg/configs\"" "$conf"
    [ "$(stat -c '%U' "$conf")" = "$user" ]
    [ ! -e "/root/.pvpnwg/pvpnwg.conf" ]
    userdel -r "$user"
}

@test "config PHOME outside home is corrected" {
    user="pvuser1c"
    userdel -r "$user" 2>/dev/null || true
    useradd -m "$user"
    mkdir -p "/home/$user/.pvpnwg"
    cat >"/home/$user/.pvpnwg/pvpnwg.conf" <<EOF
PHOME="/root/.pvpnwg"
CONFIG_DIR="/root/.pvpnwg/configs"
EOF
    chown -R "$user:$user" "/home/$user/.pvpnwg"
    run env -i PATH="$PATH:/usr/sbin:/sbin" SUDO_USER="$user" HOME="/root" bash "$SCRIPT" init
    [ "$status" -eq 0 ]
    conf="/home/$user/.pvpnwg/pvpnwg.conf"
    grep -Fq "PHOME=\"/home/$user/.pvpnwg\"" "$conf"
    [ ! -e "/root/.pvpnwg/pvpnwg.conf" ]
    userdel -r "$user"
}

@test "--user overrides SUDO_USER" {
    usera="pvuser2a"
    userb="pvuser2b"
    userdel -r "$usera" 2>/dev/null || true
    userdel -r "$userb" 2>/dev/null || true
    useradd -m "$usera"
    useradd -m "$userb"
    run env -i PATH="$PATH" SUDO_USER="$usera" HOME="/root" bash "$SCRIPT" --user "$userb" init
    [ "$status" -eq 0 ]
    [ -d "/home/$userb/.pvpnwg" ]
    [ ! -e "/home/$usera/.pvpnwg/pvpnwg.conf" ]
    [ "$(stat -c '%U' "/home/$userb/.pvpnwg/pvpnwg.conf")" = "$userb" ]
    userdel -r "$usera"
    userdel -r "$userb"
}

@test "init run as non-root creates user-owned files" {
    if ! command -v sudo >/dev/null 2>&1 && ! command -v su >/dev/null 2>&1; then
        skip "requires sudo or su"
    fi
    user="pvuser3"
    userdel -r "$user" 2>/dev/null || true
    useradd -m "$user"
    run run_as "$user" bash "$SCRIPT" init
    [ "$status" -eq 0 ]
    conf="/home/$user/.pvpnwg/pvpnwg.conf"
    [ -f "$conf" ]
    [ "$(stat -c '%U' "$conf")" = "$user" ]
    userdel -r "$user"
}

@test "non-root run ignores SUDO_USER" {
    if ! command -v sudo >/dev/null 2>&1 && ! command -v su >/dev/null 2>&1; then
        skip "requires sudo or su"
    fi
    user="pvuser3b"
    userdel -r "$user" 2>/dev/null || true
    useradd -m "$user"
    run run_as "$user" bash -c "SUDO_USER=root '$SCRIPT' init"
    [ "$status" -eq 0 ]
    conf="/home/$user/.pvpnwg/pvpnwg.conf"
    [ -f "$conf" ]
    [ "$(stat -c '%U' "$conf")" = "$user" ]
    [ ! -e "/root/.pvpnwg/pvpnwg.conf" ]
    userdel -r "$user"
}

@test "--user rejects unknown user" {
    user="pvnoexist"
    userdel -r "$user" 2>/dev/null || true
    run env -i PATH="$PATH" HOME="/root" bash "$SCRIPT" --user "$user" init
    [ "$status" -ne 0 ]
    [[ "$output" == *"Unknown user"* ]]
}

@test "falls back to su when sudo missing" {
    user="pvuser4"
    userdel -r "$user" 2>/dev/null || true
    useradd -m "$user"

    nosudo="$(mktemp -d)"
    for cmd in bash su getent install cut id mkdir touch cat dirname chmod tee date sed; do
        ln -s "$(command -v "$cmd")" "$nosudo/$cmd"
    done

    run env -i PATH="$nosudo" SUDO_USER="$user" HOME="/root" bash "$SCRIPT" init
    [ "$status" -eq 0 ]
    conf="/home/$user/.pvpnwg/pvpnwg.conf"
    [ -f "$conf" ]
    [ "$(stat -c '%U' "$conf")" = "$user" ]

    userdel -r "$user"
    rm -rf "$nosudo"
}
