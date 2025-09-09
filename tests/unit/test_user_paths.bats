#!/usr/bin/env bats
# tests/unit/test_user_paths.bats — verify user detection and ownership

SCRIPT="$BATS_TEST_DIRNAME/../../pvpnwg.sh"

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
    user="pvuser3"
    userdel -r "$user" 2>/dev/null || true
    useradd -m "$user"
    run sudo -u "$user" bash "$SCRIPT" init
    [ "$status" -eq 0 ]
    conf="/home/$user/.pvpnwg/pvpnwg.conf"
    [ -f "$conf" ]
    [ "$(stat -c '%U' "$conf")" = "$user" ]
    userdel -r "$user"
}

@test "--user rejects unknown user" {
    user="pvnoexist"
    userdel -r "$user" 2>/dev/null || true
    run env -i PATH="$PATH" HOME="/root" bash "$SCRIPT" --user "$user" init
    [ "$status" -ne 0 ]
    [[ "$output" == *"Unknown user"* ]]
}
