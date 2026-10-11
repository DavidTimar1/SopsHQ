#!/usr/bin/env bash
#
# uninstall.sh - remove a SopsHQ system install from this Linux machine.
#
#   sudo ./uninstall.sh              ask about every decision, then remove
#   sudo ./uninstall.sh --dry-run    ask the same questions, print every command, change nothing
#
# Why a script and not a `sopshq` subcommand: it must work on a machine that has the
# installed binary but not the source, and it must still work when the binary is broken.
# Why it asks: the data base and the keybase root hold the only copy of the vault and
# of plaintext private keys, so no answer is ever assumed. Every decision is asked up
# front, nothing is changed until the last confirmation, and the questions repeat until
# one of the listed answers is typed.
#
# It finds the install from the systemd unit, /etc/sopshq/location and the config file.
# It never prints the config, never needs the vault key and never reads or prints the
# contents of a key file (it lists key files by path only).
#
# Test switches (used only by scripts/test_uninstall.sh; both act on a marked scratch
# tree and can never act on /):
#   SOPSHQ_UNINSTALL_TEST_ROOT     absolute path of a directory holding the marker file
#                                  .sopshq-uninstall-test-root; every system path is
#                                  resolved inside it and the root-user check is skipped
#   SOPSHQ_UNINSTALL_TEST_NO_TTY   with the switch above, skip the terminal check
#   SOPSHQ_UNINSTALL_TEST_TS       with the switch above, use this timestamp in the names of
#                                  moved folders and backup files
# The switches are refused when the effective user is root: a root run must never be
# steered by its environment, and the accounts, groups and services it would act on are
# the real ones whatever the fake tree says.
set -euo pipefail

SERVICE_NAME="sopshq"
UNIT_PATH="/etc/systemd/system/sopshq.service"
POINTER_PATH="/etc/sopshq/location"
LINK_PATH="/usr/local/bin/sopshq"
SUDOERS_PATH="/etc/sudoers.d/sopshq-permmap"
TEST_MARKER=".sopshq-uninstall-test-root"

DRY_RUN=0
FAILURES=0
TS="$(date -u +%Y%m%dT%H%M%SZ)"

usage() {
    cat <<'EOF'
Usage: sudo ./uninstall.sh [--dry-run]

Removes a SopsHQ system install (service, binary, data, keys, accounts), asking about
every decision. --dry-run asks the same questions and prints every command it would run,
but changes nothing.
EOF
}

die() {
    printf 'uninstall.sh: %s\n' "$*" >&2
    exit 1
}

note() { printf '  note: %s\n' "$*"; }

for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            exit 2
            ;;
    esac
done

# --- guards: who may run this, and on what -----------------------------------------

FAKE_ROOT="${SOPSHQ_UNINSTALL_TEST_ROOT:-}"
if [ -n "$FAKE_ROOT" ]; then
    case "$FAKE_ROOT" in
        /*) ;;
        *) die "SOPSHQ_UNINSTALL_TEST_ROOT must be an absolute path" ;;
    esac
    case "$FAKE_ROOT" in
        / | */ | *..*) die "SOPSHQ_UNINSTALL_TEST_ROOT must be a normalised path other than /" ;;
    esac
    [ -d "$FAKE_ROOT" ] || die "SOPSHQ_UNINSTALL_TEST_ROOT is not a directory"
    [ -f "$FAKE_ROOT/$TEST_MARKER" ] || die "SOPSHQ_UNINSTALL_TEST_ROOT lacks the $TEST_MARKER marker file"
    if [ "$(id -u)" -eq 0 ]; then
        die "SOPSHQ_UNINSTALL_TEST_ROOT is refused when run as root: it only exists for the test harness"
    fi
    TS="${SOPSHQ_UNINSTALL_TEST_TS:-$TS}"
else
    # Run as root, so find every program at a fixed system location, never through a
    # PATH that sudo may have left holding a folder another user can write to.
    PATH="/usr/sbin:/usr/bin:/sbin:/bin"
    export PATH
    if [ "$(id -u)" -ne 0 ]; then
        die "must be run as root. Re-run with: sudo ./uninstall.sh (add --dry-run to preview)"
    fi
fi

if [ -n "$FAKE_ROOT" ] && [ "${SOPSHQ_UNINSTALL_TEST_NO_TTY:-}" = "1" ]; then
    :
elif [ ! -t 0 ] || [ ! -t 1 ]; then
    die "needs a terminal to ask its questions on; run it in an interactive shell (no pipes, no redirects)"
fi

# real maps a path as the system sees it (the "logical" path used in every message and
# every comparison) to the path this process touches. Outside the test it is the identity.
real() { printf '%s%s' "$FAKE_ROOT" "$1"; }

# --- asking ------------------------------------------------------------------------

trim() {
    local s="$1"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

# ask_choice VAR "question" option... : repeats until exactly one option is typed.
# There is no default: end of input is an error, never an answer.
ask_choice() {
    local __var="$1" prompt="$2"
    shift 2
    local __ans __opt __joined
    __joined="$(
        IFS=/
        printf '%s' "$*"
    )"
    while :; do
        printf '%s [%s]: ' "$prompt" "$__joined"
        IFS= read -r __ans || die "input ended before an answer was given; nothing was changed by this question"
        __ans="$(trim "$__ans")"
        for __opt in "$@"; do
            if [ "$__ans" = "$__opt" ]; then
                printf -v "$__var" '%s' "$__ans"
                return 0
            fi
        done
        printf 'Please type exactly one of: %s\n' "$__joined"
    done
}

# ask_text VAR "question" : repeats until a non-empty line is typed.
ask_text() {
    local __var="$1" prompt="$2" __ans
    while :; do
        printf '%s: ' "$prompt"
        IFS= read -r __ans || die "input ended before an answer was given; nothing was changed by this question"
        __ans="$(trim "$__ans")"
        if [ -n "$__ans" ]; then
            printf -v "$__var" '%s' "$__ans"
            return 0
        fi
        printf 'An answer is required.\n'
    done
}

# --- running and recording ---------------------------------------------------------

# run prints the command, then executes it unless this is a dry run.
run() {
    printf '  + '
    printf '%q ' "$@"
    printf '\n'
    if [ "$DRY_RUN" -eq 1 ]; then
        return 0
    fi
    "$@"
}

# soft runs a command whose failure is reported at the end instead of stopping the run.
# SOFT_OK is 1 when the command succeeded, so a caller records a change only after it
# really happened.
SOFT_OK=1
soft() {
    SOFT_OK=1
    if ! run "$@"; then
        SOFT_OK=0
        FAILURES=$((FAILURES + 1))
        printf '  FAILED: '
        printf '%q ' "$@"
        printf '\n'
    fi
}

# --- progress, so a run that stops half way can say how far it got --------------------

STEP_ORDER=(stop-service remove-unit remove-symlink remove-pointer folder-prefix folder-data
    folder-keybase parent-acls scan-leftovers shell-profiles accounts)
declare -A STEP_DONE=()
CHANGES_STARTED=0
COMPLETE=0

# run_step NAME function args... : runs one step of the removal and records that it ended.
run_step() {
    local name="$1"
    shift
    [ "$DRY_RUN" -eq 1 ] || CHANGES_STARTED=1
    "$@"
    STEP_DONE[$name]=1
}

# on_exit prints, after the first change, which steps ended and which did not whenever
# the run stops before the closing check, so a half-removed machine is never silent.
on_exit() {
    local rc=$? s
    if [ "$CHANGES_STARTED" -eq 1 ] && [ "$COMPLETE" -eq 0 ]; then
        printf '\n==============================================================================\n' >&2
        printf ' STOPPED PART-WAY (exit status %s): this machine is partly uninstalled.\n' "$rc" >&2
        for s in "${STEP_ORDER[@]}"; do
            if [ -n "${STEP_DONE[$s]:-}" ]; then
                printf '  done     : %s\n' "$s" >&2
            else
                printf '  not done : %s\n' "$s" >&2
            fi
        done
        printf ' Fix the cause and run uninstall.sh again; it skips what is already gone.\n' >&2
        printf '==============================================================================\n' >&2
    fi
}
trap on_exit EXIT

# --- paths and safety --------------------------------------------------------------

normalise() {
    local p="$1"
    while [ "${#p}" -gt 1 ] && [ "${p%/}" != "$p" ]; do
        p="${p%/}"
    done
    printf '%s' "$p"
}

is_mount() {
    local p
    p="$(real "$1")"
    if command -v findmnt >/dev/null 2>&1; then
        findmnt --mountpoint "$p" >/dev/null 2>&1
        return
    fi
    if command -v mountpoint >/dev/null 2>&1; then
        mountpoint -q -- "$p"
        return
    fi
    die "neither findmnt nor mountpoint is available, so mount points cannot be checked"
}

PREFIX="" DATA="" KEYBASE="" BIN="" SVC_USER="" SCAN_USER=""

found_for_role() {
    case "$1" in
        prefix) printf '%s' "$PREFIX" ;;
        data) printf '%s' "$DATA" ;;
        keybase) printf '%s' "$KEYBASE" ;;
        *) printf '' ;;
    esac
}

# path_hard_reason PATH prints why PATH can never be moved or deleted by this script, or
# nothing. It looks at the path alone: its shape, a deny-list of system and home folders,
# and a symbolic link anywhere above it. The config is written by the service account, so
# a path taken from it is never trusted to be a SopsHQ folder.
path_hard_reason() {
    local p="$1" slashes base parent_real expected
    if [ -z "$p" ]; then
        printf 'the path is empty'
        return 0
    fi
    case "$p" in
        /*) ;;
        *)
            printf 'the path is not absolute'
            return 0
            ;;
    esac
    if ! [[ "$p" =~ ^[A-Za-z0-9._/-]+$ ]]; then
        printf 'the path has characters this script will not handle; remove it by hand'
        return 0
    fi
    case "$p" in
        / | */ | */. | */.. | */./* | */../* | *//*)
            printf 'the path is not normalised or is the root'
            return 0
            ;;
    esac
    slashes="${p//[^\/]/}"
    if [ "${#slashes}" -lt 2 ]; then
        printf 'the path is a top-level folder'
        return 0
    fi
    case "$p" in
        /home/* | /root/*)
            printf 'the path is inside a home folder, which a SopsHQ install never uses'
            return 0
            ;;
        /usr/local | /usr/local/bin | /usr/local/sbin | /usr/local/lib | /usr/local/share | /usr/bin | /usr/sbin | /usr/lib | /usr/lib64 | /usr/share | /usr/include | /usr/src)
            printf 'the path is a system program folder'
            return 0
            ;;
        /etc/systemd | /etc/systemd/system | /etc/sudoers.d | /etc/sopshq | /var/lib | /var/log | /var/tmp | /var/cache | /var/spool | /var/run | /var/mail | /run/user)
            printf 'the path is a system folder'
            return 0
            ;;
        /mnt/* | /media/*)
            slashes="${p//[^\/]/}"
            if [ "${#slashes}" -lt 3 ]; then
                printf 'the path is the top of a mounted volume'
                return 0
            fi
            ;;
        /etc | /etc/* | /srv | /var | /boot)
            printf 'the path is a system folder'
            return 0
            ;;
        /proc/* | /sys/* | /dev/* | /boot/* | /bin/* | /sbin/* | /lib/* | /lib32/* | /lib64/*)
            printf 'the path is a system folder'
            return 0
            ;;
    esac
    # The folder above it must be what it appears to be, so a symbolic link in the path
    # cannot send a move or a delete somewhere else.
    base="$(realpath -m -- "${FAKE_ROOT:-/}")"
    [ "$base" = "/" ] && base=""
    parent_real="$(realpath -m -- "$(real "$(dirname -- "$p")")")"
    expected="$base$(dirname -- "$p")"
    if [ "$parent_real" != "$expected" ]; then
        printf 'a folder above the path is a symbolic link'
        return 0
    fi
    return 0
}

# unsafe_reason ROLE PATH prints why PATH must not be moved or deleted now, or nothing
# when it may be: it passes path_hard_reason, is exactly the path found for ROLE, is a
# real directory (not a symlink) and is not a mount point.
unsafe_reason() {
    local role="$1" p="$2" real_p reason
    reason="$(path_hard_reason "$p")"
    if [ -n "$reason" ]; then
        printf '%s' "$reason"
        return 0
    fi
    if [ "$p" != "$(found_for_role "$role")" ]; then
        printf 'the path is not the one found for this install'
        return 0
    fi
    real_p="$(real "$p")"
    if [ -L "$real_p" ]; then
        printf 'the path is a symbolic link'
        return 0
    fi
    if [ ! -d "$real_p" ]; then
        printf 'the path is not a directory'
        return 0
    fi
    if is_mount "$p"; then
        printf 'the path is a mount point (unmount or empty it by hand)'
        return 0
    fi
    return 0
}

# accept_folder ROLE PATH stops the run, before anything is changed, when PATH is a
# path this script must never act on.
accept_folder() {
    local role="$1" p="$2" reason
    [ -n "$p" ] || return 0
    reason="$(path_hard_reason "$p")"
    [ -z "$reason" ] || die "the $role folder $p cannot be handled by this script: $reason. Nothing was changed; remove it by hand."
    return 0
}

# corroborate_folders stops the run, before anything is changed, unless the folders found
# are the ones `sopshq setup` makes. The config is written by the service account, so a
# path from it is not trusted on its own: the data base and the keybase root, when they
# exist, must be owned by the service account (setup creates them with that owner), and
# the install prefix must hold the binary the unit's ExecStart names. A folder that fails
# is some other folder (for example /srv/x or /etc/ssh) and is never moved or deleted.
corroborate_folders() {
    local role p svc_uid owner
    if [ -n "$PREFIX" ] && [ -e "$(real "$PREFIX")" ]; then
        if [ -z "$BIN" ] || [ "$(dirname -- "$BIN")" != "$PREFIX" ] || [ -L "$(real "$BIN")" ] || [ ! -f "$(real "$BIN")" ]; then
            die "the install prefix $PREFIX does not hold the sopshq binary (${BIN:-none}) as a regular file, so it is not shown to be a SopsHQ install. Nothing was changed; remove it by hand."
        fi
    fi
    for role in data keybase; do
        p="$(found_for_role "$role")"
        [ -n "$p" ] || continue
        [ -e "$(real "$p")" ] || [ -L "$(real "$p")" ] || continue
        if [ -z "$SVC_USER" ] || ! account_exists "$SVC_USER"; then
            die "the $role folder $p exists but the service account is not known or not found, so it cannot be shown to be a SopsHQ folder. Nothing was changed; remove it by hand."
        fi
        svc_uid="$(account_uid "$SVC_USER")"
        owner="$(stat -c '%u' -- "$(real "$p")")" || die "cannot read the owner of $p. Nothing was changed."
        if [ "$owner" != "$svc_uid" ]; then
            die "the $role folder $p is not owned by the service account $SVC_USER, so it is not shown to be a SopsHQ folder. Nothing was changed; remove it by hand."
        fi
    done
    return 0
}

# check_volume ROLE PATH stops the run, before anything is changed, when PATH is missing
# because the volume that holds it is not mounted (or unlocked). Otherwise it would read
# as "already gone" and end with the accounts removed over files nobody can reach.
check_volume() {
    local role="$1" p="$2" a mp
    [ -n "$p" ] || return 0
    if [ -e "$(real "$p")" ] || [ -L "$(real "$p")" ]; then
        return 0
    fi
    a="$(dirname -- "$p")"
    while [ "$a" != "/" ] && [ "$a" != "." ]; do
        if [ -r "$(real /etc/fstab)" ]; then
            while IFS= read -r mp; do
                if [ "$mp" = "$a" ] && ! is_mount "$a"; then
                    die "the $role folder $p is missing and $a is a volume from /etc/fstab that is not mounted. Mount (or unlock) it, then run this again. Nothing was changed."
                fi
            done < <(awk '$1 !~ /^#/ && NF >= 2 { print $2 }' "$(real /etc/fstab)")
        fi
        a="$(dirname -- "$a")"
    done
    for mp in "${UNIT_NAMED[@]+"${UNIT_NAMED[@]}"}"; do
        if [ "$mp" = "$p" ]; then
            die "the $role folder $p is named by the systemd unit but does not exist. If it lives on an encrypted or removable volume, unlock or mount it and run this again; if it was removed on purpose, delete the unit by hand first. Nothing was changed."
        fi
    done
    return 0
}

# --- discovery ---------------------------------------------------------------------

unit_field() {
    local f
    f="$(real "$UNIT_PATH")"
    [ -f "$f" ] || return 0
    awk -v k="$1" 'BEGIN { FS = "=" } $1 == k { sub(/^[^=]*=/, ""); print; exit }' "$f"
}

# config_field KEY prints the string value of KEY from the config, one line only.
# The config is never printed as a whole: it carries sealed material.
config_field() {
    local f
    f="$(real "$CONFIG_PATH")"
    [ -r "$f" ] || return 0
    sed -n "s/^[[:space:]]*\"$1\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" "$f" | awk 'NR == 1 { print; exit }'
}

# pick_path OUT "label" candidate... : one distinct candidate is used; none or several
# make it ask. "none" is an answer.
pick_path() {
    local __out="$1" label="$2"
    shift 2
    local -a uniq=()
    local c u seen typed
    for c in "$@"; do
        [ -n "$c" ] || continue
        c="$(normalise "$c")"
        seen=0
        for u in "${uniq[@]+"${uniq[@]}"}"; do
            [ "$u" = "$c" ] && seen=1
        done
        [ "$seen" -eq 1 ] || uniq+=("$c")
    done
    if [ "${#uniq[@]}" -eq 1 ]; then
        printf -v "$__out" '%s' "${uniq[0]}"
        return 0
    fi
    if [ "${#uniq[@]}" -eq 0 ]; then
        printf 'Could not find the %s.\n' "$label"
    else
        printf 'The sources disagree about the %s:\n' "$label"
        for u in "${uniq[@]}"; do
            printf '    %s\n' "$u"
        done
    fi
    while :; do
        ask_text typed "Type the absolute path of the $label, or none if there is none"
        if [ "$typed" = "none" ]; then
            printf -v "$__out" '%s' ""
            return 0
        fi
        case "$typed" in
            /*)
                printf -v "$__out" '%s' "$(normalise "$typed")"
                return 0
                ;;
            *) printf 'The path must be absolute (start with /).\n' ;;
        esac
    done
}

valid_account_name() { [[ "$1" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; }

account_exists() { getent passwd "$1" >/dev/null 2>&1; }
group_exists() { getent group "$1" >/dev/null 2>&1; }
account_uid() { getent passwd "$1" | awk -F: 'NR == 1 { print $3 }'; }

# validate_account NAME "label" stops the run, before anything is changed, unless NAME is
# absent or is a system account of the kind `sopshq setup` creates (a uid below the
# regular-user range, a nologin or false shell, and no home folder under /home or /root).
# The names come from the unit and from the config, which the service account can write,
# so a name is never trusted to be SopsHQ's.
validate_account() {
    local name="$1" label="$2" line uid shell home uid_min
    [ -n "$name" ] || return 0
    if [ "$name" = "root" ]; then
        die "the $label is root; this script never removes root. Nothing was changed."
    fi
    account_exists "$name" || return 0
    line="$(getent passwd "$name")"
    IFS=: read -r _ _ uid _ _ home shell <<<"$line"
    uid_min="$(awk '$1 == "UID_MIN" { print $2; exit }' "$(real /etc/login.defs)" 2>/dev/null || true)"
    case "$uid_min" in
        '' | *[!0-9]*) uid_min=1000 ;;
    esac
    case "$uid" in
        '' | *[!0-9]*) die "the $label '$name' has no numeric user id; remove it by hand. Nothing was changed." ;;
    esac
    if [ "$uid" -eq 0 ]; then
        die "the $label '$name' has user id 0; this script never removes root. Nothing was changed."
    fi
    if [ "$uid" -ge "$uid_min" ]; then
        die "the $label '$name' (user id $uid) is a regular user account, not a system account like the one sopshq setup creates. Nothing was changed; remove it by hand if it is really SopsHQ's."
    fi
    case "${shell##*/}" in
        nologin | false) ;;
        *) die "the $label '$name' has the login shell '$shell', not a nologin shell. Nothing was changed; remove it by hand if it is really SopsHQ's." ;;
    esac
    case "$home" in
        /home/* | /root | /root/*)
            if [ -d "$(real "$home")" ]; then
                die "the $label '$name' has the home folder $home, so it is not a SopsHQ system account. Nothing was changed."
            fi
            ;;
    esac
    return 0
}

CONFIG_PATH=""
CONFIG_READABLE=0
POINTER_DATA=""
HAVE_SYSTEMCTL=0
SCAN_SUDOERS_PRESENT=0
declare -a BASHRC_FILES=() BASHRC_KINDS=() BASHRC_HAND=() ANCESTOR_ACL_DIRS=() KEY_FILES=() MOVED=() UNIT_NAMED=()
declare -A DECISION=() CLEAN=() CHOWNED=() MOVED_TO=() BASHRC_RESULT=()
DECIDE_SCAN="keep"
DECIDE_ACL="no"
declare -a DECIDE_BASHRC=()

discover() {
    local exec_line rw_line cfg_cand="" data_cand_unit="" bin_cand="" w i
    local -a words=() rw=()
    local keybase_cfg="" kb_cands=()

    command -v systemctl >/dev/null 2>&1 && HAVE_SYSTEMCTL=1

    local unit_user
    unit_user="$(unit_field User)"
    exec_line="$(unit_field ExecStart)"
    rw_line="$(unit_field ReadWritePaths)"

    if [ -n "$exec_line" ]; then
        read -r -a words <<<"$exec_line"
        bin_cand="${words[0]:-}"
        for ((i = 1; i < ${#words[@]}; i++)); do
            w="${words[i]}"
            case "$w" in
                -config | --config) cfg_cand="${words[i + 1]:-}" ;;
                -config=* | --config=*) cfg_cand="${w#*=}" ;;
            esac
        done
    fi
    if [ -n "$rw_line" ]; then
        read -r -a rw <<<"$rw_line"
    fi
    [ -n "$cfg_cand" ] && data_cand_unit="$(dirname -- "$cfg_cand")"
    [ -n "$data_cand_unit" ] && UNIT_NAMED+=("$(normalise "$data_cand_unit")")
    for w in "${rw[@]+"${rw[@]}"}"; do
        UNIT_NAMED+=("$(normalise "$w")")
    done

    if [ -r "$(real "$POINTER_PATH")" ]; then
        POINTER_DATA="$(awk 'NR == 1 { print; exit }' "$(real "$POINTER_PATH")")"
        POINTER_DATA="$(trim "$POINTER_DATA")"
    fi

    # Service account.
    if [ -n "$unit_user" ]; then
        SVC_USER="$unit_user"
    else
        printf 'Could not find the service account name (no systemd unit).\n'
        ask_text SVC_USER "Type the service account name, or none if there is none"
        [ "$SVC_USER" = "none" ] && SVC_USER=""
    fi
    if [ -n "$SVC_USER" ] && ! valid_account_name "$SVC_USER"; then
        die "the service account name '$SVC_USER' is not a plain account name; remove it by hand"
    fi
    validate_account "$SVC_USER" "service account"

    # Install prefix and binary.
    if [ -n "$bin_cand" ]; then
        BIN="$(normalise "$bin_cand")"
        PREFIX="$(dirname -- "$BIN")"
    else
        pick_path PREFIX "install prefix (the folder holding the sopshq binary)"
        [ -n "$PREFIX" ] && BIN="$PREFIX/sopshq"
    fi
    accept_folder prefix "$PREFIX"

    # Data base.
    pick_path DATA "data base folder" "$data_cand_unit" "${rw[0]:-}" "$POINTER_DATA"
    accept_folder data "$DATA"
    check_volume data "$DATA"
    if [ -n "$DATA" ]; then
        CONFIG_PATH="$DATA/config.jsonc"
        if [ -n "$cfg_cand" ] && [ "$(dirname -- "$cfg_cand")" = "$DATA" ]; then
            CONFIG_PATH="$cfg_cand"
        fi
        [ -r "$(real "$CONFIG_PATH")" ] && CONFIG_READABLE=1
    fi

    # Keybase root: the config value, or any other writable path the unit lists.
    if [ "$CONFIG_READABLE" -eq 1 ]; then
        keybase_cfg="$(config_field keybase_root)"
    fi
    local e
    for e in "${rw[@]+"${rw[@]}"}"; do
        [ "$(normalise "$e")" = "$DATA" ] || kb_cands+=("$e")
    done
    if [ "${#kb_cands[@]}" -gt 0 ]; then
        # The unit is written by root; the config is written by the service account. When
        # they differ the unit wins, because a hostile config must not aim a delete.
        if [ -n "$keybase_cfg" ] && [ "$(normalise "$keybase_cfg")" != "$(normalise "${kb_cands[0]}")" ]; then
            note "the config names the keybase root $keybase_cfg; the systemd unit's ${kb_cands[0]} is used instead"
        fi
        pick_path KEYBASE "keybase root folder" "${kb_cands[@]}"
    elif [ "$CONFIG_READABLE" -eq 1 ] && [ -z "$keybase_cfg" ]; then
        # The config was read and names no keybase root, and the unit lists none.
        KEYBASE=""
    else
        pick_path KEYBASE "keybase root folder" "$keybase_cfg"
    fi
    accept_folder keybase "$KEYBASE"
    check_volume keybase "$KEYBASE"

    corroborate_folders

    # Permission-scan account.
    local scan_cfg=""
    [ "$CONFIG_READABLE" -eq 1 ] && scan_cfg="$(config_field scan_user)"
    if [ -n "$scan_cfg" ]; then
        SCAN_USER="$scan_cfg"
    else
        printf 'Could not find a permission-scan account name in the config.\n'
        ask_text SCAN_USER "Type the permission-scan account name, or none if the scan was never set up"
        [ "$SCAN_USER" = "none" ] && SCAN_USER=""
    fi
    if [ -n "$SCAN_USER" ] && ! valid_account_name "$SCAN_USER"; then
        die "the scan account name '$SCAN_USER' is not a plain account name; remove it by hand"
    fi
    if [ -n "$SCAN_USER" ] && [ "$SCAN_USER" = "$SVC_USER" ]; then
        die "the scan account and the service account are the same name ($SCAN_USER)"
    fi
    validate_account "$SCAN_USER" "permission-scan account"
    [ -f "$(real "$SUDOERS_PATH")" ] && SCAN_SUDOERS_PRESENT=1

    # No two found folders may be, or sit inside, one another: moving the outer one
    # would carry the inner one along.
    local a b ra rb
    for ra in prefix data keybase; do
        for rb in prefix data keybase; do
            [ "$ra" = "$rb" ] && continue
            a="$(found_for_role "$ra")"
            b="$(found_for_role "$rb")"
            [ -n "$a" ] && [ -n "$b" ] || continue
            if [ "$a" = "$b" ] || [ "${b#"$a"/}" != "$b" ]; then
                die "the $rb folder ($b) is the same as or inside the $ra folder ($a); remove them by hand"
            fi
        done
    done
    return 0
}

home_dirs() {
    local d
    if [ -d "$(real /root)" ]; then
        printf '%s\n' /root
    fi
    for d in "$(real /home)"/*; do
        [ -d "$d" ] || continue
        printf '%s\n' "${d#"$FAKE_ROOT"}"
    done
}

MARKER_RE='^[[:space:]]*# sopshq:sops-age[[:space:]]*$'
SHIM_BEGIN_RE='^[[:space:]]*# >>> sopshq usage shim >>>[[:space:]]*$'
SHIM_END_RE='^[[:space:]]*# <<< sopshq usage shim <<<[[:space:]]*$'

# bashrc_owner_safe FILE succeeds when FILE can be edited without a user steering root:
# the file belongs to the owner of its folder, and a file owned by root sits in a folder
# no one else can write to. The edit itself then runs as that owner.
bashrc_owner_safe() {
    local rf dir fo downer dm
    rf="$(real "$1")"
    dir="$(dirname -- "$rf")"
    fo="$(stat -c '%u' -- "$rf")" || return 1
    downer="$(stat -c '%u' -- "$dir")" || return 1
    dm="$(stat -c '%a' -- "$dir")" || return 1
    [ "$fo" = "$downer" ] || return 1
    if [ "$fo" = "0" ] && [ $((8#$dm & 8#022)) -ne 0 ]; then
        return 1
    fi
    return 0
}

scan_bashrc() {
    local h f kinds hand rc
    while IFS= read -r h; do
        f="$h/.bashrc"
        if [ -L "$(real "$f")" ]; then
            note "$f is a symbolic link; it is not touched"
            continue
        fi
        [ -f "$(real "$f")" ] || continue
        if ! bashrc_owner_safe "$f"; then
            note "$f is owned by someone other than its folder's owner (or a root file in a writable folder); it is not touched"
            continue
        fi
        kinds=""
        hand=0
        if grep -Eq "$MARKER_RE" "$(real "$f")"; then
            kinds="sops-age marker"
        fi
        if grep -Eq "$SHIM_BEGIN_RE|$SHIM_END_RE" "$(real "$f")"; then
            rc=0
            awk "$OWNER_EDIT_AWK" "$(real "$f")" >/dev/null || rc=$?
            if [ "$rc" -eq 0 ]; then
                kinds="${kinds:+$kinds + }usage shim block"
            else
                kinds="${kinds:+$kinds + }usage shim lines that do not pair up (needs a hand edit; this script leaves the file unchanged)"
                hand=1
            fi
        fi
        if [ -n "$kinds" ]; then
            BASHRC_FILES+=("$f")
            BASHRC_KINDS+=("$kinds")
            BASHRC_HAND+=("$hand")
        fi
    done < <(home_dirs)
}

# Parent folders of the data base and keybase root whose ACL names the service account
# (the path-permission review adds such entries). Found now, while the name resolves.
scan_ancestor_acls() {
    local p d seen x
    [ -n "$SVC_USER" ] || return 0
    command -v getfacl >/dev/null 2>&1 || return 0
    for p in "$DATA" "$KEYBASE"; do
        [ -n "$p" ] || continue
        d="$(dirname -- "$p")"
        while [ "$d" != "/" ] && [ "$d" != "." ]; do
            seen=0
            for x in "${ANCESTOR_ACL_DIRS[@]+"${ANCESTOR_ACL_DIRS[@]}"}"; do
                [ "$x" = "$d" ] && seen=1
            done
            if [ "$seen" -eq 0 ] && [ -d "$(real "$d")" ] &&
                getfacl -p -- "$(real "$d")" 2>/dev/null | grep -q "^user:$SVC_USER:"; then
                ANCESTOR_ACL_DIRS+=("$d")
            fi
            d="$(dirname -- "$d")"
        done
    done
}

list_key_files() {
    local f
    KEY_FILES=()
    [ -n "$KEYBASE" ] && [ -d "$(real "$KEYBASE")" ] || return 0
    while IFS= read -r f; do
        KEY_FILES+=("${f#"$FAKE_ROOT"}")
    done < <(find "$(real "$KEYBASE")" -type f -name keys.txt -print | sort)
}

# --- the plan ----------------------------------------------------------------------

state_of() { # state_of PATH : found / not found
    if [ -e "$(real "$1")" ] || [ -L "$(real "$1")" ]; then printf 'found'; else printf 'not found'; fi
}

print_plan() {
    local i
    printf '\n==============================================================================\n'
    printf ' SopsHQ uninstall plan%s\n' "$([ "$DRY_RUN" -eq 1 ] && printf ' (DRY RUN: nothing will be changed)')"
    printf '==============================================================================\n'
    printf '  systemd unit    : %s (%s)\n' "$UNIT_PATH" "$(state_of "$UNIT_PATH")"
    printf '  PATH symlink    : %s (%s)\n' "$LINK_PATH" "$(state_of "$LINK_PATH")"
    printf '  machine pointer : %s (%s)\n' "$POINTER_PATH" "$(state_of "$POINTER_PATH")"
    if [ -n "$SVC_USER" ]; then
        printf '  service account : %s (%s)\n' "$SVC_USER" "$(account_exists "$SVC_USER" && printf 'exists' || printf 'not found')"
    else
        printf '  service account : (none)\n'
    fi
    if [ -n "$PREFIX" ]; then
        printf '  install prefix  : %s (%s) - the binary and update backups; no keys, no vault\n' "$PREFIX" "$(state_of "$PREFIX")"
    else
        printf '  install prefix  : (none)\n'
    fi
    if [ -n "$DATA" ]; then
        printf '  data base       : %s (%s) - HOLDS THE VAULT, THE CONFIG AND THE SEALED PRIVATE KEYS\n' "$DATA" "$(state_of "$DATA")"
    else
        printf '  data base       : (none)\n'
    fi
    if [ -n "$KEYBASE" ]; then
        printf '  keybase root    : %s (%s) - HOLDS PLAINTEXT PRIVATE KEY FILES (keys.txt)\n' "$KEYBASE" "$(state_of "$KEYBASE")"
    else
        printf '  keybase root    : (none)\n'
    fi
    if [ -n "$SCAN_USER" ]; then
        printf '  scan account    : %s (%s)\n' "$SCAN_USER" "$(account_exists "$SCAN_USER" && printf 'exists' || printf 'not found')"
    else
        printf '  scan account    : (none)\n'
    fi
    printf '  scan sudoers    : %s (%s)\n' "$SUDOERS_PATH" "$(state_of "$SUDOERS_PATH")"
    if [ "${#BASHRC_FILES[@]}" -eq 0 ]; then
        printf '  shell profiles  : none carry a SopsHQ block\n'
    else
        for ((i = 0; i < ${#BASHRC_FILES[@]}; i++)); do
            printf '  shell profile   : %s (%s)\n' "${BASHRC_FILES[i]}" "${BASHRC_KINDS[i]}"
        done
    fi
    for i in "${ANCESTOR_ACL_DIRS[@]+"${ANCESTOR_ACL_DIRS[@]}"}"; do
        printf '  parent folder   : %s has an ACL entry for %s\n' "$i" "$SVC_USER"
    done
    printf '\n  The accounts and the group of the same name are removed last, and an account is\n'
    printf '  not removed while a folder you keep (or move without making it root-only) still\n'
    printf '  holds files it owns: a later account could be given the same numeric id.\n'
}

# holds_files_of NAME PHASE prints the folders that will still hold files owned by the
# account NAME once the folder decisions are carried out. PHASE "plan" judges the
# decisions; PHASE "apply" judges what really happened (a moved folder counts only when it
# was not made root-only, or the chown did not take).
holds_files_of() {
    local name="$1" phase="$2" uid role p where
    account_exists "$name" || return 0
    uid="$(account_uid "$name")"
    [ -n "$uid" ] || return 0
    for role in prefix data keybase; do
        p="$(found_for_role "$role")"
        [ -n "$p" ] || continue
        where=""
        case "${DECISION[$role]:-absent}" in
            keep) where="$p" ;;
            move)
                if [ "$phase" = "plan" ]; then
                    [ "${CLEAN[$role]:-no}" = "yes" ] || where="$p"
                else
                    [ "${CHOWNED[$role]:-0}" = "1" ] || where="${MOVED_TO[$role]:-$p}"
                fi
                ;;
        esac
        [ -n "$where" ] || continue
        # A dry run moves nothing, so judge the folder where it still is.
        [ -e "$(real "$where")" ] || where="$p"
        [ -d "$(real "$where")" ] || continue
        if [ -n "$(find "$(real "$where")" -xdev -uid "$uid" -print -quit 2>/dev/null)" ]; then
            printf '%s\n' "$where"
        fi
    done
}

# --- decisions ---------------------------------------------------------------------

decide_folder() { # decide_folder ROLE "label" PATH
    local role="$1" label="$2" p="$3" ans typed reason
    if [ -z "$p" ]; then
        DECISION[$role]="absent"
        return 0
    fi
    if [ ! -e "$(real "$p")" ] && [ ! -L "$(real "$p")" ]; then
        printf '\n%s %s does not exist; nothing to do.\n' "$label" "$p"
        DECISION[$role]="absent"
        return 0
    fi
    if [ "$role" = "keybase" ]; then
        list_key_files
        printf '\nKey files under %s (paths only, contents are never read):\n' "$p"
        if [ "${#KEY_FILES[@]}" -eq 0 ]; then
            printf '    (no keys.txt found)\n'
        else
            for ans in "${KEY_FILES[@]}"; do
                printf '    %s\n' "$ans"
            done
        fi
    fi
    reason="$(unsafe_reason "$role" "$p")"
    if [ -n "$reason" ]; then
        printf '\n%s %s cannot be moved or deleted by this script: %s. It is kept.\n' "$label" "$p" "$reason"
        DECISION[$role]="keep"
        return 0
    fi
    while :; do
        printf '\n%s: %s\n' "$label" "$p"
        ask_choice ans "Move it aside, delete it, or keep it?" move delete keep
        case "$ans" in
            delete)
                printf 'Deleting %s cannot be undone.\n' "$p"
                ask_text typed "Type the full path to confirm the delete"
                if [ "$typed" != "$p" ]; then
                    printf 'That is not the path. Nothing was decided; asking again.\n'
                    continue
                fi
                DECISION[$role]="delete"
                return 0
                ;;
            move)
                DECISION[$role]="move"
                ask_choice ans "Make the moved folder root-only (chown -R root:root and setfacl -R -b)?" yes no
                CLEAN[$role]="$ans"
                return 0
                ;;
            keep)
                DECISION[$role]="keep"
                return 0
                ;;
        esac
    done
}

decide_all() {
    local ans i f
    printf '\nBefore you go on: any other tool that starts or unlocks SopsHQ (for example a\n'
    printf 'hook that runs when an encrypted volume is opened) must be turned off first, or\n'
    printf 'it can start the service again or fail against a half-removed install.\n\n'
    ask_choice ans "Continue with the uninstall?" continue quit
    [ "$ans" = "continue" ] || {
        printf 'Stopped. Nothing was changed.\n'
        exit 0
    }

    decide_folder prefix "Install prefix" "$PREFIX"
    decide_folder data "Data base" "$DATA"
    decide_folder keybase "Keybase root" "$KEYBASE"

    DECIDE_ACL="no"
    if [ "${#ANCESTOR_ACL_DIRS[@]}" -gt 0 ]; then
        printf '\nThese parent folders carry an ACL entry for %s:\n' "$SVC_USER"
        for f in "${ANCESTOR_ACL_DIRS[@]}"; do
            printf '    %s\n' "$f"
        done
        ask_choice DECIDE_ACL "Remove those entries (setfacl -x u:$SVC_USER) while the account still exists?" yes no
    fi

    DECIDE_SCAN="keep"
    local scan_present=0
    if [ -n "$SCAN_USER" ] && account_exists "$SCAN_USER"; then scan_present=1; fi
    if [ "$scan_present" -eq 1 ] || [ "$SCAN_SUDOERS_PRESENT" -eq 1 ]; then
        printf '\nThe permission-scan feature left: '
        [ "$scan_present" -eq 1 ] && printf 'account %s  ' "$SCAN_USER"
        [ "$SCAN_SUDOERS_PRESENT" -eq 1 ] && printf '%s' "$SUDOERS_PATH"
        printf '\n'
        ask_choice DECIDE_SCAN "Remove them?" remove keep
    fi

    DECIDE_BASHRC=()
    for ((i = 0; i < ${#BASHRC_FILES[@]}; i++)); do
        printf '\n%s carries: %s\n' "${BASHRC_FILES[i]}" "${BASHRC_KINDS[i]}"
        if [ "${BASHRC_HAND[i]}" = "1" ]; then
            printf 'It cannot be edited safely by this script, so it is not offered; edit it by hand.\n'
            DECIDE_BASHRC+=("hand")
            continue
        fi
        ask_choice ans "Remove the SopsHQ block(s), keeping a backup copy beside the file, or leave it?" remove leave
        DECIDE_BASHRC+=("$ans")
    done

    # An account whose files stay behind is kept, never orphaned.
    local held who
    for who in "$SCAN_USER" "$SVC_USER"; do
        [ -n "$who" ] || continue
        [ "$who" != "$SCAN_USER" ] || [ "$DECIDE_SCAN" = "remove" ] || continue
        held="$(holds_files_of "$who" plan | tr '\n' ' ')"
        if [ -n "$held" ]; then
            printf '\nThe account %s will NOT be removed: it still owns files in %s\n' "$who" "$held"
            printf 'after your choices. Answer yes to "root-only" for a moved folder, or remove it by hand.\n'
        fi
    done

    printf '\n------------------------------------------------------------------------------\n'
    printf ' Your decisions\n'
    printf '%s\n' '------------------------------------------------------------------------------'
    printf '  install prefix : %s\n' "${DECISION[prefix]:-absent}${CLEAN[prefix]:+ (root-only: ${CLEAN[prefix]})}"
    printf '  data base      : %s\n' "${DECISION[data]:-absent}${CLEAN[data]:+ (root-only: ${CLEAN[data]})}"
    printf '  keybase root   : %s\n' "${DECISION[keybase]:-absent}${CLEAN[keybase]:+ (root-only: ${CLEAN[keybase]})}"
    printf '  scan leftovers : %s\n' "$DECIDE_SCAN"
    printf '  parent ACLs    : %s\n' "$DECIDE_ACL"
    for ((i = 0; i < ${#BASHRC_FILES[@]}; i++)); do
        printf '  %s : %s\n' "${BASHRC_FILES[i]}" "${DECIDE_BASHRC[i]}"
    done
    printf '  always         : stop and disable the service, remove the unit, the PATH symlink\n'
    printf '                   (if it points at the binary), the pointer, and the accounts last\n\n'
    ask_choice ans "Make these changes now?" proceed quit
    [ "$ans" = "proceed" ] || {
        printf 'Stopped. Nothing was changed.\n'
        exit 0
    }
}

# --- doing it ----------------------------------------------------------------------

# preflight re-checks every folder and every precondition that can fail, after the last
# answer and before the first change, so a failure never leaves a half-removed machine.
preflight() {
    local role p reason dest d
    for role in prefix data keybase; do
        p="$(found_for_role "$role")"
        case "${DECISION[$role]:-absent}" in
            move | delete) ;;
            *) continue ;;
        esac
        reason="$(unsafe_reason "$role" "$p")"
        [ -z "$reason" ] || die "refusing to touch $p: $reason. Nothing was changed."
        if [ "${DECISION[$role]}" = "move" ]; then
            dest="$p.removed-$TS"
            if [ -e "$(real "$dest")" ] || [ -L "$(real "$dest")" ]; then
                die "$dest already exists; move or remove it first. Nothing was changed."
            fi
        fi
    done
    for d in "${DECIDE_BASHRC[@]+"${DECIDE_BASHRC[@]}"}"; do
        if [ "$d" = "remove" ] && ! command -v setpriv >/dev/null 2>&1; then
            die "setpriv (util-linux) is needed to edit shell profiles as their owner and was not found. Nothing was changed."
        fi
    done
}

step_stop_service() {
    printf '\n-> stopping the service\n'
    if [ "$HAVE_SYSTEMCTL" -eq 0 ]; then
        note "systemctl not found; the service is assumed not to be managed by systemd"
    else
        # A unit that is already gone (an earlier run got that far) has nothing to stop;
        # stopping a unit that does not exist is an error, not a reason to give up.
        if [ -f "$(real "$UNIT_PATH")" ] || systemctl is-active --quiet "$SERVICE_NAME"; then
            run systemctl stop "$SERVICE_NAME" || die "could not stop the service; nothing was removed"
            run systemctl disable "$SERVICE_NAME" || note "systemctl disable reported an error (the unit may not exist)"
        else
            note "no unit and no running service; nothing to stop"
        fi
        if [ "$DRY_RUN" -eq 0 ] && systemctl is-active --quiet "$SERVICE_NAME"; then
            die "the service is still active after stop; it is disabled, but nothing else was removed"
        fi
    fi
    if [ -n "$SVC_USER" ] && account_exists "$SVC_USER" && command -v pgrep >/dev/null 2>&1; then
        if pgrep -u "$SVC_USER" >/dev/null 2>&1; then
            printf '  processes still running as %s:\n' "$SVC_USER"
            pgrep -l -u "$SVC_USER" || true
            if [ "$DRY_RUN" -eq 0 ]; then
                die "stop those processes first (for example: sudo -u $SVC_USER $BIN stop); the service is stopped, but nothing else was removed"
            fi
        fi
    fi
}

step_remove_unit() {
    printf '\n-> removing the systemd unit\n'
    if [ -f "$(real "$UNIT_PATH")" ]; then
        # reset-failed runs while the unit is still loaded: after the file is gone and
        # systemd reloaded, it fails with "Unit ... not loaded".
        if [ "$HAVE_SYSTEMCTL" -eq 1 ]; then
            run systemctl reset-failed "$SERVICE_NAME" || true
        fi
        run rm -f -- "$(real "$UNIT_PATH")"
        if [ "$HAVE_SYSTEMCTL" -eq 1 ]; then
            run systemctl daemon-reload
        fi
    else
        note "no unit at $UNIT_PATH"
    fi
}

step_symlink() {
    printf '\n-> removing the PATH symlink\n'
    local l target
    l="$(real "$LINK_PATH")"
    if [ ! -L "$l" ]; then
        if [ -e "$l" ]; then note "$LINK_PATH is not a symbolic link; it is left alone"; else note "no $LINK_PATH"; fi
        return 0
    fi
    target="$(readlink -- "$l")"
    if [ -n "$BIN" ] && [ "$target" = "$BIN" ]; then
        run rm -f -- "$l"
    else
        note "$LINK_PATH points at $target, not at the installed binary; it is left alone"
    fi
}

step_pointer() {
    printf '\n-> removing the machine pointer\n'
    local dir
    dir="$(dirname -- "$POINTER_PATH")"
    if [ -f "$(real "$POINTER_PATH")" ]; then
        run rm -f -- "$(real "$POINTER_PATH")"
    else
        note "no $POINTER_PATH"
    fi
    if [ -d "$(real "$dir")" ]; then
        if ! run rmdir -- "$(real "$dir")"; then
            note "$dir is not empty; it is left alone"
        fi
    fi
}

apply_folder() { # apply_folder ROLE PATH
    local role="$1" p="$2" dest reason
    case "${DECISION[$role]:-absent}" in
        absent | keep) return 0 ;;
    esac
    reason="$(unsafe_reason "$role" "$p")"
    [ -z "$reason" ] || die "refusing to touch $p: $reason"
    case "${DECISION[$role]}" in
        delete)
            printf '\n-> deleting %s\n' "$p"
            soft rm -r --one-file-system -- "$(real "$p")"
            ;;
        move)
            dest="$p.removed-$TS"
            printf '\n-> moving %s to %s\n' "$p" "$dest"
            if [ -e "$(real "$dest")" ] || [ -L "$(real "$dest")" ]; then
                die "$dest already exists; this folder was not moved"
            fi
            soft mv -- "$(real "$p")" "$(real "$dest")"
            if [ "$SOFT_OK" -eq 0 ]; then
                return 0
            fi
            MOVED+=("$p -> $dest")
            MOVED_TO[$role]="$dest"
            if [ "${CLEAN[$role]:-no}" = "yes" ]; then
                make_root_only "$role" "$dest"
            fi
            ;;
    esac
}

# make_root_only ROLE DEST hands a moved folder to root and strips its ACLs. It does
# nothing to a tree that holds a file with more than one hard link: chown would also
# change the owner of the other name for that file, which may live outside the tree.
make_root_only() {
    local role="$1" dest="$2" linked ok=1
    linked="$(find "$(real "$dest")" -type f -links +1 -print -quit 2>/dev/null || true)"
    if [ -n "$linked" ]; then
        FAILURES=$((FAILURES + 1))
        printf '  FAILED: %s holds a file with several hard links, so its owner was not changed;\n' "$dest"
        printf '          change the owner by hand after checking where the other names are.\n'
        return 0
    fi
    soft chown -R -h root:root -- "$(real "$dest")"
    [ "$SOFT_OK" -eq 1 ] || ok=0
    if command -v setfacl >/dev/null 2>&1; then
        soft setfacl -R -b -- "$(real "$dest")"
        [ "$SOFT_OK" -eq 1 ] || ok=0
    else
        note "setfacl is not installed, so the ACL entries were not stripped"
    fi
    [ "$ok" -eq 1 ] && CHOWNED[$role]=1
    return 0
}

step_ancestor_acls() {
    local d
    [ "$DECIDE_ACL" = "yes" ] || return 0
    printf '\n-> removing parent folder ACL entries for %s\n' "$SVC_USER"
    for d in "${ANCESTOR_ACL_DIRS[@]}"; do
        soft setfacl -x "u:$SVC_USER" -- "$(real "$d")"
    done
}

step_scan() {
    [ "$DECIDE_SCAN" = "remove" ] || return 0
    printf '\n-> removing the permission-scan leftovers\n'
    if [ -f "$(real "$SUDOERS_PATH")" ]; then
        soft rm -f -- "$(real "$SUDOERS_PATH")"
    fi
}

ACCOUNT_NOTES=()

remove_account() { # remove_account NAME
    local name="$1" uid held members gid other
    if ! account_exists "$name"; then
        note "no account $name; a group of that name, if any, is left alone"
        return 0
    fi
    uid="$(account_uid "$name")"
    if [ "$uid" = "0" ] || [ "$name" = "root" ]; then
        die "refusing to remove $name (uid 0)"
    fi
    held="$(holds_files_of "$name" apply | tr '\n' ' ')"
    if [ -n "$held" ]; then
        printf '  NOT removed: account %s still owns files in %s\n' "$name" "$held"
        printf '  (removing it would let a later account reuse its numeric id and read them)\n'
        ACCOUNT_NOTES+=("account $name was kept: it still owns files in $held")
        return 0
    fi
    soft userdel "$name"
    [ "$SOFT_OK" -eq 1 ] || return 0
    group_exists "$name" || return 0
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '  (dry run) the group %s is removed too if userdel leaves it behind and nobody else uses it\n' "$name"
        return 0
    fi
    members="$(getent group "$name" | awk -F: 'NR == 1 { print $4 }')"
    gid="$(getent group "$name" | awk -F: 'NR == 1 { print $3 }')"
    other="$(getent passwd | awk -F: -v g="$gid" '$4 == g { print $1; exit }' || true)"
    if [ -n "$members" ] || [ -n "$other" ]; then
        note "the group $name is kept: it still has members or is another account's main group"
        return 0
    fi
    soft groupdel "$name"
}

step_accounts() {
    printf '\n-> removing the accounts (last)\n'
    if [ "$DECIDE_SCAN" = "remove" ] && [ -n "$SCAN_USER" ]; then
        remove_account "$SCAN_USER"
    fi
    if [ -n "$SVC_USER" ]; then
        remove_account "$SVC_USER"
    fi
}

# The edit of a shell profile runs as the profile's owner, never as root: the folder and
# the file belong to a user who could swap either for a symbolic link while the questions
# were being answered, and root writing through such a link would overwrite any file.
# Run as the owner, the worst a link can do is touch what that user could touch anyway.
# The script is given its paths as arguments and never builds a command from them.
read -r -d '' OWNER_EDIT_SCRIPT <<'EOF' || true
set -eu
f=$1
bak=$2
prog=$3
if [ -L "$f" ] || [ ! -f "$f" ]; then
    echo "not a regular file" >&2
    exit 3
fi
if [ -e "$bak" ] || [ -L "$bak" ]; then
    echo "backup name already exists" >&2
    exit 4
fi
tmp=$(mktemp "$f.sopshq-tmp-XXXXXX")
trap 'rm -f -- "$tmp"' EXIT
awk "$prog" "$f" >"$tmp" || {
    echo "shim lines do not pair up" >&2
    exit 5
}
cp -p -- "$f" "$bak"
chmod "$(stat -c %a "$f")" "$tmp"
mv -- "$tmp" "$f"
trap - EXIT
if grep -Eq "$4" "$f" || grep -Eq "$5" "$f" || grep -Eq "$6" "$f"; then
    exit 7
fi
EOF

# Drops every shim block (a begin line, then its end line), every marker line, the
# SOPS_AGE_KEY_FILE export under a marker and the lines a trailing backslash joins to it.
# It drops nothing else. When a begin line has no end line before the next begin line or
# the end of the file, or an end line has no begin line, it prints nothing and exits 9:
# the profile is then left exactly as it is and needs a hand edit.
read -r -d '' OWNER_EDIT_AWK <<'EOF' || true
function trimmed(s) { gsub(/^[ \t]+/, "", s); gsub(/[ \t\r]+$/, "", s); return s }
{ L[NR] = $0 }
END {
    open = 0; bad = 0
    for (i = 1; i <= NR; i++) {
        t = trimmed(L[i])
        if (t == "# >>> sopshq usage shim >>>") {
            if (open) bad = 1
            else open = i
        } else if (t == "# <<< sopshq usage shim <<<") {
            if (!open) bad = 1
            else {
                for (j = open; j <= i; j++) drop[j] = 1
                open = 0
            }
        }
    }
    if (open || bad) exit 9
    for (i = 1; i <= NR; i++) {
        t = trimmed(L[i])
        if (t == "# sopshq:sops-age") {
            drop[i] = 1
            if (i < NR && index(trimmed(L[i + 1]), "export SOPS_AGE_KEY_FILE=") == 1) {
                k = i + 1
                drop[k] = 1
                while (k < NR && trimmed(L[k]) ~ /\\$/) { k++; drop[k] = 1 }
            }
        }
    }
    for (i = 1; i <= NR; i++) if (!drop[i]) print L[i]
}
EOF

edit_bashrc() { # edit_bashrc FILE INDEX
    local f="$1" idx="$2" rf bak uid gid rc=0
    rf="$(real "$f")"
    bak="$f.sopshq-backup-$TS"
    printf '\n-> removing the SopsHQ block(s) from %s\n' "$f"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '  + (as the owner of %s) copy it to %s, then rewrite it without the marker line, its export line and the usage shim block\n' "$f" "$bak"
        BASHRC_RESULT[$idx]="dry"
        return 0
    fi
    if [ -L "$rf" ] || ! bashrc_owner_safe "$f"; then
        FAILURES=$((FAILURES + 1))
        BASHRC_RESULT[$idx]="failed"
        printf '  FAILED: %s is now a symbolic link or has an unexpected owner; it was not touched\n' "$f"
        return 0
    fi
    read -r uid gid < <(stat -c '%u %g' -- "$rf")
    printf '  + as user id %s: copy %s to %s and rewrite it in place of a temporary file\n' "$uid" "$f" "$bak"
    setpriv --reuid="$uid" --regid="$gid" --clear-groups -- /bin/sh -c "$OWNER_EDIT_SCRIPT" sopshq-edit \
        "$rf" "$rf.sopshq-backup-$TS" "$OWNER_EDIT_AWK" "$MARKER_RE" "$SHIM_BEGIN_RE" "$SHIM_END_RE" || rc=$?
    case "$rc" in
        0)
            BASHRC_RESULT[$idx]="gone"
            printf '  edited; backup: %s\n' "$bak"
            ;;
        4)
            FAILURES=$((FAILURES + 1))
            BASHRC_RESULT[$idx]="failed"
            printf '  FAILED: %s already exists, so %s was left untouched\n' "$bak" "$f"
            ;;
        5)
            FAILURES=$((FAILURES + 1))
            BASHRC_RESULT[$idx]="failed"
            printf '  FAILED: %s has usage shim begin and end lines that do not pair up; it was left unchanged and needs a hand edit\n' "$f"
            ;;
        7)
            FAILURES=$((FAILURES + 1))
            BASHRC_RESULT[$idx]="failed"
            printf '  FAILED: %s was rewritten but SopsHQ lines remain; backup: %s\n' "$f" "$bak"
            ;;
        *)
            FAILURES=$((FAILURES + 1))
            BASHRC_RESULT[$idx]="failed"
            printf '  FAILED to rewrite %s (exit %s); backup, if made: %s\n' "$f" "$rc" "$bak"
            ;;
    esac
}

step_bashrc() {
    local i
    for ((i = 0; i < ${#BASHRC_FILES[@]}; i++)); do
        if [ "${DECIDE_BASHRC[i]}" = "hand" ]; then
            printf '\n-> %s needs a hand edit and was left unchanged\n' "${BASHRC_FILES[i]}"
            BASHRC_RESULT[$i]="failed"
            [ "$DRY_RUN" -eq 1 ] || FAILURES=$((FAILURES + 1))
        elif [ "${DECIDE_BASHRC[i]}" = "remove" ]; then
            edit_bashrc "${BASHRC_FILES[i]}" "$i"
        fi
    done
    return 0
}

# --- the closing check -------------------------------------------------------------

leftover() { # leftover "label" PATH
    if [ -e "$(real "$2")" ] || [ -L "$(real "$2")" ]; then
        printf '  still present : %s (%s)\n' "$2" "$1"
    else
        printf '  gone          : %s (%s)\n' "$2" "$1"
    fi
}

leftover_account() {
    if account_exists "$1"; then
        printf '  still present : account %s\n' "$1"
    else
        printf '  gone          : account %s\n' "$1"
    fi
    if group_exists "$1"; then
        printf '  still present : group %s\n' "$1"
    else
        printf '  gone          : group %s\n' "$1"
    fi
}

final_check() {
    local m role p i h
    printf '\n==============================================================================\n'
    printf ' Check: what is left on this machine\n'
    printf '==============================================================================\n'
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '  DRY RUN: nothing was changed, so everything below is still as it was.\n'
    fi
    leftover "systemd unit" "$UNIT_PATH"
    leftover "PATH symlink" "$LINK_PATH"
    leftover "machine pointer" "$POINTER_PATH"
    leftover "scan sudoers file" "$SUDOERS_PATH"
    [ -n "$SVC_USER" ] && leftover_account "$SVC_USER"
    [ -n "$SCAN_USER" ] && leftover_account "$SCAN_USER"
    for role in prefix data keybase; do
        p="$(found_for_role "$role")"
        [ -n "$p" ] || continue
        case "${DECISION[$role]:-absent}" in
            keep) printf '  kept          : %s (%s, as you chose or because it could not be touched)\n' "$p" "$role" ;;
            *) leftover "$role folder" "$p" ;;
        esac
    done
    for m in "${MOVED[@]+"${MOVED[@]}"}"; do
        printf '  moved aside   : %s\n' "$m"
    done
    for i in "${ANCESTOR_ACL_DIRS[@]+"${ANCESTOR_ACL_DIRS[@]}"}"; do
        if [ "$DECIDE_ACL" = "yes" ]; then
            printf '  parent ACL    : %s (entry for %s removed)\n' "$i" "$SVC_USER"
        else
            printf '  still present : parent folder ACL entry for %s on %s\n' "$SVC_USER" "$i"
        fi
    done
    for ((i = 0; i < ${#BASHRC_FILES[@]}; i++)); do
        if [ "${BASHRC_RESULT[$i]:-}" = "gone" ]; then
            printf '  gone          : SopsHQ block(s) in %s\n' "${BASHRC_FILES[i]}"
        else
            printf '  still present : SopsHQ block(s) in %s\n' "${BASHRC_FILES[i]}"
        fi
    done
    # Key links SopsHQ placed in home folders point into the folders handled above.
    while IFS= read -r h; do
        local l="$h/.config/sops/age/keys.txt"
        if [ -L "$(real "$l")" ]; then
            printf '  left in place : %s -> %s (not removed by this script)\n' "$l" "$(readlink -- "$(real "$l")")"
        fi
    done < <(home_dirs)
    for m in "${ACCOUNT_NOTES[@]+"${ACCOUNT_NOTES[@]}"}"; do
        printf '  kept          : %s\n' "$m"
    done
    if [ "$FAILURES" -gt 0 ]; then
        printf '\n  %s step(s) FAILED; see the lines marked FAILED above.\n' "$FAILURES"
        return 1
    fi
    return 0
}

# --- main --------------------------------------------------------------------------

main() {
    printf 'SopsHQ uninstall%s\n' "$([ "$DRY_RUN" -eq 1 ] && printf ' (dry run)')"
    discover
    scan_bashrc
    scan_ancestor_acls
    print_plan
    decide_all
    preflight
    run_step stop-service step_stop_service
    run_step remove-unit step_remove_unit
    run_step remove-symlink step_symlink
    run_step remove-pointer step_pointer
    run_step folder-prefix apply_folder prefix "$PREFIX"
    run_step folder-data apply_folder data "$DATA"
    run_step folder-keybase apply_folder keybase "$KEYBASE"
    run_step parent-acls step_ancestor_acls
    run_step scan-leftovers step_scan
    run_step shell-profiles step_bashrc
    run_step accounts step_accounts
    COMPLETE=1
    final_check
}

main
