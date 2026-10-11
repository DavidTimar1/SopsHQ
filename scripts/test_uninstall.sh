#!/usr/bin/env bash
#
# test_uninstall.sh - tests for ../uninstall.sh. Runs without root against a fake
# system tree under a scratch folder, with systemctl, userdel, groupdel, setfacl,
# chown, findmnt, getent, getfacl and pgrep replaced by stubs on PATH. It never
# touches a real system path: the script's test switches only act inside a directory
# holding a marker file, and this harness refuses to run as root.
#
#   scripts/test_uninstall.sh
#
# Run it from any directory. Scratch lives under $TMPDIR (default /tmp) and is deleted
# by its full name on exit.
set -euo pipefail

if [ "$(id -u)" -eq 0 ]; then
    echo "test_uninstall.sh: refusing to run as root" >&2
    exit 1
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/../uninstall.sh"
WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT

STUBS="$WORK/bin"
CASE="$WORK/case"
ROOT="$CASE/root"
STATE="$CASE/state"
mkdir -p "$STUBS"

# Timestamp the script uses in the names of moved folders and backups, so a test can
# plant a file at a name the script will pick.
TSV=20260101T000000Z

PASS=0
FAIL=0
OUT=""
RC=0

# --- stubs -------------------------------------------------------------------------

cat >"$STUBS/systemctl" <<'EOF'
#!/usr/bin/env bash
echo "systemctl $*" >>"$FAKE_STATE/log"
case "$1" in
    stop) [ -f "$FAKE_STATE/stop_fails" ] && exit 1; [ -f "$FAKE_STATE/unit_missing_fails" ] && exit 5 ;;
    daemon-reload) [ -f "$FAKE_STATE/reload_fails" ] && exit 1 ;;
    is-active) [ -f "$FAKE_STATE/still_active" ] && exit 0; exit 3 ;;
esac
exit 0
EOF
cat >"$STUBS/userdel" <<'EOF'
#!/usr/bin/env bash
echo "userdel $*" >>"$FAKE_STATE/log"
[ -f "$FAKE_STATE/userdel_fails" ] && exit 1
grep -vFx "passwd:$1" "$FAKE_STATE/accounts" >"$FAKE_STATE/accounts.new" || true
mv "$FAKE_STATE/accounts.new" "$FAKE_STATE/accounts"
if [ -f "$FAKE_STATE/usergroups" ]; then
    grep -vFx "group:$1" "$FAKE_STATE/accounts" >"$FAKE_STATE/accounts.new" || true
    mv "$FAKE_STATE/accounts.new" "$FAKE_STATE/accounts"
fi
exit 0
EOF
cat >"$STUBS/groupdel" <<'EOF'
#!/usr/bin/env bash
echo "groupdel $*" >>"$FAKE_STATE/log"
grep -vFx "group:$1" "$FAKE_STATE/accounts" >"$FAKE_STATE/accounts.new" || true
mv "$FAKE_STATE/accounts.new" "$FAKE_STATE/accounts"
exit 0
EOF
for n in setfacl chown; do
    cat >"$STUBS/$n" <<EOF
#!/usr/bin/env bash
echo "$n \$*" >>"\$FAKE_STATE/log"
exit 0
EOF
done
cat >"$STUBS/findmnt" <<'EOF'
#!/usr/bin/env bash
grep -Fxq -- "$2" "$FAKE_STATE/mounts"
EOF
cat >"$STUBS/getent" <<'EOS'
#!/usr/bin/env bash
db="$1"
key="${2:-}"
if [ -z "$key" ]; then
    if [ "$db" = passwd ] && [ -f "$FAKE_STATE/other_user_in_group" ]; then
        echo "other:x:1001:981::/home/other:/bin/sh"
    fi
    exit 0
fi
if grep -Fxq -- "$db:$key" "$FAKE_STATE/accounts"; then
    case "$db" in
        passwd)
            uid=993 shell=/usr/sbin/nologin home=/nonexistent
            [ -f "$FAKE_STATE/uid_$key" ] && uid="$(cat "$FAKE_STATE/uid_$key")"
            [ -f "$FAKE_STATE/shell_$key" ] && shell="$(cat "$FAKE_STATE/shell_$key")"
            [ -f "$FAKE_STATE/home_$key" ] && home="$(cat "$FAKE_STATE/home_$key")"
            echo "$key:x:$uid:981::$home:$shell"
            ;;
        group)
            members=""
            [ -f "$FAKE_STATE/members_$key" ] && members="$(cat "$FAKE_STATE/members_$key")"
            echo "$key:x:981:$members"
            ;;
    esac
    exit 0
fi
exit 2
EOS
# setpriv: logs the identity it was asked for, then runs the command as the current
# (unprivileged) user, which owns every file in the fake tree.
cat >"$STUBS/setpriv" <<'EOS'
#!/usr/bin/env bash
echo "setpriv $1 $2 $3" >>"$FAKE_STATE/log"
while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done
shift
exec "$@"
EOS
# id: reports user id 0 when the test asks for a root run.
cat >"$STUBS/id" <<'EOS'
#!/usr/bin/env bash
if [ -f "$FAKE_STATE/pretend_root" ] && [ "${1:-}" = "-u" ]; then
    echo 0
    exit 0
fi
exec /usr/bin/id "$@"
EOS
# mv: fails for a moved-aside folder when asked; otherwise the real mv.
cat >"$STUBS/mv" <<'EOS'
#!/usr/bin/env bash
if [ -f "$FAKE_STATE/mv_fails" ] && [[ "$*" == *".removed-"* ]]; then
    exit 1
fi
exec /usr/bin/mv "$@"
EOS
cat >"$STUBS/getfacl" <<'EOF'
#!/usr/bin/env bash
echo "# file: $3"
echo "user::rwx"
if grep -Fxq -- "$3" "$FAKE_STATE/acl_dirs"; then
    echo "user:sopshq:--x"
fi
exit 0
EOF
cat >"$STUBS/pgrep" <<'EOF'
#!/usr/bin/env bash
if [ -f "$FAKE_STATE/running" ]; then
    echo "4242 sopshq"
    exit 0
fi
exit 1
EOF
# stat: the fake tree is owned by the harness user, but the script must find the data base
# and keybase root owned by the service account. For `stat -c %u` on a path outside the
# profile folders it reports the account's user id (the one getent reports), or the owner
# a test chose in owner_of_<last path component>. Everything else is the real stat.
cat >"$STUBS/stat" <<'EOS'
#!/usr/bin/env bash
if [ "${1:-}" = "-c" ] && [ "${2:-}" = "%u" ]; then
    last="${*: -1}"
    rel="${last#*/case/root}"
    case "$rel" in
        /home | /home/* | /root | /root/*) ;;
        *)
            if [ -f "$FAKE_STATE/owner_of_$(basename -- "$last")" ]; then
                cat "$FAKE_STATE/owner_of_$(basename -- "$last")"
            elif [ -f "$FAKE_STATE/uid_sopshq" ]; then
                cat "$FAKE_STATE/uid_sopshq"
            else
                echo 993
            fi
            exit 0
            ;;
    esac
fi
exec /usr/bin/stat "$@"
EOS
chmod +x "$STUBS"/*

# --- fixtures ----------------------------------------------------------------------

# fresh builds a complete default install inside a new fake tree.
fresh() {
    rm -rf -- "$CASE"
    mkdir -p "$ROOT" "$STATE"
    : >"$ROOT/.sopshq-uninstall-test-root"
    mkdir -p "$ROOT/etc/systemd/system" "$ROOT/etc/sopshq" "$ROOT/usr/local/bin" "$ROOT/etc/sudoers.d"
    mkdir -p "$ROOT/opt/sopshq/backups" "$ROOT/srv/sopshq/data" "$ROOT/srv/sopshq-keys/alice"
    mkdir -p "$ROOT/home/alice" "$ROOT/home/bob" "$ROOT/home/carol" "$ROOT/root"
    cat >"$ROOT/etc/systemd/system/sopshq.service" <<'EOF'
[Service]
User=sopshq
Group=sopshq
ExecStart=/opt/sopshq/sopshq serve -config /srv/sopshq/config.jsonc
ReadWritePaths=/srv/sopshq /srv/sopshq-keys
EOF
    echo "/srv/sopshq" >"$ROOT/etc/sopshq/location"
    ln -s /opt/sopshq/sopshq "$ROOT/usr/local/bin/sopshq"
    echo "binary" >"$ROOT/opt/sopshq/sopshq"
    echo "old" >"$ROOT/opt/sopshq/backups/sopshq-0.1.0"
    cat >"$ROOT/srv/sopshq/config.jsonc" <<'EOF'
{
  "data_dir": "/srv/sopshq/data",
  "keybase_root": "/srv/sopshq-keys",
  "sealed_marker": "SECRET-CONFIG-VALUE",
  "permission_map": {
    "enabled": false,
    "scan_user": "sopshq-scan"
  }
}
EOF
    echo "vault" >"$ROOT/srv/sopshq/data/vault.json"
    echo "AGE-SECRET-KEY-FAKE-TEST-ONLY" >"$ROOT/srv/sopshq-keys/alice/keys.txt"
    echo "sudoers" >"$ROOT/etc/sudoers.d/sopshq-permmap"
    printf '%s\n' "# alice rc" "alias ll='ls -l'" "# sopshq:sops-age" \
        'export SOPS_AGE_KEY_FILE="/srv/sopshq-keys/alice/keys.txt"' "echo after" >"$ROOT/home/alice/.bashrc"
    # shellcheck disable=SC2016
    printf '%s\n' "export A=1" "" "# >>> sopshq usage shim >>>" 'export PATH="/srv/sopshq/shim:$PATH"' \
        "# <<< sopshq usage shim <<<" "echo end" >"$ROOT/home/bob/.bashrc"
    printf '%s\n' "# plain" >"$ROOT/home/carol/.bashrc"
    printf '%s\n' "# sopshq:sops-age" 'export SOPS_AGE_KEY_FILE="/x/keys.txt"' >"$ROOT/root/.bashrc"
    printf '%s\n' "passwd:sopshq" "group:sopshq" "passwd:sopshq-scan" "group:sopshq-scan" >"$STATE/accounts"
    : >"$STATE/mounts"
    : >"$STATE/acl_dirs"
    : >"$STATE/log"
}

snapshot() { (cd "$ROOT" && find . -printf '%p %y %s %l\n' | sort); }

# run_script ARGS... : answers come from the lines in ANSWERS (one per line).
ANSWERS=""
run_script() {
    RC=0
    OUT="$(printf '%s' "$ANSWERS" | env PATH="$STUBS:$PATH" FAKE_STATE="$STATE" \
        SOPSHQ_UNINSTALL_TEST_ROOT="$ROOT" SOPSHQ_UNINSTALL_TEST_NO_TTY=1 \
        SOPSHQ_UNINSTALL_TEST_TS="$TSV" \
        bash "$SCRIPT" "$@" 2>&1)" || RC=$?
}

answers() { ANSWERS="$(printf '%s\n' "$@")"$'\n'; }

# --- assertions --------------------------------------------------------------------

ok() {
    PASS=$((PASS + 1))
    echo "ok:   $1"
}
bad() {
    FAIL=$((FAIL + 1))
    echo "FAIL: $1"
}
check() { # check "name" condition-command...
    local name="$1"
    shift
    if "$@"; then ok "$name"; else
        bad "$name"
        echo "----- output -----"
        echo "$OUT"
        echo "------------------"
    fi
}
# A here-string, not a pipe: under pipefail grep -q exits at the first match, printf gets SIGPIPE
# on a large output and the pipeline reports failure for a match that is there.
out_has() { grep -qF -- "$1" <<<"$OUT"; }
out_lacks() { ! out_has "$1"; }
rc_is() { [ "$RC" -eq "$1" ]; }
rc_nonzero() { [ "$RC" -ne 0 ]; }
there() { [ -e "$ROOT$1" ] || [ -L "$ROOT$1" ]; }
gone() { ! there "$1"; }
log_has() { grep -qF -- "$1" "$STATE/log"; }
log_lacks() { ! log_has "$1"; }
log_line() { grep -Fxq -- "$1" "$STATE/log"; }
log_lacks_line() { ! log_line "$1"; }
log_empty() { [ ! -s "$STATE/log" ]; }
moved_exists() { compgen -G "$ROOT$1.removed-*" >/dev/null; }
file_is() { # file_is PATH expected-text-with-newlines
    [ "$(cat "$ROOT$1")" = "$2" ]
}
out_order() { # out_order A B : A appears on an earlier line than B
    local a b
    a="$(printf '%s\n' "$OUT" | grep -nF -- "$1" | head -n 1 | cut -d: -f1)"
    b="$(printf '%s\n' "$OUT" | grep -nF -- "$2" | head -n 1 | cut -d: -f1)"
    [ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt "$b" ]
}
log_order() {
    local a b
    a="$(grep -nFx -- "$1" "$STATE/log" | head -n 1 | cut -d: -f1)"
    b="$(grep -nFx -- "$2" "$STATE/log" | head -n 1 | cut -d: -f1)"
    [ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt "$b" ]
}
unchanged() { [ "$(snapshot)" = "$BEFORE" ]; }
inode_differs() { [ "$(stat -c %i "$ROOT$1")" != "$2" ]; }
nothing_matches() { ! compgen -G "$1" >/dev/null; }

# repoint DATA KEYBASE : the unit, the pointer and the config all name these folders.
repoint() {
    mkdir -p "$ROOT$1" "$ROOT$2"
    cp "$ROOT/srv/sopshq/config.jsonc" "$ROOT$1/config.jsonc"
    sed -i "s#-config [^ ]*#-config $1/config.jsonc#; s#ReadWritePaths=.*#ReadWritePaths=$1 $2#" "$ROOT/etc/systemd/system/sopshq.service"
    echo "$1" >"$ROOT/etc/sopshq/location"
    sed -i "s#\"keybase_root\": \"[^\"]*\"#\"keybase_root\": \"$2\"#" "$ROOT$1/config.jsonc"
}

# --- cases: refusals ---------------------------------------------------------------

echo "== refusals (criteria 1 and 7) =="

fresh
RC=0
OUT="$(bash "$SCRIPT" --dry-run </dev/null 2>&1)" || RC=$?
check "not root, no test switch: refuses" rc_nonzero
check "not root: says it must run as root" out_has "must be run as root"

fresh
RC=0
OUT="$(printf 'continue\n' | env PATH="$STUBS:$PATH" FAKE_STATE="$STATE" SOPSHQ_UNINSTALL_TEST_ROOT="$ROOT" bash "$SCRIPT" 2>&1)" || RC=$?
check "no terminal: refuses" rc_nonzero
check "no terminal: says it needs a terminal" out_has "needs a terminal"

fresh
BEFORE="$(snapshot)"
for bad_root in "/" "relative/path" "$CASE/missing" "$ROOT/../root" "$ROOT/"; do
    RC=0
    OUT="$(env PATH="$STUBS:$PATH" FAKE_STATE="$STATE" SOPSHQ_UNINSTALL_TEST_ROOT="$bad_root" SOPSHQ_UNINSTALL_TEST_NO_TTY=1 bash "$SCRIPT" --dry-run </dev/null 2>&1)" || RC=$?
    check "test root '$bad_root' is refused" rc_nonzero
done
mkdir -p "$CASE/nomarker"
RC=0
OUT="$(env PATH="$STUBS:$PATH" FAKE_STATE="$STATE" SOPSHQ_UNINSTALL_TEST_ROOT="$CASE/nomarker" SOPSHQ_UNINSTALL_TEST_NO_TTY=1 bash "$SCRIPT" --dry-run </dev/null 2>&1)" || RC=$?
check "test root without the marker file is refused" rc_nonzero
check "test root without the marker names the marker" out_has ".sopshq-uninstall-test-root"
check "refused roots changed nothing" unchanged

fresh
answers
RC=0
OUT="$(bash "$SCRIPT" --bogus </dev/null 2>&1)" || RC=$?
check "unknown option exits 2" rc_is 2

fresh
BEFORE="$(snapshot)"
answers continue
run_script
check "input ending before the last answer: refuses" rc_nonzero
check "input ending: says input ended" out_has "input ended"
check "input ending: nothing changed" unchanged
check "input ending: no command ran" log_empty

# --- cases: answer paths -----------------------------------------------------------

echo "== answer paths (criterion 4) =="

# Order of questions on the default tree: continue; prefix; data; keybase (each
# move/delete/keep, then the path for delete or the root-only question for move);
# scan; one per shell profile (/root, alice, bob); proceed.
fresh
answers continue \
    delete /opt/sopshq \
    delete /srv/sopshq \
    delete /srv/sopshq-keys \
    remove \
    remove remove remove \
    proceed
run_script
check "delete everything: exit 0" rc_is 0
check "unit removed" gone /etc/systemd/system/sopshq.service
check "symlink removed" gone /usr/local/bin/sopshq
check "pointer removed" gone /etc/sopshq/location
check "empty /etc/sopshq removed" gone /etc/sopshq
check "prefix deleted" gone /opt/sopshq
check "data deleted" gone /srv/sopshq
check "keybase deleted" gone /srv/sopshq-keys
check "sudoers removed" gone /etc/sudoers.d/sopshq-permmap
check "log: service stopped first" log_order "systemctl stop sopshq" "userdel sopshq"
check "log: systemctl disable ran" log_has "systemctl disable sopshq"
check "log: daemon-reload ran" log_has "systemctl daemon-reload"
check "log: scan account removed before the service account" log_order "userdel sopshq-scan" "userdel sopshq"
check "log: leftover groups removed" log_has "groupdel sopshq"
check "output: folders deleted before the accounts" out_order "-> deleting /srv/sopshq-keys" "-> removing the accounts"
check "output: delete uses --one-file-system" out_has "rm -r --one-file-system -- $ROOT/srv/sopshq"
check "output: a final check is printed" out_has "Check: what is left"
check "output: accounts reported gone" out_has "gone          : account sopshq"
check "alice profile: marker and export removed, rest kept" file_is /home/alice/.bashrc "# alice rc
alias ll='ls -l'
echo after"
check "alice profile: backup copy kept beside it" compgen -G "$ROOT/home/alice/.bashrc.sopshq-backup-*"
check "bob profile: shim block removed, rest kept" file_is /home/bob/.bashrc "export A=1

echo end"
check "root profile: older marker removed" file_is /root/.bashrc ""
check "carol profile (no block) untouched, no backup" gone /home/carol/.bashrc.sopshq-backup-x

fresh
answers continue \
    move yes \
    move yes \
    move no \
    keep \
    leave leave leave \
    proceed
run_script
check "move everything: exit 0" rc_is 0
check "prefix moved aside" moved_exists /opt/sopshq
check "data moved aside" moved_exists /srv/sopshq
check "keybase moved aside" moved_exists /srv/sopshq-keys
check "moved names are not the original" gone /srv/sopshq
check "moved key file content intact" grep -rqF "FAKE-TEST-ONLY" "$ROOT/srv"
check "log: data chown to root" log_has "chown -R -h root:root -- $ROOT/srv/sopshq.removed-"
check "log: data ACL stripped" log_has "setfacl -R -b -- $ROOT/srv/sopshq.removed-"
check "log: keybase answered no, so not chowned" log_lacks "chown -R -h root:root -- $ROOT/srv/sopshq-keys.removed-"
check "scan kept: sudoers still there" there /etc/sudoers.d/sopshq-permmap
check "scan kept: scan account not removed" log_lacks "userdel sopshq-scan"
check "profiles left: alice unchanged" grep -qF "# sopshq:sops-age" "$ROOT/home/alice/.bashrc"
check "profiles left: no backup made" gone /home/alice/.bashrc.sopshq-backup-x
check "symlink still removed without a decision" gone /usr/local/bin/sopshq
check "output: moved folders are listed at the end" out_has "moved aside   : /srv/sopshq-keys -> /srv/sopshq-keys.removed-"

fresh
answers continue keep keep keep keep leave leave leave proceed
run_script
check "keep everything: exit 0" rc_is 0
check "kept prefix still there" there /opt/sopshq
check "kept data still there" there /srv/sopshq
check "kept keybase still there" there /srv/sopshq-keys
check "output: kept folders listed" out_has "kept          : /srv/sopshq"
check "service account still removed" log_has "userdel sopshq"

fresh
answers continue maybe \
    delete /wrong/path \
    keep keep keep keep leave leave leave proceed
run_script
check "unlisted answer is asked again" out_has "Please type exactly one of: move/delete/keep"
check "wrong full path for a delete asks the decision again" out_has "That is not the path"
check "wrong path deleted nothing" there /opt/sopshq

fresh
answers continue delete /opt/sopshq keep keep keep leave leave leave proceed
run_script
check "delete with the typed path deletes only that folder" gone /opt/sopshq
check "delete of prefix leaves data alone" there /srv/sopshq

fresh
answers continue keep keep keep remove leave leave leave proceed
run_script
check "scan removed alone: sudoers gone" gone /etc/sudoers.d/sopshq-permmap
check "scan removed alone: log has the scan userdel" log_has "userdel sopshq-scan"

fresh
answers continue delete /opt/sopshq keep keep keep leave leave leave quit
BEFORE="$(snapshot)"
run_script
check "last confirmation 'quit': exit 0" rc_is 0
check "last confirmation 'quit': nothing changed" unchanged
check "last confirmation 'quit': no command ran" log_empty

fresh
answers quit
BEFORE="$(snapshot)"
run_script
check "first question 'quit': nothing changed" unchanged

echo "== plan, secrets, discovery (criteria 2 and 3) =="

fresh
answers continue keep keep keep keep leave leave leave proceed
run_script
check "plan names the unit" out_has "systemd unit    : /etc/systemd/system/sopshq.service (found)"
check "plan names the data base as holding the vault" out_has "HOLDS THE VAULT"
check "plan names the keybase root as holding private keys" out_has "HOLDS PLAINTEXT PRIVATE KEY FILES"
check "plan precedes the first question" out_order "uninstall plan" "Continue with the uninstall?"
check "key files listed by path before the keybase decision" out_order "/srv/sopshq-keys/alice/keys.txt" "Keybase root: /srv/sopshq-keys"
check "key file contents never printed" out_lacks "FAKE-TEST-ONLY"
check "config contents never printed" out_lacks "SECRET-CONFIG-VALUE"
check "notice about other tools that unlock SopsHQ" out_has "hook that runs when an encrypted volume is opened"

# The pointer and the unit disagree: it asks which path.
fresh
echo "/srv/other" >"$ROOT/etc/sopshq/location"
answers /srv/sopshq continue keep keep keep keep leave leave leave proceed
run_script
check "disagreeing sources: asks for the data base" out_has "The sources disagree about the data base folder"
check "disagreeing sources: lists both candidates" out_has "/srv/other"

# No unit and no pointer: it asks for every value it cannot find.
fresh
rm -f "$ROOT/etc/systemd/system/sopshq.service" "$ROOT/etc/sopshq/location"
answers sopshq /opt/sopshq /srv/sopshq continue keep keep keep keep leave leave leave proceed
run_script
check "no unit: asks for the service account" out_has "Could not find the service account name"
check "no unit: asks for the install prefix" out_has "Could not find the install prefix"
check "no unit: asks for the data base" out_has "Could not find the data base folder"
check "no unit: still reads the keybase root from the config" out_has "keybase root    : /srv/sopshq-keys"
check "no unit: symlink checked against the typed prefix and removed" gone /usr/local/bin/sopshq

# The scan name is not in the config: it asks, and 'none' ends it.
fresh
sed -i '/scan_user/d' "$ROOT/srv/sopshq/config.jsonc"
answers none continue keep keep keep leave leave leave proceed
run_script
check "no scan name in config: asked" out_has "Could not find a permission-scan account name"
check "scan name 'none' and the sudoers file present: the scan question is still asked" out_has "Remove them?"

# Neither the scan account nor the sudoers file: no scan question.
fresh
rm -f "$ROOT/etc/sudoers.d/sopshq-permmap"
printf '%s\n' "passwd:sopshq" "group:sopshq" >"$STATE/accounts"
answers continue keep keep keep leave leave leave proceed
run_script
check "no scan leftovers: scan question not asked" out_lacks "Remove them?"

# A parent folder with an ACL entry for the service account.
fresh
echo "$ROOT/srv" >"$STATE/acl_dirs"
answers continue keep keep keep yes keep leave leave leave proceed
run_script
check "parent ACL found: plan lists it" out_has "parent folder   : /srv has an ACL entry for sopshq"
check "parent ACL 'yes': setfacl -x runs for the account" log_has "setfacl -x u:sopshq -- $ROOT/srv"
check "parent ACL runs before the account is removed" log_order "setfacl -x u:sopshq -- $ROOT/srv" "userdel sopshq"

fresh
echo "$ROOT/srv" >"$STATE/acl_dirs"
answers continue keep keep keep no keep leave leave leave proceed
run_script
check "parent ACL 'no': not removed" log_lacks "setfacl -x"
check "parent ACL 'no': reported as left" out_has "still present : parent folder ACL entry for sopshq on /srv"

echo "== safety (criterion 7) =="

fresh
echo "$ROOT/srv/sopshq" >"$STATE/mounts"
# The data base is a mount point: it is not offered, so the answers after the prefix
# decision are: keybase, scan, three profiles, proceed.
answers continue keep keep keep leave leave leave proceed
run_script
check "mount point: refused with the reason" out_has "is a mount point"
check "mount point: data kept" there /srv/sopshq/data/vault.json

fresh
rm -rf -- "$ROOT/srv/sopshq-keys"
ln -s /srv/elsewhere "$ROOT/srv/sopshq-keys"
answers continue keep keep keep leave leave leave proceed
run_script
check "symbolic link keybase: cannot be touched" out_has "the path is a symbolic link"

fresh
mkdir -p "$ROOT/data"
cp "$ROOT/srv/sopshq/config.jsonc" "$ROOT/data/config.jsonc"
sed -i 's#/srv/sopshq #/data #; s#/srv/sopshq$#/data#; s#-config /srv/sopshq/config.jsonc#-config /data/config.jsonc#' "$ROOT/etc/systemd/system/sopshq.service"
echo "/data" >"$ROOT/etc/sopshq/location"
answers continue keep keep keep leave leave leave proceed
run_script
check "top-level folder as data base: cannot be touched" out_has "the path is a top-level folder"

fresh
sed -i 's#"keybase_root": "/srv/sopshq-keys"#"keybase_root": "/srv/sopshq/keys"#; ' "$ROOT/srv/sopshq/config.jsonc"
sed -i 's#ReadWritePaths=.*#ReadWritePaths=/srv/sopshq#' "$ROOT/etc/systemd/system/sopshq.service"
answers
BEFORE="$(snapshot)"
run_script
check "keybase inside the data base: refused before any question" rc_nonzero
check "keybase inside the data base: names the overlap" out_has "inside the data folder"
check "keybase inside the data base: nothing changed" unchanged

fresh
touch "$STATE/stop_fails"
BEFORE="$(snapshot)"
answers continue delete /opt/sopshq delete /srv/sopshq delete /srv/sopshq-keys remove remove remove remove proceed
run_script
check "service will not stop: aborts" rc_nonzero
check "service will not stop: says so" out_has "could not stop the service"
check "service will not stop: nothing removed" unchanged
check "service will not stop: no account removed" log_lacks "userdel"

fresh
touch "$STATE/running"
BEFORE="$(snapshot)"
answers continue delete /opt/sopshq delete /srv/sopshq delete /srv/sopshq-keys remove remove remove remove proceed
run_script
check "processes still running as the account: aborts" rc_nonzero
check "processes still running: nothing removed" unchanged

fresh
touch "$STATE/userdel_fails"
answers continue keep keep keep keep leave leave leave proceed
run_script
check "userdel failure is reported" out_has "FAILED: userdel sopshq"
check "userdel failure: exit is non-zero" rc_nonzero

fresh
rm -f "$ROOT/usr/local/bin/sopshq"
ln -s /somewhere/else "$ROOT/usr/local/bin/sopshq"
answers continue keep keep keep keep leave leave leave proceed
run_script
check "symlink to another target is left alone" there /usr/local/bin/sopshq
check "symlink to another target: says so" out_has "not at the installed binary"

echo "== dry run (criterion 9) =="

fresh
BEFORE="$(snapshot)"
answers continue delete /opt/sopshq move yes delete /srv/sopshq-keys remove remove remove remove proceed
run_script --dry-run
check "dry run: exit 0" rc_is 0
check "dry run: tree unchanged" unchanged
check "dry run: no stubbed command ran" log_empty
check "dry run: shows the stop command" out_has "+ systemctl stop sopshq"
check "dry run: shows the delete command" out_has "+ rm -r --one-file-system -- $ROOT/opt/sopshq"
check "dry run: shows the move command" out_has "+ mv -- $ROOT/srv/sopshq $ROOT/srv/sopshq.removed-"
check "dry run: shows the chown command" out_has "+ chown -R -h root:root --"
check "dry run: shows the setfacl command" out_has "+ setfacl -R -b --"
check "dry run: shows the userdel commands" out_has "+ userdel sopshq-scan"
check "dry run: states nothing was changed" out_has "nothing was changed"
check "dry run: bashrc backup command shown, not run" out_has ".sopshq-backup-"

echo "== security fixes (criteria 13 to 16) =="

# Finding 1: the profile is edited as its owner, through a name nobody can pre-plant.
fresh
printf 'victim\n' >"$ROOT/victim"
ln -s "$ROOT/victim" "$ROOT/home/alice/.bashrc.sopshq-backup-$TSV"
answers continue keep keep keep keep leave remove leave proceed
run_script
check "f1 planted backup symlink: the file it points at is not written" file_is /victim "victim"
check "f1 planted backup symlink: the profile is left untouched" grep -qF "# sopshq:sops-age" "$ROOT/home/alice/.bashrc"
check "f1 planted backup symlink: reported as failed" out_has "already exists, so /home/alice/.bashrc was left untouched"
check "f1 planted backup symlink: exit is non-zero" rc_nonzero

fresh
INO="$(stat -c %i "$ROOT/home/alice/.bashrc")"
answers continue keep keep keep keep leave remove leave proceed
run_script
check "f1 the edit runs as the profile's owner (setpriv)" log_has "setpriv --reuid=$(id -u) --regid=$(id -g) --clear-groups"
check "f7 the rewrite replaces the file by rename (new inode)" inode_differs /home/alice/.bashrc "$INO"
check "f7 no temporary file is left beside the profile" nothing_matches "$ROOT/home/alice/.bashrc.sopshq-tmp-*"
check "f7 the closing check reports the profile clean" out_has "gone          : SopsHQ block(s) in /home/alice"

# Finding 7: several blocks, a continued export line, an unpaired shim line.
fresh
# shellcheck disable=SC1003
printf '%s\n' "a" "# >>> sopshq usage shim >>>" "x" "# <<< sopshq usage shim <<<" "b" \
    "# >>> sopshq usage shim >>>" "y" "# <<< sopshq usage shim <<<" "c" \
    "# sopshq:sops-age" 'export SOPS_AGE_KEY_FILE="/k" \' "  more" "d" >"$ROOT/home/alice/.bashrc"
answers continue keep keep keep keep leave remove leave proceed
run_script
check "f7 two shim blocks and a continued export are all removed" file_is /home/alice/.bashrc "a
b
c
d"

fresh
printf '%s\n' "# <<< sopshq usage shim <<<" "z" "# >>> sopshq usage shim >>>" >"$ROOT/home/alice/.bashrc"
answers continue keep keep keep keep leave leave proceed
run_script
check "f7 an unpaired shim line is reported, not called gone" out_has "still present : SopsHQ block(s) in /home/alice"
check "f7 an unpaired shim line: says it needs a hand edit" out_has "needs a hand edit"
check "f7 an unpaired shim line: the profile is not offered for removal" out_lacks "/home/alice/.bashrc carries: usage shim block"
check "f7 an unpaired shim line: exit is non-zero" rc_nonzero
check "f7 an unpaired shim line: no backup is made" nothing_matches "$ROOT/home/alice/.bashrc.sopshq-backup-*"

# A begin line with no end before the next begin line must not drop the user text between.
fresh
printf '%s\n' "a" "# >>> sopshq usage shim >>>" "USER TEXT" "# >>> sopshq usage shim >>>" "x" \
    "# <<< sopshq usage shim <<<" "tail" "# sopshq:sops-age" >"$ROOT/home/alice/.bashrc"
cp "$ROOT/home/alice/.bashrc" "$CASE/alice_before"
answers continue keep keep keep keep leave leave proceed
run_script
check "f7 begin, user text, begin, end: the profile is byte for byte unchanged" cmp -s "$CASE/alice_before" "$ROOT/home/alice/.bashrc"
check "f7 begin, user text, begin, end: the user text is still there" grep -qF "USER TEXT" "$ROOT/home/alice/.bashrc"
check "f7 begin, user text, begin, end: no backup is made" nothing_matches "$ROOT/home/alice/.bashrc.sopshq-backup-*"
check "f7 begin, user text, begin, end: reported as needing a hand edit" out_has "needs a hand edit"

# A begin line with no end at all, and an end line with no begin.
fresh
printf '%s\n' "a" "# >>> sopshq usage shim >>>" "USER TEXT" >"$ROOT/home/alice/.bashrc"
cp "$ROOT/home/alice/.bashrc" "$CASE/alice_before"
answers continue keep keep keep keep leave leave proceed
run_script
check "f7 begin with no end: the profile is unchanged" cmp -s "$CASE/alice_before" "$ROOT/home/alice/.bashrc"

fresh
printf '%s\n' "a" "USER TEXT" "# <<< sopshq usage shim <<<" "# sopshq:sops-age" >"$ROOT/home/alice/.bashrc"
cp "$ROOT/home/alice/.bashrc" "$CASE/alice_before"
answers continue keep keep keep keep leave leave proceed
run_script
check "f7 end with no begin: the profile is unchanged (the marker line stays too)" cmp -s "$CASE/alice_before" "$ROOT/home/alice/.bashrc"

# Defence in depth: if the profile changes between the questions and the edit, the awk
# program refuses it on its own and the owner-run script leaves the file and makes no backup.
fresh
printf '%s\n' "a" "# >>> sopshq usage shim >>>" "USER TEXT" >"$CASE/alice_late"
# shellcheck disable=SC2016
check "f7 the awk program alone exits 9 on a begin line with no end" bash -c '
    prog=$(sed -n "/^read -r -d .. OWNER_EDIT_AWK/,/^EOF/p" "$1" | sed "1d;\$d")
    rc=0; out=$(awk "$prog" "$2") || rc=$?
    [ "$rc" -eq 9 ] && [ -z "$out" ]' _ "$SCRIPT" "$CASE/alice_late"

# Finding 3: root and regular users are refused before anything is changed.
fresh
sed -i 's/User=sopshq/User=root/' "$ROOT/etc/systemd/system/sopshq.service"
BEFORE="$(snapshot)"
answers continue keep keep keep keep leave leave leave proceed
run_script
check "f3 User=root in the unit: refused" rc_nonzero
check "f3 User=root: says it never removes root" out_has "never removes root"
check "f3 User=root: nothing changed" unchanged
check "f3 User=root: no command ran" log_empty

fresh
echo 1000 >"$STATE/uid_sopshq-scan"
BEFORE="$(snapshot)"
answers continue keep keep keep keep leave leave leave proceed
run_script
check "f3 scan account that is a regular user: refused" out_has "is a regular user account"
check "f3 scan account that is a regular user: nothing changed" unchanged

fresh
printf '%s\n' "passwd:alice" "group:alice" >>"$STATE/accounts"
echo 1000 >"$STATE/uid_alice"
sed -i 's/"scan_user": "sopshq-scan"/"scan_user": "alice"/' "$ROOT/srv/sopshq/config.jsonc"
BEFORE="$(snapshot)"
answers continue keep keep keep keep leave leave leave proceed
run_script
check "f3 config naming a human as the scan account: refused" out_has "is a regular user account"
check "f3 config naming a human: nothing changed" unchanged
check "f3 config naming a human: no command ran" log_empty

fresh
printf '%s\n' "passwd:alice" "group:alice" >>"$STATE/accounts"
echo 1000 >"$STATE/uid_alice"
sed -i 's/User=sopshq/User=alice/' "$ROOT/etc/systemd/system/sopshq.service"
BEFORE="$(snapshot)"
answers continue keep keep keep keep leave leave leave proceed
run_script
check "f3 unit naming a human as the service account: refused" out_has "is a regular user account"
check "f3 unit naming a human: nothing changed" unchanged

fresh
echo 0 >"$STATE/uid_sopshq"
BEFORE="$(snapshot)"
answers continue keep keep keep keep leave leave leave proceed
run_script
check "f3 an account with user id 0 under another name: refused" out_has "has user id 0"
check "f3 user id 0: nothing changed" unchanged

fresh
echo /bin/bash >"$STATE/shell_sopshq"
BEFORE="$(snapshot)"
answers continue keep keep keep keep leave leave leave proceed
run_script
check "f3 an account with a login shell: refused" out_has "login shell"
check "f3 login shell: nothing changed" unchanged

fresh
echo /home/alice >"$STATE/home_sopshq"
BEFORE="$(snapshot)"
answers continue keep keep keep keep leave leave leave proceed
run_script
check "f3 an account whose home is a real folder under /home: refused" out_has "has the home folder /home/alice"
check "f3 home folder: nothing changed" unchanged

# Finding 4: a crafted path is refused before the plan.
fresh
sed -i 's#ReadWritePaths=.*#ReadWritePaths=/srv/sopshq#' "$ROOT/etc/systemd/system/sopshq.service"
sed -i 's#"keybase_root": "/srv/sopshq-keys"#"keybase_root": "/home/alice"#' "$ROOT/srv/sopshq/config.jsonc"
BEFORE="$(snapshot)"
answers continue keep keep keep keep leave leave leave proceed
run_script
check "f4 keybase_root naming a home folder: refused" out_has "inside a home folder"
check "f4 keybase_root naming a home folder: refused before the plan" out_lacks "uninstall plan"
check "f4 keybase_root naming a home folder: nothing changed" unchanged
check "f4 keybase_root naming a home folder: no command ran" log_empty

fresh
sed -i 's#"keybase_root": "/srv/sopshq-keys"#"keybase_root": "/srv/other-keys"#' "$ROOT/srv/sopshq/config.jsonc"
answers continue keep keep keep keep leave leave leave proceed
run_script
check "f4 config and unit disagree on the keybase root: the unit wins" out_has "keybase root    : /srv/sopshq-keys"
check "f4 config and unit disagree: says so" out_has "the systemd unit's /srv/sopshq-keys is used instead"

fresh
sed -i 's#ExecStart=/opt/sopshq/sopshq#ExecStart=/usr/local/bin/sopshq#' "$ROOT/etc/systemd/system/sopshq.service"
BEFORE="$(snapshot)"
answers continue keep keep keep keep leave leave leave proceed
run_script
check "f4 f10 install prefix /usr/local/bin: refused" out_has "the path is a system program folder"
check "f4 f10 install prefix /usr/local/bin: nothing changed" unchanged

fresh
mkdir -p "$ROOT/mnt/data"
repoint /mnt/data /srv/sopshq-keys
BEFORE="$(snapshot)"
answers continue keep keep keep keep leave leave leave proceed
run_script
check "f4 data base that is the top of a mounted volume: refused" out_has "the top of a mounted volume"
check "f4 top of a volume: nothing changed" unchanged

# Findings 4 and 10: a path the config supplies and the unit does not back up must be shown
# to be a SopsHQ folder (owned by the service account; a prefix holding the unit's binary).
fresh
sed -i 's#ReadWritePaths=.*#ReadWritePaths=/srv/sopshq#' "$ROOT/etc/systemd/system/sopshq.service"
sed -i 's#"keybase_root": "/srv/sopshq-keys"#"keybase_root": "/srv/x"#' "$ROOT/srv/sopshq/config.jsonc"
mkdir -p "$ROOT/srv/x"
echo 0 >"$STATE/owner_of_x"
BEFORE="$(snapshot)"
answers continue keep keep move yes leave leave leave proceed
run_script
check "f4 config keybase_root /srv/x not owned by the service account: refused" out_has "is not owned by the service account sopshq"
check "f4 /srv/x: refused before the plan" out_lacks "uninstall plan"
check "f4 /srv/x: nothing changed" unchanged
check "f4 /srv/x: no command ran" log_empty

for odd in /etc/ssh /etc /var /srv /boot /var/www; do
    fresh
    sed -i 's#ReadWritePaths=.*#ReadWritePaths=/srv/sopshq#' "$ROOT/etc/systemd/system/sopshq.service"
    sed -i "s#\"keybase_root\": \"/srv/sopshq-keys\"#\"keybase_root\": \"$odd\"#" "$ROOT/srv/sopshq/config.jsonc"
    mkdir -p "$ROOT$odd"
    echo 0 >"$STATE/owner_of_$(basename -- "$odd")"
    BEFORE="$(snapshot)"
    answers continue keep keep keep leave leave leave proceed
    run_script
    case "$odd" in
        /var/www) check "f4 config keybase_root $odd (not owned): refused" out_has "is not owned by the service account" ;;
        *) check "f4 config keybase_root $odd: refused as a system folder" out_has "cannot be handled by this script" ;;
    esac
    check "f4 config keybase_root $odd: nothing changed" unchanged
done

fresh
echo 0 >"$STATE/owner_of_sopshq"
BEFORE="$(snapshot)"
answers continue keep keep keep keep leave leave leave proceed
run_script
check "f4 data base not owned by the service account: refused" out_has "the data folder /srv/sopshq is not owned by the service account"
check "f4 data base not owned: nothing changed" unchanged

fresh
rm -f "$ROOT/opt/sopshq/sopshq"
BEFORE="$(snapshot)"
answers continue keep keep keep keep leave leave leave proceed
run_script
check "f4 install prefix without the unit's binary: refused" out_has "does not hold the sopshq binary"
check "f4 install prefix without the binary: nothing changed" unchanged

fresh
rm -f "$ROOT/opt/sopshq/sopshq"
ln -s /bin/sh "$ROOT/opt/sopshq/sopshq"
BEFORE="$(snapshot)"
answers continue keep keep keep keep leave leave leave proceed
run_script
check "f4 install prefix whose binary is a symbolic link: refused" out_has "does not hold the sopshq binary"

# A mounted-volume layout: unit User=sopshq, prefix /opt/sopshq, data /mnt/data/sopshq, keybase /mnt/data/keys.
fresh
mkdir -p "$ROOT/mnt/data"
repoint /mnt/data/sopshq /mnt/data/keys
answers continue keep keep keep keep leave leave leave proceed
run_script
check "volume layout: accepted, exit 0" rc_is 0
check "volume layout: the plan names the data base" out_has "data base       : /mnt/data/sopshq (found)"
check "volume layout: the plan names the keybase root" out_has "keybase root    : /mnt/data/keys (found)"
check "volume layout: no folder is refused" out_lacks "cannot be handled"
check "volume layout: the folders are offered for a decision" out_has "Keybase root: /mnt/data/keys"

# Finding 10: a symbolic link above a path, and hard links in a moved tree.
fresh
ln -s srv "$ROOT/link"
sed -i 's#/srv/#/link/#g' "$ROOT/etc/systemd/system/sopshq.service"
echo /link/sopshq >"$ROOT/etc/sopshq/location"
BEFORE="$(snapshot)"
answers continue keep keep keep keep leave leave leave proceed
run_script
check "f10 a symbolic link above the data base: refused" out_has "a folder above the path is a symbolic link"
check "f10 a symbolic link above the data base: nothing changed" unchanged

fresh
ln "$ROOT/srv/sopshq/data/vault.json" "$ROOT/srv/sopshq/data/vault_second_name.json"
answers continue keep move yes keep keep leave leave leave proceed
run_script
check "f10 hard-linked file in a moved tree: owner not changed" log_lacks "chown -R -h root:root -- $ROOT/srv/sopshq.removed-"
check "f10 hard-linked file: says why" out_has "several hard links"
check "f10 hard-linked file: exit is non-zero" rc_nonzero

# Finding 5: a run that stops part-way says how far it got, and can be repeated.
fresh
touch "$STATE/reload_fails"
answers continue keep keep keep keep leave leave leave proceed
run_script
check "f5 a step failing after the first change: reported" out_has "STOPPED PART-WAY"
check "f5 the report lists a finished step" out_has "done     : stop-service"
check "f5 the report lists steps that did not run" out_has "not done : folder-prefix"
check "f5 the report lists the accounts as not done" out_has "not done : accounts"

fresh
touch "$STATE/mv_fails"
answers continue move yes keep keep keep leave leave leave proceed
run_script
check "f5 a failed move is not recorded as moved" out_lacks "moved aside   : /opt/sopshq"
check "f5 a failed move: the folder is still where it was" there /opt/sopshq/sopshq
check "f5 a failed move: nothing is chowned afterwards" log_lacks "chown -R -h root:root -- $ROOT/opt/sopshq.removed-"
check "f5 a failed move: exit is non-zero" rc_nonzero

fresh
rm -f "$ROOT/etc/systemd/system/sopshq.service" "$ROOT/etc/sopshq/location"
touch "$STATE/unit_missing_fails"
answers sopshq /opt/sopshq /srv/sopshq continue keep keep keep keep leave leave leave proceed
run_script
check "f5 re-run with the unit already gone: does not die at stop" out_lacks "could not stop the service"
check "f5 re-run with the unit already gone: finishes" rc_is 0
check "f5 re-run with the unit already gone: no stop was attempted" log_lacks "systemctl stop"

fresh
mkdir -p "$ROOT/opt/sopshq.removed-$TSV"
BEFORE="$(snapshot)"
answers continue move yes keep keep keep leave leave leave proceed
run_script
check "f5 move target already exists: refused before the first change" out_has "already exists; move or remove it first"
check "f5 move target already exists: nothing changed" unchanged
check "f5 move target already exists: no command ran" log_empty

# Finding 6: a volume that is not mounted stops the run.
fresh
rm -rf -- "$ROOT/srv/sopshq-keys"
printf '%s\n' "/dev/mapper/vol /srv ext4 defaults 0 0" >"$ROOT/etc/fstab"
BEFORE="$(snapshot)"
answers continue keep keep keep keep leave leave leave proceed
run_script
check "f6 folder missing under an unmounted fstab volume: refused" out_has "is a volume from /etc/fstab that is not mounted"
check "f6 unmounted volume: nothing changed" unchanged
check "f6 unmounted volume: no command ran" log_empty

fresh
rm -rf -- "$ROOT/srv/sopshq-keys"
BEFORE="$(snapshot)"
answers continue keep keep keep keep leave leave leave proceed
run_script
check "f6 folder named by the unit but missing: refused" out_has "named by the systemd unit but does not exist"
check "f6 folder named by the unit but missing: nothing changed" unchanged

fresh
sed -i 's#ReadWritePaths=.*#ReadWritePaths=/srv/sopshq#' "$ROOT/etc/systemd/system/sopshq.service"
sed -i 's#"keybase_root": "/srv/sopshq-keys"#"keybase_root": "/srv/gone-keys"#' "$ROOT/srv/sopshq/config.jsonc"
answers continue keep keep keep leave leave leave proceed
run_script
check "f6 folder not named by the unit and not on a volume: nothing to do" out_has "does not exist; nothing to do"
check "f6 folder not named by the unit: the run finishes" rc_is 0

# Finding 2: an account is not removed while a kept folder still holds its files.
fresh
echo "UID_MIN 65000" >"$ROOT/etc/login.defs"
id -u >"$STATE/uid_sopshq"
answers continue keep keep keep keep leave leave leave proceed
run_script
check "f2 kept folders owned by the account: it is not removed" log_lacks_line "userdel sopshq"
check "f2 kept folders: told before the last question" out_order "will NOT be removed" "Make these changes now?"
check "f2 kept folders: told at the end" out_has "kept          : account sopshq was kept"

fresh
echo "UID_MIN 65000" >"$ROOT/etc/login.defs"
id -u >"$STATE/uid_sopshq"
answers continue move yes move yes move yes keep leave leave leave proceed
run_script
check "f2 moved root-only: the account is removed" log_line "userdel sopshq"

fresh
echo "UID_MIN 65000" >"$ROOT/etc/login.defs"
id -u >"$STATE/uid_sopshq"
answers continue move yes move no move yes keep leave leave leave proceed
run_script
check "f2 one moved folder not made root-only: the account is kept" log_lacks_line "userdel sopshq"

fresh
echo "UID_MIN 65000" >"$ROOT/etc/login.defs"
id -u >"$STATE/uid_sopshq"
answers continue delete /opt/sopshq delete /srv/sopshq delete /srv/sopshq-keys keep leave leave leave proceed
run_script
check "f2 deleted folders: the account is removed" log_line "userdel sopshq"

# Finding 8: a group is removed only with the account it belongs to.
fresh
printf '%s\n' "group:sopshq" "passwd:sopshq-scan" "group:sopshq-scan" >"$STATE/accounts"
answers continue keep keep keep keep leave leave leave proceed
run_script
check "f8 no such account: its group is left alone" log_lacks "groupdel"

fresh
echo bob >"$STATE/members_sopshq"
answers continue keep keep keep keep leave leave leave proceed
run_script
check "f8 group with members: userdel still runs" log_line "userdel sopshq"
check "f8 group with members: not removed" log_lacks "groupdel"
check "f8 group with members: says why" out_has "still has members"

fresh
touch "$STATE/other_user_in_group"
answers continue keep keep keep keep leave leave leave proceed
run_script
check "f8 another account's main group: not removed" log_lacks "groupdel"

# Finding 9: the test switch is refused for a root run.
fresh
touch "$STATE/pretend_root"
BEFORE="$(snapshot)"
answers continue keep keep keep keep leave leave leave proceed
run_script --dry-run
check "f9 test switch with an effective user of root: refused" rc_nonzero
check "f9 test switch with root: says so" out_has "refused when run as root"
check "f9 test switch with root: no command ran" log_empty
check "f9 test switch with root: nothing changed" unchanged

echo "== text hygiene (criterion 1: ASCII only) =="
check "uninstall.sh is ASCII only" bash -c "! LC_ALL=C grep -nP '[^\\x00-\\x7F]' '$SCRIPT'"
check "test_uninstall.sh is ASCII only" bash -c "! LC_ALL=C grep -nP '[^\\x00-\\x7F]' '$HERE/test_uninstall.sh'"
check "uninstall.sh sets -euo pipefail" grep -q '^set -euo pipefail$' "$SCRIPT"

echo
echo "passed: $PASS   failed: $FAIL"
[ "$FAIL" -eq 0 ]
