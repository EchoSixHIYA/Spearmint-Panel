"""Prepare a dedicated runtime when the administrator uses root over SSH."""
from hashlib import sha256
from shlex import join



PREPARE = r'''
set -eu
umask 077
[ "$(id -u)" = 0 ] || exit 41
account=$1
home=$2
location=$3
for tool in useradd getent runuser systemctl loginctl stat install readlink; do
    command -v "$tool" >/dev/null || { printf 'Missing runtime preparation tool: %s\n' "$tool" >&2; exit 44; }
done
[ "$(readlink -f -- "$(dirname -- "$location")")" = "$(dirname -- "$location")" ] || exit 45
[ ! -L /var/lib/spearmint-runtimes ] && [ ! -L "$home" ] || exit 45
if [ ! -e /var/lib/spearmint-runtimes ]; then
    install -d -m 0755 /var/lib/spearmint-runtimes
else
    [ -d /var/lib/spearmint-runtimes ] && [ "$(stat -c %u /var/lib/spearmint-runtimes)" = 0 ] || exit 45
fi
marker=$home/.spearmint-managed-account
if getent passwd "$account" >/dev/null; then
    [ -f "$marker" ] && [ ! -L "$marker" ] && [ "$(stat -c %u -- "$marker")" = 0 ] ||
        { echo 'Existing account is not a Spearmint-created runtime account' >&2; exit 45; }
    [ "$(getent passwd "$account" | cut -d: -f6)" = "$home" ] || exit 45
else
    [ ! -e "$home" ] || { echo 'Runtime home already exists' >&2; exit 45; }
    useradd --system --user-group --create-home --home-dir "$home" --shell /usr/sbin/nologin "$account"
    (set -C; printf 'Spearmint runtime account v1\n' > "$marker")
    chmod 0444 "$marker"
fi
uid=$(id -u "$account")
gid=$(id -g "$account")
[ "$uid" -ne 0 ] || exit 45
runuser -u "$account" -- test -x "$(dirname -- "$location")" ||
    { echo 'Selected parent is not accessible to the dedicated account; choose /opt or an accessible directory' >&2; exit 46; }
[ ! -L "$location" ] || exit 45
if [ -e "$location" ]; then
    [ -d "$location" ] && [ "$(stat -c %u -- "$location")" = "$uid" ] ||
        { echo 'Selected Spearmint directory already belongs to another account' >&2; exit 45; }
else
    install -d -m 0700 -o "$uid" -g "$gid" -- "$location"
fi
loginctl enable-linger "$account"
systemctl start "user@$uid.service"
runuser -u "$account" -- env HOME="$home" XDG_RUNTIME_DIR="/run/user/$uid" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" systemctl --user show-environment >/dev/null ||
    { echo 'The dedicated systemd user manager is unavailable' >&2; exit 44; }
printf 'SPMT_RUNNER_UID=%s\n' "$uid"
'''


def account_for(realm):
    account = 'spmt-' + sha256(realm.encode()).hexdigest()[:12]
    return account, '/var/lib/spearmint-runtimes/' + account


def command(account, home, uid, value):
    """Keep stdin and receipts intact while the payload runs without root."""
    return join(['runuser', '-u', account, '--', 'env', 'HOME=' + home, 'USER=' + account, 'LOGNAME=' + account,
        f'XDG_RUNTIME_DIR=/run/user/{uid}', f'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus',
        'sh', '-c', 'cd -- "$HOME" && exec sh -c "$1"', 'spearmint-seed', value])
