#!/bin/sh
# Install an extracted Spearmint package as a systemd user service.
set -eu
umask 077

fail() {
    printf '%s\n' "$*" >&2
    exit 1
}

valid_origin() {
    printf '%s' "$1" | grep -zExq 'https://(\[[0-9a-fA-F:.]+\]|[a-zA-Z0-9.-]+)(:[0-9]{1,5})?'
}

report_target() {
    case "$(uname -m 2>/dev/null || :)" in
        x86_64) printf ',"target":"linux-amd64"' ;;
        aarch64) printf ',"target":"linux-arm64"' ;;
    esac
}

read_upgrade_recovery() {
    [ -f "$recovery" ] && [ ! -L "$recovery" ] && {
        IFS=' ' read -r restore_commit interrupted_commit restore_active restore_node restore_origin restore_schema restore_package_sha256 extra &&
            [ -z "$extra" ] &&
            printf '%s' "$restore_commit $interrupted_commit $restore_active" | grep -zExq '[a-f0-9]{40} [a-f0-9]{40} (true|false)' &&
            { [ -z "$restore_node" ] || printf '%s' "$restore_node" | grep -zExq 'spm1-[a-f0-9]{64}'; } &&
            { { [ -z "$restore_origin" ] && [ -z "$restore_schema" ]; } ||
                { [ -n "$restore_node" ] && valid_origin "$restore_origin" &&
                    printf '%s' "$restore_schema" | grep -zExq '[1-9][0-9]{0,9}' && [ "$restore_schema" -le 2147483647 ]; }; } &&
            { [ -z "$restore_package_sha256" ] || { [ -n "$restore_origin" ] &&
                printf '%s' "$restore_package_sha256" | grep -zExq '[a-f0-9]{64}'; }; } &&
            ! IFS= read -r extra && [ -z "$extra" ]
    } < "$recovery" || {
        printf 'Invalid upgrade recovery record: %s\n' "$recovery" >&2
        return 1
    }
}

base="$HOME/.local/opt/spearmint"
recovery="$base/upgrade-recovery"
install_lock="$base/install.lock"
mode=install
check_only=false
keep_stopped=false
backup=
expected_backup_sha256=
expected_package_sha256=
package_sha256=
expected_node=
expected_commit=
expected_current_commit=
join_grove=
grove_ca=
requested_port=
requested_bind=
requested_cert=
requested_key=
delegated_systemd=false
case "${1:-}" in
    --stage-only) mode=stage; shift ;;
    --upgrade) mode=upgrade; shift ;;
    --check-upgrade) mode=upgrade; check_only=true; shift ;;
    --recover-upgrade) mode=recover; shift ;;
    --upgrade-recovery-status)
        [ "$#" -eq 1 ] || fail "Use --upgrade-recovery-status by itself."
        if [ ! -d "$base" ]; then
            printf 'SPEARMINT_UPGRADE_RECOVERY={"pending":false}\n'
            exit 0
        fi
        if [ -L "$install_lock" ] || { [ -e "$install_lock" ] && [ ! -f "$install_lock" ]; }; then
            fail "Invalid Spearmint install lock: $install_lock"
        fi
        # Keep the lock held until the recovery record has been read and reported.
        exec 9>>"$install_lock"
        if flock -s -n -E 75 9; then
            :
        elif [ "$?" -eq 75 ]; then
            printf 'SPEARMINT_UPGRADE_RECOVERY={"busy":true}\n'
            exit 0
        else
            fail "Could not read the Spearmint upgrade recovery status."
        fi
        if [ -e "$recovery" ] || [ -L "$recovery" ]; then
            read_upgrade_recovery || exit 1
            printf 'SPEARMINT_UPGRADE_RECOVERY={"pending":true,"previous_commit":"%s","candidate_commit":"%s","panel_was_running":%s' \
                "$restore_commit" "$interrupted_commit" "$restore_active"
            if [ -n "$restore_node" ]; then printf ',"node_id":"%s"' "$restore_node"; fi
            if [ -n "$restore_origin" ]; then printf ',"origin":"%s","schema":%s' "$restore_origin" "$restore_schema"; fi
            if [ -n "$restore_package_sha256" ]; then printf ',"package_checksums_sha256":"%s"' "$restore_package_sha256"; fi
            report_target
            printf '}\n'
        else
            printf 'SPEARMINT_UPGRADE_RECOVERY={"pending":false}\n'
        fi
        exit 0
        ;;
esac
valid_port() {
    case "$1" in
        ''|0*|*[!0-9]*) return 1 ;;
    esac
    [ "${#1}" -le 5 ] && [ "$1" -ge 1024 ] && [ "$1" -le 65535 ]
}
valid_bind() {
    printf '%s\n' "$1" | awk -F. '
        NF != 4 || NR != 1 { exit 1 }
        { for (i=1; i<=4; i++) if ($i !~ /^(0|[1-9][0-9]?[0-9]?)$/ || $i > 255) exit 1 }
        $1 == 0 || $1 >= 224 { exit 1 }'
}
absolute_path() {
    case "$1" in
        *[[:cntrl:]]*) return 1 ;;
        /*) return 0 ;;
        *) return 1 ;;
    esac
}
while [ "$#" -ge 1 ]; do
    if [ "$1" = --allow-delegated-systemd ]; then
        { [ "$mode" = install ] || [ "$mode" = stage ]; } && [ "$delegated_systemd" = false ] ||
            fail "Provide --allow-delegated-systemd once during installation."
        delegated_systemd=true
        shift
        continue
    fi
    if [ "$1" = --keep-stopped ]; then
        [ "$mode" = upgrade ] && [ "$keep_stopped" = false ] ||
            fail "Provide --keep-stopped once, with --upgrade or --check-upgrade."
        keep_stopped=true
        shift
        continue
    fi
    [ "$#" -ge 2 ] || break
    case "$1" in
        --port)
            [ -z "$requested_port" ] && valid_port "$2" || fail "Provide one panel port from 1024 to 65535."
            requested_port=$2
            ;;
        --bind)
            [ -z "$requested_bind" ] && valid_bind "$2" || fail "Provide one concrete IPv4 listen address."
            requested_bind=$2
            ;;
        --tls-cert)
            [ -z "$requested_cert" ] && absolute_path "$2" || fail "Provide one absolute TLS certificate path."
            requested_cert=$2
            ;;
        --tls-key)
            [ -z "$requested_key" ] && absolute_path "$2" || fail "Provide one absolute TLS private key path."
            requested_key=$2
            ;;
        --verify-backup)
            [ "$mode" = upgrade ] && [ -z "$backup" ] && [ -n "$2" ] ||
                fail "Provide one backup directory with --upgrade or --check-upgrade."
            backup=$(realpath -e -- "$2") || fail "The backup directory does not exist."
            ;;
        --expected-backup-sha256)
            [ "$mode" = upgrade ] && [ -z "$expected_backup_sha256" ] &&
                printf '%s' "$2" | grep -zExq '[a-f0-9]{64}' ||
                fail "Provide one backup SHA-256 with --upgrade or --check-upgrade."
            expected_backup_sha256=$2
            ;;
        --expected-node)
            [ "$mode" = upgrade ] && [ -z "$expected_node" ] &&
                printf '%s' "$2" | grep -zExq 'spm1-[a-f0-9]{64}' ||
                fail "Provide one full Node ID with --upgrade or --check-upgrade."
            expected_node=$2
            ;;
        --expected-package-sha256)
            [ "$mode" = upgrade ] && [ -z "$expected_package_sha256" ] &&
                printf '%s' "$2" | grep -zExq '[a-f0-9]{64}' ||
                fail "Provide one package checksum manifest SHA-256 with --upgrade or --check-upgrade."
            expected_package_sha256=$2
            ;;
        --expected-commit)
            [ "$mode" = upgrade ] && [ -z "$expected_commit" ] &&
                printf '%s' "$2" | grep -zExq '[a-f0-9]{40}' ||
                fail "Provide one full commit with --upgrade or --check-upgrade."
            expected_commit=$2
            ;;
        --expected-current-commit)
            [ "$mode" = upgrade ] && [ -z "$expected_current_commit" ] &&
                printf '%s' "$2" | grep -zExq '[a-f0-9]{40}' ||
                fail "Provide one current commit with --upgrade or --check-upgrade."
            expected_current_commit=$2
            ;;
        --join-grove)
            [ "$mode" = install ] && [ -z "$join_grove" ] && [ -n "$2" ] ||
                fail "Provide one Grove invitation during normal installation."
            join_grove=$(realpath -e -- "$2") || fail "The Grove invitation does not exist."
            [ -f "$join_grove" ] || fail "Use a Grove invitation JSON file."
            ;;
        --grove-ca)
            [ "$mode" = install ] && [ -z "$grove_ca" ] ||
                fail "Provide one Grove CA file during normal installation."
            case "$2" in
                *[[:cntrl:]]*) fail "The Grove CA path contains control characters." ;;
                /*) grove_ca=$2 ;;
                *) fail "Use an absolute path to the Grove CA file." ;;
            esac
            [ -f "$grove_ca" ] && [ -r "$grove_ca" ] || fail "The Grove CA file is not readable."
            ;;
        *) break ;;
    esac
    shift 2
done
[ "$#" -eq 1 ] || fail "Usage: sh deployment/install-linux.sh [MODE] [--keep-stopped] [--allow-delegated-systemd] [--port PORT] [--bind IPv4 --tls-cert PEM --tls-key PEM] [--verify-backup DIR | --join-grove FILE] [--expected-backup-sha256 SHA256] [--expected-package-sha256 SHA256] [--expected-node ID] [--expected-commit COMMIT] [--expected-current-commit COMMIT] [--grove-ca FILE] https://panel.example.net"
[ -z "$expected_backup_sha256" ] || [ -n "$backup" ] || fail "--expected-backup-sha256 requires --verify-backup."
if [ -n "$requested_cert" ] || [ -n "$requested_key" ]; then
    [ -n "$requested_cert" ] && [ -n "$requested_key" ] || fail "Supply both TLS paths."
fi
[ "$(uname -s)" = "Linux" ] || fail "This installer requires Linux."
[ "$(id -u)" -ne 0 ] || fail "Run as the dedicated Spearmint user."
origin=$1
valid_origin "$origin" ||
    fail "Enter the HTTPS scheme, host and optional port."
seed_state=${SPEARMINT_SEED_STATE_DIRECTORY:-}
if [ -n "$seed_state" ]; then
    absolute_path "$seed_state" || fail "Use an absolute Spearmint state directory."
fi

bundle=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
binary="$bundle/spearmint"
template="$bundle/deployment/spearmint.service"
manifest="$bundle/build-manifest.json"
[ -x "$binary" ] && [ -f "$template" ] && [ -f "$manifest" ] &&
    [ -f "$bundle/web/index.html" ] && [ -f "$bundle/checksums.json" ] ||
    fail "Extract the complete Linux native package first."
commit=$(sed -nE 's/^ *"commit": "([a-f0-9]{40})",? *$/\1/p' "$manifest")
[ "${#commit}" -eq 40 ] || fail "The package commit is missing."
[ -z "$expected_commit" ] || [ "$commit" = "$expected_commit" ] ||
    fail "The package commit does not match the selected candidate."
if [ "$mode" = upgrade ] || [ "$mode" = recover ]; then
    package_sha256=$(sha256sum < "$bundle/checksums.json") || fail "Could not read the package checksum manifest."
    package_sha256=${package_sha256%% *}
    [ -z "$expected_package_sha256" ] || [ "$package_sha256" = "$expected_package_sha256" ] ||
        fail "The package checksum manifest changed. Run the upgrade preflight again."
fi
"$binary" --version
set -- --origin "$origin"
if [ -n "$grove_ca" ]; then
    set -- "$@" --grove-ca "$grove_ca"
fi
if [ -n "$join_grove" ]; then
    "$binary" "$@" validate-config --join-grove "$join_grove" || fail "Check the Grove invitation and CA configuration."
else
    "$binary" "$@" validate-config
fi

if [ "$mode" != stage ]; then
    command -v curl >/dev/null && command -v ss >/dev/null ||
        fail "The panel health check requires curl and ss (iproute2)."
    systemctl --user show-environment >/dev/null ||
        fail "The systemd user manager is unavailable. Use --stage-only to prepare the files."
fi

releases="$base/releases"
release="$releases/$commit"
current="$base/current"
config="$HOME/.config/spearmint/environment"
unit="$HOME/.config/systemd/user/spearmint.service"
port_config="$unit.d/10-spearmint-port.conf"
delegation_config="$unit.d/20-spearmint-delegated-systemd.conf"
service=spearmint.service
case "$releases/" in
    "$bundle/"*) fail "Extract the package outside the installation directory before installing." ;;
esac
mkdir -p -- "$releases" "$(dirname -- "$config")" "$(dirname -- "$unit")"
exec 9>"$install_lock"
flock -n 9 || fail "A Spearmint install is already in progress."

port_override() {
    printf '[Service]\nExecStart=\nExecStart=%%h/.local/opt/spearmint/current/spearmint serve --port %s\n' "$1"
}

listener_override() {
    if [ -z "$panel_cert" ]; then
        port_override "$panel_port"
        return
    fi
    cert_arg=$(printf '%s' "$panel_cert" | sed -e 's/[\\"]/\\&/g' -e 's/[%$]/&&/g')
    key_arg=$(printf '%s' "$panel_key" | sed -e 's/[\\"]/\\&/g' -e 's/[%$]/&&/g')
    printf '# Port: %s\n# Bind: %s\n# Certificate: %s\n# Key: %s\n' "$panel_port" "$panel_bind" "$panel_cert" "$panel_key"
    printf '[Service]\nExecStart=\nExecStart=%%h/.local/opt/spearmint/current/spearmint serve --port %s --bind %s --tls-cert "%s" --tls-key "%s"\n' \
        "$panel_port" "$panel_bind" "$cert_arg" "$key_arg"
}

panel_port=8765
panel_bind=127.0.0.1
panel_cert=
panel_key=
expected_drop_in=
if [ -e "$port_config" ] || [ -L "$port_config" ]; then
    [ -f "$port_config" ] && [ ! -L "$port_config" ] || fail "Invalid panel port configuration: $port_config"
    if grep -q '^# Port: ' "$port_config"; then
        [ "$(wc -l < "$port_config")" -eq 7 ] || fail "Invalid TLS listener configuration: $port_config"
        panel_port=$(sed -n 's/^# Port: //p' "$port_config")
        panel_bind=$(sed -n 's/^# Bind: //p' "$port_config")
        panel_cert=$(sed -n 's/^# Certificate: //p' "$port_config")
        panel_key=$(sed -n 's/^# Key: //p' "$port_config")
        valid_bind "$panel_bind" && absolute_path "$panel_cert" && absolute_path "$panel_key" ||
            fail "Invalid TLS listener configuration: $port_config"
    else
        panel_port=$(sed -nE 's/^ExecStart=%h\/\.local\/opt\/spearmint\/current\/spearmint serve --port ([0-9]+)$/\1/p' "$port_config")
    fi
    valid_port "$panel_port" && listener_override | cmp -s -- - "$port_config" ||
        fail "Invalid panel listener configuration: $port_config"
    expected_drop_in=$port_config
elif [ ! -e "$current" ] && [ ! -L "$current" ] && [ "$mode" != upgrade ] && [ "$mode" != recover ]; then
    panel_port=${requested_port:-8765}
    panel_bind=${requested_bind:-127.0.0.1}
    panel_cert=$requested_cert
    panel_key=$requested_key
fi
delegation_override() {
    printf '[Service]\nNoNewPrivileges=no\n'
}
if [ -e "$delegation_config" ] || [ -L "$delegation_config" ]; then
    [ -f "$delegation_config" ] && [ ! -L "$delegation_config" ] &&
        delegation_override | cmp -s -- - "$delegation_config" ||
        fail "Invalid delegated systemd configuration: $delegation_config"
    delegated_systemd=true
fi
[ -z "$requested_port" ] || [ "$requested_port" = "$panel_port" ] ||
    fail "This installation uses panel port $panel_port. Use the same port."
[ -z "$requested_bind" ] || [ "$requested_bind" = "$panel_bind" ] ||
    fail "This installation uses panel address $panel_bind. Use the same address."
[ -z "$requested_cert" ] || { [ "$requested_cert" = "$panel_cert" ] && [ "$requested_key" = "$panel_key" ]; } ||
    fail "The requested TLS paths differ from the installed listener."
[ "$panel_bind" = 127.0.0.1 ] || [ -n "$panel_cert" ] || fail "A non-loopback address requires TLS."
if [ -n "$panel_cert" ]; then
    "$binary" --origin "$origin" validate-config --tls-cert "$panel_cert" --tls-key "$panel_key" ||
        fail "The TLS certificate or private key is unavailable."
    health_url=$origin
else
    health_url="http://127.0.0.1:$panel_port"
fi

release_root=$(readlink -f -- "$releases")

load_current_release() {
    [ -L "$current" ] && current_release=$(readlink -f -- "$current") || return 1
    current_commit=${current_release##*/}
    printf '%s\n' "$current_commit" | grep -Eq '^[a-f0-9]{40}$' &&
        [ "$current_release" = "$release_root/$current_commit" ]
}

if [ -e "$recovery" ] || [ -L "$recovery" ]; then
    [ "$mode" = recover ] || fail "An upgrade was interrupted. Use --recover-upgrade with the same HTTPS origin."
    [ -f "$recovery" ] && [ ! -L "$recovery" ] || fail "Invalid upgrade recovery file: $recovery"
elif [ "$mode" = recover ]; then
    printf 'No interrupted upgrade to recover.\n'
    exit 0
fi

if [ "$mode" = upgrade ] || [ "$mode" = recover ]; then
    [ -f "$config" ] && cmp -s "$unit" "$template" ||
        fail "Upgrade and recovery require an existing packaged Spearmint user service."
    load_current_release ||
        fail "The current link does not identify an installed Spearmint release."
fi
if [ "$mode" = upgrade ]; then
    previous_release=$current_release
    previous_commit=$current_commit
    [ -z "$expected_current_commit" ] || [ "$previous_commit" = "$expected_current_commit" ] ||
        fail "The installed commit changed. Run the upgrade preflight again."
    [ -x "$previous_release/spearmint" ] || fail "The current release executable is missing."
    schema=$(sed -nE 's/^ *"schema": ([1-9][0-9]*),? *$/\1/p' "$manifest")
    previous_schema=$(sed -nE 's/^ *"schema": ([1-9][0-9]*),? *$/\1/p' "$previous_release/build-manifest.json")
    case "$schema" in
        ''|*[!0-9]*) fail "The package schema is missing." ;;
    esac
    [ "$schema" = "$previous_schema" ] ||
        fail "This upgrade changes the database schema. Follow the backup and migration instructions."
elif [ "$mode" != recover ] && { [ -e "$current" ] || [ -L "$current" ]; }; then
    [ "$current/spearmint" -ef "$release/spearmint" ] ||
        fail "A different release is installed. Follow the package upgrade instructions."
fi
if [ -e "$unit" ] || [ -L "$unit" ]; then
    cmp -s "$unit" "$template" ||
        fail "A custom Spearmint service exists. Use its current deployment instructions."
fi
if [ -e "$config" ] || [ -L "$config" ]; then
    [ -f "$config" ] || fail "The Spearmint environment path is not a file."
    if [ -n "$seed_state" ]; then
        state_value=$(printf '%s' "$seed_state" | sed 's/[\\"]/\\&/g')
        grep -Fxq -- "SPEARMINT_STATE_DIR=\"$state_value\"" "$config" ||
            fail "The Spearmint service uses a different state directory."
    fi
fi

check_staged_package() {
    [ -n "$package_sha256" ] || return 0
    staged_sha256=$(sha256sum < "$1/checksums.json") || fail "Could not read the staged package checksum manifest."
    [ "${staged_sha256%% *}" = "$package_sha256" ] ||
        fail "The staged package checksum manifest changed. Run the upgrade preflight again."
}

if [ "$mode" = recover ]; then
    : # Recovery uses the releases already installed at the time of the switch.
elif [ -e "$release" ] || [ -L "$release" ]; then
    check_staged_package "$release"
    "$binary" --verify-package "$release" || fail "The existing release directory does not match this package."
    [ -x "$release/spearmint" ] || fail "The installed executable is not runnable."
else
    temporary=$(mktemp -d "$releases/.install.XXXXXXXX")
    trap 'rm -rf -- "$temporary"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    cp -a -- "$bundle/." "$temporary/"
    check_staged_package "$temporary"
    "$binary" --verify-package "$temporary"
    "$temporary/spearmint" --version >/dev/null
    mv -T -- "$temporary" "$release"
    trap - EXIT INT TERM
fi

panel_request() {
    path=$1
    shift
    if response=$(curl -q --noproxy '*' -fsS --max-time 1 --connect-to "::$panel_bind:$panel_port" \
        -H "Host: ${origin#https://}" "$@" "$health_url$path"); then
        printf '%s\n' "$response"
        return
    fi
    # Reverse proxies may terminate public TLS and use a private localhost certificate upstream.
    [ -n "$panel_cert" ] &&
        curl -q --noproxy '*' -fsS --max-time 1 --cacert "$panel_cert" --connect-to "::$panel_bind:$panel_port" \
            -H "Host: ${origin#https://}" "$@" "https://localhost:$panel_port$path"
}

wait_ready() {
    expected=$1
    check_web=${2:-false}
    attempts=40
    while [ "$attempts" -gt 0 ]; do
        pid=$(systemctl --user show "$service" -p MainPID --value)
        case "$pid" in
            ''|0|*[!0-9]*) ;;
            *)
                if [ "$(readlink -f -- "/proc/$pid/exe")" = "$expected" ] &&
                    ss -H -ltnp "sport = :$panel_port" |
                        awk -v address="$panel_bind:$panel_port" -v owner="pid=$pid," '$4 == address && index($0, owner) { found=1 } END { exit !found }' &&
                    panel_request /healthz 2>/dev/null | grep -qx '{"status":"ok"}' &&
                    { [ "$check_web" = false ] || panel_request / \
                        -o /dev/null -w '%{http_code} %{content_type}\n' 2>/dev/null |
                        grep -Eq '^200 text/html([[:space:]]*;|$)'; } &&
                    [ "$(systemctl --user show "$service" -p MainPID --value)" = "$pid" ] &&
                    systemctl --user is-active --quiet "$service"; then
                    return 0
                fi
                ;;
        esac
        attempts=$((attempts - 1))
        sleep .25
    done
    return 1
}

require_free_panel_port() {
    listeners=$(ss -H -ltn "sport = :$panel_port") || fail "Could not check the local panel port $panel_port."
    if printf '%s\n' "$listeners" |
        awk -v address="$panel_bind:$panel_port" -v port=":$panel_port" \
            '$4 == address || $4 == "0.0.0.0" port || $4 == "*" port { found=1 } END { exit !found }'; then
        fail "The local panel port $panel_port is already in use."
    fi
}

check_loaded_unit() {
    systemctl --user daemon-reload
    expected_drop_ins=$expected_drop_in
    if [ "$delegated_systemd" = true ]; then
        expected_drop_ins=${expected_drop_ins:+"$expected_drop_ins "}$delegation_config
    fi
    [ "$(systemctl --user show "$service" -p FragmentPath --value)" = "$unit" ] &&
        [ "$(systemctl --user show "$service" -p DropInPaths --value)" = "$expected_drop_ins" ] ||
        fail "The loaded user unit uses a custom definition. Follow its deployment instructions."
}

# Use the service manager's environment, including its EnvironmentFile parsing.
run_panel_command() {
    directory=$1
    shift
    systemd-run --user --quiet --pipe --collect --expand-environment=no \
        --property="EnvironmentFile=$config" --property=RuntimeMaxSec=30s \
        --working-directory="$directory" -- "$@"
}

switch_current() {
    ln -sfn -- "releases/$1" "$base/.upgrade-current" && mv -Tf -- "$base/.upgrade-current" "$current"
}

restore_upgrade() {
    read_upgrade_recovery || return 1
    if [ "$commit" != "$interrupted_commit" ]; then
        printf 'Use the package for interrupted upgrade commit %s to recover.\n' "$interrupted_commit" >&2
        return 1
    fi
    if [ -n "$restore_package_sha256" ] && [ "$package_sha256" != "$restore_package_sha256" ]; then
        printf 'Use the native package from the interrupted upgrade. Its checksum manifest does not match this package.\n' >&2
        return 1
    fi
    if [ -n "$restore_origin" ] && [ "$origin" != "$restore_origin" ]; then
        printf 'Use the HTTPS origin from the upgrade recovery record.\n' >&2
        return 1
    fi
    restore_release="$release_root/$restore_commit"
    restore_binary="$restore_release/spearmint"
    load_current_release && { [ "$current_commit" = "$restore_commit" ] || [ "$current_commit" = "$interrupted_commit" ]; } &&
        [ "$(readlink -f -- "$restore_release")" = "$restore_release" ] && [ -x "$restore_binary" ] || {
        printf 'The installed releases have changed since the interrupted upgrade.\n' >&2
        return 1
    }
    if [ "$mode" = recover ]; then
        run_panel_command "$restore_release" "$binary" validate-config --expected-origin "$origin" || {
            printf 'Check the existing panel environment in %s.\n' "$config" >&2
            return 1
        }
    fi
    if [ -n "$restore_node" ]; then
        restore_plan=$(run_panel_command "$restore_release" "$restore_binary" migrate --plan) &&
            [ "$(printf '%s\n' "$restore_plan" | sed -nE 's/^ *"node_id": "(spm1-[a-f0-9]{64})",? *$/\1/p')" = "$restore_node" ] || {
            printf 'The current node state does not match the upgrade recovery record.\n' >&2
            return 1
        }
        if ! printf '%s\n' "$restore_plan" | grep -Eq '^ *"migration_required": false,? *$'; then
            printf 'The previous release cannot use the current database schema. Follow the backup and recovery instructions.\n' >&2
            return 1
        fi
        if [ -n "$restore_schema" ] &&
            [ "$(printf '%s\n' "$restore_plan" | sed -nE 's/^ *"current_schema": ([1-9][0-9]*),? *$/\1/p')" != "$restore_schema" ]; then
            printf 'The database schema changed since the upgrade began. Follow the backup and recovery instructions.\n' >&2
            return 1
        fi
    fi
    restored=false
    if [ "$current_commit" = "$restore_commit" ]; then
        case "$restore_active:$(systemctl --user show "$service" -p ActiveState --value)" in
            false:inactive) restored=true ;;
            true:active) if wait_ready "$restore_binary" true; then restored=true; fi ;;
        esac
    fi
    if [ "$restored" = false ]; then
        systemctl --user stop "$service" && switch_current "$restore_commit" || return 1
        if [ "$restore_active" = true ]; then
            systemctl --user reset-failed "$service" && systemctl --user start "$service" || return 1
            if ! wait_ready "$restore_binary" true; then
                printf 'The previous panel did not pass its local health and Web entry checks.\n' >&2
                return 1
            fi
        else
            [ "$(systemctl --user show "$service" -p ActiveState --value)" = inactive ] || return 1
        fi
    fi
    rm -f -- "$base/.upgrade-current" && rm -- "$recovery" && sync "$base" || return 1
    printf 'Restored %s\n' "$restore_release"
}

if [ "$mode" = recover ]; then
    check_loaded_unit
    restore_upgrade || fail "Could not recover the upgrade. After resolving the issue above, retry --recover-upgrade."
    exit 0
fi

if [ "$mode" = upgrade ]; then
    check_loaded_unit
    run_panel_command "$release" "$release/spearmint" validate-config --expected-origin "$origin" --check-web ||
        fail "Check the panel environment in $config and the Web files for the new release."
    plan=$(run_panel_command "$current" "$release/spearmint" migrate --plan) ||
        fail "Could not read the existing panel state. Check its environment and state directory."
    node=$(printf '%s\n' "$plan" | sed -nE 's/^ *"node_id": "(spm1-[a-f0-9]{64})",? *$/\1/p')
    actual_schema=$(printf '%s\n' "$plan" | sed -nE 's/^ *"current_schema": ([1-9][0-9]*),? *$/\1/p')
    target_schema=$(printf '%s\n' "$plan" | sed -nE 's/^ *"target_schema": ([1-9][0-9]*),? *$/\1/p')
    [ "${#node}" -eq 69 ] && [ "$actual_schema" = "$schema" ] && [ "$target_schema" = "$schema" ] ||
        fail "The existing database schema does not match the package. Follow the backup and migration instructions."
    [ -z "$expected_node" ] || [ "$node" = "$expected_node" ] ||
        fail "The existing database does not belong to the selected Node ID."
    if ! printf '%s\n' "$plan" | grep -Eq '^ *"migration_required": false,? *$'; then
        fail "The existing database requires migration. Follow the backup and migration instructions."
    fi
    if [ "$commit" != "$previous_commit" ]; then
        next_plan=$(run_panel_command "$release" "$release/spearmint" migrate --plan) || fail "Could not read the same state from the new release. Use an absolute state directory."
        [ "$next_plan" = "$plan" ] || fail "The new release would use a different state directory. Use an absolute state directory."
    fi
    if [ -n "$backup" ]; then
        report=$("$release/spearmint" verify-backup "$backup") || fail "The upgrade backup did not pass verification."
        backup_node=$(printf '%s\n' "$report" | sed -nE 's/^ *"node_id": "(spm1-[a-f0-9]{64})",? *$/\1/p')
        [ "$backup_node" = "$node" ] && printf '%s\n' "$report" | grep -Eq '^ *"restore_compatible": true,? *$' ||
            fail "The upgrade backup belongs to a different node or schema."
        backup_sha256=$(printf '%s\n' "$report" | sed -nE 's/^ *"backup_sha256": "([a-f0-9]{64})",? *$/\1/p')
        [ -z "$expected_backup_sha256" ] || [ "$backup_sha256" = "$expected_backup_sha256" ] ||
            fail "The upgrade backup changed. Run the upgrade preflight again."
    fi
    was_active=false
    case "$(systemctl --user show "$service" -p ActiveState --value)" in
        active)
            [ "$keep_stopped" = false ] || fail "Stop the existing panel before using --keep-stopped."
            was_active=true
            wait_ready "$previous_release/spearmint" ||
                fail "The current panel is not healthy at this origin."
            ;;
        inactive) require_free_panel_port ;;
        *) fail "The user service is changing state. Check it before upgrading." ;;
    esac
    check_staged_package "$release"
    if [ "$check_only" = true ]; then
        printf 'Upgrade checks passed: %s -> %s\n' "$previous_commit" "$commit"
        backup_verified=false
        if [ -n "$backup" ]; then backup_verified=true; fi
        printf 'SPEARMINT_UPGRADE_PREFLIGHT={"version":1,"node_id":"%s","origin":"%s","previous_commit":"%s","candidate_commit":"%s","schema":%s,"panel_running":%s,"backup_verified":%s' \
            "$node" "$origin" "$previous_commit" "$commit" "$schema" "$was_active" "$backup_verified"
        printf ',"keep_stopped":%s' "$keep_stopped"
        if [ -n "${backup_sha256:-}" ]; then printf ',"backup_sha256":"%s"' "$backup_sha256"; fi
        printf ',"package_checksums_sha256":"%s"' "$package_sha256"
        report_target
        printf '}\n'
        exit 0
    fi
    if [ "$commit" = "$previous_commit" ] && [ "$was_active" = true ]; then
        wait_ready "$previous_release/spearmint" true || fail "The current panel does not serve its Web entry."
        printf 'Already running %s\n' "$release"
        exit 0
    fi
    if [ "$commit" = "$previous_commit" ] && [ "$keep_stopped" = true ]; then
        printf 'Already installed and stopped: %s\n' "$release"
        exit 0
    fi

    record=$(mktemp "$base/.upgrade-recovery.XXXXXXXX")
    finish_upgrade() {
        result=$?
        trap - EXIT
        trap '' HUP INT TERM
        if [ -f "$recovery" ] && ! restore_upgrade >&2; then
            printf 'Could not restore %s. Check systemctl --user status %s, then retry --recover-upgrade.\n' "$previous_release" "$service" >&2
        fi
        rm -f -- "$record"
        exit "$result"
    }
    trap finish_upgrade EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    printf '%s %s %s %s %s %s %s\n' "$previous_commit" "$commit" "$was_active" "$node" "$origin" "$schema" "$package_sha256" > "$record"
    sync "$record"
    mv -T -- "$record" "$recovery"
    sync "$base"
    switch_current "$commit"
    if [ "$keep_stopped" = true ]; then
        [ "$(systemctl --user show "$service" -p ActiveState --value)" = inactive ] ||
            fail "The panel did not remain stopped during the upgrade."
    else
        systemctl --user restart "$service" && wait_ready "$(readlink -f -- "$release/spearmint")" true ||
            fail "The new panel did not pass its local health and Web entry checks."
    fi
    rm -- "$recovery"
    sync "$base"
    printf 'Upgraded to %s\n' "$release"
    if [ "$keep_stopped" = true ]; then
        printf 'Panel remains stopped. Start it with: systemctl --user start %s\n' "$service"
    fi
    exit 0
fi

if [ ! -e "$config" ]; then
    (
        set -C
        {
            printf 'SPEARMINT_ORIGIN=%s\n' "$origin"
            if [ -n "$seed_state" ]; then
                state_value=$(printf '%s' "$seed_state" | sed 's/[\\"]/\\&/g')
                printf 'SPEARMINT_STATE_DIR="%s"\n' "$state_value"
            fi
            if [ -n "$grove_ca" ]; then
                ca_value=$(printf '%s' "$grove_ca" | sed 's/[\\"]/\\&/g')
                printf 'SPEARMINT_GROVE_CA="%s"\n' "$ca_value"
            fi
        } > "$config"
    )
fi
if [ "$mode" = install ]; then
    set -- --expected-origin "$origin" --check-web
    if [ -n "$grove_ca" ]; then
        set -- "$@" --expected-grove-ca "$grove_ca"
    fi
    run_panel_command "$release" "$release/spearmint" validate-config "$@" ||
        fail "Check the panel environment in $config and the installed Web files."
fi
if [ ! -e "$unit" ]; then
    install -m 644 -- "$template" "$unit"
fi
if { [ "$panel_port" != 8765 ] || [ -n "$panel_cert" ]; } && [ -z "$expected_drop_in" ]; then
    mkdir -p -- "${port_config%/*}"
    temporary=$(mktemp "$port_config.XXXXXXXX")
    trap 'rm -f -- "$temporary"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    listener_override > "$temporary"
    mv -T -- "$temporary" "$port_config"
    trap - EXIT INT TERM
    expected_drop_in=$port_config
fi
if [ "$delegated_systemd" = true ] && [ ! -e "$delegation_config" ]; then
    mkdir -p -- "${delegation_config%/*}"
    temporary=$(mktemp "$delegation_config.XXXXXXXX")
    trap 'rm -f -- "$temporary"' EXIT
    delegation_override > "$temporary"
    mv -T -- "$temporary" "$delegation_config"
    trap - EXIT
fi
if [ ! -L "$current" ] && [ ! -e "$current" ]; then
    ln -s -- "releases/$commit" "$current"
fi

if [ "$mode" = install ]; then
    check_loaded_unit
    if [ -n "$join_grove" ]; then
        seed_receipt=$(run_panel_command "$current" "$release/spearmint" setup-link --renew-if-expired --join-grove "$join_grove" --seed-receipt) ||
            fail "Could not prepare the Grove first-run link. Check the invitation and the node state."
    fi
    case "$(systemctl --user show "$service" -p ActiveState --value)" in
        active|activating)
            wait_ready "$(readlink -f -- "$release/spearmint")" true ||
                fail "The existing panel did not pass its local health and Web entry checks at $origin."
            ;;
        inactive|failed)
            require_free_panel_port
            finish_install() {
                result=$?
                trap - EXIT
                trap '' HUP INT TERM
                systemctl --user stop "$service" ||
                    printf 'Could not stop %s. Check systemctl --user status %s.\n' "$service" "$service" >&2
                exit "$result"
            }
            trap finish_install EXIT
            trap 'exit 129' HUP
            trap 'exit 130' INT
            trap 'exit 143' TERM
            systemctl --user start "$service" &&
                wait_ready "$(readlink -f -- "$release/spearmint")" true ||
                fail "The installed panel did not pass its local health and Web entry checks. Check journalctl --user -u $service."
            ;;
        *) fail "The user service is changing state. Check it before installing." ;;
    esac
    systemctl --user enable "$service"
    trap - EXIT HUP INT TERM
    printf 'Installed %s\n' "$release"
    if [ -z "$join_grove" ]; then
        run_panel_command "$current" "$release/spearmint" setup-link --status ||
            printf 'Could not read first-run status. Check journalctl --user -u %s for the setup file path.\n' "$service" >&2
    fi
else
    printf 'Staged %s\n' "$release"
fi
printf 'Service definition %s\nEnvironment %s\n' "$unit" "$config"
if [ -n "$panel_cert" ]; then
    printf 'Panel HTTPS listener %s:%s (%s)\n' "$panel_bind" "$panel_port" "$origin"
else
    printf 'Panel backend http://127.0.0.1:%s\n' "$panel_port"
fi
if [ -n "$join_grove" ]; then
    printf '%s\n' "$seed_receipt"
fi
