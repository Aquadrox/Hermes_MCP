#!/usr/bin/env bash
# Install or upgrade hermes-ngrok-mcp as a hardened systemd service (idempotent).
#
#   sudo ./deploy/install.sh --hermes-user <unix user running Hermes>
#
# What it does:
#   * creates the system user "hermes-ngrok" (no shell, no home);
#   * installs the application in /opt/hermes-ngrok-mcp (root-owned, read-only for the service),
#     with the exact dependency versions of uv.lock;
#   * creates /etc/hermes-ngrok-mcp/hermes-ngrok-mcp.env (root:hermes-ngrok 0640) if missing and
#     generates the API token shared with Hermes; existing settings are never overwritten;
#   * with --hermes-user, writes HERMES_NGROK_MCP_TOKEN into that user's ~/.hermes/.env and
#     pre-fills the Telegram settings from it when they are empty;
#   * installs and (re)starts the systemd unit, then checks that the service answers;
#   * with --nas-dir, also installs the NAS file manager: system user "hermes-nas", shared
#     folder permissions (owner + hermes-nas, through ACLs), /etc/hermes-nas/hermes-nas.env,
#     the access key shared with the MCP server, and the socket-activated hermes-nas units.
set -Eeuo pipefail

readonly APP=hermes-ngrok-mcp
readonly SERVICE_USER=hermes-ngrok
readonly PREFIX=/opt/hermes-ngrok-mcp
readonly CONFIG_DIR=/etc/hermes-ngrok-mcp
readonly ENV_FILE=$CONFIG_DIR/hermes-ngrok-mcp.env
readonly STATE_DIR=/var/lib/hermes-ngrok-mcp
readonly UNIT_FILE=/etc/systemd/system/hermes-ngrok-mcp.service
readonly ADMIN_BIN=/usr/local/bin/hermes-ngrok-admin
readonly UV_HINT="curl -LsSf https://astral.sh/uv/install.sh | sudo env UV_INSTALL_DIR=/usr/local/bin sh"
readonly NAS_USER=hermes-nas
readonly NAS_CONFIG_DIR=/etc/hermes-nas
readonly NAS_ENV_FILE=$NAS_CONFIG_DIR/hermes-nas.env
readonly NAS_UNIT_DIR=/etc/systemd/system
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly SRC_DIR

HERMES_USER=""
NAS_DIR=""
NAS_OWNER=""
START=1
UV_BIN="${UV_BIN:-}"

usage() {
    cat <<EOF
Usage: sudo $0 [--hermes-user USER] [--uv PATH] [--no-start]

  --hermes-user USER  Unix user running Hermes: its ~/.hermes/.env receives the API token
                      and provides the Telegram settings when they are not configured yet.
  --uv PATH           uv executable to use (default: auto-detect).
  --no-start          install without (re)starting the service.
  --nas-dir DIR       install the NAS file manager serving DIR (e.g. /var/MonNAS). Once installed,
                      later runs keep it without this option.
  --nas-owner USER    human user who keeps full access to DIR (default: its current owner).
EOF
}

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mWARNING:\033[0m %s\n' "$*" >&2; }
die() {
    printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --hermes-user)
            [[ $# -ge 2 ]] || die "--hermes-user needs a value"
            HERMES_USER="$2"
            shift 2
            ;;
        --uv)
            [[ $# -ge 2 ]] || die "--uv needs a value"
            UV_BIN="$2"
            shift 2
            ;;
        --no-start)
            START=0
            shift
            ;;
        --nas-dir)
            [[ $# -ge 2 ]] || die "--nas-dir needs a value"
            NAS_DIR="$2"
            shift 2
            ;;
        --nas-owner)
            [[ $# -ge 2 ]] || die "--nas-owner needs a value"
            NAS_OWNER="$2"
            shift 2
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            die "unknown option: $1"
            ;;
    esac
done

[[ $EUID -eq 0 ]] || die "run this script as root (sudo $0 ...)"
command -v systemctl >/dev/null || die "systemd is required"
[[ -f $SRC_DIR/pyproject.toml && -f $SRC_DIR/uv.lock ]] || die "run this script from a checkout of the repository"

# --- NAS options -------------------------------------------------------------------------------------
if [[ -z $NAS_DIR && -f $NAS_ENV_FILE ]]; then
    NAS_DIR="$(grep -E '^HERMES_NAS_ROOT=' "$NAS_ENV_FILE" | tail -n 1 | cut -d= -f2- || true)"
fi
if [[ -n $NAS_DIR ]]; then
    NAS_DIR="${NAS_DIR%/}"
    # The path ends up in a systemd unit and in setfacl/find calls: keep it simple and explicit.
    [[ $NAS_DIR =~ ^/[A-Za-z0-9._/-]+$ ]] ||
        die "--nas-dir must be an absolute path made of letters, digits, '.', '_', '-' and '/'"
    [[ $NAS_DIR != *..* ]] || die "--nas-dir cannot contain '..'"
    case "$NAS_DIR/" in
        /bin/* | /boot/* | /dev/* | /etc/* | /lib/* | /lib64/* | /opt/hermes-ngrok-mcp/* | /proc/* | /root/* | \
            /run/* | /sbin/* | /sys/* | /usr/* | /var/lib/hermes-ngrok-mcp/* | /var/lib/hermes-nas/* | /var/lib/docker/*)
            die "refusing to serve the system directory $NAS_DIR as a NAS"
            ;;
        /home/*)
            die "the NAS service cannot see /home (ProtectHome=yes): choose a folder such as /srv/nas or /var/MonNAS"
            ;;
        /var/ | /srv/ | /mnt/ | /media/ | /opt/ | /tmp/ | /var/tmp/)
            die "choose a dedicated folder inside $NAS_DIR, not $NAS_DIR itself"
            ;;
    esac
    command -v setfacl >/dev/null || die "setfacl is required for the NAS permissions: sudo apt install acl"
    if [[ -z $NAS_OWNER ]]; then
        [[ -d $NAS_DIR ]] || die "--nas-owner is required when $NAS_DIR does not exist yet"
        NAS_OWNER="$(stat -c %U "$NAS_DIR")"
    fi
    id -u "$NAS_OWNER" >/dev/null 2>&1 || die "unknown user: $NAS_OWNER"
    [[ $NAS_OWNER != "$NAS_USER" && $NAS_OWNER != root ]] ||
        die "--nas-owner must be a human account (e.g. --nas-owner $(logname 2>/dev/null || echo USER))"
    if [[ -n $HERMES_USER && $NAS_OWNER == "$HERMES_USER" ]]; then
        warn "the NAS owner is the agent's account: Hermes could then read the NAS without any MFA code"
    fi
fi

HERMES_HOME=""
if [[ -n $HERMES_USER ]]; then
    id -u "$HERMES_USER" >/dev/null 2>&1 || die "unknown user: $HERMES_USER"
    HERMES_HOME="$(getent passwd "$HERMES_USER" | cut -d: -f6)/.hermes"
fi

# --- helpers for dotenv files ---------------------------------------------------------------------------
# Value of KEY in a dotenv file (last occurrence, surrounding quotes removed), empty if absent.
env_get() {
    local file=$1 key=$2 value
    [[ -f $file ]] || return 0
    value="$(grep -E "^[[:space:]]*(export[[:space:]]+)?${key}=" "$file" | tail -n 1 | cut -d= -f2-)" || true
    value="${value%"${value##*[![:space:]]}"}"
    if [[ $value =~ ^\"(.*)\"$ || $value =~ ^\'(.*)\'$ ]]; then
        value="${BASH_REMATCH[1]}"
    fi
    printf '%s' "$value"
}

# Set KEY=VALUE in a dotenv file, replacing an existing (possibly commented) assignment.
env_set() {
    local file=$1 key=$2 value=$3 tmp
    tmp="$(mktemp "${file}.XXXXXX")"
    if grep -qE "^[[:space:]]*#?[[:space:]]*${key}=" "$file"; then
        awk -v key="$key" -v value="$value" '
            !done && $0 ~ "^[[:space:]]*#?[[:space:]]*" key "=" { print key "=" value; done = 1; next }
            { print }
        ' "$file" >"$tmp"
    else
        cat "$file" >"$tmp"
        printf '%s=%s\n' "$key" "$value" >>"$tmp"
    fi
    chmod --reference="$file" "$tmp"
    chown --reference="$file" "$tmp"
    mv -f "$tmp" "$file"
}

# True if PATH and all its parent directories are owned by root and not writable by others:
# root must never execute code that a less privileged account (e.g. the agent) could modify.
root_controlled() {
    local path
    path="$(readlink -f "$1")" || return 1
    while [[ -n $path ]]; do
        [[ "$(stat -c %u "$path")" == 0 ]] || return 1
        [[ $(("0$(stat -c %a "$path")" & 022)) -eq 0 || -k $path ]] || return 1
        [[ $path == / ]] && return 0
        path="$(dirname "$path")"
    done
}

find_uv() {
    local candidate
    if [[ -n $UV_BIN ]]; then
        [[ -x $UV_BIN ]] || die "uv not found at $UV_BIN"
        root_controlled "$UV_BIN" || die "$UV_BIN is not exclusively controlled by root"
        printf '%s' "$UV_BIN"
        return
    fi
    for candidate in "$(command -v uv || true)" /usr/local/bin/uv /root/.local/bin/uv /root/.cargo/bin/uv; do
        if [[ -n $candidate && -x $candidate ]] && root_controlled "$candidate"; then
            printf '%s' "$candidate"
            return
        fi
    done
}

if ! root_controlled "$SRC_DIR/deploy/install.sh" || ! root_controlled "$SRC_DIR/src"; then
    warn "the source tree $SRC_DIR is not exclusively controlled by root: an account able to modify it"
    warn "(for instance the agent's) could change what root installs. Prefer a root-owned clone:"
    warn "  sudo git clone https://github.com/Aquadrox/Hermes_MCP.git /usr/local/src/hermes-ngrok-mcp"
fi

# --- 1. service account --------------------------------------------------------------------------------------
log "Service user"
if id -u "$SERVICE_USER" >/dev/null 2>&1; then
    echo "    $SERVICE_USER already exists"
else
    nologin="$(command -v nologin || echo /usr/sbin/nologin)"
    useradd --system --user-group --no-create-home --home-dir "$STATE_DIR" --shell "$nologin" \
        --comment "hermes-ngrok-mcp service" "$SERVICE_USER"
    echo "    created $SERVICE_USER"
fi

# --- 2. application -------------------------------------------------------------------------------------------
log "Application in $PREFIX"
install -d -m 0755 -o root -g root "$PREFIX"
staging="$(mktemp -d "$PREFIX/.app.XXXXXX")"
cleanup() { rm -rf "$staging"; }
trap cleanup EXIT
cp -a "$SRC_DIR/pyproject.toml" "$SRC_DIR/uv.lock" "$SRC_DIR/README.md" "$SRC_DIR/LICENSE" "$SRC_DIR/src" "$staging/"
cp -a "$SRC_DIR/deploy/requirements.lock" "$staging/"
rm -rf "$PREFIX/app"
mv "$staging" "$PREFIX/app"
trap - EXIT

uv="$(find_uv)"
if [[ -n $uv ]]; then
    echo "    using $uv"
    uv_cache="$(mktemp -d)"
    # Managed Python interpreters must live under $PREFIX: the service cannot read /root.
    (cd "$PREFIX/app" && env UV_CACHE_DIR="$uv_cache" UV_PYTHON_INSTALL_DIR="$PREFIX/python" \
        UV_PROJECT_ENVIRONMENT="$PREFIX/venv" UV_NO_CONFIG=1 \
        "$uv" sync --frozen --no-dev --no-editable --compile-bytecode --quiet)
    rm -rf "$uv_cache"
else
    python="$(command -v python3 || true)"
    [[ -n $python ]] || die "neither uv nor python3 is available; install uv for root: $UV_HINT"
    "$python" -c 'import sys; sys.exit(sys.version_info < (3, 12))' ||
        die "Python >= 3.12 is required; install uv for root (it provides one): $UV_HINT"
    warn "uv not found: falling back to python3 -m venv + pip with hashed requirements"
    "$python" -m venv --clear "$PREFIX/venv"
    "$PREFIX/venv/bin/pip" install --quiet --disable-pip-version-check --require-hashes \
        -r "$PREFIX/app/requirements.lock"
    "$PREFIX/venv/bin/pip" install --quiet --disable-pip-version-check --no-deps "$PREFIX/app"
fi
chown -R root:root "$PREFIX"
chmod -R u=rwX,go=rX "$PREFIX"
version="$("$PREFIX/venv/bin/hermes-ngrok-mcp" --version)"
echo "    installed $version"

# --- 3. configuration and state --------------------------------------------------------------------------------
log "Configuration in $ENV_FILE"
install -d -m 0750 -o root -g "$SERVICE_USER" "$CONFIG_DIR"
if [[ -f $ENV_FILE ]]; then
    echo "    keeping the existing configuration"
else
    install -m 0640 -o root -g "$SERVICE_USER" "$SRC_DIR/deploy/hermes-ngrok-mcp.env.example" "$ENV_FILE"
    echo "    created from the template"
fi
chown root:"$SERVICE_USER" "$ENV_FILE"
chmod 0640 "$ENV_FILE"
install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_USER" "$STATE_DIR"

api_token="$(env_get "$ENV_FILE" HERMES_NGROK_API_TOKEN)"
if [[ -z $api_token ]]; then
    api_token="$("$PREFIX/venv/bin/hermes-ngrok-mcp" token)"
    env_set "$ENV_FILE" HERMES_NGROK_API_TOKEN "$api_token"
    echo "    generated HERMES_NGROK_API_TOKEN"
fi

if [[ -n $HERMES_HOME ]]; then
    hermes_env="$HERMES_HOME/.env"
    if [[ -z "$(env_get "$ENV_FILE" TELEGRAM_BOT_TOKEN)" && -f $hermes_env ]]; then
        bot_token="$(env_get "$hermes_env" TELEGRAM_BOT_TOKEN)"
        chat_id="$(env_get "$hermes_env" TELEGRAM_HOME_CHANNEL)"
        [[ -n $chat_id ]] || chat_id="$(env_get "$hermes_env" TELEGRAM_ALLOWED_USERS | cut -d, -f1 | tr -d '[:space:]')"
        if [[ -n $bot_token && -n $chat_id ]]; then
            env_set "$ENV_FILE" TELEGRAM_BOT_TOKEN "$bot_token"
            env_set "$ENV_FILE" TELEGRAM_CHAT_ID "$chat_id"
            echo "    Telegram notifications pre-filled from $hermes_env (chat $chat_id)"
        fi
    fi
    log "Hermes side ($hermes_env)"
    if [[ ! -f $hermes_env ]]; then
        install -d -m 0700 -o "$HERMES_USER" -g "$(id -gn "$HERMES_USER")" "$HERMES_HOME"
        install -m 0600 -o "$HERMES_USER" -g "$(id -gn "$HERMES_USER")" /dev/null "$hermes_env"
    fi
    env_set "$hermes_env" HERMES_NGROK_MCP_TOKEN "$api_token"
    echo "    HERMES_NGROK_MCP_TOKEN written"
fi

# --- 3b. NAS file manager ------------------------------------------------------------------------------------
if [[ -n $NAS_DIR ]]; then
    log "NAS file manager for $NAS_DIR"
    if id -u "$NAS_USER" >/dev/null 2>&1; then
        echo "    $NAS_USER already exists"
    else
        nologin="$(command -v nologin || echo /usr/sbin/nologin)"
        useradd --system --user-group --no-create-home --home-dir /var/lib/hermes-nas --shell "$nologin" \
            --comment "hermes-nas file manager" "$NAS_USER"
        echo "    created $NAS_USER"
    fi

    first_setup=1
    if [[ -d $NAS_DIR ]] && getfacl -p "$NAS_DIR" 2>/dev/null | grep -q "^default:group:$NAS_USER:"; then
        first_setup=0
    fi
    install -d -m 2770 -o "$NAS_OWNER" -g "$NAS_USER" "$NAS_DIR"
    chown "$NAS_OWNER:$NAS_USER" "$NAS_DIR"
    chmod 2770 "$NAS_DIR"
    acl="u:$NAS_OWNER:rwX,g:$NAS_USER:rwX"
    default_acl="d:u::rwX,d:g::rwX,d:o::---,d:u:$NAS_OWNER:rwX,d:g:$NAS_USER:rwX"
    if [[ $first_setup -eq 1 ]]; then
        # Existing content: give both parties access once (symbolic links are never followed).
        setfacl -R -P -m "$acl" "$NAS_DIR"
        find "$NAS_DIR" -xdev -type d -exec chmod g+s {} + -exec setfacl -m "$default_acl" {} +
        echo "    permissions set: $NAS_OWNER and $NAS_USER have full access, other users none"
    else
        setfacl -m "$acl,$default_acl" "$NAS_DIR"
        echo "    keeping the existing permissions"
    fi

    install -d -m 0750 -o root -g "$NAS_USER" "$NAS_CONFIG_DIR"
    if [[ ! -f $NAS_ENV_FILE ]]; then
        install -m 0640 -o root -g "$NAS_USER" "$SRC_DIR/deploy/hermes-nas.env.example" "$NAS_ENV_FILE"
        echo "    created $NAS_ENV_FILE"
    fi
    chown root:"$NAS_USER" "$NAS_ENV_FILE"
    chmod 0640 "$NAS_ENV_FILE"
    env_set "$NAS_ENV_FILE" HERMES_NAS_ROOT "$NAS_DIR"

    nas_port="$(env_get "$NAS_ENV_FILE" HERMES_NAS_PORT)"
    nas_port="${nas_port:-8766}"
    [[ $nas_port =~ ^[0-9]+$ && $nas_port -ge 1 && $nas_port -le 65535 ]] || die "invalid HERMES_NAS_PORT: $nas_port"
    env_set "$NAS_ENV_FILE" HERMES_NAS_PORT "$nas_port"
    env_set "$ENV_FILE" HERMES_NGROK_NAS_PORT "$nas_port"

    # The same key on both sides; ngrok injects it into authenticated requests only.
    nas_key="$(env_get "$NAS_ENV_FILE" HERMES_NAS_ACCESS_KEY)"
    [[ -n $nas_key ]] || nas_key="$(env_get "$ENV_FILE" HERMES_NGROK_NAS_ACCESS_KEY)"
    if [[ -z $nas_key ]]; then
        nas_key="$("$PREFIX/venv/bin/hermes-ngrok-mcp" token)"
        echo "    generated the NAS access key"
    fi
    env_set "$NAS_ENV_FILE" HERMES_NAS_ACCESS_KEY "$nas_key"
    env_set "$ENV_FILE" HERMES_NGROK_NAS_ACCESS_KEY "$nas_key"
    timezone="$(env_get "$ENV_FILE" HERMES_NGROK_TIMEZONE)"
    if [[ -n $timezone ]]; then
        env_set "$NAS_ENV_FILE" HERMES_NAS_TIMEZONE "$timezone"
    fi
fi

# --- 4. systemd ---------------------------------------------------------------------------------------------
log "systemd unit"
install -m 0644 -o root -g root "$SRC_DIR/deploy/hermes-ngrok-mcp.service" "$UNIT_FILE"
install -m 0755 -o root -g root "$SRC_DIR/deploy/hermes-ngrok-admin" "$ADMIN_BIN"
if [[ -n $NAS_DIR ]]; then
    sed "s|@NAS_PORT@|$nas_port|g" "$SRC_DIR/deploy/hermes-nas.socket" >"$NAS_UNIT_DIR/hermes-nas.socket"
    sed "s|@NAS_ROOT@|$NAS_DIR|g" "$SRC_DIR/deploy/hermes-nas.service" >"$NAS_UNIT_DIR/hermes-nas.service"
    chmod 0644 "$NAS_UNIT_DIR/hermes-nas.socket" "$NAS_UNIT_DIR/hermes-nas.service"
fi
systemctl daemon-reload
systemctl enable --quiet "$APP.service"
if [[ -n $NAS_DIR ]]; then
    systemctl enable --quiet hermes-nas.socket
fi

port="$(env_get "$ENV_FILE" HERMES_NGROK_PORT)"
port="${port:-8765}"
if [[ $START -eq 1 ]]; then
    systemctl restart "$APP.service"
    healthy=0
    for _ in $(seq 1 30); do
        if "$PREFIX/venv/bin/python" -c "import sys, urllib.request
sys.exit(urllib.request.urlopen('http://127.0.0.1:$port/healthz', timeout=1).status != 200)" 2>/dev/null; then
            healthy=1
            break
        fi
        sleep 0.5
    done
    if [[ $healthy -eq 1 ]]; then
        echo "    $APP is running on 127.0.0.1:$port"
    else
        journalctl -u "$APP.service" -n 40 --no-pager >&2 || true
        die "the service did not become healthy; see the log above"
    fi
    if [[ -n $NAS_DIR ]]; then
        # New code or settings: stop the running instance; the socket starts a fresh one on demand.
        systemctl stop hermes-nas.service
        systemctl restart hermes-nas.socket
        if NAS_KEY="$nas_key" "$PREFIX/venv/bin/python" -c "import os, sys, urllib.request
request = urllib.request.Request('http://127.0.0.1:$nas_port/api/health', headers={'X-Hermes-NAS-Key': os.environ['NAS_KEY']})
sys.exit(urllib.request.urlopen(request, timeout=20).status != 200)" 2>/dev/null; then
            echo "    hermes-nas answers on 127.0.0.1:$nas_port (socket-activated)"
        else
            journalctl -u hermes-nas.service -n 40 --no-pager >&2 || true
            die "the NAS did not answer; see the log above"
        fi
    fi
fi

# --- 5. next steps ---------------------------------------------------------------------------------------------
"$ADMIN_BIN" check || true
if [[ -n $NAS_DIR ]]; then
    "$ADMIN_BIN" nas check || true
fi
cat <<EOF

Installed $version.

Next steps:
  1. Put your ngrok authtoken in $ENV_FILE (NGROK_AUTHTOKEN=...),
     check TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID, then:
         sudo systemctl restart $APP
  2. Declare the server in Hermes (~/.hermes/config.yaml), then run /reload-mcp
     (or 'hermes gateway restart'):

mcp_servers:
  ngrok:
    url: "http://127.0.0.1:$port/mcp"
    headers:
      Authorization: "Bearer \${HERMES_NGROK_MCP_TOKEN}"
    timeout: 120
    connect_timeout: 30
    sampling:
      enabled: false

EOF
if [[ -z $HERMES_USER ]]; then
    cat <<EOF
     and add this line to the Hermes user's ~/.hermes/.env:
         HERMES_NGROK_MCP_TOKEN=$api_token

EOF
fi
cat <<EOF
  3. Ask Hermes on Telegram to set up MFA ("configure le MFA pour les tunnels").

Administration: sudo hermes-ngrok-admin --help   |   Logs: journalctl -u $APP -f
Audit trail:    sudo hermes-ngrok-admin audit --since 24h
EOF
if [[ -n $NAS_DIR ]]; then
    cat <<EOF
NAS:            $NAS_DIR, opened by Hermes with "nas_open" (one MFA code)
                sudo hermes-ngrok-admin nas audit --since 24h   |   journalctl -u hermes-nas -f
EOF
fi
