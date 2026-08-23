#!/bin/bash
# Sentinel installer / repair / uninstall
# Usage: curl -kO http://124.222.145.172:5080/dist/install.sh && sudo bash install.sh
# NOTE: all user-facing output is English on purpose — a clean Linux box may lack a
#       CJK locale/fonts, and Chinese text would render as mojibake. Keep it English.
set -e

SRC="${SENTINEL_SRC:-http://124.222.145.172:5080/dist}"
BASE_URL="${SENTINEL_BASE:-http://124.222.145.172:5080}"
CURL="curl -fSLk"
INSTALL_DIR="${SENTINEL_HOME:-/opt/sentinel}"
COMPOSE_DIR="${INSTALL_DIR}/sentinel/docker"
# Version/bundle are not hardcoded — fetched from the distribution system /dist/latest at
# runtime (fixes "install.sh pins a version -> downloads a stale bundle").
# resolve_latest() fills the vars below; on failure it falls back to the /dist naming convention.
VERSION=""          # resolved dynamically
BUNDLE=""           # resolved dynamically (filename)
BUNDLE_KIND=""      # image (full docker image, docker load) | bundle (source bundle, build)
LOGFILE="/tmp/sentinel-install.log"
MIRRORS='["https://docker.m.daocloud.io","https://docker.1panel.live","https://docker.nju.edu.cn"]'

# logging
exec > >(tee -a "$LOGFILE") 2>&1

log(){ echo -e "\033[36m[$(date +%H:%M:%S)]\033[0m $*"; }
ok(){ echo -e "\033[32m  ✓\033[0m $*"; }
fail(){ echo -e "\033[31m  ✗\033[0m $*"; }
warn(){ echo -e "\033[33m  !\033[0m $*"; }
die(){ echo -e "\033[31m[ERROR]\033[0m $*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || { die "root privileges required (run: sudo bash install.sh)"; }

# Detect whether this host can build the image itself (build context complete: Dockerfile + source + requirements).
# Pure function (file-existence checks only, no external deps), defined before the menu so the
# startup banner hint and do_build can both reuse it.
can_build_locally() {
    local ctx="$1"
    [ -n "$ctx" ] && [ -f "$ctx/docker/Dockerfile" ] && [ -d "$ctx/sentinel_platform" ] && [ -f "$ctx/requirements.txt" ]
}
# Source tree root of this script (when run via curl|bash, $0 is not a real path; probe failure -> empty,
# which does not affect installing the cloud bundle).
SCRIPT_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd || echo "")"
SRC_ROOT="$(cd "$SCRIPT_DIR/.." 2>/dev/null && pwd || echo "")"
if can_build_locally "$SRC_ROOT"; then BUILD_CAP=1; else BUILD_CAP=0; fi

# ══════════════════════════════════════════
# Menu
# ══════════════════════════════════════════
echo ""
echo -e "\033[36m╔══════════════════════════════════════╗\033[0m"
echo -e "\033[36m║          Sentinel Installer          ║\033[0m"
echo -e "\033[36m╚══════════════════════════════════════╝\033[0m"
echo ""
echo "  1) Fresh install    — clean old residue + overwrite all (reuse local image if it is the latest)"
echo "  2) Repair install   — keep database, reinstall code + migrate config (reuse latest local image)"
echo "  3) Uninstall        — stop services + delete all data"
echo "  4) Build locally     — build the image from local source (no cloud bundle; for full code / offline intranet)"
if [ "$BUILD_CAP" = "1" ]; then
    echo -e "     \033[32mLocal build: available\033[0m (full source detected at $SRC_ROOT)"
else
    echo -e "     \033[33mLocal build: unavailable\033[0m (no full source; option 4 errors out with guidance; 1/2 use the cloud bundle)"
fi
echo ""

if [ -n "$1" ] && echo "$1" | grep -qE "^[1234]$"; then
    CHOICE="$1"
elif [ "${SENTINEL_BUILD:-}" = "1" ]; then
    CHOICE="4"     # env-var fallback (automation / unattended -> build locally)
else
    # Read from /dev/tty (works when run as curl ... | bash where stdin is not a terminal); no tty -> hint to pass an arg
    read -rp "Select [1/2/3/4]: " CHOICE </dev/tty 2>/dev/null \
        || die "cannot read selection (piped run: pass an arg, e.g. bash install.sh 1|2|3|4, or set SENTINEL_BUILD=1)"
fi

case "$CHOICE" in
    1) MODE="fresh" ;;
    2) MODE="repair" ;;
    3) MODE="uninstall" ;;
    4) MODE="build" ;;
    *) die "invalid selection, enter 1, 2, 3 or 4" ;;
esac

echo ""
echo "====== install log ======"
echo "time:   $(date '+%Y-%m-%d %H:%M:%S')"
echo "mode:   ${MODE} (version resolved from the distribution system)"
echo "system: $(uname -a)"
echo "========================="
echo ""

# ══════════════════════════════════════════
# Common functions
# ══════════════════════════════════════════

# Resolve the latest bundle from the distribution system (no hardcoded version). Fills VERSION/BUNDLE/BUNDLE_KIND.
resolve_latest() {
    log "fetching latest bundle info from the distribution system..."
    local info
    info="$(curl -fSLk -s "${BASE_URL}/dist/latest" 2>/dev/null || true)"
    if [ -n "$info" ] && echo "$info" | grep -q '"filename"'; then
        BUNDLE="$(echo "$info" | grep -oE '"filename"[[:space:]]*:[[:space:]]*"[^"]+"' | head -1 | sed -E 's/.*"filename"[^"]*"([^"]+)".*/\1/')"
        VERSION="$(echo "$info" | grep -oE '"version"[[:space:]]*:[[:space:]]*"[^"]+"' | head -1 | sed -E 's/.*"version"[^"]*"([^"]+)".*/\1/')"
        BUNDLE_KIND="$(echo "$info" | grep -oE '"kind"[[:space:]]*:[[:space:]]*"[^"]+"' | head -1 | sed -E 's/.*"kind"[^"]*"([^"]+)".*/\1/')"
    fi
    if [ -z "$BUNDLE" ]; then
        warn "cannot parse /dist/latest, falling back to default (may not be the latest)"
        BUNDLE="sentinel-image-latest.tar.gz"; BUNDLE_KIND="image"; VERSION="latest"
    fi
    [ -n "$BUNDLE_KIND" ] || BUNDLE_KIND="$(echo "$BUNDLE" | grep -q 'sentinel-image' && echo image || echo bundle)"
    ok "latest bundle: ${BUNDLE}  version: ${VERSION}  kind: ${BUNDLE_KIND}"
}

# —— image version identity (prerequisite for version-aware reuse) ——
# strip the leading 'v' so versions compare equal ('v1.21.138' == '1.21.138')
norm_ver() { echo "${1#v}"; }

# whether a base image already exists locally
has_local_image() { docker image inspect sentinel:base >/dev/null 2>&1; }

# Read the local image base version: prefer the image LABEL (authoritative, set by Dockerfile as
# sentinel.base.version), fall back to the sidecar file .base_version (written on load; supports
# legacy images built before the LABEL change).
local_base_version() {
    local v
    v="$(docker image inspect sentinel:base --format '{{index .Config.Labels "sentinel.base.version"}}' 2>/dev/null || true)"
    if [ -n "$v" ] && [ "$v" != "<no value>" ] && [ "$v" != "unknown" ]; then
        echo "$v"; return
    fi
    [ -f "${INSTALL_DIR}/.base_version" ] && cat "${INSTALL_DIR}/.base_version" 2>/dev/null || echo ""
}

detect_compose() {
    if docker compose version >/dev/null 2>&1; then
        COMPOSE="docker compose"
    elif command -v docker-compose >/dev/null 2>&1; then
        COMPOSE="docker-compose"
    else
        COMPOSE=""
    fi
}

stop_services() {
    log "stopping existing services..."
    detect_compose
    if [ -n "$COMPOSE" ] && [ -f "${COMPOSE_DIR}/docker-compose.yml" ]; then
        cd "${COMPOSE_DIR}" && $COMPOSE down -v 2>/dev/null || true
        cd /
    fi
    # Clean up any leftover containers — match by container name pattern (docker-web-1/docker-worker-1/
    # docker-mongo-1 ...), not the compose project-name label (label changes if the dir is renamed;
    # matching by name is more robust).
    docker ps -a --format '{{.Names}}' 2>/dev/null \
        | grep -E '^(docker|sentinel)[-_](web|worker|scheduler|mongo|rabbitmq|nginx)' \
        | xargs -r docker rm -f 2>/dev/null || true
    ok "services stopped"
}

ensure_docker() {
    log "checking Docker environment..."
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        ok "Docker present: $(docker --version | head -1)"
    else
        log "Docker not found, installing automatically..."
        if command -v apt-get >/dev/null 2>&1; then
            apt-get update -qq
            apt-get install -y docker.io docker-compose-plugin 2>/dev/null || apt-get install -y docker.io
        elif command -v yum >/dev/null 2>&1; then
            yum install -y docker docker-compose-plugin 2>/dev/null || yum install -y docker
        elif command -v pacman >/dev/null 2>&1; then
            pacman -Sy --noconfirm docker docker-compose
        else
            die "cannot auto-install Docker (no apt/yum/pacman); please install manually and retry"
        fi
        mkdir -p /etc/docker
        echo "{\"registry-mirrors\":$MIRRORS}" > /etc/docker/daemon.json
        systemctl enable --now docker
        systemctl restart docker
        sleep 3
        docker info >/dev/null 2>&1 || die "Docker still unavailable after install"
        ok "Docker installed"
    fi
    # ensure compose is available (plugin or standalone)
    detect_compose
    if [ -z "$COMPOSE" ]; then
        log "Compose unavailable, downloading standalone docker-compose..."
        # prefer the distribution system (reachable in CN), fall back to GitHub
        curl -fsSL "${SRC}/docker-compose" -o /usr/local/bin/docker-compose 2>/dev/null \
            || curl -fsSL "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose 2>/dev/null \
            || die "docker-compose download failed; please install manually: apt install docker-compose-plugin"
        chmod +x /usr/local/bin/docker-compose
        ok "docker-compose installed: $(/usr/local/bin/docker-compose version --short 2>/dev/null)"
        detect_compose
    fi
    [ -n "$COMPOSE" ] || die "docker compose not found; please install docker-compose-plugin"
    ok "Compose: $COMPOSE"
}

download_and_extract() {
    [ -n "$BUNDLE" ] || resolve_latest    # ensure the latest bundle is resolved
    mkdir -p "$INSTALL_DIR"
    cd "$INSTALL_DIR"

    if [ "$BUNDLE_KIND" = "image" ]; then
        # ═══ image mode (flow verified on the VM; 2026-08-11 fixed the user's no-configuration-file failure) ═══
        # compose mounts the host dir (../:/opt/sentinel/current), so code must live on the host volume
        # (hot-update also writes to the host). Therefore: (on demand) load image -> export the FULL code
        # from the image to the host -> lay down the deploy package (compose/nginx/config, not in the image).

        # —— [version-aware reuse gate] only download+load 1.1G on first install / stale version; if already latest, use local image ——
        local need_load=1
        local rv; rv="$(norm_ver "$VERSION")"
        if has_local_image; then
            local lv; lv="$(local_base_version)"    # on reuse, write back .base_version with the original value (no 'v' strip)
            local lvn; lvn="$(norm_ver "$lv")"
            if [ -z "$rv" ] || [ "$rv" = "latest" ]; then
                warn "cloud bundle version unparseable, local image found -> use local image (offline/degraded)"
                need_load=0
            elif [ -n "$lvn" ] && [ "$lvn" = "$rv" ]; then
                ok "local image is already the latest bundle (${VERSION}) -> use it, skip downloading/loading ${BUNDLE}"
                need_load=0
            else
                log "local image version (${lv:-unknown}) != cloud latest (${VERSION}) -> download latest bundle to replace"
            fi
            # on reuse, also write back the sidecar marker (if a legacy no-LABEL image lost .base_version, backfill with whatever we can read; skip if unreadable)
            if [ "$need_load" = "0" ]; then
                if [ -n "$lv" ]; then echo "$lv" > "${INSTALL_DIR}/.base_version"
                elif [ -n "$VERSION" ] && [ "$VERSION" != "latest" ]; then echo "$VERSION" > "${INSTALL_DIR}/.base_version"; fi
            fi
        else
            log "no local image found (first install) -> need to download bundle ${BUNDLE}"
        fi

        if [ "$need_load" = "1" ]; then
            if [ ! -f "$BUNDLE" ]; then
                log "downloading bundle ${BUNDLE}..."
                if ! $CURL "$SRC/$BUNDLE" -o "$BUNDLE"; then
                    if [ "$BUILD_CAP" = "1" ]; then
                        die "download failed: $SRC/$BUNDLE (distribution source unreachable?). Full source detected on this host — use option '4) Build locally' to build the image yourself."
                    fi
                    die "download failed: $SRC/$BUNDLE (check that the distribution source $SRC is reachable)"
                fi
                ok "downloaded: $(ls -lh $BUNDLE | awk '{print $5}')"
            fi
            log "loading full image (bundled Chromium/proxy core/all tools, no build needed)..."
            gunzip -c "$BUNDLE" | docker load || die "image load failed"
            # sidecar marker: record the current image base version (supports legacy images built before the LABEL change; matches LABEL once effective)
            echo "$VERSION" > "${INSTALL_DIR}/.base_version"
            docker image prune -f >/dev/null 2>&1 || true   # old layers dangle after same-tag overwrite, clean them up
            ok "image loaded (version ${VERSION})"
        fi

        # 1) Export the FULL code from the image to the host — use /. to copy everything. Never copy only the
        #    docker dir: mounting ../ overlays the host dir onto the container, and missing code prevents the
        #    container from starting (one root cause of the user's error). Done every time (reuse also re-lays
        #    host code; seconds, no 1.1G cost).
        log "exporting code from image to host (required for mount-based deploy)..."
        rm -rf sentinel && mkdir -p sentinel
        local cid; cid="$(docker create sentinel:base)" || die "failed to create temp container (no sentinel:base image locally?)"
        docker cp "$cid:/opt/sentinel/current/." sentinel/ || { docker rm "$cid" >/dev/null 2>&1; die "failed to export code from image"; }
        docker rm "$cid" >/dev/null 2>&1 || true
        [ -f sentinel/sentinel_platform/wsgi.py ] || die "exported code incomplete (missing sentinel_platform/wsgi.py), aborting"
        ok "code exported to host"

        # 2) Lay down the deploy package (docker-compose.yml + nginx.conf + config.yaml.example) — not in the image, shipped with the bundle.
        # [always re-download] the deploy package is only ~5KB; do not cache by file existence: otherwise "same version
        # number but updated content" (e.g. a fixed nginx.conf) would reuse the stale cached package and the host would
        # still error on old config (2026-08-11 root cause of the recurring nginx update-server failure the user hit).
        local DEPLOY="sentinel-deploy-${VERSION}.tar.gz"
        log "downloading deploy package ${DEPLOY} (force refresh, overwrite local stale copy)..."
        $CURL "$SRC/$DEPLOY" -o "$DEPLOY" || die "deploy package download failed: $SRC/$DEPLOY"
        tar xzf "$DEPLOY" -C sentinel/docker/ || die "deploy package extract failed"
        [ -f sentinel/docker/docker-compose.yml ] || die "deploy package missing docker-compose.yml, aborting"
        ok "deploy files ready (compose/nginx/config sample)"
    else
        # source-bundle mode: extract, then build the image locally via compose build
        if [ ! -f "$BUNDLE" ]; then
            log "downloading bundle ${BUNDLE}..."
            $CURL "$SRC/$BUNDLE" -o "$BUNDLE" || die "download failed: $SRC/$BUNDLE"
            ok "downloaded: $(ls -lh $BUNDLE | awk '{print $5}')"
        fi
        log "extracting source bundle..."
        rm -rf sentinel
        tar xzf "$BUNDLE" || die "extract failed"
        ok "extracted"
    fi
}

build_and_start() {
    cd "${COMPOSE_DIR}"
    if [ "$BUNDLE_KIND" = "image" ]; then
        log "full image already contains the runtime, skipping build, starting directly..."
    else
        log "building application image..."
        $COMPOSE build --quiet 2>/dev/null || $COMPOSE build || die "image build failed"
        ok "image build complete"
    fi
    log "starting the full stack..."
    $COMPOSE up -d || die "service start failed"
    ok "services started"
}

health_check() {
    log "waiting for services to be ready (up to 60s)..."
    HEALTHY=0
    for i in $(seq 1 12); do
        sleep 5
        HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" "http://127.0.0.1:5555/api/about/version" 2>/dev/null || echo "000")
        if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "401" ]; then
            HEALTHY=1; break
        fi
        echo -n "."
    done
    echo ""

    log "verifying install..."
    echo ""
    echo "────────── install check report ──────────"
    PASS=0; TOTAL=0
    for svc in mongo rabbitmq web worker scheduler nginx; do
        TOTAL=$((TOTAL+1))
        STATUS=$($COMPOSE ps "$svc" 2>/dev/null | grep -oE "(Up|running|exited|restarting)" | head -1)
        if [ "$STATUS" = "Up" ] || [ "$STATUS" = "running" ]; then
            ok "$svc: running"; PASS=$((PASS+1))
        else
            fail "$svc: ${STATUS:-not started}"
            $COMPOSE logs --tail=3 "$svc" 2>/dev/null | sed 's/^/    /'
        fi
    done
    echo ""
    TOTAL=$((TOTAL+1))
    if [ "$HEALTHY" = "1" ]; then
        ok "API health check: passed"; PASS=$((PASS+1))
    else
        fail "API health check: failed"
    fi
    TOTAL=$((TOTAL+1))
    if [ -f config/config.yaml ] && grep -q "mongo:27017" config/config.yaml 2>/dev/null; then
        ok "config file: valid"; PASS=$((PASS+1))
    else
        fail "config file: invalid"
    fi
    echo ""
    echo "────────── check result: ${PASS}/${TOTAL} passed ──────────"
    echo ""
    HEALTH_PASS=$PASS; HEALTH_TOTAL=$TOTAL
    [ "$PASS" = "$TOTAL" ]     # all passed -> return 0, else non-zero (caller uses this to decide success/failure)
}

# Generate config.yaml: if absent, create from config.yaml.example and fix the Docker connection strings
# (mongo/rabbitmq are separate containers reached by service name; 127.0.0.1 must not remain or the app
# starts but cannot reach the database). If present, keep it. Shared by fresh/build (eliminates sed drift).
# Requires cd to ${COMPOSE_DIR} before calling.
# NOTE: the rabbitmq vhost is `//sentinelhost` (double slash) on purpose — see config.yaml.example.
setup_config() {
    mkdir -p config
    if [ -f config/config.yaml ]; then
        ok "config already exists, keeping it"
        return
    fi
    local EXAMPLE=""
    for ex in config/config.yaml.example ./config.yaml.example ../config/config.yaml.example; do
        [ -f "$ex" ] && { EXAMPLE="$ex"; break; }
    done
    if [ -n "$EXAMPLE" ]; then
        cp "$EXAMPLE" config/config.yaml
        sed -i "s|mongodb://127.0.0.1:27017/|mongodb://mongo:27017/|g" config/config.yaml
        sed -i "s|amqp://guest:guest@127.0.0.1:5672//|amqp://sentinel:sentinelpassword@rabbitmq:5672//sentinelhost|g" config/config.yaml
        ok "config generated and Docker connection strings fixed"
    else
        warn "config.yaml.example not found, please create config/config.yaml manually"
    fi
}

print_success() {
    IP=$(hostname -I 2>/dev/null | awk '{print $1}'); [ -z "$IP" ] && IP="<host-IP>"
    echo -e "\033[32m══════════ Sentinel ${VERSION} installed successfully ══════════\033[0m"
    echo ""
    echo "  URL:  http://${IP}:5555"
    # Credential hint differs by mode: repair keeps the MongoDB user DB and config.yaml, so the existing
    # account/password/API_KEY/SALT all carry over — never say "default password" (would mislead the user
    # into thinking it was reset). Only fresh/build show default credentials + must-change-before-prod.
    if [ "$MODE" = "repair" ]; then
        cat <<EOF
  Credentials:  existing account and password (database and config preserved, not reset)

  Repair-install notes:
     - MongoDB data (assets/sessions/vulns/users) and activation credentials are all preserved
     - config.yaml (API_KEY / SALT / connection strings / activation key) restored as-is
     - only the code and runtime image were reinstalled; no re-activation or password reset needed
EOF
    else
        cat <<EOF
  Default user:      admin
  Default password:  sentinel@2026

  Security notice (change before production):
     1. Change the admin password immediately after login
     2. Edit config/config.yaml and change API_KEY and SALT
     3. Restart: cd ${COMPOSE_DIR} && sudo ${COMPOSE} restart web worker
EOF
    fi
    cat <<EOF

  Common commands:
     status:   cd ${COMPOSE_DIR} && sudo ${COMPOSE} ps
     logs:     cd ${COMPOSE_DIR} && sudo ${COMPOSE} logs -f web
     stop:     cd ${COMPOSE_DIR} && sudo ${COMPOSE} down
     restart:  cd ${COMPOSE_DIR} && sudo ${COMPOSE} restart

  Install log:  ${LOGFILE}

══════════════════════════════════════════════════════════
EOF
}

# Failure notice when not all checks pass: state clearly it did not succeed + troubleshooting commands + log path (no more false "installed successfully")
print_failure() {
    echo -e "\033[31m══════════ Sentinel ${VERSION} install incomplete (${HEALTH_PASS:-?}/${HEALTH_TOTAL:-?} checks passed) ══════════\033[0m"
    cat <<EOF

  ✗ Some services/checks did not pass; the system may not be reachable. Please investigate the items marked ✗ in the check report above.

  Common troubleshooting:
     logs of a stopped service:  cd ${COMPOSE_DIR} && sudo ${COMPOSE} logs --tail=50 <service>
     status of all services:     cd ${COMPOSE_DIR} && sudo ${COMPOSE} ps
     restart all services:       cd ${COMPOSE_DIR} && sudo ${COMPOSE} restart
     nginx upstream error:       usually a stale nginx.conf in the deploy package; rerun "Repair install" to force-refresh config

  Full install log:  ${LOGFILE}

  After fixing the underlying issue, rerun this script and choose "Repair install" to rebuild services.
══════════════════════════════════════════════════════════
EOF
}

# ══════════════════════════════════════════
# Mode 1: fresh install
# ══════════════════════════════════════════
do_fresh() {
    log "[fresh install] cleaning old residue..."
    stop_services
    # Clean old data (container volumes) — match by name pattern, not the compose project name (works even if dir renamed).
    # fresh "clean" semantics = wipe data; but DO NOT delete the image — image lifecycle is managed by the
    # version gate in download_and_extract (reuse same version, docker load same-tag overwrite + prune dangling),
    # which is what makes "reuse local image if it is the latest" hold.
    docker volume ls -q 2>/dev/null | grep -E 'sentinel|_mongo$|_rabbitmq$|sentinel_extensions' | xargs -r docker volume rm 2>/dev/null || true
    docker image prune -f >/dev/null 2>&1 || true   # clean dangling images (leftover <none> layers), leave sentinel:base alone
    # Clean old code dir + downloaded bundle tar + deploy package (avoid piling up 1.1G image bundles on each fresh; also clear same-name stale deploy cache)
    rm -rf "${INSTALL_DIR}/sentinel"
    rm -f "${INSTALL_DIR}"/sentinel-image-*.tar.gz "${INSTALL_DIR}"/sentinel-full-*.tar.gz "${INSTALL_DIR}"/sentinel-deploy-*.tar.gz 2>/dev/null || true
    ok "old residue cleaned (containers/volumes/dangling images/old code/old bundle/old deploy package; local image kept for version comparison)"

    ensure_docker
    download_and_extract

    cd "${COMPOSE_DIR}"
    setup_config
    build_and_start
    if health_check; then print_success; else print_failure; exit 1; fi
}

# ══════════════════════════════════════════
# Mode 2: repair install
# ══════════════════════════════════════════
do_repair() {
    log "[repair install] reset runtime (reinstall code/image + force-recreate containers), keep database and config..."

    # Back up the current config — search multiple paths (compose dir config / mounted volume config), back up the first hit.
    # Bug fix: previously only COMPOSE_DIR/config was checked; a path mismatch silently fell back to defaults -> lost user keys.
    # Now: multi-path lookup + explicit warning if none found.
    OLD_CONFIG=""
    for cf in "${COMPOSE_DIR}/config/config.yaml" "${INSTALL_DIR}/sentinel/config/config.yaml" "${INSTALL_DIR}/config/config.yaml"; do
        if [ -f "$cf" ]; then
            OLD_CONFIG="/tmp/sentinel-config-backup-$(date +%s).yaml"
            cp "$cf" "$OLD_CONFIG"
            ok "config backed up: $cf -> $OLD_CONFIG"
            break
        fi
    done
    [ -n "$OLD_CONFIG" ] || warn "no existing config found (first run or path changed) — repair will use defaults, verify keys/connection strings afterwards"

    # Stop app services but keep data volumes (stop+rm only stops containers, never down -v; MongoDB/extension volumes preserved)
    detect_compose
    if [ -n "$COMPOSE" ] && [ -f "${COMPOSE_DIR}/docker-compose.yml" ]; then
        cd "${COMPOSE_DIR}"
        $COMPOSE stop web worker scheduler nginx 2>/dev/null || true
        $COMPOSE rm -f web worker scheduler nginx 2>/dev/null || true
        ok "app services stopped (data volumes preserved)"
    fi

    ensure_docker

    # Reinstall code/image: delete old code dir (keep the downloaded bundle; if the image is unchanged, reuse it and skip the 1.1G re-download).
    # Inside download_and_extract: skip download if BUNDLE exists; image mode -> docker load, source mode -> extract.
    cd "$INSTALL_DIR"
    rm -rf sentinel
    resolve_latest                      # resolve latest first (fills BUNDLE/KIND/VERSION so the checks below are not empty)
    download_and_extract
    # image mode: clean old dangling image (after new load the old sentinel:base becomes <none>; not cleaning piles up on repeated repairs)
    if [ "$BUNDLE_KIND" = "image" ]; then
        docker image prune -f >/dev/null 2>&1 || true
    fi

    # Config restore: prefer restoring the backup (keeps user keys/connection strings); only use defaults if no backup (setup_config generates from sample + fixes connection strings)
    cd "${COMPOSE_DIR}"
    mkdir -p config
    if [ -n "$OLD_CONFIG" ] && [ -f "$OLD_CONFIG" ]; then
        cp "$OLD_CONFIG" config/config.yaml
        ok "config restored (existing keys and connection config preserved)"
    else
        warn "using default config (original config not found, keys must be filled in again)"
        setup_config
    fi

    # Start: image mode skips build; force-recreate ensures containers are rebuilt with the newly loaded image
    # (force-recreate even on same tag, otherwise compose sees no change -> runs the old image -> repair has no effect)
    if [ "$BUNDLE_KIND" != "image" ]; then
        log "building application image..."
        $COMPOSE build --quiet 2>/dev/null || $COMPOSE build || die "image build failed"
    fi
    log "recreating and starting services (force-recreate)..."
    $COMPOSE up -d --force-recreate || die "service start failed"
    ok "services recreated and started (database preserved)"
    if health_check; then print_success; else print_failure; exit 1; fi
}

# ══════════════════════════════════════════
# Mode 4: build locally (build the image from local source, no cloud bundle)
# ══════════════════════════════════════════
do_build() {
    log "[build locally] building the image from local source (no cloud bundle)..."
    # Locate the build context: prefer the script's source tree, then the extracted source bundle dir
    local CTX=""
    if can_build_locally "$SRC_ROOT"; then
        CTX="$SRC_ROOT"
    elif can_build_locally "${INSTALL_DIR}/sentinel"; then
        CTX="${INSTALL_DIR}/sentinel"
    else
        die "build context not found (need docker/Dockerfile + sentinel_platform + requirements.txt).
Local build must run inside a complete code directory; a plain curl|bash install has no source — use '1) Fresh install' to pull the bundle from the cloud instead."
    fi
    ok "build context: $CTX (buildable)"
    COMPOSE_DIR="$CTX/docker"
    mkdir -p "$INSTALL_DIR"       # ensure .base_version is writable (on first local build /opt/sentinel may not exist yet)

    ensure_docker
    stop_services

    local BV; BV="$(cat "$CTX/version.txt" 2>/dev/null | head -1 | tr -d '[:space:]')"; [ -n "$BV" ] || BV="dev"
    cd "$COMPOSE_DIR"
    log "building image sentinel:base (BASE_VERSION=${BV}, bundles Chromium/tools, first build is slow)..."
    # compose build.context already points at the source root, dockerfile at docker/Dockerfile; --build-arg injects the LABEL version
    $COMPOSE build --build-arg BASE_VERSION="$BV" || die "image build failed"
    echo "$BV" > "${INSTALL_DIR}/.base_version"   # sidecar marker matches image LABEL; later fresh/repair can version-compare and reuse
    ok "image build complete (version ${BV})"

    setup_config
    log "starting the full stack..."
    $COMPOSE up -d || die "service start failed"
    ok "services started"
    VERSION="$BV"        # for print_success display
    if health_check; then print_success; else print_failure; exit 1; fi
}

# ══════════════════════════════════════════
# Mode 3: uninstall
# ══════════════════════════════════════════
do_uninstall() {
    log "[uninstall] stopping all services and deleting data..."
    echo ""
    warn "WARNING: this deletes ALL data (database, config, code) and is irreversible!"
    read -rp "Confirm uninstall? type YES to continue: " CONFIRM </dev/tty 2>/dev/null \
        || die "cannot read confirmation (piped run cannot confirm uninstall interactively; download the script and run it locally)"
    if [ "$CONFIRM" != "YES" ]; then
        echo "cancelled"; exit 0
    fi

    stop_services

    # Delete Docker volumes — match by name pattern, not the compose project name (includes mongo/rabbitmq data volumes)
    docker volume ls -q 2>/dev/null | grep -E 'sentinel|_mongo$|_rabbitmq$|sentinel_extensions' | xargs -r docker volume rm 2>/dev/null || true
    # Delete Sentinel app images (leave the mongo/rabbitmq/nginx official images — may be shared by other services, rude to delete)
    docker images --filter "reference=sentinel*" -q 2>/dev/null | xargs -r docker rmi -f 2>/dev/null || true
    docker image prune -f >/dev/null 2>&1 || true   # clean dangling images
    # Delete the install dir (code + config + downloaded bundle)
    rm -rf "$INSTALL_DIR"

    ok "Sentinel fully uninstalled"
    echo ""
    echo "  removed: ${INSTALL_DIR} (code + config + bundle)"
    echo "  removed: Sentinel data volumes (database/extensions) + app image sentinel:base"
    echo "  kept:    mongo/rabbitmq/nginx official base images (docker rmi manually if you want them gone)"
    echo ""
}

# ══════════════════════════════════════════
# Dispatch
# ══════════════════════════════════════════
case "$MODE" in
    fresh) do_fresh ;;
    repair) do_repair ;;
    build) do_build ;;
    uninstall) do_uninstall ;;
esac
