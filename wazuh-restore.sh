#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# Wazuh Central Components Restoration Script (Improved)
# Based on: https://documentation.wazuh.com/current/migration-guide/restoring/wazuh-central-components.html#single-node-data-restoration


# -------- CONFIG/FLAGS --------
BACKUP_DIR=""
FORCE=false
DRY_RUN=false
SKIP_HEALTH=false
LOG_FILE="/var/log/wazuh_restore_$(date +%F_%H%M%S).log"

# -------- COLORS / helpers --------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; NC='\033[0m'

log()  { printf "%b [%s] %s\n" "${BLUE}" "$(date '+%F %T')" "$1" | tee -a "$LOG_FILE"; }
warn() { printf "%b [%s] %s\n" "${YELLOW}" "$(date '+%F %T')" "WARNING: $1" | tee -a "$LOG_FILE"; }
err()  { printf "%b [%s] %s\n" "${RED}" "$(date '+%F %T')" "ERROR: $1" | tee -a "$LOG_FILE" >&2; }

# Run a command (logs + supports dry-run). Exits on failure.
run_cmd() {
  if [ "$DRY_RUN" = true ]; then
    log "[DRY-RUN] $*"
    return 0
  fi
  log "RUN: $*"
  if ! eval "$@"; then
    err "Command failed: $*"
    exit 1
  fi
}

usage() {
  cat <<EOF
Usage: $0 <backup-directory> [--force] [--dry-run] [--skip-health]

  <backup-directory>   Path to the backup folder (required).
  --force              Skip confirmation prompt (dangerous).
  --dry-run            Show actions without executing them.
  --skip-health        Skip post-restore health checks.
EOF
  exit 1
}

# -------- ARG PARSING --------
if [ $# -lt 1 ]; then
  usage
fi

BACKUP_DIR="$1"
shift

while (( $# )); do
  case "$1" in
    --force) FORCE=true ;;
    --dry-run) DRY_RUN=true ;;
    --skip-health) SKIP_HEALTH=true ;;
    *) usage ;;
  esac
  shift
done

# -------- PRECHECKS & TRAP --------
trap 'log "Script finished (exit code: $?)";' EXIT

if [ "$(id -u)" -ne 0 ]; then
  err "This script must be run as root."
  exit 1
fi

if [ ! -d "$BACKUP_DIR" ]; then
  err "Backup directory not found: $BACKUP_DIR"
  exit 1
fi

log "Starting Wazuh restore from: $BACKUP_DIR"
log "Options -> FORCE: $FORCE | DRY-RUN: $DRY_RUN | SKIP-HEALTH: $SKIP_HEALTH"

if [ "$FORCE" = false ] && [ "$DRY_RUN" = false ]; then
  read -rp "This will overwrite existing Wazuh data. Type 'yes' to continue: " CONF
  if [ "$CONF" != "yes" ]; then
    log "Aborted by user."
    exit 0
  fi
fi

# -------- SAFETY: allowed cleanup targets --------
_allowed_targets=("/var/lib/wazuh-indexer" "/usr/share/wazuh-dashboard/data" "/var/ossec")

safe_clean_dir() {
  local dir="$1"
  # ensure directory exists
  if [ ! -d "$dir" ]; then
    warn "Directory does not exist (skip clean): $dir"
    return 0
  fi
  # check allowed list
  local ok=false
  for t in "${_allowed_targets[@]}"; do
    if [ "$dir" = "$t" ] || [[ "$dir" == "$t/"* ]]; then
      ok=true; break
    fi
  done
  if [ "$ok" = false ]; then
    err "Refusing to clean unsafe path: $dir"
    exit 1
  fi
  # delete contents safely (not the directory itself)
  run_cmd "find \"$dir\" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +"
}

# -------- VERIFY CHECKSUMS --------
verify_backups() {
  log "Verifying backup integrity..."
  if [ -f "$BACKUP_DIR/backup_checksums.sha256" ]; then
    if [ "$DRY_RUN" = true ]; then
      log "[DRY-RUN] sha256sum -c $BACKUP_DIR/backup_checksums.sha256"
    else
      (cd "$BACKUP_DIR" && sha256sum -c backup_checksums.sha256) >> "$LOG_FILE" 2>&1 \
        || { err "Checksum verification failed"; exit 1; }
      log "Checksum verification OK."
    fi
  else
    warn "Checksum file not found in backup; continuing without verification."
  fi
}

# -------- RESTORE FUNCTIONS --------
restore_indexer() {
  log "Restoring Wazuh Indexer..."
  run_cmd systemctl stop wazuh-indexer || warn "Failed to stop wazuh-indexer (continuing)"

  if [ -f "$BACKUP_DIR/wazuh_indexer_config.tar.gz" ]; then
    run_cmd tar -xzf "$BACKUP_DIR/wazuh_indexer_config.tar.gz" -C /etc/
  else
    warn "Indexer config archive missing"
  fi

  if [ -f "$BACKUP_DIR/wazuh_indexer_security.tar.gz" ]; then
    run_cmd tar -xzf "$BACKUP_DIR/wazuh_indexer_security.tar.gz" -C /usr/share/wazuh-indexer/plugins/opensearch-security/
  else
    warn "Indexer security archive missing"
  fi

  if [ -f "$BACKUP_DIR/wazuh_indexer_data.tar.gz" ]; then
    safe_clean_dir /var/lib/wazuh-indexer
    run_cmd tar -xzf "$BACKUP_DIR/wazuh_indexer_data.tar.gz" -C /var/lib/
  else
    warn "Indexer data archive missing"
  fi

  run_cmd chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer /var/lib/wazuh-indexer /usr/share/wazuh-indexer/plugins/opensearch-security || warn "chown indexer"
  run_cmd systemctl start wazuh-indexer || warn "Failed to start wazuh-indexer"
  log "Indexer restore complete."
}

restore_dashboard() {
  log "Restoring Wazuh Dashboard..."
  run_cmd systemctl stop wazuh-dashboard || warn "Failed to stop wazuh-dashboard (continuing)"

  if [ -f "$BACKUP_DIR/wazuh_dashboard_config.tar.gz" ]; then
    run_cmd tar -xzf "$BACKUP_DIR/wazuh_dashboard_config.tar.gz" -C /etc/
  else
    warn "Dashboard config archive missing"
  fi

  if [ -f "$BACKUP_DIR/wazuh_dashboard_data.tar.gz" ]; then
    safe_clean_dir /usr/share/wazuh-dashboard/data
    run_cmd tar -xzf "$BACKUP_DIR/wazuh_dashboard_data.tar.gz" -C /usr/share/wazuh-dashboard/data/
  else
    warn "Dashboard data archive missing"
  fi

  run_cmd chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard /usr/share/wazuh-dashboard/data || warn "chown dashboard"
  run_cmd systemctl start wazuh-dashboard || warn "Failed to start wazuh-dashboard"
  log "Dashboard restore complete."
}

restore_manager() {
  log "Restoring Wazuh Manager..."
  run_cmd systemctl stop wazuh-manager || warn "Failed to stop wazuh-manager (continuing)"

  if [ -f "$BACKUP_DIR/wazuh_manager_config.tar.gz" ]; then
    run_cmd tar -xzf "$BACKUP_DIR/wazuh_manager_config.tar.gz" -C /etc/
  else
    warn "Manager config archive missing"
  fi

  if [ -f "$BACKUP_DIR/wazuh_manager_var.tar.gz" ]; then
    safe_clean_dir /var/ossec
    run_cmd tar -xzf "$BACKUP_DIR/wazuh_manager_var.tar.gz" -C /var/ossec/
  else
    warn "Manager var archive missing"
  fi

  if [ -f "$BACKUP_DIR/wazuh_rules_decoders.tar.gz" ]; then
    run_cmd tar -xzf "$BACKUP_DIR/wazuh_rules_decoders.tar.gz" -C /var/ossec/
  else
    warn "Rules/decoders archive missing"
  fi

  run_cmd chown -R wazuh:wazuh /etc/wazuh /var/ossec || warn "chown manager"
  run_cmd systemctl start wazuh-manager || warn "Failed to start wazuh-manager"
  log "Manager restore complete."
}

# -------- HEALTH CHECKS --------
post_health_checks() {
  log "Running post-restore health checks..."
  for svc in wazuh-indexer wazuh-dashboard wazuh-manager; do
    if systemctl is-active --quiet "$svc"; then
      log "Service $svc: active"
    else
      warn "Service $svc: not active"
    fi
  done

  # optional basic network check for indexer (port 9200 commonly used)
  if command -v ss >/dev/null 2>&1 && [ "$SKIP_HEALTH" = false ]; then
    if ss -ltn | grep -q ':9200'; then
      log "Port 9200 listening (indexer/opensearch likely up)"
    else
      warn "Port 9200 not listening (indexer may not be fully ready)"
    fi
  fi
}

# -------- MAIN FLOW --------
verify_backups
restore_indexer
restore_dashboard
restore_manager

if [ "$SKIP_HEALTH" = false ]; then
  post_health_checks
else
  log "Skipping post-restore health checks (skipped by flag)."
fi

log "Restore finished. See log: $LOG_FILE"
exit 0
