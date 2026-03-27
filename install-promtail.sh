#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# install-promtail.sh — Installation et configuration de Promtail
# Envoie les logs journald (+ fichiers optionnels) vers une instance Loki
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Tenta-dev/adminSys/main/install-promtail.sh \
#     | bash -s -- --loki-url http://192.168.2.8:3100
#
# Options:
#   --loki-url URL        URL de l'instance Loki (requis)
#   --host NAME           Nom du host (défaut: hostname -s)
#   --max-age AGE         Âge max des logs à ingérer (défaut: 72h)
#   --version VER         Version de Promtail à installer (défaut: latest)
#   --dry-run             Afficher les actions sans les exécuter
#   --force-update-repo   Forcer apt-get update même si le repo Grafana existe
# ============================================================================

SCRIPT_VERSION="2.0.1"

# --- Couleurs ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'
BOLD='\033[1m'

# --- Fonctions d'affichage ---
info()    { echo -e "${BLUE}[INFO]${NC}    $*"; }
success() { echo -e "${GREEN}[OK]${NC}      $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}    $*"; }
die()     { echo -e "${RED}[ERREUR]${NC}  $*" >&2; exit 1; }

# --- Fonction dry-run ---
run() {
    if [[ "${DRY_RUN}" == true ]]; then
        info "[DRY-RUN] $*"
        return 0
    fi
    "$@"
}

# --- Valeurs par défaut ---
LOKI_URL=""
HOST_NAME=""
MAX_AGE="72h"
PROMTAIL_VERSION=""
DRY_RUN=false
FORCE_UPDATE_REPO=false

# --- Parsing des arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --loki-url)
            [[ -z "${2:-}" ]] && die "--loki-url nécessite une valeur."
            LOKI_URL="$2"
            shift 2
            ;;
        --host)
            [[ -z "${2:-}" ]] && die "--host nécessite une valeur."
            HOST_NAME="$2"
            shift 2
            ;;
        --max-age)
            [[ -z "${2:-}" ]] && die "--max-age nécessite une valeur."
            MAX_AGE="$2"
            shift 2
            ;;
        --version)
            [[ -z "${2:-}" ]] && die "--version nécessite une valeur."
            PROMTAIL_VERSION="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --force-update-repo)
            FORCE_UPDATE_REPO=true
            shift
            ;;
        -h|--help)
            cat <<HELP
Usage: $0 --loki-url <URL> [OPTIONS]

Options:
  --loki-url URL           URL de l'instance Loki (requis). Ex: http://192.168.2.8:3100
  --host NAME              Nom du host (défaut: hostname -s)
  --max-age AGE            Âge max des logs à ingérer (défaut: 72h)
  --version VER            Version de Promtail à installer (défaut: latest)
                           Ex: --version 3.4.2
  --dry-run                Afficher les actions sans les exécuter
  --force-update-repo      Forcer apt-get update même si le repo Grafana existe
  -h, --help               Afficher cette aide
HELP
            exit 0
            ;;
        *)
            die "Option inconnue : $1. Utilisez --help pour l'aide."
            ;;
    esac
done

# --- Validations ---
[[ -z "${LOKI_URL}" ]] && die "--loki-url est requis. Ex: --loki-url http://192.168.2.8:3100"
[[ "$(id -u)" -ne 0 ]] && die "Ce script doit être exécuté en tant que root."

# Nettoyer l'URL (supprimer le / final si présent)
LOKI_URL="${LOKI_URL%/}"

# Valider le format de l'URL
if ! [[ "${LOKI_URL}" =~ ^https?:// ]]; then
    die "L'URL Loki doit commencer par http:// ou https://. Reçu : ${LOKI_URL}"
fi

# Avertissement si HTTP sans tunnel
if [[ "${LOKI_URL}" =~ ^http:// ]]; then
    warn "Connexion vers Loki en HTTP clair. Assurez-vous que le trafic est protégé (WireGuard, VLAN isolé, etc.)."
fi

# Hostname par défaut
if [[ -z "${HOST_NAME}" ]]; then
    HOST_NAME=$(hostname -s)
fi

# --- Bannière ---
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  install-promtail.sh v${SCRIPT_VERSION}${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
info "Host          : ${HOST_NAME}"
info "Loki URL      : ${LOKI_URL}"
info "Max age       : ${MAX_AGE}"
info "Version       : ${PROMTAIL_VERSION:-latest}"
info "Dry-run       : ${DRY_RUN}"
echo ""

# --- Détection OS ---
if [[ -f /etc/os-release ]]; then
    # shellcheck source=/dev/null
    source /etc/os-release
    OS_ID="${ID}"
    info "OS détecté : ${PRETTY_NAME}"
else
    die "Impossible de détecter l'OS. Fichier /etc/os-release absent."
fi

case "${OS_ID}" in
    debian|ubuntu) ;;
    *) die "OS non supporté : ${OS_ID}. Seuls Debian et Ubuntu sont supportés." ;;
esac

# --- Test de connectivité vers Loki ---
info "Test de connectivité vers Loki..."
if [[ "${DRY_RUN}" == false ]]; then
    loki_response=$(curl -s --connect-timeout 5 "${LOKI_URL}/ready" 2>/dev/null || echo "UNREACHABLE")

    if [[ "${loki_response}" == "UNREACHABLE" ]]; then
        die "Impossible de joindre Loki sur ${LOKI_URL}. Vérifiez le réseau et les VLANs."
    elif echo "${loki_response}" | grep -q "ready"; then
        success "Loki joignable et prêt."
    else
        warn "Loki répond mais n'est pas encore ready : ${loki_response}"
        info "Poursuite de l'installation..."
    fi
else
    info "[DRY-RUN] Test de connectivité vers ${LOKI_URL}/ready"
fi

# --- Installation de Promtail ---
if command -v promtail &>/dev/null && [[ -z "${PROMTAIL_VERSION}" ]]; then
    current_version=$(promtail --version 2>&1 | head -1 || echo "version inconnue")
    info "Promtail déjà installé (${current_version})."
else
    info "Installation de Promtail..."

    if [[ "${DRY_RUN}" == false ]]; then
        # Ajouter le repo Grafana si nécessaire
        if [[ ! -f /etc/apt/sources.list.d/grafana.list ]] || [[ "${FORCE_UPDATE_REPO}" == true ]]; then
            info "Ajout/mise à jour du dépôt Grafana..."
            apt-get install -y -qq apt-transport-https > /dev/null 2>&1 || true
            mkdir -p /etc/apt/keyrings/
            curl -fsSL https://apt.grafana.com/gpg.key | gpg --dearmor -o /etc/apt/keyrings/grafana.gpg 2>/dev/null
            chmod 644 /etc/apt/keyrings/grafana.gpg
            echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" \
                > /etc/apt/sources.list.d/grafana.list
        fi

        # Toujours mettre à jour le cache pour le repo Grafana
        apt-get update -qq -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/grafana.list \
            -o Dir::Etc::sourceparts="-" > /dev/null 2>&1

        # Installation avec ou sans version pinning
        if [[ -n "${PROMTAIL_VERSION}" ]]; then
            info "Version demandée : ${PROMTAIL_VERSION}"
            apt-get install -y "promtail=${PROMTAIL_VERSION}" > /dev/null 2>&1 \
                || die "Échec de l'installation de promtail=${PROMTAIL_VERSION}. Versions disponibles : apt-cache policy promtail"
        else
            apt-get install -y promtail > /dev/null 2>&1 \
                || die "Échec de l'installation de Promtail. Vérifiez : apt install promtail -y"
        fi

        installed_version=$(promtail --version 2>&1 | head -1 || echo "?")
        success "Promtail installé (${installed_version})."
    else
        info "[DRY-RUN] apt-get install promtail${PROMTAIL_VERSION:+=${PROMTAIL_VERSION}}"
    fi
fi

# --- Utilisateur système Promtail ---
if [[ "${DRY_RUN}" == false ]]; then
    if ! id -u promtail &>/dev/null; then
        info "Création de l'utilisateur système promtail..."
        useradd --system --no-create-home --shell /usr/sbin/nologin --user-group promtail
        success "Utilisateur promtail créé."
    elif ! getent group promtail &>/dev/null; then
        info "Création du groupe promtail..."
        groupadd --system promtail
        usermod -g promtail promtail
        success "Groupe promtail créé."
    fi
else
    info "[DRY-RUN] Vérification/création de l'utilisateur promtail"
fi

# --- Répertoire de données Promtail ---
PROMTAIL_DATA_DIR="/var/lib/promtail"
info "Création du répertoire de données ${PROMTAIL_DATA_DIR}..."

if [[ "${DRY_RUN}" == false ]]; then
    mkdir -p "${PROMTAIL_DATA_DIR}"
    chown promtail:promtail "${PROMTAIL_DATA_DIR}"
    chmod 750 "${PROMTAIL_DATA_DIR}"
    success "Répertoire ${PROMTAIL_DATA_DIR} prêt."
else
    info "[DRY-RUN] mkdir -p ${PROMTAIL_DATA_DIR} && chown promtail:promtail"
fi

# --- Configuration de Promtail ---
info "Configuration de Promtail..."

PROMTAIL_CONFIG="/etc/promtail/config.yml"

if [[ "${DRY_RUN}" == false ]]; then
    mkdir -p /etc/promtail

    # Backup de la configuration existante
    if [[ -f "${PROMTAIL_CONFIG}" ]]; then
        backup_path="${PROMTAIL_CONFIG}.bak.$(date +%s)"
        cp "${PROMTAIL_CONFIG}" "${backup_path}"
        info "Backup de la configuration existante : ${backup_path}"
    fi

    cat > "${PROMTAIL_CONFIG}" << EOF
# Configuration Promtail — générée par install-promtail.sh v${SCRIPT_VERSION}
# Host: ${HOST_NAME} — $(date '+%Y-%m-%d %H:%M:%S')
#
# Positions stockées dans ${PROMTAIL_DATA_DIR} (persistant entre redémarrages).
# gRPC désactivé (grpc_listen_port: 0) — pas de communication inter-promtail.

server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: ${PROMTAIL_DATA_DIR}/positions.yaml

clients:
  - url: ${LOKI_URL}/loki/api/v1/push

scrape_configs:
  # --- Journald (systemd) ---
  - job_name: journal
    journal:
      max_age: ${MAX_AGE}
      labels:
        job: systemd-journal
        host: ${HOST_NAME}
    relabel_configs:
      - source_labels: ['__journal__systemd_unit']
        target_label: 'unit'
      - source_labels: ['__journal__hostname']
        target_label: 'hostname'
      - source_labels: ['__journal_priority_keyword']
        target_label: 'level'
      - source_labels: ['__journal_syslog_identifier']
        target_label: 'syslog_identifier'
EOF

    success "Configuration écrite dans ${PROMTAIL_CONFIG}."
else
    info "[DRY-RUN] Écriture de la configuration dans ${PROMTAIL_CONFIG}"
fi

# --- Permissions ---
info "Configuration des permissions..."

if [[ "${DRY_RUN}" == false ]]; then
    if getent group systemd-journal &>/dev/null; then
        usermod -aG systemd-journal promtail 2>/dev/null || true
    fi

    if getent group adm &>/dev/null; then
        usermod -aG adm promtail 2>/dev/null || true
    fi

    success "Permissions configurées (groupes: systemd-journal, adm)."
else
    info "[DRY-RUN] usermod -aG systemd-journal,adm promtail"
fi

# --- Démarrage ---
info "Démarrage de Promtail..."

if [[ "${DRY_RUN}" == false ]]; then
    systemctl enable promtail > /dev/null 2>&1
    systemctl restart promtail

    # Vérification via le endpoint /ready de Promtail
    info "Attente du démarrage de Promtail..."
    retries=0
    max_retries=10
    while [[ ${retries} -lt ${max_retries} ]]; do
        if curl -s --connect-timeout 2 "http://localhost:9080/ready" 2>/dev/null | grep -qi "ready"; then
            success "Promtail actif et ready."
            break
        fi
        retries=$((retries + 1))
        sleep 1
    done

    if [[ ${retries} -ge ${max_retries} ]]; then
        warn "Promtail démarré mais /ready n'a pas répondu dans les ${max_retries}s."
        info "Vérifiez : journalctl -u promtail -n 30 --no-pager"
    fi
else
    info "[DRY-RUN] systemctl enable --now promtail"
fi

# --- Résumé ---
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║              PROMTAIL INSTALLÉ AVEC SUCCÈS                  ║${NC}"
echo -e "${BOLD}╠══════════════════════════════════════════════════════════════╣${NC}"

if [[ "${DRY_RUN}" == false ]]; then
    promtail_status=$(systemctl is-active promtail 2>/dev/null || echo "inconnu")
    installed_ver=$(promtail --version 2>&1 | head -1 || echo "?")
    echo -e "║ Host          : ${HOST_NAME}"
    echo -e "║ Loki URL      : ${LOKI_URL}"
    echo -e "║ Config        : ${PROMTAIL_CONFIG}"
    echo -e "║ Positions     : ${PROMTAIL_DATA_DIR}/positions.yaml"
    echo -e "║ Max age       : ${MAX_AGE}"
    echo -e "║ Version       : ${installed_ver}"
    echo -e "║ Status        : ${promtail_status}"
    echo -e "${BOLD}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "║ Grafana query : {host=\"${HOST_NAME}\"}"
    echo -e "║ Erreurs only  : {host=\"${HOST_NAME}\", level=\"err\"}"
else
    echo -e "║ Mode          : DRY-RUN (aucune modification effectuée)"
    echo -e "║ Host          : ${HOST_NAME}"
    echo -e "║ Loki URL      : ${LOKI_URL}"
fi

echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

if [[ "${DRY_RUN}" == false ]]; then
    info "Commandes utiles :"
    info "  journalctl -u promtail -f          # Logs Promtail en live"
    info "  curl -s localhost:9080/metrics      # Métriques Promtail"
    info "  curl -s localhost:9080/ready        # Healthcheck"
fi