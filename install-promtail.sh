#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# install-promtail.sh — Installation et configuration de Promtail
# Envoie les logs journald vers une instance Loki centralisée
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Tenta-dev/adminSys/main/install-promtail.sh \
#     | bash -s -- --loki-url http://192.168.2.8:3100
#
# Options:
#   --loki-url URL    URL de l'instance Loki (requis)
#   --host NAME       Nom du host (défaut: hostname -s)
#   --max-age AGE     Âge max des logs à ingérer (défaut: 72h)
#   --dry-run         Afficher les actions sans les exécuter
# ============================================================================

VERSION="1.0.0"

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

# --- Valeurs par défaut ---
LOKI_URL=""
HOST_NAME=""
MAX_AGE="72h"
DRY_RUN=false

# --- Parsing des arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --loki-url)
            LOKI_URL="$2"
            shift 2
            ;;
        --host)
            HOST_NAME="$2"
            shift 2
            ;;
        --max-age)
            MAX_AGE="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 --loki-url <URL> [--host <NAME>] [--max-age <AGE>] [--dry-run]"
            echo ""
            echo "Options:"
            echo "  --loki-url URL    URL de l'instance Loki (requis). Ex: http://192.168.2.8:3100"
            echo "  --host NAME       Nom du host (défaut: hostname -s)"
            echo "  --max-age AGE     Âge max des logs à ingérer (défaut: 72h)"
            echo "  --dry-run         Afficher les actions sans les exécuter"
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

# Hostname par défaut
if [[ -z "${HOST_NAME}" ]]; then
    HOST_NAME=$(hostname -s)
fi

# --- Bannière ---
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  install-promtail.sh v${VERSION}${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
info "Host      : ${HOST_NAME}"
info "Loki URL  : ${LOKI_URL}"
info "Max age   : ${MAX_AGE}"
echo ""

# --- Détection OS ---
if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    OS_ID="${ID}"
    OS_VERSION="${VERSION_ID:-unknown}"
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
if curl -s --connect-timeout 5 "${LOKI_URL}/ready" | grep -q "ready"; then
    success "Loki joignable et prêt."
else
    # Loki peut retourner "Ingester not ready" mais quand même être fonctionnel
    loki_response=$(curl -s --connect-timeout 5 "${LOKI_URL}/ready" 2>/dev/null || echo "UNREACHABLE")
    if [[ "${loki_response}" == "UNREACHABLE" ]]; then
        die "Impossible de joindre Loki sur ${LOKI_URL}. Vérifiez le réseau et les VLANs."
    else
        warn "Loki répond mais n'est pas encore ready : ${loki_response}"
        info "Poursuite de l'installation..."
    fi
fi

# --- Installation de Promtail ---
if command -v promtail &>/dev/null; then
    info "Promtail déjà installé ($(promtail --version 2>&1 | head -1 || echo 'version inconnue'))."
else
    info "Installation de Promtail..."

    if [[ "${DRY_RUN}" == true ]]; then
        info "[DRY-RUN] Installation du repo Grafana et du paquet promtail"
    else
        # Ajouter le repo Grafana si nécessaire
        if [[ ! -f /etc/apt/sources.list.d/grafana.list ]]; then
            info "Ajout du dépôt Grafana..."
            apt-get install -y -qq apt-transport-https software-properties-common > /dev/null 2>&1
            mkdir -p /etc/apt/keyrings/
            curl -fsSL https://apt.grafana.com/gpg.key | gpg --dearmor -o /etc/apt/keyrings/grafana.gpg 2>/dev/null
            echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" \
                > /etc/apt/sources.list.d/grafana.list
            apt-get update -qq > /dev/null 2>&1
        fi

        apt-get install -y -qq promtail > /dev/null 2>&1
        success "Promtail installé."
    fi
fi

# --- Configuration de Promtail ---
info "Configuration de Promtail..."

PROMTAIL_CONFIG="/etc/promtail/config.yml"

if [[ "${DRY_RUN}" == true ]]; then
    info "[DRY-RUN] Écriture de la configuration dans ${PROMTAIL_CONFIG}"
else
    mkdir -p /etc/promtail

    cat > "${PROMTAIL_CONFIG}" << EOF
# Configuration Promtail — générée par install-promtail.sh v${VERSION}
# Host: ${HOST_NAME} — $(date '+%Y-%m-%d %H:%M:%S')

server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /tmp/positions.yaml

clients:
  - url: ${LOKI_URL}/loki/api/v1/push

scrape_configs:
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
EOF

    success "Configuration écrite dans ${PROMTAIL_CONFIG}."
fi

# --- Permissions ---
info "Configuration des permissions..."

if [[ "${DRY_RUN}" == true ]]; then
    info "[DRY-RUN] Ajout de promtail aux groupes systemd-journal et adm"
else
    # Accès au journal systemd
    if getent group systemd-journal &>/dev/null; then
        usermod -aG systemd-journal promtail 2>/dev/null || true
    fi

    # Accès aux fichiers de logs classiques
    if getent group adm &>/dev/null; then
        usermod -aG adm promtail 2>/dev/null || true
    fi

    success "Permissions configurées."
fi

# --- Démarrage ---
info "Démarrage de Promtail..."

if [[ "${DRY_RUN}" == true ]]; then
    info "[DRY-RUN] systemctl enable --now promtail"
else
    systemctl enable promtail > /dev/null 2>&1
    systemctl restart promtail

    # Attendre 3 secondes et vérifier
    sleep 3
    if systemctl is-active promtail &>/dev/null; then
        success "Promtail actif et en cours d'exécution."
    else
        die "Promtail n'a pas démarré. Vérifiez : journalctl -u promtail -n 20"
    fi
fi

# --- Vérification ---
info "Vérification de l'envoi des logs..."

if [[ "${DRY_RUN}" == true ]]; then
    info "[DRY-RUN] Vérification de la présence du hostname dans Loki"
else
    # Attendre que Promtail envoie des logs
    sleep 5

    # Vérifier que le hostname apparaît dans Loki
    hostnames=$(curl -sG "${LOKI_URL}/loki/api/v1/label/hostname/values" 2>/dev/null || echo "")

    if echo "${hostnames}" | grep -q "${HOST_NAME}\|$(hostname)"; then
        success "Logs de ${HOST_NAME} visibles dans Loki."
    else
        warn "Les logs ne sont pas encore visibles dans Loki (peut prendre 1-2 minutes)."
        info "Vérifiez manuellement : curl -sG '${LOKI_URL}/loki/api/v1/label/hostname/values'"
    fi
fi

# --- Résumé ---
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║              PROMTAIL INSTALLÉ AVEC SUCCÈS                  ║${NC}"
echo -e "${BOLD}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "║ Host          : ${HOST_NAME}"
echo -e "║ Loki URL      : ${LOKI_URL}"
echo -e "║ Config        : ${PROMTAIL_CONFIG}"
echo -e "║ Max age       : ${MAX_AGE}"
echo -e "║ Status        : $(systemctl is-active promtail 2>/dev/null || echo 'dry-run')"
echo -e "${BOLD}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "║ Grafana query : {hostname=\"$(hostname)\"}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""