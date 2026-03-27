#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# install-promtail.sh — Installation et configuration de Promtail
# Envoie les logs journald + fichiers applicatifs vers une instance Loki
#
# Usage (auto-détection des profils):
#   curl -fsSL https://raw.githubusercontent.com/Tenta-dev/adminSys/main/install-promtail.sh \
#     | bash -s -- --loki-url http://192.168.2.8:3100
#
# Usage avec profils explicites:
#   bash install-promtail.sh --loki-url http://192.168.2.8:3100 --profiles arr,nginx,syslog
#
# Usage journald uniquement:
#   bash install-promtail.sh --loki-url http://192.168.2.8:3100 --profiles none
#
# Options:
#   --loki-url URL           URL de l'instance Loki (requis)
#   --host NAME              Nom du host (défaut: hostname -s)
#   --max-age AGE            Âge max des logs journald (défaut: 72h)
#   --version VER            Version de Promtail à installer (défaut: latest)
#   --profiles LIST          Profils de logs séparés par des virgules (skip l'auto-détection)
#                            Profils: syslog, authlog, nginx, docker, arr, fail2ban, aide, rkhunter, unattended-upgrades
#                            Spécial: "none" pour désactiver tous les profils (journald seul)
#   --custom-path PATH       Chemin personnalisé à scraper (détection auto du format)
#   --dry-run                Afficher les actions sans les exécuter
#   --force-update-repo      Forcer apt-get update même si le repo existe
#   --list-profiles          Lister les profils disponibles et quitter
# ============================================================================

SCRIPT_VERSION="3.2.0"

# --- Couleurs ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'

# --- Fonctions d'affichage ---
info()    { echo -e "${BLUE}[INFO]${NC}    $*"; }
success() { echo -e "${GREEN}[OK]${NC}      $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}    $*"; }
die()     { echo -e "${RED}[ERREUR]${NC}  $*" >&2; exit 1; }

# --- Valeurs par défaut ---
LOKI_URL=""
HOST_NAME=""
MAX_AGE="72h"
PROMTAIL_VERSION=""
DRY_RUN=false
FORCE_UPDATE_REPO=false
PROFILES_CLI=""
CUSTOM_PATHS=()

# Variable globale pour tracker les apps *arr détectées (utilisée dans le résumé)
DETECTED_ARR_APPS=()

# ============================================================================
# PROFILS DE LOGS
# Chaque profil définit : description, chemins, détection, pipeline_stages
# ============================================================================

# Liste ordonnée des profils disponibles
AVAILABLE_PROFILES=(syslog authlog nginx docker arr fail2ban aide rkhunter unattended-upgrades)

declare -A PROFILE_DESC=(
    [syslog]="Syslog système (/var/log/syslog)"
    [authlog]="Logs d'authentification (/var/log/auth.log)"
    [nginx]="Nginx access + error logs"
    [docker]="Conteneurs Docker (JSON logs)"
    [arr]="*Arr stack (Radarr, Sonarr, Lidarr, Prowlarr, etc.)"
    [fail2ban]="Fail2ban (/var/log/fail2ban.log)"
    [aide]="AIDE — contrôle d'intégrité (/var/log/aide/aide.log)"
    [rkhunter]="Rkhunter — détection de rootkits (/var/log/rkhunter.log)"
    [unattended-upgrades]="Mises à jour automatiques (/var/log/unattended-upgrades/)"
)

# --- Détection de la présence d'un profil sur le système ---
profile_detect() {
    local profile="$1"
    case "${profile}" in
        syslog)
            [[ -f /var/log/syslog ]]
            ;;
        authlog)
            [[ -f /var/log/auth.log ]]
            ;;
        nginx)
            command -v nginx &>/dev/null || [[ -d /var/log/nginx ]]
            ;;
        docker)
            command -v docker &>/dev/null || [[ -d /var/lib/docker/containers ]]
            ;;
        arr)
            local arr_found=false
            for app in radarr sonarr lidarr prowlarr readarr bazarr whisparr; do
                for dir in "/opt/${app}" "/var/lib/${app}" "/config/logs"; do
                    [[ -d "${dir}" ]] && arr_found=true && break 2
                done
                systemctl list-unit-files "${app}.service" &>/dev/null 2>&1 && arr_found=true && break
            done
            ${arr_found}
            ;;
        fail2ban)
            [[ -f /var/log/fail2ban.log ]] || command -v fail2ban-client &>/dev/null
            ;;
        aide)
            [[ -d /var/log/aide ]] || command -v aide &>/dev/null
            ;;
        rkhunter)
            [[ -f /var/log/rkhunter.log ]] || command -v rkhunter &>/dev/null
            ;;
        unattended-upgrades)
            [[ -d /var/log/unattended-upgrades ]]
            ;;
        *)
            return 1
            ;;
    esac
}

# --- Génération du bloc scrape_config pour un profil ---
profile_scrape_config() {
    local profile="$1"
    local host="$2"

    case "${profile}" in

        syslog)
            cat <<'YAML'
  # --- Syslog système ---
  - job_name: syslog
    static_configs:
      - targets: [localhost]
        labels:
          job: syslog
          host: __HOST__
          __path__: /var/log/syslog
    pipeline_stages:
      - regex:
          expression: '^(?P<timestamp>\S+ \d+ \S+) (?P<hostname>\S+) (?P<process>[^\[:]+)(?:\[(?P<pid>\d+)\])?: (?P<message>.*)'
      - timestamp:
          source: timestamp
          format: "Jan  2 15:04:05"
      - output:
          source: message
YAML
            ;;

        authlog)
            cat <<'YAML'
  # --- Auth log ---
  - job_name: authlog
    static_configs:
      - targets: [localhost]
        labels:
          job: authlog
          host: __HOST__
          __path__: /var/log/auth.log
    pipeline_stages:
      - regex:
          expression: '^(?P<timestamp>\S+ \d+ \S+) (?P<hostname>\S+) (?P<process>[^\[:]+)(?:\[(?P<pid>\d+)\])?: (?P<message>.*)'
      - timestamp:
          source: timestamp
          format: "Jan  2 15:04:05"
      - output:
          source: message
YAML
            ;;

        nginx)
            cat <<'YAML'
  # --- Nginx access logs ---
  - job_name: nginx-access
    static_configs:
      - targets: [localhost]
        labels:
          job: nginx
          log_type: access
          host: __HOST__
          __path__: /var/log/nginx/access.log
    pipeline_stages:
      - regex:
          expression: '^(?P<remote_addr>\S+) - (?P<remote_user>\S+) \[(?P<time_local>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d+) (?P<body_bytes>\d+) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
      - labels:
          method:
          status:
      - timestamp:
          source: time_local
          format: "02/Jan/2006:15:04:05 -0700"

  # --- Nginx error logs ---
  - job_name: nginx-error
    static_configs:
      - targets: [localhost]
        labels:
          job: nginx
          log_type: error
          host: __HOST__
          __path__: /var/log/nginx/error.log
    pipeline_stages:
      - regex:
          expression: '^(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] (?P<message>.*)'
      - labels:
          level:
      - timestamp:
          source: timestamp
          format: "2006/01/02 15:04:05"
      - output:
          source: message
YAML
            ;;

        docker)
            cat <<'YAML'
  # --- Docker container logs (JSON) ---
  - job_name: docker
    static_configs:
      - targets: [localhost]
        labels:
          job: docker
          host: __HOST__
          __path__: /var/lib/docker/containers/**/*-json.log
    pipeline_stages:
      - json:
          expressions:
            log: log
            stream: stream
            time: time
      - labels:
          stream:
      - timestamp:
          source: time
          format: "RFC3339Nano"
      - output:
          source: log
YAML
            ;;

        arr)
            # Détection dynamique des apps *arr installées
            local arr_configs=""
            DETECTED_ARR_APPS=()
            for app in radarr sonarr lidarr prowlarr readarr bazarr whisparr; do
                local log_dir=""
                for candidate in \
                    "/opt/${app}/logs" \
                    "/var/lib/${app}/logs" \
                    "/config/logs" \
                    "/home/${app}/.config/${app^}/logs" \
                    "/root/.config/${app^}/logs"; do
                    if [[ -d "${candidate}" ]]; then
                        log_dir="${candidate}"
                        break
                    fi
                done

                [[ -z "${log_dir}" ]] && continue

                DETECTED_ARR_APPS+=("${app}")
                arr_configs+="
  # --- ${app^} ---
  - job_name: ${app}
    static_configs:
      - targets: [localhost]
        labels:
          job: ${app}
          host: __HOST__
          __path__: ${log_dir}/*.txt
    pipeline_stages:
      - multiline:
          firstline: '^\d{4}-\d{2}-\d{2}'
      - regex:
          expression: '^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\|(?P<level>\w+)\|(?P<component>[^|]+)\|(?P<message>.*)'
      - labels:
          level:
      - timestamp:
          source: timestamp
          format: \"2006-01-02 15:04:05.0\"
      - output:
          source: message
"
            done

            if [[ -z "${arr_configs}" ]]; then
                warn "Profil arr sélectionné mais aucun répertoire de logs trouvé."
                warn "Chemins vérifiés : /opt/<app>/logs, /var/lib/<app>/logs, /config/logs"
                return 0
            fi
            echo "${arr_configs}"
            ;;

        fail2ban)
            cat <<'YAML'
  # --- Fail2ban ---
  - job_name: fail2ban
    static_configs:
      - targets: [localhost]
        labels:
          job: fail2ban
          host: __HOST__
          __path__: /var/log/fail2ban.log
    pipeline_stages:
      - regex:
          expression: '^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+)\s+fail2ban\.(?P<component>\S+)\s+\[(?P<pid>\d+)\]:\s+(?P<level>\w+)\s+(?P<message>.*)'
      - labels:
          level:
          component:
      - timestamp:
          source: timestamp
          format: "2006-01-02 15:04:05,000"
      - output:
          source: message
YAML
            ;;

        aide)
            cat <<'YAML'
  # --- AIDE (contrôle d'intégrité) ---
  - job_name: aide
    static_configs:
      - targets: [localhost]
        labels:
          job: aide
          host: __HOST__
          __path__: /var/log/aide/*.log
    pipeline_stages:
      - multiline:
          firstline: '^(Start timestamp|AIDE|Summary|---)'
          max_wait_time: 3s
YAML
            ;;

        rkhunter)
            cat <<'YAML'
  # --- Rkhunter ---
  - job_name: rkhunter
    static_configs:
      - targets: [localhost]
        labels:
          job: rkhunter
          host: __HOST__
          __path__: /var/log/rkhunter.log
    pipeline_stages:
      - multiline:
          firstline: '^\[\d{2}:\d{2}:\d{2}\]|^System checks summary'
          max_wait_time: 3s
      - regex:
          expression: '^\[(?P<timestamp>\d{2}:\d{2}:\d{2})\]\s+(?P<message>.*)'
      - output:
          source: message
YAML
            ;;

        unattended-upgrades)
            cat <<'YAML'
  # --- Unattended Upgrades ---
  - job_name: unattended-upgrades
    static_configs:
      - targets: [localhost]
        labels:
          job: unattended-upgrades
          host: __HOST__
          __path__: /var/log/unattended-upgrades/unattended-upgrades.log
    pipeline_stages:
      - regex:
          expression: '^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+) (?P<level>\w+)\s+(?P<message>.*)'
      - labels:
          level:
      - timestamp:
          source: timestamp
          format: "2006-01-02 15:04:05,000"
      - output:
          source: message

  # --- Unattended Upgrades dpkg log ---
  - job_name: unattended-upgrades-dpkg
    static_configs:
      - targets: [localhost]
        labels:
          job: unattended-upgrades
          log_type: dpkg
          host: __HOST__
          __path__: /var/log/unattended-upgrades/unattended-upgrades-dpkg.log
    pipeline_stages:
      - regex:
          expression: '^Log started: (?P<timestamp>.+)|(?P<message>.+)'
YAML
            ;;
    esac
}

# --- Détection auto du format d'un fichier de log ---
detect_log_format() {
    local filepath="$1"

    if [[ ! -f "${filepath}" ]]; then
        echo "unknown"
        return
    fi

    local first_line
    first_line=$(head -1 "${filepath}" 2>/dev/null || echo "")

    if [[ -z "${first_line}" ]]; then
        echo "unknown"
    elif echo "${first_line}" | python3 -c "import sys, json; json.loads(sys.stdin.read())" 2>/dev/null; then
        echo "json"
    elif echo "${first_line}" | grep -qP '^\w+=\S+\s+\w+='; then
        echo "logfmt"
    else
        echo "plaintext"
    fi
}

# --- Génération de pipeline_stages pour un chemin custom ---
generate_custom_scrape_config() {
    local filepath="$1"
    local host="$2"
    local job_name
    job_name=$(basename "$(dirname "${filepath}")" | tr '.' '-' | tr '/' '-')
    [[ "${job_name}" == "-" || "${job_name}" == "log" ]] && job_name=$(basename "${filepath}" | sed 's/\..*//')

    local format
    format=$(detect_log_format "${filepath}")
    info "Format détecté pour ${filepath} : ${format}"

    cat <<YAML
  # --- Custom: ${filepath} (format: ${format}) ---
  - job_name: custom-${job_name}
    static_configs:
      - targets: [localhost]
        labels:
          job: ${job_name}
          host: ${host}
          __path__: ${filepath}
YAML

    case "${format}" in
        json)
            cat <<'YAML'
    pipeline_stages:
      - json:
          expressions:
            message: message
            level: level
            timestamp: timestamp
      - labels:
          level:
YAML
            ;;
        logfmt)
            cat <<'YAML'
    pipeline_stages:
      - logfmt:
          mapping:
            level:
            msg:
      - labels:
          level:
YAML
            ;;
        *)
            echo "    # Format plaintext — pas de pipeline spécifique"
            echo "    # Ajoutez des pipeline_stages manuellement si nécessaire"
            ;;
    esac
}

# --- Auto-détection de tous les profils présents ---
autodetect_profiles() {
    local detected=()
    for profile in "${AVAILABLE_PROFILES[@]}"; do
        if profile_detect "${profile}" 2>/dev/null; then
            detected+=("${profile}")
        fi
    done
    SELECTED_PROFILES=("${detected[@]}")

    if [[ ${#SELECTED_PROFILES[@]} -gt 0 ]]; then
        info "Profils auto-détectés : ${SELECTED_PROFILES[*]}"
    else
        info "Aucun profil détecté sur ce système — journald uniquement."
    fi
}

# --- Menu interactif ---
interactive_select_profiles() {
    local detected=()
    local not_detected=()

    echo ""
    echo -e "${BOLD}═══ Profils de logs disponibles ═══${NC}"
    echo ""

    for profile in "${AVAILABLE_PROFILES[@]}"; do
        if profile_detect "${profile}" 2>/dev/null; then
            detected+=("${profile}")
            echo -e "  ${GREEN}●${NC} ${BOLD}${profile}${NC} — ${PROFILE_DESC[${profile}]} ${GREEN}(détecté)${NC}"
        else
            not_detected+=("${profile}")
            echo -e "  ${DIM}○ ${profile} — ${PROFILE_DESC[${profile}]} (non détecté)${NC}"
        fi
    done

    echo ""

    if [[ ${#detected[@]} -gt 0 ]]; then
        echo -e "${CYAN}Profils détectés : ${detected[*]}${NC}"
    fi

    echo ""
    echo -e "Saisissez les profils à activer, séparés par des espaces."
    echo -e "Appuyez sur ${BOLD}Entrée${NC} pour accepter les profils détectés."
    echo -e "Tapez ${BOLD}none${NC} pour ne garder que journald."
    echo ""
    read -r -p "Profils > " user_input

    if [[ -z "${user_input}" ]]; then
        SELECTED_PROFILES=("${detected[@]}")
    elif [[ "${user_input}" == "none" ]]; then
        SELECTED_PROFILES=()
    else
        IFS=' ,' read -ra SELECTED_PROFILES <<< "${user_input}"
    fi

    # Validation
    for p in "${SELECTED_PROFILES[@]}"; do
        if [[ -z "${PROFILE_DESC[${p}]+_}" ]]; then
            die "Profil inconnu : ${p}. Disponibles : ${AVAILABLE_PROFILES[*]}"
        fi
    done

    # Proposer un chemin custom
    echo ""
    read -r -p "Chemin de log custom à ajouter (vide pour passer) > " custom_path
    if [[ -n "${custom_path}" ]]; then
        CUSTOM_PATHS+=("${custom_path}")
    fi
}

# ============================================================================
# PARSING DES ARGUMENTS
# ============================================================================

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
        --profiles)
            [[ -z "${2:-}" ]] && die "--profiles nécessite une valeur. Ex: --profiles nginx,arr,syslog"
            PROFILES_CLI="$2"
            shift 2
            ;;
        --custom-path)
            [[ -z "${2:-}" ]] && die "--custom-path nécessite un chemin."
            CUSTOM_PATHS+=("$2")
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
        --list-profiles)
            echo ""
            echo "Profils disponibles :"
            for p in "${AVAILABLE_PROFILES[@]}"; do
                echo "  ${p} — ${PROFILE_DESC[${p}]}"
            done
            echo ""
            echo "Usage: --profiles syslog,nginx,arr,fail2ban"
            exit 0
            ;;
        -h|--help)
            cat <<HELP
Usage: $0 --loki-url <URL> [OPTIONS]

Options:
  --loki-url URL           URL de l'instance Loki (requis)
  --host NAME              Nom du host (défaut: hostname -s)
  --max-age AGE            Âge max des logs journald (défaut: 72h)
  --version VER            Version de Promtail (défaut: latest)
  --profiles LIST          Profils séparés par des virgules (override auto-détection)
                           Disponibles : ${AVAILABLE_PROFILES[*]}
                           "none" pour journald uniquement
  --custom-path PATH       Chemin custom à scraper (répétable)
  --dry-run                Afficher les actions sans les exécuter
  --force-update-repo      Forcer apt-get update
  --list-profiles          Lister les profils et quitter
  -h, --help               Afficher cette aide

Exemples:
  # Auto-détection (curl | bash ou terminal)
  bash install-promtail.sh --loki-url http://192.168.2.8:3100

  # Profils explicites (override auto-détection)
  bash install-promtail.sh --loki-url http://192.168.2.8:3100 --profiles arr,syslog,fail2ban

  # Journald uniquement
  bash install-promtail.sh --loki-url http://192.168.2.8:3100 --profiles none

  # Avec chemin custom
  bash install-promtail.sh --loki-url http://192.168.2.8:3100 \\
    --custom-path /opt/myapp/logs/*.log
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

LOKI_URL="${LOKI_URL%/}"

if ! [[ "${LOKI_URL}" =~ ^https?:// ]]; then
    die "L'URL Loki doit commencer par http:// ou https://. Reçu : ${LOKI_URL}"
fi

if [[ "${LOKI_URL}" =~ ^http:// ]]; then
    warn "Connexion vers Loki en HTTP clair. Assurez-vous que le trafic est protégé (WireGuard, VLAN isolé, etc.)."
fi

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

# --- Sélection des profils ---
SELECTED_PROFILES=()

if [[ "${PROFILES_CLI}" == "none" ]]; then
    info "Profils désactivés (--profiles none) — journald uniquement."
elif [[ -n "${PROFILES_CLI}" ]]; then
    IFS=',' read -ra SELECTED_PROFILES <<< "${PROFILES_CLI}"
    for p in "${SELECTED_PROFILES[@]}"; do
        if [[ -z "${PROFILE_DESC[${p}]+_}" ]]; then
            die "Profil inconnu : ${p}. Disponibles : ${AVAILABLE_PROFILES[*]}"
        fi
    done
    info "Profils sélectionnés (CLI) : ${SELECTED_PROFILES[*]}"
else
    if [[ -t 0 ]]; then
        # Terminal interactif → menu de sélection
        interactive_select_profiles
    else
        # Non-interactif (curl | bash, SaltStack, etc.) → auto-détection
        info "Auto-détection des profils..."
        autodetect_profiles
    fi
fi

if [[ ${#SELECTED_PROFILES[@]} -gt 0 ]]; then
    info "Profils activés : ${SELECTED_PROFILES[*]}"
else
    info "Aucun profil supplémentaire — journald uniquement."
fi

if [[ ${#CUSTOM_PATHS[@]} -gt 0 ]]; then
    info "Chemins custom : ${CUSTOM_PATHS[*]}"
fi

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
        if [[ ! -f /etc/apt/sources.list.d/grafana.list ]] || [[ "${FORCE_UPDATE_REPO}" == true ]]; then
            info "Ajout/mise à jour du dépôt Grafana..."
            apt-get install -y -qq apt-transport-https > /dev/null 2>&1 || true
            mkdir -p /etc/apt/keyrings/
            curl -fsSL https://apt.grafana.com/gpg.key | gpg --dearmor -o /etc/apt/keyrings/grafana.gpg 2>/dev/null
            chmod 644 /etc/apt/keyrings/grafana.gpg
            echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" \
                > /etc/apt/sources.list.d/grafana.list
        fi

        apt-get update -qq -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/grafana.list \
            -o Dir::Etc::sourceparts="-" > /dev/null 2>&1

        if [[ -n "${PROMTAIL_VERSION}" ]]; then
            info "Version demandée : ${PROMTAIL_VERSION}"
            apt-get install -y "promtail=${PROMTAIL_VERSION}" > /dev/null 2>&1 \
                || die "Échec de l'installation de promtail=${PROMTAIL_VERSION}. Vérifiez : apt-cache policy promtail"
        else
            apt-get install -y promtail > /dev/null 2>&1 \
                || die "Échec de l'installation de Promtail."
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

# --- Génération de la configuration Promtail ---
info "Génération de la configuration Promtail..."

PROMTAIL_CONFIG="/etc/promtail/config.yml"

# Assembler la config
CONFIG_CONTENT=""

read -r -d '' CONFIG_HEADER << EOF || true
# Configuration Promtail — générée par install-promtail.sh v${SCRIPT_VERSION}
# Host: ${HOST_NAME} — $(date '+%Y-%m-%d %H:%M:%S')
# Profils actifs : journald ${SELECTED_PROFILES[*]:-} ${CUSTOM_PATHS[*]:+(custom)}
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
  # --- Journald (systemd) — toujours actif ---
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

CONFIG_CONTENT="${CONFIG_HEADER}"

# Ajouter les profils sélectionnés
for profile in "${SELECTED_PROFILES[@]}"; do
    profile_config=$(profile_scrape_config "${profile}" "${HOST_NAME}")
    profile_config="${profile_config//__HOST__/${HOST_NAME}}"
    CONFIG_CONTENT+=$'\n'"${profile_config}"
done

# Reconstituer DETECTED_ARR_APPS depuis la config générée (subshell workaround)
# profile_scrape_config() est appelé via $() → les variables meurent avec le subshell.
if [[ " ${SELECTED_PROFILES[*]:-} " =~ " arr " ]]; then
    DETECTED_ARR_APPS=()
    for _app in radarr sonarr lidarr prowlarr readarr bazarr whisparr; do
        if echo "${CONFIG_CONTENT}" | grep -q "job_name: ${_app}"; then
            DETECTED_ARR_APPS+=("${_app}")
        fi
    done
fi

# Ajouter les chemins custom
for custom_path in "${CUSTOM_PATHS[@]}"; do
    first_file=$(compgen -G "${custom_path}" 2>/dev/null | head -1 || echo "${custom_path}")
    custom_config=$(generate_custom_scrape_config "${first_file}" "${HOST_NAME}")
    custom_config="${custom_config//${first_file}/${custom_path}}"
    CONFIG_CONTENT+=$'\n'"${custom_config}"
done

# Écrire la config
if [[ "${DRY_RUN}" == false ]]; then
    mkdir -p /etc/promtail

    if [[ -f "${PROMTAIL_CONFIG}" ]]; then
        backup_path="${PROMTAIL_CONFIG}.bak.$(date +%s)"
        cp "${PROMTAIL_CONFIG}" "${backup_path}"
        info "Backup de la configuration existante : ${backup_path}"
    fi

    echo "${CONFIG_CONTENT}" > "${PROMTAIL_CONFIG}"
    success "Configuration écrite dans ${PROMTAIL_CONFIG}."
else
    info "[DRY-RUN] Configuration générée :"
    echo ""
    echo "${CONFIG_CONTENT}"
    echo ""
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

    # Permissions supplémentaires selon les profils
    if [[ " ${SELECTED_PROFILES[*]:-} " =~ " docker " ]]; then
        if getent group docker &>/dev/null; then
            usermod -aG docker promtail 2>/dev/null || true
            info "Promtail ajouté au groupe docker."
        fi
    fi

    # Permissions lecture pour les logs AIDE et rkhunter (souvent root-only)
    if [[ " ${SELECTED_PROFILES[*]:-} " =~ " aide " ]]; then
        if [[ -d /var/log/aide ]]; then
            setfacl -R -m u:promtail:r /var/log/aide 2>/dev/null \
                || chmod -R o+r /var/log/aide 2>/dev/null \
                || warn "Impossible de donner accès à /var/log/aide — vérifiez les ACL manuellement."
            info "Permissions lecture accordées sur /var/log/aide."
        fi
    fi

    if [[ " ${SELECTED_PROFILES[*]:-} " =~ " rkhunter " ]]; then
        if [[ -f /var/log/rkhunter.log ]]; then
            setfacl -m u:promtail:r /var/log/rkhunter.log 2>/dev/null \
                || chmod o+r /var/log/rkhunter.log 2>/dev/null \
                || warn "Impossible de donner accès à /var/log/rkhunter.log — vérifiez les ACL manuellement."
            info "Permissions lecture accordées sur /var/log/rkhunter.log."
        fi
    fi

    success "Permissions configurées."
else
    info "[DRY-RUN] usermod -aG systemd-journal,adm promtail"
    [[ " ${SELECTED_PROFILES[*]:-} " =~ " aide " ]] && info "[DRY-RUN] setfacl -R -m u:promtail:r /var/log/aide"
    [[ " ${SELECTED_PROFILES[*]:-} " =~ " rkhunter " ]] && info "[DRY-RUN] setfacl -m u:promtail:r /var/log/rkhunter.log"
fi

# --- Démarrage ---
info "Démarrage de Promtail..."

if [[ "${DRY_RUN}" == false ]]; then
    systemctl enable promtail > /dev/null 2>&1
    systemctl restart promtail

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
    echo -e "║ Profils       : journald ${SELECTED_PROFILES[*]:-}"
    [[ ${#CUSTOM_PATHS[@]} -gt 0 ]] && echo -e "║ Custom        : ${CUSTOM_PATHS[*]}"
    echo -e "║ Status        : ${promtail_status}"
    echo -e "${BOLD}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "║ Requêtes Grafana utiles :"
    echo -e "║   Tous les logs  : {host=\"${HOST_NAME}\"}"
    echo -e "║   Erreurs        : {host=\"${HOST_NAME}\", level=\"err\"}"
    for p in "${SELECTED_PROFILES[@]}"; do
        if [[ "${p}" == "arr" ]]; then
            # Afficher les jobs réels détectés dynamiquement
            if [[ ${#DETECTED_ARR_APPS[@]} -gt 0 ]]; then
                for arr_app in "${DETECTED_ARR_APPS[@]}"; do
                    printf "║   %-15s: {host=\"%s\", job=\"%s\"}\n" "${arr_app^}" "${HOST_NAME}" "${arr_app}"
                done
            else
                printf "║   %-15s: (aucune app *arr détectée)\n" "Arr"
            fi
        elif [[ "${p}" == "nginx" ]]; then
            printf "║   %-15s: {host=\"%s\", job=\"nginx\", log_type=\"access\"}\n" "Nginx access" "${HOST_NAME}"
            printf "║   %-15s: {host=\"%s\", job=\"nginx\", log_type=\"error\"}\n" "Nginx error" "${HOST_NAME}"
        elif [[ "${p}" == "unattended-upgrades" ]]; then
            printf "║   %-15s: {host=\"%s\", job=\"%s\"}\n" "Unattended" "${HOST_NAME}" "unattended-upgrades"
        else
            printf "║   %-15s: {host=\"%s\", job=\"%s\"}\n" "${p^}" "${HOST_NAME}" "${p}"
        fi
    done
else
    echo -e "║ Mode          : DRY-RUN (aucune modification effectuée)"
    echo -e "║ Host          : ${HOST_NAME}"
    echo -e "║ Loki URL      : ${LOKI_URL}"
    echo -e "║ Profils       : journald ${SELECTED_PROFILES[*]:-}"
fi

echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

if [[ "${DRY_RUN}" == false ]]; then
    info "Commandes utiles :"
    info "  journalctl -u promtail -f          # Logs Promtail en live"
    info "  curl -s localhost:9080/metrics      # Métriques Promtail"
    info "  curl -s localhost:9080/ready        # Healthcheck"
    info "  promtail --config.file=${PROMTAIL_CONFIG} --dry-run  # Valider la config"
fi