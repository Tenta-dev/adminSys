#!/usr/bin/env bash
###############################################################################
# security-audit.sh
# Audit de sécurité pour conteneurs LXC / VMs Proxmox
# Peut être lancé localement sur une machine ou depuis le host Proxmox
# sur tout l'inventaire.
#
# Usage :
#   # Audit local sur une machine
#   ./security-audit.sh
#
#   # Depuis le host Proxmox : audit de tout l'inventaire
#   ./security-audit.sh --all
#
#   # Avec notification Telegram
#   ./security-audit.sh --telegram
#
#   # Export du rapport en fichier
#   ./security-audit.sh --export /root/reports/
#
# Auteur : AdminSys_Linux
# Licence : MIT
###############################################################################
set -euo pipefail

# =============================================================================
# CONFIGURATION
# =============================================================================
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_VERSION="1.0.0"
readonly REPORT_DIR="${REPORT_DIR:-/root/security-reports}"

# Couleurs
readonly RED=$'\033[0;31m'
readonly GREEN=$'\033[0;32m'
readonly YELLOW=$'\033[1;33m'
readonly BLUE=$'\033[0;34m'
readonly CYAN=$'\033[0;36m'
readonly BOLD=$'\033[1m'
readonly DIM=$'\033[2m'
readonly NC=$'\033[0m'

# Seuils d'alerte
readonly DISK_WARN_PERCENT=80
readonly DISK_CRIT_PERCENT=90
readonly UPDATES_WARN=5
readonly UPDATES_CRIT=20
readonly LYNIS_WARN=70
readonly LYNIS_CRIT=50

# Variables
MODE="local"
ENABLE_TELEGRAM=false
EXPORT_DIR=""
INVENTORY_FILE="/root/inventaire.csv"
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"

# Compteurs globaux
TOTAL_CHECKS=0
TOTAL_OK=0
TOTAL_WARN=0
TOTAL_CRIT=0

# =============================================================================
# FONCTIONS UTILITAIRES
# =============================================================================

log() {
    local level="$1"; shift
    local message="$*"
    echo "${message}" >> /tmp/security-audit-$$.log 2>/dev/null || true
}

print_section() {
    echo ""
    echo -e "${BOLD}${CYAN}━━━ $* ━━━${NC}"
    echo ""
}

result_ok() {
    echo -e "  ${GREEN}✓${NC} $*"
    TOTAL_OK=$((TOTAL_OK + 1))
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
}

result_warn() {
    echo -e "  ${YELLOW}⚠${NC} $*"
    TOTAL_WARN=$((TOTAL_WARN + 1))
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
}

result_crit() {
    echo -e "  ${RED}✗${NC} $*"
    TOTAL_CRIT=$((TOTAL_CRIT + 1))
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
}

result_info() {
    echo -e "  ${BLUE}ℹ${NC} $*"
}

print_separator() {
    echo -e "${DIM}$(printf '%0.s─' $(seq 1 70))${NC}"
}

check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo -e "${RED}[ERREUR]${NC} Ce script doit être exécuté en root." >&2
        exit 1
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        source /etc/os-release
        OS_ID="${ID}"
        OS_NAME="${PRETTY_NAME}"
    else
        OS_ID="unknown"
        OS_NAME="Unknown"
    fi
}

detect_environment() {
    if [[ -f /run/systemd/container ]]; then
        CONTAINER_TYPE="$(cat /run/systemd/container)"
    elif systemd-detect-virt --quiet 2>/dev/null; then
        CONTAINER_TYPE="$(systemd-detect-virt)"
    else
        CONTAINER_TYPE="bare-metal"
    fi
}

# =============================================================================
# MODULES D'AUDIT
# =============================================================================

# --- 1. Informations système ---
audit_system_info() {
    print_section "Informations système"

    local hostname_val ip_addr uptime_val kernel_ver
    hostname_val="$(hostname -f 2>/dev/null || hostname)"
    ip_addr="$(hostname -I 2>/dev/null | awk '{print $1}')" || ip_addr="N/A"
    uptime_val="$(uptime -p 2>/dev/null || echo 'N/A')"
    kernel_ver="$(uname -r)"

    echo -e "  Hostname    : ${BOLD}${hostname_val}${NC}"
    echo -e "  IP          : ${ip_addr}"
    echo -e "  OS          : ${OS_NAME}"
    echo -e "  Kernel      : ${kernel_ver}"
    echo -e "  Type        : ${CONTAINER_TYPE}"
    echo -e "  Uptime      : ${uptime_val}"
}

# --- 2. Mises à jour de sécurité en attente ---
audit_pending_updates() {
    print_section "Mises à jour de sécurité"

    # Rafraîchir la liste des paquets silencieusement
    apt-get update -qq 2>/dev/null || true

    # Compter les mises à jour disponibles
    local all_updates=0
    local security_updates=0

    if command -v apt-get &>/dev/null; then
        all_updates=$(apt-get -s upgrade 2>/dev/null | grep -c "^Inst " || true)
        security_updates=$(apt-get -s upgrade 2>/dev/null | grep "^Inst " | grep -ci "securi" || true)
    fi

    if [[ "${security_updates}" -ge "${UPDATES_CRIT}" ]]; then
        result_crit "${security_updates} mises à jour de sécurité en attente (total: ${all_updates})"
    elif [[ "${security_updates}" -ge "${UPDATES_WARN}" ]]; then
        result_warn "${security_updates} mises à jour de sécurité en attente (total: ${all_updates})"
    elif [[ "${security_updates}" -gt 0 ]]; then
        result_warn "${security_updates} mise(s) à jour de sécurité en attente (total: ${all_updates})"
    else
        result_ok "Aucune mise à jour de sécurité en attente (total en attente: ${all_updates})"
    fi

    # Vérifier si unattended-upgrades est actif
    if systemctl is-active unattended-upgrades &>/dev/null; then
        result_ok "unattended-upgrades est actif"
    elif dpkg -l unattended-upgrades &>/dev/null 2>&1; then
        result_warn "unattended-upgrades est installé mais inactif"
    else
        result_crit "unattended-upgrades n'est pas installé"
    fi

    # Vérifier la date de la dernière mise à jour
    if [[ -f /var/log/apt/history.log ]]; then
        local last_update
        last_update=$(grep "Start-Date" /var/log/apt/history.log 2>/dev/null | tail -1 | awk '{print $2}' || echo "")
        if [[ -n "${last_update}" ]]; then
            local days_since
            days_since=$(( ($(date +%s) - $(date -d "${last_update}" +%s 2>/dev/null || echo "0")) / 86400 ))
            if [[ "${days_since}" -gt 30 ]]; then
                result_crit "Dernière mise à jour il y a ${days_since} jours (${last_update})"
            elif [[ "${days_since}" -gt 7 ]]; then
                result_warn "Dernière mise à jour il y a ${days_since} jours (${last_update})"
            else
                result_ok "Dernière mise à jour il y a ${days_since} jour(s) (${last_update})"
            fi
        fi
    fi

    # Lister les paquets de sécurité en attente si présents
    if [[ "${security_updates}" -gt 0 ]]; then
        echo ""
        echo -e "  ${DIM}Paquets de sécurité en attente :${NC}"
        apt-get -s upgrade 2>/dev/null | grep "^Inst " | grep -i "securi" | awk '{print "    - " $2 " (" $3 " → " $4 ")"}' | head -20
        [[ "${security_updates}" -gt 20 ]] && echo -e "    ${DIM}... et $((security_updates - 20)) autres${NC}"
    fi
}

# --- 3. Configuration SSH ---
audit_ssh() {
    print_section "Configuration SSH"

    # Vérifier si sshd est installé et actif
    if ! command -v sshd &>/dev/null; then
        result_info "sshd n'est pas installé (peut être normal selon le service)"
        return
    fi

    # Port SSH
    local ssh_port
    ssh_port=$(sshd -T 2>/dev/null | grep "^port " | awk '{print $2}' || echo "22")
    if [[ "${ssh_port}" == "22" ]]; then
        result_warn "SSH sur le port par défaut (22)"
    else
        result_ok "SSH sur le port ${ssh_port}"
    fi

    # Root login
    local root_login
    root_login=$(sshd -T 2>/dev/null | grep "^permitrootlogin " | awk '{print $2}' || echo "unknown")
    if [[ "${root_login}" == "no" ]]; then
        result_ok "Login root désactivé"
    else
        result_crit "Login root autorisé (${root_login})"
    fi

    # Password authentication
    local password_auth
    password_auth=$(sshd -T 2>/dev/null | grep "^passwordauthentication " | awk '{print $2}' || echo "unknown")
    if [[ "${password_auth}" == "no" ]]; then
        result_ok "Authentification par mot de passe désactivée"
    else
        result_crit "Authentification par mot de passe activée"
    fi

    # Max auth tries
    local max_tries
    max_tries=$(sshd -T 2>/dev/null | grep "^maxauthtries " | awk '{print $2}' || echo "6")
    if [[ "${max_tries}" -le 3 ]]; then
        result_ok "Tentatives max : ${max_tries}"
    else
        result_warn "Tentatives max : ${max_tries} (recommandé: 3)"
    fi

    # X11 forwarding
    local x11
    x11=$(sshd -T 2>/dev/null | grep "^x11forwarding " | awk '{print $2}' || echo "unknown")
    if [[ "${x11}" == "no" ]]; then
        result_ok "X11 forwarding désactivé"
    else
        result_warn "X11 forwarding activé"
    fi

    # AllowUsers défini ?
    local allow_users
    allow_users=$(sshd -T 2>/dev/null | grep "^allowusers " | awk '{$1=""; print $0}' || echo "")
    if [[ -n "${allow_users}" ]]; then
        result_ok "AllowUsers restreint à :${allow_users}"
    else
        result_warn "AllowUsers non défini (tous les utilisateurs peuvent se connecter)"
    fi
}

# --- 4. Fail2ban ---
audit_fail2ban() {
    print_section "Fail2ban"

    if ! command -v fail2ban-client &>/dev/null; then
        result_crit "fail2ban n'est pas installé"
        return
    fi

    if systemctl is-active fail2ban &>/dev/null; then
        result_ok "fail2ban est actif"
    else
        result_crit "fail2ban est installé mais inactif"
        return
    fi

    # Vérifier la jail sshd
    if fail2ban-client status sshd &>/dev/null; then
        local banned
        banned=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $NF}')
        local total_banned
        total_banned=$(fail2ban-client status sshd 2>/dev/null | grep "Total banned" | awk '{print $NF}')
        result_ok "Jail SSH active — ${banned} IP bannie(s) actuellement, ${total_banned} au total"

        # Lister les IP bannies si présentes
        if [[ "${banned}" -gt 0 ]]; then
            local banned_list
            banned_list=$(fail2ban-client status sshd 2>/dev/null | grep "Banned IP list" | sed 's/.*://;s/^ *//')
            echo -e "    ${DIM}IP bannies : ${banned_list}${NC}"
        fi
    else
        result_warn "Jail SSH non configurée"
    fi
}

# --- 5. Ports ouverts ---
audit_open_ports() {
    print_section "Ports ouverts"

    local port_count=0
    local seen_ports=""

    # ss -tulnp format: proto state recv-q send-q local_addr:port peer_addr:port process
    while IFS= read -r line; do
        local proto port process addr
        proto=$(echo "${line}" | awk '{print $1}')
        addr=$(echo "${line}" | awk '{print $5}')
        port=$(echo "${addr}" | rev | cut -d: -f1 | rev)
        # Extraire le nom du process : users:(("sshd",pid=123,fd=4)) → sshd
        process=$(echo "${line}" | grep -oP '"\K[^"]+' | head -1)
        [[ -z "${process}" ]] && process="unknown"

        # Dédupliquer (même port+proto vu en IPv4 et IPv6)
        local key="${proto}/${port}/${process}"
        if echo "${seen_ports}" | grep -qF "${key}"; then
            continue
        fi
        seen_ports="${seen_ports} ${key}"

        # Classifier le port
        case "${port}" in
            22|2222)
                result_ok "${proto}/${port} — ${process} (SSH)"
                ;;
            80|443|8080|8443|81)
                result_ok "${proto}/${port} — ${process} (Web)"
                ;;
            3306|5432|6379|27017)
                result_warn "${proto}/${port} — ${process} (Base de données — vérifier l'exposition)"
                ;;
            *)
                result_info "${proto}/${port} — ${process}"
                ;;
        esac
        port_count=$((port_count + 1))
    done < <(ss -tulnp 2>/dev/null | grep "LISTEN" || true)

    if [[ "${port_count}" -eq 0 ]]; then
        result_info "Aucun port en écoute détecté"
    else
        echo ""
        echo -e "  ${DIM}${port_count} port(s) en écoute au total${NC}"
    fi
}

# --- 6. Utilisateurs et permissions ---
audit_users() {
    print_section "Utilisateurs et permissions"

    # Compter les utilisateurs avec un shell de login
    local login_users
    login_users=$(grep -E '/bin/(bash|sh|zsh|fish)$' /etc/passwd | grep -v "^root:" || true)
    local login_count
    login_count=$(echo "${login_users}" | grep -c '[^[:space:]]' || true)

    result_info "${login_count} utilisateur(s) avec shell de login (hors root)"

    if [[ -n "${login_users}" ]]; then
        while IFS=: read -r username _ uid _ _ home shell; do
            echo -e "    ${DIM}${username} (UID:${uid}) — ${shell}${NC}"
        done <<< "${login_users}"
    fi

    # Utilisateurs avec UID 0 (root)
    local uid0_count
    uid0_count=$(awk -F: '$3 == 0 {print $1}' /etc/passwd | wc -l)
    if [[ "${uid0_count}" -gt 1 ]]; then
        result_crit "${uid0_count} utilisateurs avec UID 0 (devrait être uniquement root)"
        awk -F: '$3 == 0 {print "    - " $1}' /etc/passwd
    else
        result_ok "Seul root a l'UID 0"
    fi

    # Utilisateurs sans mot de passe
    local no_password
    no_password=$(awk -F: '($2 == "" || $2 == "!") && $1 != "root" {print $1}' /etc/shadow 2>/dev/null || true)
    if [[ -n "${no_password}" ]]; then
        # Filtrer les comptes système/verrouillés (c'est normal)
        local real_no_pass=0
        while IFS= read -r user; do
            if grep -qE '/bin/(bash|sh|zsh)$' /etc/passwd | grep "^${user}:" 2>/dev/null; then
                real_no_pass=$((real_no_pass + 1))
            fi
        done <<< "${no_password}"
        if [[ "${real_no_pass}" -gt 0 ]]; then
            result_warn "${real_no_pass} utilisateur(s) avec shell de login sans mot de passe"
        fi
    fi

    # Fichiers SUID suspects
    local suid_files
    suid_files=$(find / -perm -4000 -type f 2>/dev/null | grep -v -E "^/(usr/(bin|lib|libexec|sbin)|bin|sbin)/" || true)
    local suid_count
    suid_count=$(echo "${suid_files}" | grep -c '[^[:space:]]' || true)
    if [[ "${suid_count}" -gt 0 ]]; then
        result_warn "${suid_count} fichier(s) SUID hors chemins standards"
        echo "${suid_files}" | head -10 | while read -r f; do
            echo -e "    ${DIM}${f}${NC}"
        done
    else
        result_ok "Aucun fichier SUID suspect détecté"
    fi

    # Fichiers world-writable dans /etc
    local world_writable
    world_writable=$(find /etc -perm -o+w -type f 2>/dev/null || true)
    local ww_count
    ww_count=$(echo "${world_writable}" | grep -c '[^[:space:]]' || true)
    if [[ "${ww_count}" -gt 0 ]]; then
        result_crit "${ww_count} fichier(s) world-writable dans /etc"
        echo "${world_writable}" | head -10 | while read -r f; do
            echo -e "    ${DIM}${f}${NC}"
        done
    else
        result_ok "Aucun fichier world-writable dans /etc"
    fi
}

# --- 7. Espace disque ---
audit_disk() {
    print_section "Espace disque"

    while IFS= read -r line; do
        local usage mount filesystem
        usage=$(echo "${line}" | awk '{print $5}' | tr -d '%')
        mount=$(echo "${line}" | awk '{print $6}')
        filesystem=$(echo "${line}" | awk '{print $1}')

        if [[ "${usage}" -ge "${DISK_CRIT_PERCENT}" ]]; then
            result_crit "${mount} — ${usage}% utilisé (${filesystem})"
        elif [[ "${usage}" -ge "${DISK_WARN_PERCENT}" ]]; then
            result_warn "${mount} — ${usage}% utilisé (${filesystem})"
        else
            result_ok "${mount} — ${usage}% utilisé (${filesystem})"
        fi
    done < <(df -h --output=source,size,used,avail,pcent,target -x tmpfs -x devtmpfs -x squashfs 2>/dev/null | tail -n +2 || true)

    # Inodes
    while IFS= read -r line; do
        local iuse imount
        iuse=$(echo "${line}" | awk '{print $5}' | tr -d '%')
        imount=$(echo "${line}" | awk '{print $6}')

        # Ignorer si vide
        [[ -z "${iuse}" || "${iuse}" == "-" ]] && continue

        if [[ "${iuse}" -ge 90 ]]; then
            result_crit "Inodes ${imount} — ${iuse}% utilisés"
        elif [[ "${iuse}" -ge 80 ]]; then
            result_warn "Inodes ${imount} — ${iuse}% utilisés"
        fi
    done < <(df -i --output=source,itotal,iused,iavail,ipcent,target -x tmpfs -x devtmpfs -x squashfs 2>/dev/null | tail -n +2 || true)
}

# --- 8. Services systemd en échec ---
audit_failed_services() {
    print_section "Services systemd"

    local failed
    failed=$(systemctl --failed --no-legend 2>/dev/null || true)
    local failed_count
    failed_count=$(echo "${failed}" | grep -c '[^[:space:]]' || true)

    if [[ "${failed_count}" -gt 0 ]]; then
        result_crit "${failed_count} service(s) en échec"
        echo "${failed}" | while IFS= read -r line; do
            # systemctl --failed: "● service.name loaded failed failed Description"
            local svc
            svc=$(echo "${line}" | awk '{print $2}')
            # Fallback si $2 est vide (format alternatif)
            [[ -z "${svc}" ]] && svc=$(echo "${line}" | awk '{print $1}')
            echo -e "    ${RED}${svc}${NC}"
        done
    else
        result_ok "Aucun service en échec"
    fi
}

# --- 9. Docker (si installé) ---
audit_docker() {
    if ! command -v docker &>/dev/null; then
        return
    fi

    print_section "Docker"

    # Docker daemon
    if systemctl is-active docker &>/dev/null; then
        result_ok "Docker daemon actif"
    else
        result_warn "Docker installé mais daemon inactif"
        return
    fi

    # Version Docker
    local docker_version
    docker_version=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "inconnue")
    result_info "Docker version ${docker_version}"

    # Conteneurs en cours
    local running
    running=$(docker ps -q 2>/dev/null | wc -l || echo "0")
    local total
    total=$(docker ps -aq 2>/dev/null | wc -l || echo "0")
    local stopped=$((total - running))

    result_info "${running} conteneur(s) en cours, ${stopped} arrêté(s)"

    # Conteneurs en restart loop
    local restarting
    restarting=$(docker ps --filter "status=restarting" -q 2>/dev/null | wc -l || echo "0")
    if [[ "${restarting}" -gt 0 ]]; then
        result_crit "${restarting} conteneur(s) en boucle de redémarrage"
        docker ps --filter "status=restarting" --format "    {{.Names}} ({{.Image}})" 2>/dev/null
    fi

    # --- Sécurité des conteneurs en cours ---
    if [[ "${running}" -gt 0 ]]; then

        # Conteneurs en mode privileged
        local priv_count=0
        while read -r cid; do
            local cname cpriv
            cname=$(docker inspect "${cid}" --format '{{.Name}}' 2>/dev/null | sed 's|^/||')
            cpriv=$(docker inspect "${cid}" --format '{{.HostConfig.Privileged}}' 2>/dev/null)
            if [[ "${cpriv}" == "true" ]]; then
                if [[ "${priv_count}" -eq 0 ]]; then
                    result_crit "Conteneur(s) en mode --privileged (accès total au host) :"
                fi
                echo -e "    ${RED}${cname}${NC}"
                priv_count=$((priv_count + 1))
            fi
        done < <(docker ps -q 2>/dev/null)
        if [[ "${priv_count}" -eq 0 ]]; then
            result_ok "Aucun conteneur en mode privileged"
        fi

        # Conteneurs en mode --net=host
        local nethost_count=0
        while read -r cid; do
            local cname cnet
            cname=$(docker inspect "${cid}" --format '{{.Name}}' 2>/dev/null | sed 's|^/||')
            cnet=$(docker inspect "${cid}" --format '{{.HostConfig.NetworkMode}}' 2>/dev/null)
            if [[ "${cnet}" == "host" ]]; then
                if [[ "${nethost_count}" -eq 0 ]]; then
                    result_warn "Conteneur(s) en mode --net=host (pas d'isolation réseau) :"
                fi
                echo -e "    ${YELLOW}${cname}${NC}"
                nethost_count=$((nethost_count + 1))
            fi
        done < <(docker ps -q 2>/dev/null)

        # Conteneurs exécutant en tant que root
        local root_count=0
        local non_root_count=0
        while read -r cid; do
            local cname cuser
            cname=$(docker inspect "${cid}" --format '{{.Name}}' 2>/dev/null | sed 's|^/||')
            cuser=$(docker inspect "${cid}" --format '{{.Config.User}}' 2>/dev/null)
            if [[ -z "${cuser}" || "${cuser}" == "root" || "${cuser}" == "0" ]]; then
                root_count=$((root_count + 1))
            else
                non_root_count=$((non_root_count + 1))
            fi
        done < <(docker ps -q 2>/dev/null)
        if [[ "${root_count}" -gt 0 ]]; then
            result_warn "${root_count} conteneur(s) exécuté(s) en tant que root"
        fi
        if [[ "${non_root_count}" -gt 0 ]]; then
            result_ok "${non_root_count} conteneur(s) exécuté(s) avec un utilisateur non-root"
        fi

        # Conteneurs avec des ports bindés sur 0.0.0.0 (exposés sur toutes les interfaces)
        local exposed_count=0
        while read -r cid; do
            local cname ports_all
            cname=$(docker inspect "${cid}" --format '{{.Name}}' 2>/dev/null | sed 's|^/||')
            ports_all=$(docker port "${cid}" 2>/dev/null | grep "0.0.0.0:" || true)
            if [[ -n "${ports_all}" ]]; then
                if [[ "${exposed_count}" -eq 0 ]]; then
                    result_warn "Conteneur(s) avec des ports exposés sur toutes les interfaces (0.0.0.0) :"
                fi
                echo -e "    ${YELLOW}${cname}${NC} — $(echo "${ports_all}" | awk '{print $3}' | tr '\n' ' ')"
                exposed_count=$((exposed_count + 1))
            fi
        done < <(docker ps -q 2>/dev/null)
        if [[ "${exposed_count}" -eq 0 && "${running}" -gt 0 ]]; then
            result_ok "Aucun port exposé sur 0.0.0.0"
        fi

        # Conteneurs sans restart policy
        local norestart_count=0
        while read -r cid; do
            local cname cpolicy
            cname=$(docker inspect "${cid}" --format '{{.Name}}' 2>/dev/null | sed 's|^/||')
            cpolicy=$(docker inspect "${cid}" --format '{{.HostConfig.RestartPolicy.Name}}' 2>/dev/null)
            if [[ "${cpolicy}" == "no" || -z "${cpolicy}" ]]; then
                norestart_count=$((norestart_count + 1))
            fi
        done < <(docker ps -q 2>/dev/null)
        if [[ "${norestart_count}" -gt 0 ]]; then
            result_info "${norestart_count} conteneur(s) sans politique de redémarrage"
        fi

        # Conteneurs avec le socket Docker monté (risque d'évasion)
        local socket_count=0
        while read -r cid; do
            local cname cmounts
            cname=$(docker inspect "${cid}" --format '{{.Name}}' 2>/dev/null | sed 's|^/||')
            cmounts=$(docker inspect "${cid}" --format '{{range .Mounts}}{{.Source}} {{end}}' 2>/dev/null)
            if echo "${cmounts}" | grep -q "docker.sock"; then
                if [[ "${socket_count}" -eq 0 ]]; then
                    result_crit "Conteneur(s) avec le socket Docker monté (risque d'évasion) :"
                fi
                echo -e "    ${RED}${cname}${NC}"
                socket_count=$((socket_count + 1))
            fi
        done < <(docker ps -q 2>/dev/null)
        if [[ "${socket_count}" -eq 0 ]]; then
            result_ok "Aucun conteneur avec le socket Docker monté"
        fi

    fi

    # --- Hygiène Docker ---

    # Images sans tag (dangling)
    local dangling
    dangling=$(docker images -f "dangling=true" -q 2>/dev/null | wc -l || echo "0")
    if [[ "${dangling}" -gt 0 ]]; then
        result_warn "${dangling} image(s) orpheline(s) (dangling) — récupérable avec 'docker image prune'"
    else
        result_ok "Aucune image orpheline"
    fi

    # Volumes orphelins
    local orphan_volumes
    orphan_volumes=$(docker volume ls -f "dangling=true" -q 2>/dev/null | wc -l || echo "0")
    if [[ "${orphan_volumes}" -gt 0 ]]; then
        result_warn "${orphan_volumes} volume(s) orphelin(s) — récupérable avec 'docker volume prune'"
    fi

    # Docker API exposée sur le réseau
    if ss -tlnp 2>/dev/null | grep -q ":2375 \|:2376 "; then
        result_crit "API Docker exposée sur le réseau (port 2375/2376) — risque majeur"
    else
        result_ok "API Docker non exposée sur le réseau"
    fi

    # Espace disque Docker
    local docker_disk
    docker_disk=$(docker system df --format '{{.Size}}' 2>/dev/null | head -1 || echo "N/A")
    result_info "Espace Docker utilisé : images=${docker_disk:-N/A}"
}

# --- 10. Lynis (si installé) ---
audit_lynis() {
    if ! command -v lynis &>/dev/null; then
        print_section "Lynis"
        result_info "Lynis n'est pas installé — installation recommandée : apt install lynis"
        return
    fi

    print_section "Lynis (audit complet)"

    echo -e "  ${DIM}Exécution de Lynis en cours...${NC}"

    # Lancer Lynis silencieusement
    local lynis_log="/tmp/lynis-audit-$$.log"
    lynis audit system --no-colors --quick 2>/dev/null > "${lynis_log}" || true

    # Extraire le score
    local score
    score=$(grep "Hardening index" "${lynis_log}" 2>/dev/null | grep -oP '\d+' | head -1 || echo "0")

    if [[ "${score}" -ge "${LYNIS_WARN}" ]]; then
        result_ok "Score Lynis : ${score}/100"
    elif [[ "${score}" -ge "${LYNIS_CRIT}" ]]; then
        result_warn "Score Lynis : ${score}/100 (recommandé: > ${LYNIS_WARN})"
    else
        result_crit "Score Lynis : ${score}/100 (critique, recommandé: > ${LYNIS_WARN})"
    fi

    # Extraire les warnings et suggestions
    local warnings suggestions
    warnings=$(grep "^  \! " "${lynis_log}" 2>/dev/null || true)
    suggestions=$(grep "^  - " "${lynis_log}" 2>/dev/null | head -10 || true)

    local warn_count
    warn_count=$(echo "${warnings}" | grep -c '[^[:space:]]' || true)
    local sugg_count
    sugg_count=$(grep -c "^  - " "${lynis_log}" 2>/dev/null || true)

    if [[ "${warn_count}" -gt 0 ]]; then
        result_warn "${warn_count} avertissement(s) Lynis"
        echo "${warnings}" | head -10 | while IFS= read -r line; do
            echo -e "    ${DIM}${line}${NC}"
        done
        [[ "${warn_count}" -gt 10 ]] && echo -e "    ${DIM}... et $((warn_count - 10)) autres${NC}"
    fi

    result_info "${sugg_count} suggestion(s) d'amélioration"

    # Sauvegarder le rapport Lynis complet
    if [[ -n "${EXPORT_DIR}" ]]; then
        local lynis_dest="${EXPORT_DIR}/lynis-$(hostname)-$(date '+%Y%m%d').log"
        cp "${lynis_log}" "${lynis_dest}"
        echo -e "  ${DIM}Rapport Lynis complet : ${lynis_dest}${NC}"
    fi

    rm -f "${lynis_log}"
}

# --- 11. Certificats TLS ---
audit_certificates() {
    print_section "Certificats TLS"

    local cert_found=false

    # Vérifier les certificats Let's Encrypt
    if [[ -d /etc/letsencrypt/live ]]; then
        for domain_dir in /etc/letsencrypt/live/*/; do
            [[ -d "${domain_dir}" ]] || continue
            cert_found=true

            local domain
            domain=$(basename "${domain_dir}")
            local cert_file="${domain_dir}cert.pem"

            if [[ -f "${cert_file}" ]]; then
                local expiry
                expiry=$(openssl x509 -enddate -noout -in "${cert_file}" 2>/dev/null | cut -d= -f2)
                local expiry_epoch
                expiry_epoch=$(date -d "${expiry}" +%s 2>/dev/null || echo "0")
                local now_epoch
                now_epoch=$(date +%s)
                local days_left=$(( (expiry_epoch - now_epoch) / 86400 ))

                if [[ "${days_left}" -le 0 ]]; then
                    result_crit "${domain} — EXPIRÉ depuis $((days_left * -1)) jour(s)"
                elif [[ "${days_left}" -le 7 ]]; then
                    result_crit "${domain} — expire dans ${days_left} jour(s)"
                elif [[ "${days_left}" -le 14 ]]; then
                    result_warn "${domain} — expire dans ${days_left} jour(s)"
                else
                    result_ok "${domain} — expire dans ${days_left} jour(s)"
                fi
            fi
        done
    fi

    # Vérifier les certificats dans /etc/ssl personnalisés
    for cert in /etc/ssl/certs/local-*.pem /etc/ssl/private/*.crt; do
        [[ -f "${cert}" ]] || continue
        cert_found=true

        local cn
        cn=$(openssl x509 -subject -noout -in "${cert}" 2>/dev/null | sed 's/.*CN = //' || echo "unknown")
        local expiry
        expiry=$(openssl x509 -enddate -noout -in "${cert}" 2>/dev/null | cut -d= -f2)
        local expiry_epoch
        expiry_epoch=$(date -d "${expiry}" +%s 2>/dev/null || echo "0")
        local now_epoch
        now_epoch=$(date +%s)
        local days_left=$(( (expiry_epoch - now_epoch) / 86400 ))

        if [[ "${days_left}" -le 14 ]]; then
            result_warn "${cn} (${cert}) — expire dans ${days_left} jour(s)"
        else
            result_ok "${cn} — expire dans ${days_left} jour(s)"
        fi
    done

    if [[ "${cert_found}" == false ]]; then
        result_info "Aucun certificat TLS trouvé"
    fi
}

# --- 12. Crontabs ---
audit_crontabs() {
    print_section "Tâches planifiées (crontabs)"

    local cron_found=false

    # Crontabs utilisateurs
    for user_cron in /var/spool/cron/crontabs/*; do
        [[ -f "${user_cron}" ]] || continue
        cron_found=true
        local user
        user=$(basename "${user_cron}")
        local count
        count=$(grep -cvE '^#|^$' "${user_cron}" 2>/dev/null || true)
        result_info "Crontab ${user} : ${count} entrée(s)"
    done

    # Cron système
    for cron_dir in /etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
        if [[ -d "${cron_dir}" ]]; then
            local count
            count=$(find "${cron_dir}" -type f | wc -l)
            if [[ "${count}" -gt 0 ]]; then
                result_info "${cron_dir} : ${count} fichier(s)"
                cron_found=true
            fi
        fi
    done

    # Timers systemd
    local timer_count
    timer_count=$(systemctl list-timers --no-legend 2>/dev/null | wc -l || true)
    if [[ "${timer_count}" -gt 0 ]]; then
        result_info "${timer_count} timer(s) systemd actif(s)"
        cron_found=true
    fi

    if [[ "${cron_found}" == false ]]; then
        result_info "Aucune tâche planifiée détectée"
    fi
}

# =============================================================================
# RAPPORT
# =============================================================================

print_report_header() {
    local hostname_val
    hostname_val="$(hostname -f 2>/dev/null || hostname)"
    local date_now
    date_now="$(date '+%Y-%m-%d %H:%M:%S')"

    echo ""
    echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║          🔍 AUDIT DE SÉCURITÉ — ${hostname_val}${NC}"
    echo -e "${BOLD}║          ${DIM}${date_now}${NC}"
    echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
}

print_report_summary() {
    local hostname_val
    hostname_val="$(hostname -f 2>/dev/null || hostname)"

    echo ""
    print_separator

    # Score global
    local score_color="${GREEN}"
    local score_label="BON"
    if [[ "${TOTAL_CRIT}" -gt 0 ]]; then
        score_color="${RED}"
        score_label="CRITIQUE"
    elif [[ "${TOTAL_WARN}" -gt 3 ]]; then
        score_color="${YELLOW}"
        score_label="ATTENTION"
    elif [[ "${TOTAL_WARN}" -gt 0 ]]; then
        score_color="${YELLOW}"
        score_label="CORRECT"
    fi

    echo ""
    echo -e "  ${BOLD}Résumé ${hostname_val}${NC}"
    echo ""
    echo -e "  Statut global  : ${score_color}${BOLD}${score_label}${NC}"
    echo -e "  ${GREEN}✓ OK${NC}            : ${TOTAL_OK}"
    echo -e "  ${YELLOW}⚠ Avertissements${NC} : ${TOTAL_WARN}"
    echo -e "  ${RED}✗ Critiques${NC}      : ${TOTAL_CRIT}"
    echo -e "  Total vérifiés : ${TOTAL_CHECKS}"
    echo ""
    print_separator
    echo ""
}

generate_telegram_message() {
    local hostname_val
    hostname_val="$(hostname -f 2>/dev/null || hostname)"
    local ip_addr
    ip_addr="$(hostname -I 2>/dev/null | awk '{print $1}')" || ip_addr="N/A"

    local status_emoji="🟢"
    local status_label="BON"
    if [[ "${TOTAL_CRIT}" -gt 0 ]]; then
        status_emoji="🔴"
        status_label="CRITIQUE"
    elif [[ "${TOTAL_WARN}" -gt 3 ]]; then
        status_emoji="🟡"
        status_label="ATTENTION"
    elif [[ "${TOTAL_WARN}" -gt 0 ]]; then
        status_emoji="🟡"
        status_label="CORRECT"
    fi

    cat << EOF
${status_emoji} *Audit sécurité — ${hostname_val}*

🖥 \`${hostname_val}\` (${ip_addr})
📊 Statut : *${status_label}*

✅ OK : ${TOTAL_OK}
⚠️ Avertissements : ${TOTAL_WARN}
❌ Critiques : ${TOTAL_CRIT}

📅 $(date '+%Y-%m-%d %H:%M')
EOF
}

send_telegram() {
    if [[ "${ENABLE_TELEGRAM}" == false ]]; then
        return
    fi

    if [[ -z "${TELEGRAM_BOT_TOKEN}" || -z "${TELEGRAM_CHAT_ID}" ]]; then
        echo -e "${YELLOW}[WARN]${NC} Telegram activé mais TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID non définis."
        return
    fi

    local message
    message=$(generate_telegram_message)

    curl -s -X POST \
        "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -d chat_id="${TELEGRAM_CHAT_ID}" \
        -d text="${message}" \
        -d parse_mode="Markdown" > /dev/null 2>&1 \
        && echo -e "${GREEN}[OK]${NC} Notification Telegram envoyée." \
        || echo -e "${YELLOW}[WARN]${NC} Échec de l'envoi Telegram."
}

export_report() {
    if [[ -z "${EXPORT_DIR}" ]]; then
        return
    fi

    mkdir -p "${EXPORT_DIR}"

    local hostname_val
    hostname_val="$(hostname -s 2>/dev/null || hostname)"
    local report_file="${EXPORT_DIR}/audit-${hostname_val}-$(date '+%Y%m%d_%H%M%S').md"

    # Relancer l'audit en capturant la sortie sans couleurs
    cat > "${report_file}" << MDEOF
# 🔍 Rapport d'audit sécurité

- **Machine** : $(hostname -f 2>/dev/null || hostname)
- **IP** : $(hostname -I 2>/dev/null | awk '{print $1}')
- **Date** : $(date '+%Y-%m-%d %H:%M:%S')
- **OS** : ${OS_NAME}
- **Type** : ${CONTAINER_TYPE}

## Résumé

| Statut | Nombre |
|--------|--------|
| ✅ OK | ${TOTAL_OK} |
| ⚠️ Avertissements | ${TOTAL_WARN} |
| ❌ Critiques | ${TOTAL_CRIT} |
| Total | ${TOTAL_CHECKS} |

MDEOF

    echo -e "${GREEN}[OK]${NC} Rapport exporté : ${report_file}"
}

# =============================================================================
# MODE --all (depuis le host Proxmox)
# =============================================================================

run_on_all_inventory() {
    if [[ ! -f "${INVENTORY_FILE}" ]]; then
        echo -e "${RED}[ERREUR]${NC} Fichier d'inventaire introuvable : ${INVENTORY_FILE}"
        echo "Utilisez 'inventory list' pour vérifier votre inventaire."
        exit 1
    fi

    local total
    total=$(tail -n +2 "${INVENTORY_FILE}" | grep -c '[^[:space:]]' || true)

    echo ""
    echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║     🔍 AUDIT DE SÉCURITÉ — ${total} machine(s)${NC}"
    echo -e "${BOLD}║     ${DIM}$(date '+%Y-%m-%d %H:%M:%S')${NC}"
    echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    local global_ok=0
    local global_warn=0
    local global_crit=0
    local global_unreachable=0

    while IFS=',' read -r hostname ip port user os type date_h; do
        echo -e "${BOLD}━━━ ${hostname} (${ip}:${port}) ━━━${NC}"

        # Test de connectivité
        if ! nc -z -w 3 "${ip}" "${port}" 2>/dev/null && ! timeout 3 bash -c "echo >/dev/tcp/${ip}/${port}" 2>/dev/null; then
            echo -e "  ${RED}✗ Machine injoignable${NC}"
            global_unreachable=$((global_unreachable + 1))
            echo ""
            continue
        fi

        # Envoyer et exécuter le script sur la machine distante
        local remote_output
        remote_output=$(ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 \
            -p "${port}" "${user}@${ip}" \
            "curl -fsSL https://raw.githubusercontent.com/Tenta-dev/adminSys/main/security-audit.sh 2>/dev/null | sudo bash -s -- --summary-only" 2>/dev/null) || {
            echo -e "  ${YELLOW}⚠ Exécution échouée sur ${hostname}${NC}"
            global_unreachable=$((global_unreachable + 1))
            echo ""
            continue
        }

        echo "${remote_output}"

        # Extraire les compteurs depuis la sortie
        local ok warn crit
        ok=$(echo "${remote_output}" | grep -oP '✓ OK\s*:\s*\K\d+' || echo "0")
        warn=$(echo "${remote_output}" | grep -oP '⚠ Avertissements\s*:\s*\K\d+' || echo "0")
        crit=$(echo "${remote_output}" | grep -oP '✗ Critiques\s*:\s*\K\d+' || echo "0")

        global_ok=$((global_ok + ok))
        global_warn=$((global_warn + warn))
        global_crit=$((global_crit + crit))
        echo ""

    done < <(tail -n +2 "${INVENTORY_FILE}" | grep '[^[:space:]]' || true)

    # Résumé global
    echo ""
    print_separator
    echo ""
    echo -e "  ${BOLD}Résumé global — ${total} machine(s)${NC}"
    echo ""
    echo -e "  ${GREEN}✓ OK${NC}            : ${global_ok}"
    echo -e "  ${YELLOW}⚠ Avertissements${NC} : ${global_warn}"
    echo -e "  ${RED}✗ Critiques${NC}      : ${global_crit}"
    echo -e "  ${RED}✗ Injoignables${NC}   : ${global_unreachable}"
    echo ""
}

# =============================================================================
# AIDE
# =============================================================================

show_help() {
    cat << EOF

${BOLD}${SCRIPT_NAME}${NC} v${SCRIPT_VERSION} — Audit de sécurité pour LXC/VM Proxmox

${BOLD}USAGE${NC}
    ${SCRIPT_NAME} [OPTIONS]

${BOLD}OPTIONS${NC}
    --all                   Auditer toutes les machines de l'inventaire (depuis le host Proxmox)
    --telegram              Envoyer le rapport par Telegram
    --export <dir>          Exporter le rapport en Markdown
    --summary-only          Afficher uniquement le résumé (pour mode --all)
    --inventory <path>      Chemin du fichier inventaire (défaut: /root/inventaire.csv)
    --help                  Afficher cette aide

${BOLD}EXEMPLES${NC}
    # Audit local
    ${SCRIPT_NAME}

    # Audit de toutes les machines depuis le Proxmox
    ${SCRIPT_NAME} --all

    # Avec notification Telegram et export
    ${SCRIPT_NAME} --telegram --export /root/reports/

    # En cron quotidien
    0 7 * * * /usr/local/bin/security-audit --telegram --export /root/reports/

EOF
    exit 0
}

# =============================================================================
# PARSING DES ARGUMENTS
# =============================================================================

SUMMARY_ONLY=false

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --all)           MODE="all";            shift ;;
            --telegram)      ENABLE_TELEGRAM=true;  shift ;;
            --export)        EXPORT_DIR="$2";       shift 2 ;;
            --summary-only)  SUMMARY_ONLY=true;     shift ;;
            --inventory)     INVENTORY_FILE="$2";   shift 2 ;;
            --help|-h)       show_help ;;
            *) echo -e "${RED}Option inconnue : $1${NC}"; show_help ;;
        esac
    done
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    parse_args "$@"

    check_root

    # Mode --all : exécuter sur tout l'inventaire depuis le Proxmox
    if [[ "${MODE}" == "all" ]]; then
        run_on_all_inventory
        exit 0
    fi

    # Mode local : audit de la machine courante
    detect_os
    detect_environment

    print_report_header

    audit_system_info
    audit_pending_updates
    audit_ssh
    audit_fail2ban
    audit_open_ports
    audit_users
    audit_disk
    audit_failed_services
    audit_docker
    audit_certificates
    audit_crontabs

    if [[ "${SUMMARY_ONLY}" == false ]]; then
        audit_lynis
    fi

    print_report_summary
    send_telegram
    export_report

    # Nettoyage
    rm -f /tmp/security-audit-$$.log

    # Code de sortie basé sur les résultats
    if [[ "${TOTAL_CRIT}" -gt 0 ]]; then
        exit 2
    elif [[ "${TOTAL_WARN}" -gt 0 ]]; then
        exit 1
    fi
    exit 0
}

main "$@"