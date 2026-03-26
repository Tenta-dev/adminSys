#!/usr/bin/env bash
###############################################################################
# security-audit.sh
# Audit de sécurité pour conteneurs LXC / VMs Proxmox
#
# Usage :
#   # Audit local sur une machine
#   ./security-audit.sh
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
readonly SCRIPT_VERSION="2.0.0"
readonly REPORT_DIR="${REPORT_DIR:-/root/security-reports}"
readonly HARDENING_STAMP="/etc/hardening-version"

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
ENABLE_TELEGRAM=false
EXPORT_DIR=""
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

    # Afficher le stamp de hardening si présent
    if [[ -f "${HARDENING_STAMP}" ]]; then
        local h_version h_date
        h_version=$(grep "^version=" "${HARDENING_STAMP}" 2>/dev/null | cut -d= -f2 || echo "inconnue")
        h_date=$(grep "^date=" "${HARDENING_STAMP}" 2>/dev/null | cut -d= -f2 || echo "inconnue")
        echo -e "  Hardening   : v${h_version} (${h_date})"
    else
        echo -e "  Hardening   : ${YELLOW}aucun stamp trouvé${NC}"
    fi
}

# --- 2. Mises à jour de sécurité en attente ---
audit_pending_updates() {
    print_section "Mises à jour de sécurité"

    apt-get update -qq 2>/dev/null || true

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

    # Lister les paquets de sécurité en attente
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

    if ! command -v sshd &>/dev/null; then
        result_info "sshd n'est pas installé"
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

    # AllowUsers
    local allow_users
    allow_users=$(sshd -T 2>/dev/null | grep "^allowusers " | awk '{$1=""; print $0}' || echo "")
    if [[ -n "${allow_users}" ]]; then
        result_ok "AllowUsers restreint à :${allow_users}"
    else
        result_warn "AllowUsers non défini (tous les utilisateurs peuvent se connecter)"
    fi

    # Bannière SSH
    local banner
    banner=$(sshd -T 2>/dev/null | grep "^banner " | awk '{print $2}' || echo "none")
    if [[ "${banner}" != "none" && -f "${banner}" ]]; then
        result_ok "Bannière SSH active (${banner})"
    else
        result_warn "Bannière SSH non configurée"
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

    if fail2ban-client status sshd &>/dev/null; then
        local banned
        banned=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $NF}')
        local total_banned
        total_banned=$(fail2ban-client status sshd 2>/dev/null | grep "Total banned" | awk '{print $NF}')
        result_ok "Jail SSH active — ${banned} IP bannie(s) actuellement, ${total_banned} au total"

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

    while IFS= read -r line; do
        local proto port process addr
        proto=$(echo "${line}" | awk '{print $1}')
        addr=$(echo "${line}" | awk '{print $5}')
        port=$(echo "${addr}" | rev | cut -d: -f1 | rev)
        process=$(echo "${line}" | grep -oP '"\K[^"]+' | head -1)
        [[ -z "${process}" ]] && process="unknown"

        local key="${proto}/${port}/${process}"
        if echo "${seen_ports}" | grep -qF "${key}"; then
            continue
        fi
        seen_ports="${seen_ports} ${key}"

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

    # UID 0
    local uid0_count
    uid0_count=$(awk -F: '$3 == 0 {print $1}' /etc/passwd | wc -l)
    if [[ "${uid0_count}" -gt 1 ]]; then
        result_crit "${uid0_count} utilisateurs avec UID 0 (devrait être uniquement root)"
        awk -F: '$3 == 0 {print "    - " $1}' /etc/passwd
    else
        result_ok "Seul root a l'UID 0"
    fi

    # Utilisateurs sans mot de passe avec shell de login
    local no_password
    no_password=$(awk -F: '($2 == "" || $2 == "!") && $1 != "root" {print $1}' /etc/shadow 2>/dev/null || true)
    if [[ -n "${no_password}" ]]; then
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

    # SUID suspects
    local suid_files
    suid_files=$(find / -perm -4000 -type f 2>/dev/null | grep -v -E "^/(usr/(bin|lib|libexec|sbin)|bin|sbin|opt|var/lib/(docker|containerd))/" || true)
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

    # World-writable dans /etc
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
            local svc
            svc=$(echo "${line}" | awk '{print $2}')
            [[ -z "${svc}" ]] && svc=$(echo "${line}" | awk '{print $1}')
            echo -e "    ${RED}${svc}${NC}"
        done
    else
        result_ok "Aucun service en échec"
    fi
}

# --- 9. Synchronisation NTP ---
audit_ntp() {
    print_section "Synchronisation NTP"

    # Chrony
    if command -v chronyc &>/dev/null; then
        if systemctl is-active chronyd &>/dev/null || systemctl is-active chrony &>/dev/null; then
            result_ok "Chrony est actif"

            # Vérifier la synchronisation
            local leap
            leap=$(chronyc tracking 2>/dev/null | grep "Leap status" | awk -F: '{print $2}' | xargs || echo "")
            if [[ "${leap}" == "Normal" ]]; then
                local offset
                offset=$(chronyc tracking 2>/dev/null | grep "System time" | awk '{print $4}' || echo "N/A")
                result_ok "Horloge synchronisée (offset: ${offset}s)"
            else
                result_warn "Chrony actif mais pas encore synchronisé (leap: ${leap})"
            fi
        else
            result_crit "Chrony installé mais service inactif"
        fi
    # systemd-timesyncd
    elif systemctl is-active systemd-timesyncd &>/dev/null; then
        result_ok "systemd-timesyncd est actif"

        local synced
        synced=$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo "no")
        if [[ "${synced}" == "yes" ]]; then
            result_ok "Horloge synchronisée via systemd-timesyncd"
        else
            result_warn "systemd-timesyncd actif mais horloge non synchronisée"
        fi
    else
        result_crit "Aucun service NTP actif (ni chrony, ni systemd-timesyncd)"
    fi
}

# --- 10. AppArmor ---
audit_apparmor() {
    print_section "AppArmor"

    # En LXC, AppArmor est géré par le host
    if [[ "${CONTAINER_TYPE}" == "lxc" ]]; then
        result_info "Environnement LXC — AppArmor géré par le host"
        return
    fi

    if ! command -v aa-status &>/dev/null && ! command -v apparmor_status &>/dev/null; then
        result_crit "AppArmor n'est pas installé"
        return
    fi

    local aa_output
    aa_output=$(aa-status 2>/dev/null || apparmor_status 2>/dev/null || echo "")

    if [[ -z "${aa_output}" ]]; then
        result_crit "Impossible de lire le statut AppArmor"
        return
    fi

    local loaded enforced complain
    loaded=$(echo "${aa_output}" | grep "profiles are loaded" | awk '{print $1}' || echo "0")
    enforced=$(echo "${aa_output}" | grep "profiles are in enforce mode" | awk '{print $1}' || echo "0")
    complain=$(echo "${aa_output}" | grep "profiles are in complain mode" | awk '{print $1}' || echo "0")

    if [[ "${enforced}" -gt 0 ]]; then
        result_ok "AppArmor actif — ${enforced} profil(s) en enforce, ${complain} en complain"
    elif [[ "${loaded}" -gt 0 ]]; then
        result_warn "AppArmor chargé (${loaded} profils) mais aucun en mode enforce"
    else
        result_crit "AppArmor sans profil chargé"
    fi

    if [[ "${complain}" -gt 0 ]]; then
        result_warn "${complain} profil(s) en mode complain (devraient être en enforce)"
    fi
}

# --- 11. Auditd et règles ---
audit_auditd() {
    print_section "Auditd"

    if [[ "${CONTAINER_TYPE}" == "lxc" ]]; then
        result_info "Environnement LXC — auditd non applicable"
        return
    fi

    if ! command -v auditd &>/dev/null; then
        result_warn "auditd n'est pas installé"
        return
    fi

    if systemctl is-active auditd &>/dev/null; then
        result_ok "auditd est actif"
    else
        result_crit "auditd est installé mais inactif"
        return
    fi

    # Vérifier le nombre de règles chargées
    local rule_count
    rule_count=$(auditctl -l 2>/dev/null | grep -cv "^No rules" || echo "0")

    if [[ "${rule_count}" -gt 0 ]]; then
        result_ok "${rule_count} règle(s) auditd chargée(s)"
    else
        result_crit "auditd actif mais AUCUNE règle chargée (pas de surveillance effective)"
    fi

    # Vérifier si les règles sont immuables
    local immutable
    immutable=$(auditctl -s 2>/dev/null | grep "enabled" | awk '{print $2}' || echo "")
    if [[ "${immutable}" == "2" ]]; then
        result_ok "Règles auditd verrouillées (immuables)"
    elif [[ -n "${immutable}" ]]; then
        result_info "Règles auditd modifiables (enabled=${immutable})"
    fi

    # Vérifier si le log audit existe et est récent
    if [[ -f /var/log/audit/audit.log ]]; then
        local last_event
        last_event=$(tail -1 /var/log/audit/audit.log 2>/dev/null | grep -oP 'msg=audit\(\K[0-9]+' || echo "0")
        if [[ "${last_event}" -gt 0 ]]; then
            local age=$(( $(date +%s) - last_event ))
            if [[ "${age}" -gt 86400 ]]; then
                result_warn "Dernier événement audit il y a $((age / 3600))h"
            else
                result_ok "Audit log actif (dernier événement il y a $((age / 60))min)"
            fi
        fi
    fi
}

# --- 12. AIDE (intégrité fichiers) ---
audit_aide() {
    print_section "AIDE (intégrité)"

    if ! command -v aide &>/dev/null; then
        result_info "AIDE n'est pas installé"
        return
    fi

    # Vérifier si la base est initialisée
    if [[ -f /var/lib/aide/aide.db ]]; then
        result_ok "Base AIDE initialisée"

        # Vérifier la fraîcheur de la base
        local db_age_days
        db_age_days=$(( ($(date +%s) - $(stat -c %Y /var/lib/aide/aide.db 2>/dev/null || echo "0")) / 86400 ))

        if [[ "${db_age_days}" -gt 30 ]]; then
            result_crit "Base AIDE obsolète (${db_age_days} jours) — Exécutez : aideinit"
        elif [[ "${db_age_days}" -gt 7 ]]; then
            result_warn "Base AIDE vieille de ${db_age_days} jours — Pensez à la rafraîchir"
        else
            result_ok "Base AIDE récente (${db_age_days} jour(s))"
        fi
    elif pgrep -f "aideinit|aide.*--config" &>/dev/null; then
        result_info "AIDE est en cours d'initialisation..."
    else
        result_crit "Base AIDE non initialisée — Exécutez : aideinit"
    fi

    # Vérifier s'il y a un cron AIDE
    if crontab -l 2>/dev/null | grep -q "aide" || \
       find /etc/cron.* -name "*aide*" 2>/dev/null | grep -q .; then
        result_ok "Vérification AIDE planifiée (cron)"
    else
        result_warn "Aucune vérification AIDE planifiée — Ajoutez un cron pour 'aide --check'"
    fi
}

# --- 13. Montages sécurisés ---
audit_secure_mounts() {
    print_section "Montages sécurisés"

    if [[ "${CONTAINER_TYPE}" == "lxc" ]]; then
        result_info "Environnement LXC — montages gérés par le host"
        return
    fi

    # /tmp
    local tmp_opts
    tmp_opts=$(mount 2>/dev/null | grep ' /tmp ' | awk '{print $6}' || echo "")
    if [[ -n "${tmp_opts}" ]]; then
        if echo "${tmp_opts}" | grep -q "noexec"; then
            result_ok "/tmp monté avec noexec"
        else
            result_warn "/tmp monté SANS noexec (exécution possible)"
        fi
    else
        result_warn "/tmp n'est pas un montage séparé"
    fi

    # /dev/shm
    local shm_opts
    shm_opts=$(mount 2>/dev/null | grep ' /dev/shm ' | awk '{print $6}' || echo "")
    if [[ -n "${shm_opts}" ]]; then
        if echo "${shm_opts}" | grep -q "noexec"; then
            result_ok "/dev/shm monté avec noexec"
        else
            result_warn "/dev/shm monté SANS noexec (exécution possible)"
        fi
    else
        result_info "/dev/shm non trouvé dans les montages"
    fi

    # hidepid sur /proc
    local proc_opts
    proc_opts=$(mount 2>/dev/null | grep ' /proc ' | awk '{print $6}' || echo "")
    if echo "${proc_opts}" | grep -q "hidepid="; then
        result_ok "/proc monté avec hidepid"
    else
        result_warn "/proc monté SANS hidepid (tous les processus visibles par tous)"
    fi
}

# --- 14. Core dumps ---
audit_core_dumps() {
    print_section "Core dumps"

    local core_disabled=true

    # Vérifier limits.conf
    if grep -rq "hard core 0" /etc/security/limits.conf /etc/security/limits.d/ 2>/dev/null; then
        result_ok "Core dumps désactivés (limits.conf)"
    else
        result_warn "Core dumps non désactivés dans limits.conf"
        core_disabled=false
    fi

    # Vérifier sysctl fs.suid_dumpable
    local suid_dump
    suid_dump=$(sysctl -n fs.suid_dumpable 2>/dev/null || echo "")
    if [[ "${suid_dump}" == "0" ]]; then
        result_ok "fs.suid_dumpable = 0"
    elif [[ -n "${suid_dump}" ]]; then
        result_warn "fs.suid_dumpable = ${suid_dump} (devrait être 0)"
        core_disabled=false
    fi

    # Vérifier systemd-coredump
    if [[ -d /etc/systemd/coredump.conf.d ]]; then
        if grep -rq "Storage=none" /etc/systemd/coredump.conf.d/ 2>/dev/null; then
            result_ok "systemd-coredump désactivé (Storage=none)"
        fi
    fi
}

# --- 15. Shell timeout et su restriction ---
audit_shell_hardening() {
    print_section "Hardening shell"

    # TMOUT
    if grep -rq "TMOUT=" /etc/profile.d/ /etc/profile /etc/bash.bashrc 2>/dev/null; then
        local tmout_val
        tmout_val=$(grep -rh "TMOUT=" /etc/profile.d/ /etc/profile /etc/bash.bashrc 2>/dev/null | grep -oP 'TMOUT=\K[0-9]+' | head -1)
        if [[ -n "${tmout_val}" && "${tmout_val}" -le 900 ]]; then
            result_ok "Shell TMOUT configuré (${tmout_val}s)"
        else
            result_warn "Shell TMOUT configuré mais valeur élevée (${tmout_val}s)"
        fi
    else
        result_warn "Aucun TMOUT configuré (sessions shell inactives ne sont pas coupées)"
    fi

    # Restriction su
    if grep -q "^auth.*required.*pam_wheel.so" /etc/pam.d/su 2>/dev/null; then
        result_ok "su restreint au groupe sudo/wheel (pam_wheel.so)"
    else
        result_warn "su non restreint (tout utilisateur peut tenter su)"
    fi
}

# --- 16. Backups ---
audit_backups() {
    print_section "Backups"

    local backup_found=false

    # Vérifier les emplacements communs de backup
    local backup_dirs=(
        /var/backups
        /root/backups
        /backup
        /mnt/backup
    )

    for dir in "${backup_dirs[@]}"; do
        if [[ -d "${dir}" ]]; then
            # Chercher des fichiers récents (< 7 jours)
            local recent_count
            recent_count=$(find "${dir}" -type f -mtime -7 2>/dev/null | wc -l || echo "0")
            local total_count
            total_count=$(find "${dir}" -type f 2>/dev/null | wc -l || echo "0")

            if [[ "${recent_count}" -gt 0 ]]; then
                result_ok "${dir} — ${recent_count} fichier(s) récent(s) (< 7j), ${total_count} total"
                backup_found=true
            elif [[ "${total_count}" -gt 0 ]]; then
                # Trouver le fichier le plus récent
                local newest
                newest=$(find "${dir}" -type f -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -1 | awk '{print $2}')
                local newest_age
                newest_age=$(( ($(date +%s) - $(stat -c %Y "${newest}" 2>/dev/null || echo "0")) / 86400 ))
                result_warn "${dir} — backup le plus récent date de ${newest_age} jour(s)"
                backup_found=true
            fi
        fi
    done

    # Vérifier /var/backups standard (dpkg, apt)
    if [[ -f /var/backups/dpkg.status.0 ]]; then
        local dpkg_age
        dpkg_age=$(( ($(date +%s) - $(stat -c %Y /var/backups/dpkg.status.0 2>/dev/null || echo "0")) / 86400 ))
        result_info "Backup dpkg : ${dpkg_age} jour(s)"
    fi

    # Vérifier les tâches de backup planifiées
    if crontab -l 2>/dev/null | grep -qiE "backup|rsync|borg|restic|duplicity|rclone"; then
        result_ok "Tâche de backup détectée dans crontab root"
        backup_found=true
    fi

    if systemctl list-timers --no-legend 2>/dev/null | grep -qiE "backup|borg|restic"; then
        result_ok "Timer systemd de backup détecté"
        backup_found=true
    fi

    if [[ "${backup_found}" == false ]]; then
        result_warn "Aucun backup récent ni tâche de backup détecté"
    fi
}

# --- 17. Docker (si installé) ---
audit_docker() {
    if ! command -v docker &>/dev/null; then
        return
    fi

    print_section "Docker"

    if systemctl is-active docker &>/dev/null; then
        result_ok "Docker daemon actif"
    else
        result_warn "Docker installé mais daemon inactif"
        return
    fi

    local docker_version
    docker_version=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "inconnue")
    result_info "Docker version ${docker_version}"

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

    if [[ "${running}" -gt 0 ]]; then

        # Conteneurs privileged
        local priv_count=0
        while read -r cid; do
            local cname cpriv
            cname=$(docker inspect "${cid}" --format '{{.Name}}' 2>/dev/null | sed 's|^/||')
            cpriv=$(docker inspect "${cid}" --format '{{.HostConfig.Privileged}}' 2>/dev/null)
            if [[ "${cpriv}" == "true" ]]; then
                [[ "${priv_count}" -eq 0 ]] && result_crit "Conteneur(s) en mode --privileged :"
                echo -e "    ${RED}${cname}${NC}"
                priv_count=$((priv_count + 1))
            fi
        done < <(docker ps -q 2>/dev/null)
        [[ "${priv_count}" -eq 0 ]] && result_ok "Aucun conteneur en mode privileged"

        # Conteneurs --net=host
        local nethost_count=0
        while read -r cid; do
            local cname cnet
            cname=$(docker inspect "${cid}" --format '{{.Name}}' 2>/dev/null | sed 's|^/||')
            cnet=$(docker inspect "${cid}" --format '{{.HostConfig.NetworkMode}}' 2>/dev/null)
            if [[ "${cnet}" == "host" ]]; then
                [[ "${nethost_count}" -eq 0 ]] && result_warn "Conteneur(s) en mode --net=host :"
                echo -e "    ${YELLOW}${cname}${NC}"
                nethost_count=$((nethost_count + 1))
            fi
        done < <(docker ps -q 2>/dev/null)

        # Conteneurs root
        local root_count=0
        local non_root_count=0
        while read -r cid; do
            local cuser
            cuser=$(docker inspect "${cid}" --format '{{.Config.User}}' 2>/dev/null)
            if [[ -z "${cuser}" || "${cuser}" == "root" || "${cuser}" == "0" ]]; then
                root_count=$((root_count + 1))
            else
                non_root_count=$((non_root_count + 1))
            fi
        done < <(docker ps -q 2>/dev/null)
        [[ "${root_count}" -gt 0 ]] && result_warn "${root_count} conteneur(s) exécuté(s) en tant que root"
        [[ "${non_root_count}" -gt 0 ]] && result_ok "${non_root_count} conteneur(s) exécuté(s) avec un utilisateur non-root"

        # Ports sur 0.0.0.0
        local exposed_count=0
        while read -r cid; do
            local cname ports_all
            cname=$(docker inspect "${cid}" --format '{{.Name}}' 2>/dev/null | sed 's|^/||')
            ports_all=$(docker port "${cid}" 2>/dev/null | grep "0.0.0.0:" || true)
            if [[ -n "${ports_all}" ]]; then
                [[ "${exposed_count}" -eq 0 ]] && result_warn "Conteneur(s) avec ports sur 0.0.0.0 :"
                echo -e "    ${YELLOW}${cname}${NC} — $(echo "${ports_all}" | awk '{print $3}' | tr '\n' ' ')"
                exposed_count=$((exposed_count + 1))
            fi
        done < <(docker ps -q 2>/dev/null)
        [[ "${exposed_count}" -eq 0 && "${running}" -gt 0 ]] && result_ok "Aucun port exposé sur 0.0.0.0"

        # Socket Docker monté
        local socket_count=0
        while read -r cid; do
            local cname cmounts
            cname=$(docker inspect "${cid}" --format '{{.Name}}' 2>/dev/null | sed 's|^/||')
            cmounts=$(docker inspect "${cid}" --format '{{range .Mounts}}{{.Source}} {{end}}' 2>/dev/null)
            if echo "${cmounts}" | grep -q "docker.sock"; then
                [[ "${socket_count}" -eq 0 ]] && result_crit "Conteneur(s) avec socket Docker monté :"
                echo -e "    ${RED}${cname}${NC}"
                socket_count=$((socket_count + 1))
            fi
        done < <(docker ps -q 2>/dev/null)
        [[ "${socket_count}" -eq 0 ]] && result_ok "Aucun conteneur avec le socket Docker monté"
    fi

    # Images dangling
    local dangling
    dangling=$(docker images -f "dangling=true" -q 2>/dev/null | wc -l || echo "0")
    if [[ "${dangling}" -gt 0 ]]; then
        result_warn "${dangling} image(s) orpheline(s) — récupérable avec 'docker image prune'"
    else
        result_ok "Aucune image orpheline"
    fi

    # Volumes orphelins
    local orphan_volumes
    orphan_volumes=$(docker volume ls -f "dangling=true" -q 2>/dev/null | wc -l || echo "0")
    [[ "${orphan_volumes}" -gt 0 ]] && result_warn "${orphan_volumes} volume(s) orphelin(s) — 'docker volume prune'"

    # API Docker exposée
    if ss -tlnp 2>/dev/null | grep -q ":2375 \|:2376 "; then
        result_crit "API Docker exposée sur le réseau (port 2375/2376)"
    else
        result_ok "API Docker non exposée sur le réseau"
    fi

    local docker_disk
    docker_disk=$(docker system df --format '{{.Size}}' 2>/dev/null | head -1 || echo "N/A")
    result_info "Espace Docker utilisé : images=${docker_disk:-N/A}"
}

# --- 18. Certificats TLS ---
audit_certificates() {
    print_section "Certificats TLS"

    local cert_found=false

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

# --- 19. Crontabs ---
audit_crontabs() {
    print_section "Tâches planifiées (crontabs)"

    local cron_found=false

    for user_cron in /var/spool/cron/crontabs/*; do
        [[ -f "${user_cron}" ]] || continue
        cron_found=true
        local user
        user=$(basename "${user_cron}")
        local count
        count=$(grep -cvE '^#|^$' "${user_cron}" 2>/dev/null || true)
        result_info "Crontab ${user} : ${count} entrée(s)"
    done

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
# AIDE
# =============================================================================

show_help() {
    cat << EOF

${BOLD}${SCRIPT_NAME}${NC} v${SCRIPT_VERSION} — Audit de sécurité pour LXC/VM Proxmox

${BOLD}USAGE${NC}
    ${SCRIPT_NAME} [OPTIONS]

${BOLD}OPTIONS${NC}
    --telegram              Envoyer le rapport par Telegram
    --export <dir>          Exporter le rapport en Markdown
    --summary-only          Afficher uniquement le résumé
    --help                  Afficher cette aide

${BOLD}MODULES D'AUDIT${NC}
     1. Informations système + stamp hardening
     2. Mises à jour de sécurité
     3. Configuration SSH
     4. Fail2ban
     5. Ports ouverts
     6. Utilisateurs et permissions
     7. Espace disque
     8. Services systemd
     9. Synchronisation NTP
    10. AppArmor
    11. Auditd et règles
    12. AIDE (intégrité)
    13. Montages sécurisés
    14. Core dumps
    15. Hardening shell (TMOUT, su)
    16. Backups
    17. Docker (si installé)
    18. Certificats TLS
    19. Tâches planifiées
    20. Lynis (si installé)

${BOLD}EXEMPLES${NC}
    # Audit local
    ${SCRIPT_NAME}

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
            --telegram)      ENABLE_TELEGRAM=true;  shift ;;
            --export)        EXPORT_DIR="$2";       shift 2 ;;
            --summary-only)  SUMMARY_ONLY=true;     shift ;;
            --help|-h)       show_help ;;
            *) echo -e "${RED}Option inconnue : $1${NC}"; show_help ;;
        esac
    done
}

# =============================================================================
# LYNIS
# =============================================================================

audit_lynis() {
    if ! command -v lynis &>/dev/null; then
        print_section "Lynis"
        result_info "Lynis n'est pas installé — installation recommandée : apt install lynis"
        return
    fi

    print_section "Lynis (audit complet)"

    echo -e "  ${DIM}Exécution de Lynis en cours...${NC}"

    local lynis_log="/tmp/lynis-audit-$$.log"
    lynis audit system --no-colors --quick 2>/dev/null > "${lynis_log}" || true

    local score
    score=$(grep "Hardening index" "${lynis_log}" 2>/dev/null | grep -oP '\d+' | head -1 || echo "0")

    if [[ "${score}" -ge "${LYNIS_WARN}" ]]; then
        result_ok "Score Lynis : ${score}/100"
    elif [[ "${score}" -ge "${LYNIS_CRIT}" ]]; then
        result_warn "Score Lynis : ${score}/100 (recommandé: > ${LYNIS_WARN})"
    else
        result_crit "Score Lynis : ${score}/100 (critique, recommandé: > ${LYNIS_WARN})"
    fi

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

    if [[ -n "${EXPORT_DIR}" ]]; then
        local lynis_dest="${EXPORT_DIR}/lynis-$(hostname)-$(date '+%Y%m%d').log"
        cp "${lynis_log}" "${lynis_dest}"
        echo -e "  ${DIM}Rapport Lynis complet : ${lynis_dest}${NC}"
    fi

    rm -f "${lynis_log}"
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    parse_args "$@"

    check_root
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
    audit_ntp
    audit_apparmor
    audit_auditd
    audit_aide
    audit_secure_mounts
    audit_core_dumps
    audit_shell_hardening
    audit_backups
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