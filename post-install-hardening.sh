#!/usr/bin/env bash
###############################################################################
# post-install-hardening.sh
# Script de hardening post-installation pour conteneurs LXC / VMs Proxmox
# Compatible : Debian 12 (Bookworm), Ubuntu 22.04/24.04 LTS
#
# Usage (depuis le host Proxmox ou en SSH sur la machine cible) :
#   ./post-install-hardening.sh [OPTIONS]
#
# Options :
#   -u, --username <user>       Nom de l'utilisateur admin à créer (défaut: admin)
#   -k, --ssh-key <path|url>    Chemin ou URL de la clé publique SSH
#   -p, --ssh-port <port>       Port SSH personnalisé (défaut: 22)
#   -h, --hostname <name>       Nom d'hôte à configurer
#   -t, --telegram              Activer la notification Telegram
#   --no-fail2ban               Ne pas installer fail2ban
#   --no-ufw                    Ne pas configurer UFW
#   --no-unattended             Ne pas configurer unattended-upgrades
#   --dry-run                   Afficher les actions sans les exécuter
#   --help                      Afficher l'aide
#
# Auteur : AdminSys_Linux
# Licence : MIT
###############################################################################
set -euo pipefail

# =============================================================================
# CONSTANTES & CONFIGURATION PAR DÉFAUT
# =============================================================================
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_VERSION="2.0.0"
readonly LOG_FILE="/var/log/post-install-hardening.log"
readonly SYSCTL_HARDENING_FILE="/etc/sysctl.d/99-hardening.conf"
readonly SSH_CONFIG="/etc/ssh/sshd_config"
readonly SSH_HARDENING_DIR="/etc/ssh/sshd_config.d"
readonly HARDENING_STAMP="/etc/hardening-version"

# Couleurs pour l'affichage
readonly RED=$'\033[0;31m'
readonly GREEN=$'\033[0;32m'
readonly YELLOW=$'\033[1;33m'
readonly BLUE=$'\033[0;34m'
readonly NC=$'\033[0m' # No Color

# Variables configurables
ADMIN_USER="admin"
SSH_KEY=""
SSH_PORT="22"
NEW_HOSTNAME=""
ENABLE_FAIL2BAN=true
ENABLE_UFW=true
ENABLE_UNATTENDED=true
ENABLE_TELEGRAM=false
DRY_RUN=false

# Telegram (à configurer si besoin)
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"

# =============================================================================
# FONCTIONS UTILITAIRES
# =============================================================================

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "${timestamp} [${level}] ${message}" >> "${LOG_FILE}" 2>/dev/null || true
}

info()    { echo -e "${BLUE}[INFO]${NC}    $*"; log "INFO" "$*"; }
success() { echo -e "${GREEN}[OK]${NC}      $*"; log "OK" "$*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}    $*"; log "WARN" "$*"; }
error()   { echo -e "${RED}[ERROR]${NC}   $*"; log "ERROR" "$*"; }

die() {
    error "$*"
    exit 1
}

run() {
    if [[ "${DRY_RUN}" == true ]]; then
        info "[DRY-RUN] $*"
    else
        eval "$@"
    fi
}

check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        die "Ce script doit être exécuté en tant que root."
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        source /etc/os-release
        OS_ID="${ID}"
        OS_VERSION="${VERSION_ID}"
        OS_NAME="${PRETTY_NAME}"
    else
        die "Impossible de détecter l'OS. Fichier /etc/os-release absent."
    fi

    case "${OS_ID}" in
        debian|ubuntu)
            PKG_MANAGER="apt-get"
            PKG_UPDATE="${PKG_MANAGER} update -qq"
            PKG_INSTALL="${PKG_MANAGER} install -y -qq"
            ;;
        *)
            die "OS non supporté : ${OS_ID}. Seuls Debian et Ubuntu sont supportés."
            ;;
    esac

    info "OS détecté : ${OS_NAME}"
}

detect_environment() {
    # Détection LXC vs VM vs Bare-metal
    if [[ -f /run/systemd/container ]]; then
        CONTAINER_TYPE="$(cat /run/systemd/container)"
        info "Environnement : conteneur ${CONTAINER_TYPE}"
    elif systemd-detect-virt --quiet 2>/dev/null; then
        CONTAINER_TYPE="$(systemd-detect-virt)"
        info "Environnement : VM (${CONTAINER_TYPE})"
    else
        CONTAINER_TYPE="bare-metal"
        info "Environnement : bare-metal"
    fi
}

show_help() {
    cat << EOF
${SCRIPT_NAME} v${SCRIPT_VERSION} — Hardening post-installation pour LXC/VM Proxmox

Usage : ${SCRIPT_NAME} [OPTIONS]

Options :
  -u, --username <user>       Utilisateur admin à créer (défaut: admin)
  -k, --ssh-key <path|url>    Clé publique SSH (fichier local ou URL)
  -p, --ssh-port <port>       Port SSH (défaut: 22)
  -h, --hostname <name>       Nom d'hôte à configurer
  -t, --telegram              Notification Telegram à la fin
  --no-fail2ban               Désactiver l'installation de fail2ban
  --no-ufw                    Désactiver la configuration UFW
  --no-unattended             Désactiver unattended-upgrades
  --dry-run                   Mode simulation (aucune modification)
  --help                      Afficher cette aide

Modules appliqués :
   1. Mise à jour système + paquets essentiels
   2. Configuration hostname
   3. Création utilisateur admin (sudo, clé SSH)
   4. Hardening SSH (root off, password off, MaxSessions 2, TCPKeepAlive no)
   5. Fail2ban (SSH jail)
   6. UFW (VMs uniquement)
   7. Mises à jour de sécurité automatiques
   8. Hardening sysctl (VMs uniquement)
   9. Désactivation services inutiles
  10. Configuration logging (journald)
  11. Synchronisation NTP (chrony)
  12. Restriction su (pam_wheel)
  13. Timeout shell (TMOUT)
  14. Désactivation core dumps
  15. Montages sécurisés (/tmp, /dev/shm)
  16. Hidepid /proc (VMs uniquement)
  17. AppArmor enforcement
  18. Règles auditd (VMs uniquement)
  19. Hardening avancé Lynis (rkhunter, bannière, login.defs, modprobe, permissions, passwdqc)
  20. Stamp de version

Exemples :
  # Hardening complet avec clé SSH
  ${SCRIPT_NAME} -u sysadmin -k ~/.ssh/id_ed25519.pub -p 2222

  # Hardening minimal sans firewall
  ${SCRIPT_NAME} -u admin -k https://github.com/monuser.keys --no-ufw

  # Simulation
  ${SCRIPT_NAME} --dry-run -u admin
EOF
    exit 0
}

# =============================================================================
# PARSING DES ARGUMENTS
# =============================================================================

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -u|--username)    ADMIN_USER="$2";    shift 2 ;;
            -k|--ssh-key)     SSH_KEY="$2";       shift 2 ;;
            -p|--ssh-port)    SSH_PORT="$2";      shift 2 ;;
            -h|--hostname)    NEW_HOSTNAME="$2";  shift 2 ;;
            -t|--telegram)    ENABLE_TELEGRAM=true; shift ;;
            --no-fail2ban)    ENABLE_FAIL2BAN=false; shift ;;
            --no-ufw)        ENABLE_UFW=false;   shift ;;
            --no-unattended)  ENABLE_UNATTENDED=false; shift ;;
            --dry-run)        DRY_RUN=true;       shift ;;
            --help)           show_help ;;
            *) die "Option inconnue : $1. Utilisez --help pour l'aide." ;;
        esac
    done
}

# =============================================================================
# MODULES DE HARDENING
# =============================================================================

# --- 1. Mise à jour système ---
module_system_update() {
    info "━━━ Module 1/20 : Mise à jour du système ━━━"
    run "${PKG_UPDATE}"
    run "${PKG_MANAGER} upgrade -y -qq"
    success "Système mis à jour."
}

# --- 2. Installation des paquets essentiels ---
module_install_essentials() {
    info "━━━ Module 2/20 : Installation des paquets essentiels ━━━"

    local packages=(
        curl wget vim-tiny
        htop iotop
        net-tools iputils-ping dnsutils
        ca-certificates gnupg
        sudo
        openssh-server
        logrotate
        bash-completion
    )

    run "${PKG_INSTALL} ${packages[*]}"
    success "Paquets essentiels installés."
}

# --- 3. Configuration du hostname ---
module_set_hostname() {
    if [[ -n "${NEW_HOSTNAME}" ]]; then
        info "━━━ Module 3/20 : Configuration du hostname : ${NEW_HOSTNAME} ━━━"
        run "hostnamectl set-hostname '${NEW_HOSTNAME}'"

        # Mise à jour /etc/hosts
        if ! grep -q "${NEW_HOSTNAME}" /etc/hosts 2>/dev/null; then
            run "echo '127.0.1.1 ${NEW_HOSTNAME}' >> /etc/hosts"
        fi

        success "Hostname configuré : ${NEW_HOSTNAME}"
    fi
}

# --- 4. Création utilisateur admin ---
module_create_admin_user() {
    info "━━━ Module 4/20 : Création de l'utilisateur admin : ${ADMIN_USER} ━━━"

    if id "${ADMIN_USER}" &>/dev/null; then
        warn "L'utilisateur ${ADMIN_USER} existe déjà, mise à jour de la configuration."
    else
        run "useradd -m -s /bin/bash -G sudo '${ADMIN_USER}'"
        # Verrouillage du mot de passe (auth par clé uniquement)
        run "passwd -l '${ADMIN_USER}'"
        success "Utilisateur ${ADMIN_USER} créé et ajouté au groupe sudo."
    fi

    # Sudo sans mot de passe (l'auth se fait par clé SSH)
    run "echo '${ADMIN_USER} ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/${ADMIN_USER}"
    run "chmod 440 /etc/sudoers.d/${ADMIN_USER}"

    # Déploiement de la clé SSH
    if [[ -n "${SSH_KEY}" ]]; then
        local ssh_dir="/home/${ADMIN_USER}/.ssh"
        local auth_keys="${ssh_dir}/authorized_keys"
        local tmp_keys
        tmp_keys=$(mktemp)

        run "mkdir -p '${ssh_dir}'"

        # Récupérer les clés depuis la source
        if [[ "${SSH_KEY}" =~ ^https?:// ]]; then
            info "Téléchargement de la clé SSH depuis ${SSH_KEY}..."
            if ! curl -fsSL "${SSH_KEY}" > "${tmp_keys}" 2>/dev/null; then
                warn "Impossible de télécharger la clé depuis ${SSH_KEY}. Étape ignorée."
                rm -f "${tmp_keys}"
                return
            fi
        elif [[ -f "${SSH_KEY}" ]]; then
            cp "${SSH_KEY}" "${tmp_keys}"
        else
            warn "Clé SSH introuvable : ${SSH_KEY}. Étape ignorée."
            rm -f "${tmp_keys}"
            return
        fi

        # Créer le fichier authorized_keys s'il n'existe pas
        [[ -f "${auth_keys}" ]] || touch "${auth_keys}"

        # Ajouter uniquement les clés absentes (dédoublonnage)
        local added=0
        local skipped=0
        while IFS= read -r key; do
            # Ignorer les lignes vides et commentaires
            [[ -z "${key}" || "${key}" =~ ^# ]] && continue

            if grep -qF "${key}" "${auth_keys}" 2>/dev/null; then
                skipped=$((skipped + 1))
            else
                echo "${key}" >> "${auth_keys}"
                added=$((added + 1))
            fi
        done < "${tmp_keys}"

        rm -f "${tmp_keys}"

        run "chmod 700 '${ssh_dir}'"
        run "chmod 600 '${auth_keys}'"
        run "chown -R '${ADMIN_USER}:${ADMIN_USER}' '${ssh_dir}'"

        if [[ "${added}" -gt 0 ]]; then
            success "Clé(s) SSH déployée(s) pour ${ADMIN_USER} (${added} ajoutée(s), ${skipped} déjà présente(s))."
        else
            info "Toutes les clés SSH sont déjà présentes pour ${ADMIN_USER} (${skipped} existante(s))."
        fi
    else
        warn "Aucune clé SSH fournie (-k). L'accès SSH par clé devra être configuré manuellement."
    fi
}

# --- 5. Hardening SSH ---
module_harden_ssh() {
    info "━━━ Module 5/20 : Hardening SSH ━━━"

    # Créer le répertoire sshd_config.d s'il n'existe pas
    run "mkdir -p '${SSH_HARDENING_DIR}'"

    local hardening_conf="${SSH_HARDENING_DIR}/99-hardening.conf"

    cat > /tmp/ssh-hardening.conf << 'SSHEOF'
# =============================================================================
# Hardening SSH — généré par post-install-hardening.sh
# =============================================================================

# Authentification
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
PermitEmptyPasswords no
MaxAuthTries 3
MaxSessions 2

# Sécurité protocole
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
TCPKeepAlive no

# Timeout et keep-alive
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30

# Logging
LogLevel VERBOSE

# Bannière
Banner /etc/issue.net
SSHEOF

    # Ajout du port personnalisé
    if [[ "${SSH_PORT}" != "22" ]]; then
        echo "Port ${SSH_PORT}" >> /tmp/ssh-hardening.conf
    fi

    # Restreindre l'accès à l'utilisateur admin
    echo "AllowUsers ${ADMIN_USER}" >> /tmp/ssh-hardening.conf

    run "cp /tmp/ssh-hardening.conf '${hardening_conf}'"
    run "chmod 644 '${hardening_conf}'"
    rm -f /tmp/ssh-hardening.conf

    # Créer /run/sshd si absent (nécessaire sur les LXC minimalistes)
    run "mkdir -p /run/sshd"

    # Ubuntu 24.04+ utilise ssh.socket (activation par socket systemd)
    if systemctl is-active ssh.socket &>/dev/null || systemctl is-enabled ssh.socket &>/dev/null; then
        info "ssh.socket détecté (Ubuntu 24.04+). Bascule vers ssh.service..."
        run "systemctl disable --now ssh.socket"
        run "systemctl enable ssh.service"
    fi

    # Vérification de la config SSH avant redémarrage
    if [[ "${DRY_RUN}" == false ]]; then
        local sshd_errors
        if sshd_errors="$(sshd -t 2>&1)"; then
            run "systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true"
            success "SSH hardened et redémarré (port ${SSH_PORT})."
        else
            error "La configuration SSH est invalide ! Rollback..."
            error "Détail : ${sshd_errors}"
            rm -f "${hardening_conf}"
            die "Hardening SSH annulé. Vérifiez la configuration manuellement."
        fi
    else
        success "[DRY-RUN] SSH hardening préparé."
    fi

    # ⚠️ Avertissement critique
    echo ""
    warn "╔══════════════════════════════════════════════════════════════╗"
    warn "║  IMPORTANT : Avant de fermer cette session, vérifiez que   ║"
    warn "║  vous pouvez vous connecter avec :                         ║"
    warn "║  ssh -p ${SSH_PORT} ${ADMIN_USER}@<IP_MACHINE>                          ║"
    warn "║  Le login root par mot de passe est désormais DÉSACTIVÉ.   ║"
    warn "╚══════════════════════════════════════════════════════════════╝"
    echo ""
}

# --- 6. Fail2ban ---
module_install_fail2ban() {
    if [[ "${ENABLE_FAIL2BAN}" == false ]]; then
        info "Fail2ban : désactivé par option."
        return
    fi

    info "━━━ Module 6/20 : Installation et configuration de fail2ban ━━━"
    run "${PKG_INSTALL} fail2ban"

    cat > /tmp/fail2ban-jail.local << JAILEOF
# fail2ban — configuration post-install-hardening.sh
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 3
banaction = %(banaction_allports)s

# Ignorer le réseau local Proxmox (adapter selon votre réseau)
ignoreip = 127.0.0.1/8 ::1 10.0.0.0/8 192.168.0.0/16 172.16.0.0/12

[sshd]
enabled  = true
port     = ${SSH_PORT}
logpath  = %(sshd_log)s
backend  = systemd
maxretry = 3
JAILEOF

    run "cp /tmp/fail2ban-jail.local /etc/fail2ban/jail.local"
    run "chmod 644 /etc/fail2ban/jail.local"
    rm -f /tmp/fail2ban-jail.local

    run "systemctl enable fail2ban"
    run "systemctl restart fail2ban"
    success "Fail2ban installé et configuré (SSH port ${SSH_PORT})."
}

# --- 7. UFW Firewall ---
module_configure_ufw() {
    if [[ "${ENABLE_UFW}" == false ]]; then
        info "UFW : désactivé par option."
        return
    fi

    # UFW ne fonctionne pas correctement dans les conteneurs LXC non-privilégiés
    if [[ "${CONTAINER_TYPE}" == "lxc" ]]; then
        warn "Environnement LXC détecté. UFW ignoré (firewall géré au niveau du host Proxmox)."
        return
    fi

    info "━━━ Module 7/20 : Configuration du firewall UFW ━━━"
    run "${PKG_INSTALL} ufw"

    # Politique par défaut
    run "ufw default deny incoming"
    run "ufw default allow outgoing"

    # Autoriser SSH
    run "ufw allow ${SSH_PORT}/tcp comment 'SSH'"

    # Activer UFW
    if [[ "${DRY_RUN}" == false ]]; then
        echo "y" | ufw enable
    else
        info "[DRY-RUN] ufw enable"
    fi

    success "UFW activé — seul le port SSH (${SSH_PORT}) est ouvert."
    info "Pensez à ouvrir les ports nécessaires : ufw allow <port>/tcp comment '<service>'"
}

# --- 8. Unattended-upgrades ---
module_configure_unattended_upgrades() {
    if [[ "${ENABLE_UNATTENDED}" == false ]]; then
        info "Unattended-upgrades : désactivé par option."
        return
    fi

    info "━━━ Module 8/20 : Configuration des mises à jour automatiques de sécurité ━━━"
    run "${PKG_INSTALL} unattended-upgrades apt-listchanges"

    cat > /tmp/50unattended-upgrades << 'UUEOF'
// Unattended-Upgrades — post-install-hardening.sh
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};

Unattended-Upgrade::Package-Blacklist {
};

// Redémarrage automatique si nécessaire, à 4h du matin
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";

// Supprimer les dépendances inutilisées
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";

// Logging
Unattended-Upgrade::SyslogEnable "true";
UUEOF

    run "cp /tmp/50unattended-upgrades /etc/apt/apt.conf.d/50unattended-upgrades"
    rm -f /tmp/50unattended-upgrades

    cat > /tmp/20auto-upgrades << 'AUEOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
AUEOF

    run "cp /tmp/20auto-upgrades /etc/apt/apt.conf.d/20auto-upgrades"
    rm -f /tmp/20auto-upgrades

    success "Mises à jour de sécurité automatiques activées (reboot auto à 04:00 si nécessaire)."
}

# --- 9. Hardening sysctl ---
module_harden_sysctl() {
    info "━━━ Module 9/20 : Hardening kernel (sysctl) ━━━"

    # En LXC, la plupart des paramètres sysctl ne sont pas modifiables
    if [[ "${CONTAINER_TYPE}" == "lxc" ]]; then
        warn "Environnement LXC : les paramètres sysctl sont limités. Hardening kernel ignoré."
        return
    fi

    cat > /tmp/99-hardening.conf << 'SYSCTLEOF'
# =============================================================================
# Hardening sysctl — post-install-hardening.sh v2
# =============================================================================

# --- Protection réseau ---
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# SYN flood
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2

# Redirections ICMP
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Reverse path filtering (anti-spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Smurf protection
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Loguer les paquets martiens
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# --- Protection mémoire ---
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.randomize_va_space = 2
kernel.yama.ptrace_scope = 1

# --- Core dumps (désactivation) ---
fs.suid_dumpable = 0

# --- Performances réseau ---
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
SYSCTLEOF

    run "cp /tmp/99-hardening.conf '${SYSCTL_HARDENING_FILE}'"
    rm -f /tmp/99-hardening.conf

    if [[ "${DRY_RUN}" == false ]]; then
        sysctl --system > /dev/null 2>&1
    fi

    success "Paramètres sysctl de hardening appliqués."
}

# --- 10. Désactivation de services inutiles ---
module_disable_unnecessary_services() {
    info "━━━ Module 10/20 : Désactivation des services inutiles ━━━"

    local services_to_disable=(
        avahi-daemon        # mDNS — inutile sur un serveur
        cups                # Impression — inutile sur un serveur
        bluetooth           # Bluetooth — inutile sur un serveur
        ModemManager        # Modem — inutile sur un serveur
    )

    for service in "${services_to_disable[@]}"; do
        if systemctl is-enabled "${service}" &>/dev/null 2>&1; then
            run "systemctl disable --now '${service}'"
            info "Service désactivé : ${service}"
        fi
    done

    success "Services inutiles vérifiés et désactivés."
}

# --- 11. Configuration des logs ---
module_configure_logging() {
    info "━━━ Module 11/20 : Configuration du logging ━━━"

    run "mkdir -p /etc/systemd/journald.conf.d"

    cat > /tmp/size-limit.conf << 'LOGEOF'
[Journal]
SystemMaxUse=200M
MaxRetentionSec=1month
Compress=yes
LOGEOF

    run "cp /tmp/size-limit.conf /etc/systemd/journald.conf.d/size-limit.conf"
    rm -f /tmp/size-limit.conf

    run "systemctl restart systemd-journald"
    success "Journald configuré (max 200M, rétention 1 mois)."
}

# --- 12. Synchronisation NTP ---
module_configure_ntp() {
    info "━━━ Module 12/20 : Synchronisation NTP (chrony) ━━━"

    # Préférer chrony à systemd-timesyncd (plus précis, recommandé par Lynis)
    run "${PKG_INSTALL} chrony"

    # Désactiver systemd-timesyncd s'il est actif (conflit avec chrony)
    if systemctl is-active systemd-timesyncd &>/dev/null; then
        run "systemctl disable --now systemd-timesyncd"
    fi

    run "systemctl enable chrony"
    run "systemctl restart chrony"

    # Vérifier la synchronisation
    if [[ "${DRY_RUN}" == false ]]; then
        if chronyc tracking &>/dev/null; then
            success "Chrony installé et synchronisé."
        else
            warn "Chrony installé mais pas encore synchronisé (normal au premier démarrage)."
        fi
    else
        success "[DRY-RUN] Chrony configuré."
    fi
}

# --- 13. Restriction de su via PAM ---
module_restrict_su() {
    info "━━━ Module 13/20 : Restriction de su (pam_wheel) ━━━"

    local pam_su="/etc/pam.d/su"

    if [[ ! -f "${pam_su}" ]]; then
        warn "/etc/pam.d/su introuvable. Module ignoré."
        return
    fi

    if [[ "${DRY_RUN}" == true ]]; then
        info "[DRY-RUN] Activation pam_wheel.so dans ${pam_su}"
    else
        # Activer la ligne pam_wheel.so si elle est commentée
        if grep -q "^#.*pam_wheel.so" "${pam_su}"; then
            sed -i 's/^#\s*\(auth\s\+required\s\+pam_wheel.so\)/\1/' "${pam_su}"
            success "su restreint au groupe sudo/wheel via pam_wheel.so."
        elif grep -q "^auth.*pam_wheel.so" "${pam_su}"; then
            info "pam_wheel.so déjà actif dans ${pam_su}."
        else
            # Ajouter la ligne si elle n'existe pas du tout
            sed -i '/^auth\s\+sufficient\s\+pam_rootok.so/a auth       required   pam_wheel.so' "${pam_su}"
            success "su restreint au groupe sudo/wheel via pam_wheel.so."
        fi
    fi
}

# --- 14. Timeout shell (TMOUT) ---
module_shell_timeout() {
    info "━━━ Module 14/20 : Timeout shell (TMOUT) ━━━"

    local tmout_file="/etc/profile.d/99-tmout.sh"

    if [[ "${DRY_RUN}" == true ]]; then
        info "[DRY-RUN] Création ${tmout_file} (TMOUT=900)"
    else
        cat > "${tmout_file}" << 'TMEOF'
# Timeout shell — généré par post-install-hardening.sh
# Déconnexion automatique après 15 minutes d'inactivité
readonly TMOUT=900
export TMOUT
TMEOF
        chmod 644 "${tmout_file}"
    fi

    success "Timeout shell configuré (15 minutes)."
}

# --- 15. Désactivation des core dumps ---
module_disable_core_dumps() {
    info "━━━ Module 15/20 : Désactivation des core dumps ━━━"

    local limits_file="/etc/security/limits.d/99-no-core.conf"

    if [[ "${DRY_RUN}" == true ]]; then
        info "[DRY-RUN] Création ${limits_file}"
    else
        cat > "${limits_file}" << 'COREEOF'
# Désactivation core dumps — post-install-hardening.sh
* hard core 0
* soft core 0
COREEOF
        chmod 644 "${limits_file}"
    fi

    # Désactiver aussi dans systemd (coredump service)
    local coredump_conf="/etc/systemd/coredump.conf.d"
    if [[ "${DRY_RUN}" == true ]]; then
        info "[DRY-RUN] Configuration systemd-coredump"
    else
        mkdir -p "${coredump_conf}"
        cat > "${coredump_conf}/disable.conf" << 'SDCEOF'
[Coredump]
Storage=none
ProcessSizeMax=0
SDCEOF
    fi

    # fs.suid_dumpable est déjà dans le sysctl (module 9)
    success "Core dumps désactivés (limits.conf + systemd-coredump + sysctl)."
}

# --- 16. Montages sécurisés (/tmp, /dev/shm) ---
module_secure_mounts() {
    info "━━━ Module 16/20 : Montages sécurisés (/tmp, /dev/shm) ━━━"

    # En LXC, les montages sont gérés par le host
    if [[ "${CONTAINER_TYPE}" == "lxc" ]]; then
        warn "Environnement LXC : montages gérés par le host. Module ignoré."
        return
    fi

    local fstab="/etc/fstab"
    local changed=false

    if [[ "${DRY_RUN}" == true ]]; then
        info "[DRY-RUN] Sécurisation des montages /tmp et /dev/shm"
        return
    fi

    # /dev/shm — ajouter noexec,nosuid,nodev si pas déjà configuré
    if grep -q '/dev/shm' "${fstab}"; then
        # Vérifier si les options sont déjà présentes
        if ! grep '/dev/shm' "${fstab}" | grep -q 'noexec'; then
            sed -i '/\/dev\/shm/s/defaults/defaults,noexec,nosuid,nodev/' "${fstab}"
            changed=true
        fi
    else
        echo "tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> "${fstab}"
        changed=true
    fi

    # /tmp — si c'est un tmpfs, ajouter noexec,nosuid,nodev
    if grep -q '/tmp' "${fstab}"; then
        if ! grep '/tmp' "${fstab}" | grep -q 'noexec'; then
            sed -i '/[[:space:]]\/tmp[[:space:]]/s/defaults/defaults,noexec,nosuid,nodev/' "${fstab}"
            changed=true
        fi
    else
        # Monter /tmp en tmpfs avec les bonnes options
        echo "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev,size=512M 0 0" >> "${fstab}"
        changed=true
    fi

    if [[ "${changed}" == true ]]; then
        # Remonter immédiatement
        mount -o remount /dev/shm 2>/dev/null || true
        mount -o remount /tmp 2>/dev/null || true
        success "Montages /tmp et /dev/shm sécurisés (noexec,nosuid,nodev)."
    else
        info "Montages /tmp et /dev/shm déjà sécurisés."
    fi
}

# --- 17. Hidepid /proc ---
module_hidepid() {
    info "━━━ Module 17/20 : Hidepid /proc ━━━"

    if [[ "${CONTAINER_TYPE}" == "lxc" ]]; then
        warn "Environnement LXC : hidepid non applicable. Module ignoré."
        return
    fi

    local fstab="/etc/fstab"

    if [[ "${DRY_RUN}" == true ]]; then
        info "[DRY-RUN] Configuration hidepid=2 sur /proc"
        return
    fi

    # Vérifier si déjà configuré
    if grep -q 'hidepid=' "${fstab}" 2>/dev/null; then
        info "hidepid déjà configuré dans fstab."
        return
    fi

    if mount | grep -q 'proc.*hidepid='; then
        info "hidepid déjà actif."
        return
    fi

    # Ajouter au fstab
    echo "proc /proc proc defaults,hidepid=2,gid=sudo 0 0" >> "${fstab}"

    # Remonter immédiatement
    mount -o remount,hidepid=2,gid=sudo /proc 2>/dev/null || {
        warn "Impossible de remonter /proc avec hidepid=2. Sera actif au prochain reboot."
        return
    }

    success "hidepid=2 activé sur /proc (seuls les membres de sudo voient tous les processus)."
}

# --- 18. AppArmor ---
module_apparmor() {
    info "━━━ Module 18/20 : AppArmor ━━━"

    # En LXC, AppArmor est géré par le host
    if [[ "${CONTAINER_TYPE}" == "lxc" ]]; then
        warn "Environnement LXC : AppArmor géré par le host. Module ignoré."
        return
    fi

    # Installer AppArmor s'il n'est pas présent
    if ! command -v apparmor_status &>/dev/null && ! command -v aa-status &>/dev/null; then
        run "${PKG_INSTALL} apparmor apparmor-utils"
    fi

    # S'assurer qu'AppArmor est activé et en enforce
    if [[ "${DRY_RUN}" == false ]]; then
        run "systemctl enable apparmor"
        run "systemctl start apparmor"

        # Mettre tous les profils en mode enforce
        if command -v aa-enforce &>/dev/null; then
            aa-enforce /etc/apparmor.d/* 2>/dev/null || true
        fi

        # Vérifier le statut
        local profiles_enforced
        profiles_enforced=$(aa-status 2>/dev/null | grep "profiles are in enforce mode" | awk '{print $1}' || echo "0")
        success "AppArmor actif — ${profiles_enforced} profil(s) en mode enforce."
    else
        success "[DRY-RUN] AppArmor configuré."
    fi
}

# --- 19. Règles auditd ---
module_auditd_rules() {
    info "━━━ Module 19/20 : Règles auditd ━━━"

    if [[ "${CONTAINER_TYPE}" == "lxc" ]]; then
        warn "Environnement LXC : auditd non supporté. Module ignoré."
        return
    fi

    # auditd est installé dans le module advanced_hardening, vérifier qu'il est présent
    if ! command -v auditd &>/dev/null; then
        info "auditd non installé. Les règles seront appliquées si auditd est installé par le module avancé."
        return
    fi

    local rules_file="/etc/audit/rules.d/99-hardening.rules"

    if [[ "${DRY_RUN}" == true ]]; then
        info "[DRY-RUN] Création des règles auditd dans ${rules_file}"
        return
    fi

    cat > "${rules_file}" << 'AUDITEOF'
# =============================================================================
# Règles auditd — post-install-hardening.sh v2
# Basées sur les recommandations CIS et STIG
# =============================================================================

# --- Fichiers d'identité et d'authentification ---
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k identity
-w /etc/sudoers.d/ -p wa -k identity

# --- Configuration SSH ---
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/sshd_config.d/ -p wa -k sshd_config

# --- Configuration réseau ---
-w /etc/hosts -p wa -k network
-w /etc/hostname -p wa -k network
-w /etc/resolv.conf -p wa -k network

# --- Cron et tâches planifiées ---
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# --- Changements de date/heure ---
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time_change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time_change
-w /etc/localtime -p wa -k time_change

# --- Changements de contexte utilisateur ---
-w /bin/su -p x -k su_usage
-w /usr/bin/sudo -p x -k sudo_usage

# --- Modules kernel ---
-w /sbin/insmod -p x -k kernel_modules
-w /sbin/rmmod -p x -k kernel_modules
-w /sbin/modprobe -p x -k kernel_modules

# --- Login/Logout ---
-w /var/log/lastlog -p wa -k login
-w /var/log/faillog -p wa -k login
-w /var/log/wtmp -p wa -k login
-w /var/log/btmp -p wa -k login

# --- Rendre les règles immuables (doit être la dernière ligne) ---
-e 2
AUDITEOF

    chmod 640 "${rules_file}"

    # Recharger les règles
    augenrules --load 2>/dev/null || auditctl -R "${rules_file}" 2>/dev/null || true

    local rule_count
    rule_count=$(auditctl -l 2>/dev/null | wc -l || echo "0")
    success "Règles auditd déployées (${rule_count} règles actives)."
}

# --- 20. Hardening avancé (recommandations Lynis) ---
module_advanced_hardening() {
    info "━━━ Module 20/20 : Hardening avancé (Lynis) ━━━"

    # --- Paquets de sécurité recommandés ---
    local lynis_packages=(
        libpam-tmpdir       # Isole $TMP/$TMPDIR par session PAM
        libpam-passwdqc     # Politique de force des mots de passe (AUTH-9262)
        needrestart         # Détecte les daemons nécessitant un restart (DEB-0831)
        debsums             # Vérification d'intégrité des paquets (PKGS-7370)
        apt-show-versions   # Gestion des versions pour le patching (PKGS-7394)
        rkhunter            # Scanner de rootkits (HRDN-7230)
        aide                # Surveillance d'intégrité des fichiers (FINT-4350)
        sysstat             # Collecte de métriques système (ACCT-9626)
    )

    # apt-listbugs n'existe que sur Debian
    if [[ "${OS_ID}" == "debian" ]]; then
        lynis_packages+=("apt-listbugs")
    fi

    # acct et auditd nécessitent un accès kernel — skip en LXC
    if [[ "${CONTAINER_TYPE}" != "lxc" ]]; then
        lynis_packages+=("acct" "auditd")
    fi

    local packages_to_install=()
    for pkg in "${lynis_packages[@]}"; do
        if ! dpkg -l "${pkg}" 2>/dev/null | grep -q "^ii"; then
            if apt-cache show "${pkg}" &>/dev/null; then
                packages_to_install+=("${pkg}")
            else
                info "Paquet ${pkg} non disponible dans les repos — ignoré."
            fi
        fi
    done

    if [[ "${#packages_to_install[@]}" -gt 0 ]]; then
        info "Installation des paquets de sécurité : ${packages_to_install[*]}"
        run "DEBIAN_FRONTEND=noninteractive apt-get install -y ${packages_to_install[*]}"
    else
        info "Paquets de sécurité déjà installés."
    fi

    # Initialiser la base rkhunter si installé
    if command -v rkhunter &>/dev/null; then
        run "rkhunter --propupd" 2>/dev/null || true
    fi

    # Initialiser la base AIDE si installé
    if command -v aide &>/dev/null; then
        local aide_excl="/etc/aide/aide.conf.d/00_aide_local_exclusions"
        if [[ ! -f "${aide_excl}" ]]; then
            if [[ "${DRY_RUN}" == false ]]; then
                cat > "${aide_excl}" << 'AIDEEOF'
# Exclusions locales — générées par post-install-hardening.sh
!/dev/.lxc
!/lost+found
!/mnt/data01
!/mnt/data02
AIDEEOF
            fi
        fi

        if [[ ! -f /var/lib/aide/aide.db ]]; then
            if pgrep -f "aideinit|aide.*--config" &>/dev/null; then
                info "AIDE est déjà en cours d'initialisation."
            else
                info "Initialisation de la base AIDE en arrière-plan (peut prendre 10-30 min)..."
                if [[ "${DRY_RUN}" == false ]]; then
                    nohup aideinit > /var/log/aide-init.log 2>&1 &
                    info "AIDE PID: $! — Progression dans /var/log/aide-init.log"
                fi
            fi
        fi
    fi

    # Activer sysstat si installé
    if [[ -f /etc/default/sysstat ]]; then
        run "sed -i 's/ENABLED=\"false\"/ENABLED=\"true\"/' /etc/default/sysstat"
        run "systemctl enable --now sysstat" 2>/dev/null || true
    fi

    # Activer acct si installé ET pas en LXC
    if [[ "${CONTAINER_TYPE}" != "lxc" ]] && command -v accton &>/dev/null; then
        run "systemctl enable --now acct" 2>/dev/null || true
    fi

    # Nettoyer acct/auditd si installés en échec sur un LXC
    if [[ "${CONTAINER_TYPE}" == "lxc" ]]; then
        for svc in acct auditd audit-rules; do
            if systemctl is-failed "${svc}" &>/dev/null 2>&1; then
                run "systemctl disable ${svc}" 2>/dev/null || true
                run "systemctl reset-failed ${svc}" 2>/dev/null || true
                info "Service ${svc} désactivé (non supporté en LXC)."
            fi
        done
    fi

    # Activer auditd si installé ET pas en LXC
    if [[ "${CONTAINER_TYPE}" != "lxc" ]] && command -v auditd &>/dev/null; then
        run "systemctl enable --now auditd" 2>/dev/null || true
    fi

    # Configurer debsums pour vérification régulière via cron
    if [[ -f /etc/default/debsums ]]; then
        if [[ "${DRY_RUN}" == false ]]; then
            sed -i 's/^CRON_CHECK=.*/CRON_CHECK=weekly/' /etc/default/debsums 2>/dev/null || true
            grep -q "^CRON_CHECK" /etc/default/debsums 2>/dev/null || echo "CRON_CHECK=weekly" >> /etc/default/debsums
        fi
    fi

    success "Paquets de sécurité installés et configurés."

    # --- Configuration libpam-passwdqc ---
    local passwdqc_conf="/etc/security/passwdqc.conf"
    if dpkg -l libpam-passwdqc 2>/dev/null | grep -q "^ii"; then
        if [[ "${DRY_RUN}" == true ]]; then
            info "[DRY-RUN] Configuration libpam-passwdqc"
        else
            cat > "${passwdqc_conf}" << 'PWQCEOF'
# Configuration passwdqc — post-install-hardening.sh v2
# Format min=disabled,disabled,disabled,8,8 :
#   N0 = mots de passe à 1 classe de caractères (désactivé)
#   N1 = mots de passe à 2 classes (désactivé)
#   N2 = passphrase (désactivé — on force N3/N4)
#   N3 = mots de passe à 3 classes (min 8 caractères)
#   N4 = mots de passe à 4 classes (min 8 caractères)
min=disabled,disabled,disabled,8,8
max=256
passphrase=3
match=4
similar=deny
enforce=everyone
retry=3
PWQCEOF
            success "libpam-passwdqc configuré (min 8 caractères, 3+ classes)."
        fi
    fi

    # --- Bannière légale (BANN-7126 / BANN-7130) ---
    local banner_text="###############################################################
#  Unauthorized access to this system is prohibited.          #
#  All activity may be monitored and reported.                #
#                                                             #
#  Acces reserve aux utilisateurs autorises.                  #
#  Toute activite est susceptible d'etre surveillee.          #
###############################################################"

    if [[ "${DRY_RUN}" == true ]]; then
        info "[DRY-RUN] Écriture bannière légale dans /etc/issue et /etc/issue.net"
    else
        echo "${banner_text}" > /etc/issue
        echo "${banner_text}" > /etc/issue.net
    fi
    success "Bannière légale configurée (/etc/issue et /etc/issue.net)."

    # --- Politique de mots de passe (login.defs) ---
    local login_defs="/etc/login.defs"
    if [[ -f "${login_defs}" ]]; then
        _set_login_defs() {
            local key="$1" value="$2"
            if grep -q "^${key}" "${login_defs}" 2>/dev/null; then
                sed -i "s|^${key}.*|${key}    ${value}|" "${login_defs}"
            elif grep -q "^#.*${key}" "${login_defs}" 2>/dev/null; then
                sed -i "s|^#.*${key}.*|${key}    ${value}|" "${login_defs}"
            else
                echo "${key}    ${value}" >> "${login_defs}"
            fi
        }

        if [[ "${DRY_RUN}" == false ]]; then
            _set_login_defs "UMASK" "027"
            _set_login_defs "PASS_MIN_DAYS" "1"
            _set_login_defs "PASS_MAX_DAYS" "365"
            _set_login_defs "SHA_CRYPT_MIN_ROUNDS" "5000"
            _set_login_defs "SHA_CRYPT_MAX_ROUNDS" "5000"
        fi

        success "Politique de mots de passe renforcée (login.defs)."
    fi

    # --- Désactivation des protocoles réseau inutiles ---
    local modprobe_conf="/etc/modprobe.d/hardening.conf"
    if [[ ! -f "${modprobe_conf}" ]]; then
        if [[ "${DRY_RUN}" == false ]]; then
            cat > "${modprobe_conf}" << 'MODEOF'
# Protocoles réseau inutiles — désactivés par post-install-hardening.sh
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
# Stockage externe
install usb-storage /bin/true
install firewire-core /bin/true
MODEOF
        fi
        success "Protocoles réseau et stockage USB/FireWire désactivés."
    else
        info "Hardening modprobe déjà en place."
    fi

    # --- Permissions restrictives sur les fichiers sensibles ---
    local sensitive_files=(
        "/etc/crontab:600"
        "/etc/ssh/sshd_config:600"
        "/etc/shadow:640"
    )

    for entry in "${sensitive_files[@]}"; do
        local filepath="${entry%%:*}"
        local perms="${entry##*:}"
        if [[ -f "${filepath}" ]]; then
            local current_perms
            current_perms=$(stat -c "%a" "${filepath}" 2>/dev/null || echo "")
            if [[ "${current_perms}" != "${perms}" ]]; then
                run "chmod ${perms} '${filepath}'"
            fi
        fi
    done

    # Restreindre l'accès aux compilateurs si présents
    for compiler in /usr/bin/gcc /usr/bin/g++ /usr/bin/cc; do
        if [[ -f "${compiler}" && ! -L "${compiler}" ]]; then
            local current_perms
            current_perms=$(stat -c "%a" "${compiler}" 2>/dev/null || echo "")
            if [[ "${current_perms}" != "700" ]]; then
                run "chmod 700 '${compiler}'"
            fi
        fi
    done

    success "Permissions restrictives appliquées."

    # --- Profil Lynis custom pour LXC (faux positifs) ---
    if [[ "${CONTAINER_TYPE}" == "lxc" ]]; then
        local lynis_prf="/etc/lynis/custom.prf"
        run "mkdir -p /etc/lynis"
        if [[ "${DRY_RUN}" == false ]]; then
            cat > "${lynis_prf}" << 'LYNISEOF'
# Profil Lynis custom — faux positifs LXC
# Généré par post-install-hardening.sh

# iptables chargé par le host mais pas de règles dans le conteneur (normal)
skip-test=FIRE-4512

# Pas de kernel propre en LXC
skip-test=KRNL-5788
skip-test=KRNL-5830

# sysctl géré par le host
skip-test=KRNL-6000

# Pas de boot propre en LXC
skip-test=BOOT-5180

# Partitions séparées non pertinentes en LXC
skip-test=FILE-6310
LYNISEOF
            success "Profil Lynis LXC configuré (faux positifs ignorés)."
        fi
    fi

    success "Hardening avancé terminé."
}

# --- Stamp de version ---
module_write_version_stamp() {
    info "━━━ Écriture du stamp de version ━━━"

    if [[ "${DRY_RUN}" == true ]]; then
        info "[DRY-RUN] Écriture de ${HARDENING_STAMP}"
        return
    fi

    cat > "${HARDENING_STAMP}" << STAMPEOF
# Hardening appliqué par post-install-hardening.sh
version=${SCRIPT_VERSION}
date=$(date '+%Y-%m-%d %H:%M:%S')
user=${ADMIN_USER}
ssh_port=${SSH_PORT}
os=${OS_NAME}
type=${CONTAINER_TYPE}
STAMPEOF

    chmod 644 "${HARDENING_STAMP}"
    success "Stamp de version écrit dans ${HARDENING_STAMP}."
}

# --- Notification Telegram ---
module_notify_telegram() {
    if [[ "${ENABLE_TELEGRAM}" == false ]]; then
        return
    fi

    if [[ -z "${TELEGRAM_BOT_TOKEN}" || -z "${TELEGRAM_CHAT_ID}" ]]; then
        warn "Telegram activé mais TELEGRAM_BOT_TOKEN et/ou TELEGRAM_CHAT_ID non définis."
        return
    fi

    info "━━━ Notification Telegram ━━━"

    local ip_addr
    ip_addr="$(hostname -I 2>/dev/null | awk '{print $1}')" || ip_addr="N/A"
    local hostname_val
    hostname_val="$(hostname -f 2>/dev/null)" || hostname_val="$(hostname)"

    local message="🔒 *Hardening terminé*
🖥 Host : \`${hostname_val}\`
🌐 IP : \`${ip_addr}\`
👤 Admin : \`${ADMIN_USER}\`
🔑 SSH port : \`${SSH_PORT}\`
📦 OS : ${OS_NAME}
🏷 Version : v${SCRIPT_VERSION}
📅 Date : $(date '+%Y-%m-%d %H:%M')"

    if [[ "${DRY_RUN}" == false ]]; then
        curl -s -X POST \
            "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
            -d chat_id="${TELEGRAM_CHAT_ID}" \
            -d text="${message}" \
            -d parse_mode="Markdown" > /dev/null 2>&1 \
            && success "Notification Telegram envoyée." \
            || warn "Échec de l'envoi de la notification Telegram."
    else
        info "[DRY-RUN] Notification Telegram préparée."
    fi
}

# =============================================================================
# RÉSUMÉ FINAL
# =============================================================================

print_summary() {
    local ip_addr
    ip_addr="$(hostname -I 2>/dev/null | awk '{print $1}')" || ip_addr="N/A"

    # État réel (prend en compte les skips LXC)
    local ufw_status="${ENABLE_UFW}"
    local sysctl_status="true"
    local apparmor_status="true"
    local auditd_status="true"
    local hidepid_status="true"
    local mounts_status="true"
    if [[ "${CONTAINER_TYPE}" == "lxc" ]]; then
        ufw_status="ignoré (LXC)"
        sysctl_status="ignoré (LXC)"
        apparmor_status="ignoré (LXC)"
        auditd_status="ignoré (LXC)"
        hidepid_status="ignoré (LXC)"
        mounts_status="ignoré (LXC)"
    fi

    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║              HARDENING TERMINÉ AVEC SUCCÈS                  ║${NC}"
    echo -e "${GREEN}║              post-install-hardening.sh v${SCRIPT_VERSION}              ║${NC}"
    echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║${NC} OS            : ${OS_NAME}"
    echo -e "${GREEN}║${NC} Type          : ${CONTAINER_TYPE}"
    echo -e "${GREEN}║${NC} IP            : ${ip_addr}"
    echo -e "${GREEN}║${NC} Utilisateur   : ${ADMIN_USER}"
    echo -e "${GREEN}║${NC} Port SSH      : ${SSH_PORT}"
    echo -e "${GREEN}║${NC} Fail2ban      : ${ENABLE_FAIL2BAN}"
    echo -e "${GREEN}║${NC} UFW           : ${ufw_status}"
    echo -e "${GREEN}║${NC} Sysctl        : ${sysctl_status}"
    echo -e "${GREEN}║${NC} Auto-updates  : ${ENABLE_UNATTENDED}"
    echo -e "${GREEN}║${NC} NTP (chrony)  : true"
    echo -e "${GREEN}║${NC} su restreint  : true (pam_wheel)"
    echo -e "${GREEN}║${NC} Shell TMOUT   : 900s"
    echo -e "${GREEN}║${NC} Core dumps    : désactivés"
    echo -e "${GREEN}║${NC} Montages sec. : ${mounts_status}"
    echo -e "${GREEN}║${NC} hidepid /proc : ${hidepid_status}"
    echo -e "${GREEN}║${NC} AppArmor      : ${apparmor_status}"
    echo -e "${GREEN}║${NC} auditd règles : ${auditd_status}"
    echo -e "${GREEN}║${NC} Lynis harden  : true (rkhunter, bannière, modprobe, login.defs, passwdqc)"
    echo -e "${GREEN}║${NC} Stamp version : ${HARDENING_STAMP}"
    echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║${NC} Connexion     : ssh -p ${SSH_PORT} ${ADMIN_USER}@${ip_addr}"
    echo -e "${GREEN}║${NC} Log           : ${LOG_FILE}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    parse_args "$@"

    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  post-install-hardening.sh v${SCRIPT_VERSION}${NC}"
    if [[ "${DRY_RUN}" == true ]]; then
        echo -e "${YELLOW}  ⚡ MODE DRY-RUN — Aucune modification ne sera appliquée${NC}"
    fi
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    check_root
    detect_os
    detect_environment

    module_system_update
    module_install_essentials
    module_set_hostname
    module_create_admin_user
    module_harden_ssh
    module_install_fail2ban
    module_configure_ufw
    module_configure_unattended_upgrades
    module_harden_sysctl
    module_disable_unnecessary_services
    module_configure_logging
    module_configure_ntp
    module_restrict_su
    module_shell_timeout
    module_disable_core_dumps
    module_secure_mounts
    module_hidepid
    module_apparmor
    module_auditd_rules
    module_advanced_hardening
    module_write_version_stamp
    module_notify_telegram

    print_summary
}

main "$@"