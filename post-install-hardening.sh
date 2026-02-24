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
#   -i, --inventory <path>      Chemin du fichier d'inventaire (sur machine locale)
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
readonly SCRIPT_VERSION="1.0.0"
readonly LOG_FILE="/var/log/post-install-hardening.log"
readonly SYSCTL_HARDENING_FILE="/etc/sysctl.d/99-hardening.conf"
readonly SSH_CONFIG="/etc/ssh/sshd_config"
readonly SSH_HARDENING_DIR="/etc/ssh/sshd_config.d"
readonly INVENTORY_DEFAULT="/root/infrastructure-inventory.csv"

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
INVENTORY_FILE="${INVENTORY_DEFAULT}"
PROXMOX_HOST=""
PROXMOX_INVENTORY="/root/inventaire.csv"
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
  -i, --inventory <path>      Fichier d'inventaire CSV (mode local)
  --proxmox-host <IP|host>    IP du host Proxmox pour inventaire centralisé
  -t, --telegram              Notification Telegram à la fin
  --no-fail2ban               Désactiver l'installation de fail2ban
  --no-ufw                    Désactiver la configuration UFW
  --no-unattended             Désactiver unattended-upgrades
  --dry-run                   Mode simulation (aucune modification)
  --help                      Afficher cette aide

Modules appliqués :
  1. Mise à jour système + paquets essentiels
  2. Création utilisateur admin (sudo, clé SSH)
  3. Hardening SSH (root off, password off, MaxSessions 2, TCPKeepAlive no)
  4. Fail2ban (SSH jail)
  5. UFW (VMs uniquement)
  6. Mises à jour de sécurité automatiques
  7. Hardening sysctl (VMs uniquement)
  8. Hardening avancé Lynis (rkhunter, bannière, login.defs, modprobe, permissions)
  9. Enregistrement inventaire

Exemples :
  # Hardening complet avec clé SSH et inventaire centralisé
  ${SCRIPT_NAME} -u sysadmin -k ~/.ssh/id_ed25519.pub -p 2222 --proxmox-host 192.168.1.1

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
            -i|--inventory)   INVENTORY_FILE="$2"; shift 2 ;;
            --proxmox-host)   PROXMOX_HOST="$2";  shift 2 ;;
            -t|--telegram)    ENABLE_TELEGRAM=true; shift ;;
            --no-fail2ban)    ENABLE_FAIL2BAN=false; shift ;;
            --no-ufw)         ENABLE_UFW=false;   shift ;;
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
    info "━━━ Mise à jour du système ━━━"
    run "${PKG_UPDATE}"
    run "${PKG_MANAGER} upgrade -y -qq"
    success "Système mis à jour."
}

# --- 2. Installation des paquets essentiels ---
module_install_essentials() {
    info "━━━ Installation des paquets essentiels ━━━"

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
        info "━━━ Configuration du hostname : ${NEW_HOSTNAME} ━━━"
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
    info "━━━ Création de l'utilisateur admin : ${ADMIN_USER} ━━━"

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
    info "━━━ Hardening SSH ━━━"

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
Banner none
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
    # Le socket ignore sshd_config et écoute sur son propre port.
    # On désactive le socket et on utilise le service classique.
    if systemctl is-active ssh.socket &>/dev/null || systemctl is-enabled ssh.socket &>/dev/null; then
        info "ssh.socket détecté (Ubuntu 24.04+). Bascule vers ssh.service..."
        run "systemctl disable --now ssh.socket"
        run "systemctl enable ssh.service"
    fi

    # Vérification de la config SSH avant redémarrage
    if [[ "${DRY_RUN}" == false ]]; then
        local sshd_errors
        if sshd_errors="$(sshd -t 2>&1)"; then
            # Restart (pas reload) : nécessaire pour un changement de port
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

    info "━━━ Installation et configuration de fail2ban ━━━"
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
        warn "Environnement LXC détecté. UFW peut ne pas fonctionner correctement."
        warn "Le firewall devrait être géré au niveau du host Proxmox (iptables/nftables)."
        warn "Installation d'UFW ignorée pour ce conteneur."
        return
    fi

    info "━━━ Configuration du firewall UFW ━━━"
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

    info "━━━ Configuration des mises à jour automatiques de sécurité ━━━"
    run "${PKG_INSTALL} unattended-upgrades apt-listchanges"

    cat > /tmp/50unattended-upgrades << 'UUEOF'
// Unattended-Upgrades — post-install-hardening.sh
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};

// Ne pas mettre à jour automatiquement les paquets non-sécurité
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
    info "━━━ Hardening kernel (sysctl) ━━━"

    # En LXC, la plupart des paramètres sysctl ne sont pas modifiables
    if [[ "${CONTAINER_TYPE}" == "lxc" ]]; then
        warn "Environnement LXC : les paramètres sysctl sont limités."
        warn "Le hardening kernel doit être appliqué sur le host Proxmox."
        return
    fi

    cat > /tmp/99-hardening.conf << 'SYSCTLEOF'
# =============================================================================
# Hardening sysctl — post-install-hardening.sh
# =============================================================================

# --- Protection réseau ---
# Désactiver le routage IP (sauf si c'est un routeur)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Protection contre le SYN flood
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2

# Ignorer les redirections ICMP
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Ne pas envoyer de redirections ICMP
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Ignorer les paquets source-routed
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Protection contre le spoofing (reverse path filtering)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignorer les pings broadcast (protection smurf)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Loguer les paquets martiens
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# --- Protection mémoire ---
# Restreindre l'accès aux pointeurs kernel
kernel.kptr_restrict = 2

# Restreindre dmesg aux utilisateurs privilégiés
kernel.dmesg_restrict = 1

# ASLR complet
kernel.randomize_va_space = 2

# Restreindre l'utilisation de ptrace
kernel.yama.ptrace_scope = 1

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
    info "━━━ Désactivation des services inutiles ━━━"

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
    info "━━━ Configuration du logging ━━━"

    # Limiter la taille du journal systemd
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

# --- 12. Hardening avancé (recommandations Lynis) ---
module_advanced_hardening() {
    info "━━━ Hardening avancé (Lynis) ━━━"

    # --- Paquets de sécurité recommandés ---
    local lynis_packages=(
        libpam-tmpdir       # Isole $TMP/$TMPDIR par session PAM
        libpam-passwdqc     # Politique de force des mots de passe (AUTH-9262)
        needrestart         # Détecte les daemons nécessitant un restart (DEB-0831)
        debsums             # Vérification d'intégrité des paquets (PKGS-7370)
        apt-show-versions   # Gestion des versions pour le patching (PKGS-7394)
        apt-listbugs        # Affiche les bugs critiques avant install (DEB-0810)
        rkhunter            # Scanner de rootkits (HRDN-7230)
        aide                # Surveillance d'intégrité des fichiers (FINT-4350)
        sysstat             # Collecte de métriques système (ACCT-9626)
    )

    # acct et auditd nécessitent un accès kernel — skip en LXC
    if [[ "${CONTAINER_TYPE}" != "lxc" ]]; then
        lynis_packages+=("acct" "auditd")
    fi

    local packages_to_install=()
    for pkg in "${lynis_packages[@]}"; do
        if ! dpkg -l "${pkg}" 2>/dev/null | grep -q "^ii"; then
            packages_to_install+=("${pkg}")
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

    # Initialiser la base AIDE si installé (en arrière-plan, peut être long)
    if command -v aide &>/dev/null; then
        if [[ ! -f /var/lib/aide/aide.db ]]; then
            info "Initialisation de la base AIDE en arrière-plan (peut prendre 10-30 min)..."
            if [[ "${DRY_RUN}" == false ]]; then
                nohup aideinit > /var/log/aide-init.log 2>&1 &
                info "AIDE PID: $! — Progression dans /var/log/aide-init.log"
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

    # Nettoyer acct/auditd si installés en échec sur un LXC (run précédent sans ce fix)
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

    # Configurer debsums pour vérification régulière via cron (PKGS-7370)
    if [[ -f /etc/default/debsums ]]; then
        if [[ "${DRY_RUN}" == true ]]; then
            info "[DRY-RUN] Activation CRON_CHECK dans /etc/default/debsums"
        else
            sed -i 's/^CRON_CHECK=.*/CRON_CHECK=weekly/' /etc/default/debsums 2>/dev/null || true
            # Si la variable n'existe pas, l'ajouter
            grep -q "^CRON_CHECK" /etc/default/debsums 2>/dev/null || echo "CRON_CHECK=weekly" >> /etc/default/debsums
        fi
    fi

    success "Paquets de sécurité installés et configurés."

    # --- Bannière légale (BANN-7126 / BANN-7130) ---
    # Lynis cherche des mots-clés anglais : authorized, unauthorized, prohibited, monitored
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
        # Helper pour modifier ou ajouter un paramètre dans login.defs
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

        if [[ "${DRY_RUN}" == true ]]; then
            info "[DRY-RUN] Configuration login.defs (UMASK, SHA_ROUNDS, PASS_MIN/MAX_DAYS)"
        else
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
        if [[ "${DRY_RUN}" == true ]]; then
            info "[DRY-RUN] Création ${modprobe_conf} (protocoles réseau + USB/FireWire)"
        else
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
    success "Hardening avancé terminé."
}

# --- 13. Enregistrement dans l'inventaire ---
module_register_inventory() {
    info "━━━ Enregistrement dans l'inventaire ━━━"

    local ip_addr
    ip_addr="$(hostname -I 2>/dev/null | awk '{print $1}')" || ip_addr="N/A"
    local hostname_val
    hostname_val="$(hostname -f 2>/dev/null)" || hostname_val="$(hostname)"
    local date_install
    date_install="$(date '+%Y-%m-%d %H:%M:%S')"

    local entry="${hostname_val},${ip_addr},${SSH_PORT},${ADMIN_USER},${OS_NAME},${CONTAINER_TYPE},${date_install}"
    local header="hostname,ip,ssh_port,admin_user,os,type,date_hardening"

    if [[ "${DRY_RUN}" == true ]]; then
        info "[DRY-RUN] Entrée inventaire : ${entry}"
        return
    fi

    # Mode centralisé : envoi vers le host Proxmox via SSH
    if [[ -n "${PROXMOX_HOST}" ]]; then
        info "Envoi vers le host Proxmox (${PROXMOX_HOST})..."

        # Créer le fichier si absent, supprimer l'ancienne entrée (même hostname ou IP), ajouter la nouvelle
        local remote_cmd="
            if [ ! -f '${PROXMOX_INVENTORY}' ]; then
                echo '${header}' > '${PROXMOX_INVENTORY}'
            fi
            tmp=\$(mktemp)
            head -1 '${PROXMOX_INVENTORY}' > \"\${tmp}\"
            tail -n +2 '${PROXMOX_INVENTORY}' | grep -v '^${hostname_val},\|,${ip_addr},' >> \"\${tmp}\" || true
            echo '${entry}' >> \"\${tmp}\"
            mv \"\${tmp}\" '${PROXMOX_INVENTORY}'
        "

        if ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 \
            "root@${PROXMOX_HOST}" "${remote_cmd}" 2>/dev/null; then
            success "Machine enregistrée sur ${PROXMOX_HOST}:${PROXMOX_INVENTORY}"
        else
            warn "Impossible de joindre le host Proxmox (${PROXMOX_HOST})."
            warn "Enregistrement local de secours dans ${INVENTORY_FILE}"
            _register_local "${header}" "${entry}" "${hostname_val}" "${ip_addr}"
        fi
    else
        # Mode local (fallback)
        _register_local "${header}" "${entry}" "${hostname_val}" "${ip_addr}"
    fi
}

_register_local() {
    local header="$1"
    local entry="$2"
    local hostname_val="$3"
    local ip_addr="$4"

    if [[ ! -f "${INVENTORY_FILE}" ]]; then
        echo "${header}" > "${INVENTORY_FILE}"
    fi

    # Supprimer l'ancienne entrée si même hostname ou IP
    local tmp
    tmp=$(mktemp)
    head -1 "${INVENTORY_FILE}" > "${tmp}"
    tail -n +2 "${INVENTORY_FILE}" | grep -v "^${hostname_val},\|,${ip_addr}," >> "${tmp}" || true
    echo "${entry}" >> "${tmp}"
    mv "${tmp}" "${INVENTORY_FILE}"

    success "Machine enregistrée dans ${INVENTORY_FILE}"
}

# --- 13. Notification Telegram ---
module_notify_telegram() {
    if [[ "${ENABLE_TELEGRAM}" == false ]]; then
        return
    fi

    if [[ -z "${TELEGRAM_BOT_TOKEN}" || -z "${TELEGRAM_CHAT_ID}" ]]; then
        warn "Telegram activé mais TELEGRAM_BOT_TOKEN et/ou TELEGRAM_CHAT_ID non définis."
        warn "Exportez ces variables d'environnement avant de lancer le script."
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
    if [[ "${CONTAINER_TYPE}" == "lxc" ]]; then
        ufw_status="ignoré (LXC)"
        sysctl_status="ignoré (LXC)"
    fi

    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║              HARDENING TERMINÉ AVEC SUCCÈS                  ║${NC}"
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
    echo -e "${GREEN}║${NC} Lynis harden  : true (rkhunter, bannière, modprobe, login.defs)"
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
    module_advanced_hardening
    module_register_inventory
    module_notify_telegram

    print_summary
}

main "$@"