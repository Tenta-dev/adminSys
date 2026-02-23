#!/usr/bin/env bash
###############################################################################
# inventory.sh
# Gestion centralisée de l'inventaire des machines durcies (LXC/VM)
# À déployer sur le host Proxmox
#
# Usage :
#   inventory list                          Afficher toutes les machines
#   inventory search <terme>                Rechercher par hostname, IP, OS...
#   inventory add <champs...>               Ajouter une entrée manuellement
#   inventory remove <hostname|IP>          Supprimer une entrée
#   inventory export [--format md|csv]      Exporter l'inventaire
#   inventory stats                         Statistiques de l'infrastructure
#   inventory check                         Vérifier la connectivité SSH
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
readonly INVENTORY_FILE="${INVENTORY_FILE:-/root/inventaire.csv}"
readonly EXPORT_DIR="${EXPORT_DIR:-/root/exports}"

# En-tête CSV
readonly CSV_HEADER="hostname,ip,ssh_port,admin_user,os,type,date_hardening"

# Couleurs
readonly RED=$'\033[0;31m'
readonly GREEN=$'\033[0;32m'
readonly YELLOW=$'\033[1;33m'
readonly BLUE=$'\033[0;34m'
readonly CYAN=$'\033[0;36m'
readonly BOLD=$'\033[1m'
readonly DIM=$'\033[2m'
readonly NC=$'\033[0m'

# Largeurs des colonnes
readonly COL_HOST=25
readonly COL_IP=17
readonly COL_PORT=6
readonly COL_USER=12
readonly COL_OS=28
readonly COL_TYPE=6
readonly COL_DATE=20

# =============================================================================
# FONCTIONS UTILITAIRES
# =============================================================================

die() {
    echo -e "${RED}[ERREUR]${NC} $*" >&2
    exit 1
}

info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

ensure_inventory() {
    if [[ ! -f "${INVENTORY_FILE}" ]]; then
        echo "${CSV_HEADER}" > "${INVENTORY_FILE}"
        info "Fichier d'inventaire créé : ${INVENTORY_FILE}"
    fi
}

count_machines() {
    local count
    count=$(tail -n +2 "${INVENTORY_FILE}" 2>/dev/null | grep -c '[^[:space:]]' || echo "0")
    echo "${count}"
}

# =============================================================================
# AFFICHAGE TABLEAU COLORÉ
# =============================================================================

print_separator() {
    local char="${1:-─}"
    echo -e "${DIM}$(printf '%0.s─' $(seq 1 130))${NC}"
}

print_header() {
    echo ""
    echo -e "${BOLD}${CYAN}$(printf "%-${COL_HOST}s" "HOSTNAME") $(printf "%-${COL_IP}s" "IP") $(printf "%-${COL_PORT}s" "PORT") $(printf "%-${COL_USER}s" "ADMIN") $(printf "%-${COL_OS}s" "OS") $(printf "%-${COL_TYPE}s" "TYPE") $(printf "%-${COL_DATE}s" "DATE HARDENING")${NC}"
    print_separator
}

print_row() {
    local hostname="$1"
    local ip="$2"
    local port="$3"
    local user="$4"
    local os="$5"
    local type="$6"
    local date="$7"

    # Couleur du type
    local type_color="${NC}"
    case "${type}" in
        lxc)  type_color="${GREEN}" ;;
        kvm|qemu) type_color="${BLUE}" ;;
        bare*) type_color="${YELLOW}" ;;
    esac

    printf "%-${COL_HOST}s " "${hostname}"
    printf "%-${COL_IP}s " "${ip}"
    printf "%-${COL_PORT}s " "${port}"
    printf "%-${COL_USER}s " "${user}"
    printf "%-${COL_OS}s " "${os}"
    echo -e "${type_color}$(printf "%-${COL_TYPE}s" "${type}")${NC} ${DIM}${date}${NC}"
}

print_table() {
    local data="$1"

    if [[ -z "${data}" ]]; then
        echo ""
        warn "Aucune machine trouvée."
        return
    fi

    print_header

    while IFS=',' read -r hostname ip port user os type date; do
        print_row "${hostname}" "${ip}" "${port}" "${user}" "${os}" "${type}" "${date}"
    done <<< "${data}"

    print_separator
    local total
    total=$(echo "${data}" | grep -c '[^[:space:]]' || echo "0")
    echo -e "${DIM}${total} machine(s)${NC}"
    echo ""
}

# =============================================================================
# COMMANDES
# =============================================================================

# --- LIST : Afficher toutes les machines ---
cmd_list() {
    ensure_inventory

    local data
    data=$(tail -n +2 "${INVENTORY_FILE}" | grep '[^[:space:]]' || true)

    local total
    total=$(count_machines)

    echo ""
    echo -e "${BOLD}📋 Inventaire infrastructure — ${total} machine(s)${NC}"

    print_table "${data}"
}

# --- SEARCH : Rechercher ---
cmd_search() {
    local term="${1:-}"

    if [[ -z "${term}" ]]; then
        die "Usage : ${SCRIPT_NAME} search <terme>"
    fi

    ensure_inventory

    local results
    results=$(tail -n +2 "${INVENTORY_FILE}" | grep -i "${term}" || true)

    echo ""
    echo -e "${BOLD}🔍 Recherche : \"${term}\"${NC}"

    print_table "${results}"
}

# --- ADD : Ajouter une entrée ---
cmd_add() {
    ensure_inventory

    local hostname="${1:-}"
    local ip="${2:-}"
    local port="${3:-22}"
    local user="${4:-admin}"
    local os="${5:-unknown}"
    local type="${6:-unknown}"

    if [[ -z "${hostname}" || -z "${ip}" ]]; then
        echo ""
        echo -e "${BOLD}Ajout interactif d'une machine${NC}"
        echo ""

        read -rp "Hostname       : " hostname
        read -rp "IP             : " ip
        read -rp "Port SSH  [22] : " port
        port="${port:-22}"
        read -rp "Admin    [admin]: " user
        user="${user:-admin}"
        read -rp "OS             : " os
        read -rp "Type (lxc/kvm) : " type

        [[ -z "${hostname}" || -z "${ip}" ]] && die "Hostname et IP sont obligatoires."
    fi

    local date_now
    date_now="$(date '+%Y-%m-%d %H:%M:%S')"

    # Vérifier si la machine existe déjà
    if tail -n +2 "${INVENTORY_FILE}" | grep -q "^${hostname},\|,${ip}," 2>/dev/null; then
        warn "Une entrée avec ce hostname ou cette IP existe déjà :"
        cmd_search "${hostname}"
        read -rp "Remplacer l'entrée existante ? [o/N] : " confirm
        if [[ "${confirm}" =~ ^[oOyY]$ ]]; then
            # Supprimer l'ancienne entrée
            local tmp
            tmp=$(mktemp)
            head -1 "${INVENTORY_FILE}" > "${tmp}"
            tail -n +2 "${INVENTORY_FILE}" | grep -v "^${hostname},\|,${ip}," >> "${tmp}" || true
            mv "${tmp}" "${INVENTORY_FILE}"
        else
            info "Ajout annulé."
            return
        fi
    fi

    echo "${hostname},${ip},${port},${user},${os},${type},${date_now}" >> "${INVENTORY_FILE}"
    echo ""
    echo -e "${GREEN}✓${NC} Machine ajoutée :"
    echo ""
    print_header
    print_row "${hostname}" "${ip}" "${port}" "${user}" "${os}" "${type}" "${date_now}"
    echo ""
}

# --- REMOVE : Supprimer une entrée ---
cmd_remove() {
    local term="${1:-}"

    if [[ -z "${term}" ]]; then
        die "Usage : ${SCRIPT_NAME} remove <hostname|IP>"
    fi

    ensure_inventory

    # Trouver les entrées correspondantes
    local matches
    matches=$(tail -n +2 "${INVENTORY_FILE}" | grep -i "${term}" || true)

    if [[ -z "${matches}" ]]; then
        warn "Aucune machine trouvée pour \"${term}\"."
        return
    fi

    echo ""
    echo -e "${BOLD}Machines correspondantes :${NC}"
    print_table "${matches}"

    read -rp "Confirmer la suppression ? [o/N] : " confirm
    if [[ ! "${confirm}" =~ ^[oOyY]$ ]]; then
        info "Suppression annulée."
        return
    fi

    local tmp
    tmp=$(mktemp)
    head -1 "${INVENTORY_FILE}" > "${tmp}"
    tail -n +2 "${INVENTORY_FILE}" | grep -iv "${term}" >> "${tmp}" || true
    mv "${tmp}" "${INVENTORY_FILE}"

    echo -e "${GREEN}✓${NC} Entrée(s) supprimée(s)."
}

# --- EXPORT : Exporter l'inventaire ---
cmd_export() {
    local format="${1:-md}"

    # Gérer --format xx
    if [[ "${format}" == "--format" ]]; then
        format="${2:-md}"
    fi

    ensure_inventory
    mkdir -p "${EXPORT_DIR}"

    local date_export
    date_export="$(date '+%Y%m%d_%H%M%S')"

    case "${format}" in
        md|markdown)
            _export_markdown "${date_export}"
            ;;
        csv)
            _export_csv "${date_export}"
            ;;
        *)
            die "Format inconnu : ${format}. Formats supportés : md, csv"
            ;;
    esac
}

_export_markdown() {
    local date_export="$1"
    local output="${EXPORT_DIR}/inventaire_${date_export}.md"
    local total
    total=$(count_machines)

    cat > "${output}" << MDEOF
# 📋 Inventaire Infrastructure

> Généré le $(date '+%Y-%m-%d à %H:%M:%S') — ${total} machine(s)

| Hostname | IP | Port SSH | Admin | OS | Type | Date hardening |
|----------|-----|----------|-------|----|------|----------------|
MDEOF

    while IFS=',' read -r hostname ip port user os type date; do
        echo "| ${hostname} | ${ip} | ${port} | ${user} | ${os} | ${type} | ${date} |" >> "${output}"
    done < <(tail -n +2 "${INVENTORY_FILE}" | grep '[^[:space:]]' || true)

    # Ajouter les stats
    cat >> "${output}" << MDEOF

---

## Statistiques

MDEOF

    _stats_for_markdown >> "${output}"

    echo -e "${GREEN}✓${NC} Export Markdown : ${output}"
}

_stats_for_markdown() {
    local total lxc_count vm_count
    total=$(count_machines)
    lxc_count=$(tail -n +2 "${INVENTORY_FILE}" | grep -c ',lxc,' || echo "0")
    vm_count=$(tail -n +2 "${INVENTORY_FILE}" | grep -c ',kvm\|,qemu' || echo "0")
    local other_count=$((total - lxc_count - vm_count))

    echo "- **Total** : ${total} machine(s)"
    echo "- **Conteneurs LXC** : ${lxc_count}"
    echo "- **Machines virtuelles** : ${vm_count}"
    [[ "${other_count}" -gt 0 ]] && echo "- **Autres** : ${other_count}"

    echo ""
    echo "### Répartition par OS"
    echo ""

    tail -n +2 "${INVENTORY_FILE}" | cut -d',' -f5 | sort | uniq -c | sort -rn | while read -r count os; do
        echo "- ${os} : ${count}"
    done
}

_export_csv() {
    local date_export="$1"
    local output="${EXPORT_DIR}/inventaire_${date_export}.csv"

    cp "${INVENTORY_FILE}" "${output}"
    echo -e "${GREEN}✓${NC} Export CSV : ${output}"
}

# --- STATS : Statistiques ---
cmd_stats() {
    ensure_inventory

    local total lxc_count vm_count
    total=$(count_machines)
    lxc_count=$(tail -n +2 "${INVENTORY_FILE}" | grep -c ',lxc,' || echo "0")
    vm_count=$(tail -n +2 "${INVENTORY_FILE}" | grep -c ',kvm\|,qemu' || echo "0")
    local other_count=$((total - lxc_count - vm_count))

    echo ""
    echo -e "${BOLD}📊 Statistiques infrastructure${NC}"
    echo ""
    print_separator

    echo -e "  ${BOLD}Total machines${NC}      ${total}"
    echo -e "  ${GREEN}Conteneurs LXC${NC}      ${lxc_count}"
    echo -e "  ${BLUE}Machines virtuelles${NC} ${vm_count}"
    [[ "${other_count}" -gt 0 ]] && echo -e "  ${YELLOW}Autres${NC}              ${other_count}"

    print_separator
    echo ""

    if [[ "${total}" -gt 0 ]]; then
        echo -e "${BOLD}  Répartition par OS :${NC}"
        echo ""
        tail -n +2 "${INVENTORY_FILE}" | cut -d',' -f5 | sort | uniq -c | sort -rn | while read -r count os; do
            # Barre de progression visuelle
            local bar_length=$(( (count * 30) / total ))
            [[ "${bar_length}" -lt 1 ]] && bar_length=1
            local bar
            bar=$(printf '%0.s█' $(seq 1 "${bar_length}"))
            printf "  ${CYAN}%-30s${NC} %s %s\n" "${os}" "${bar}" "(${count})"
        done
        echo ""

        echo -e "${BOLD}  Ports SSH utilisés :${NC}"
        echo ""
        tail -n +2 "${INVENTORY_FILE}" | cut -d',' -f3 | sort | uniq -c | sort -rn | while read -r count port; do
            printf "  Port %-6s — %s machine(s)\n" "${port}" "${count}"
        done
        echo ""
    fi
}

# --- CHECK : Vérifier la connectivité SSH ---
cmd_check() {
    ensure_inventory

    local total
    total=$(count_machines)

    if [[ "${total}" -eq 0 ]]; then
        warn "Inventaire vide."
        return
    fi

    echo ""
    echo -e "${BOLD}🔌 Vérification de la connectivité SSH${NC}"
    echo ""

    local ok=0
    local ko=0

    print_header

    while IFS=',' read -r hostname ip port user os type date; do
        local status_icon status_color
        if timeout 5 bash -c "echo > /dev/tcp/${ip}/${port}" 2>/dev/null; then
            status_icon="✓"
            status_color="${GREEN}"
            ((ok++))
        else
            status_icon="✗"
            status_color="${RED}"
            ((ko++))
        fi

        echo -e "${status_color}${status_icon}${NC} $(print_row "${hostname}" "${ip}" "${port}" "${user}" "${os}" "${type}" "${date}")"
    done < <(tail -n +2 "${INVENTORY_FILE}" | grep '[^[:space:]]' || true)

    print_separator
    echo -e "  ${GREEN}✓ Accessible : ${ok}${NC}   ${RED}✗ Injoignable : ${ko}${NC}   Total : ${total}"
    echo ""
}

# =============================================================================
# AIDE
# =============================================================================

show_help() {
    cat << EOF

${BOLD}${SCRIPT_NAME}${NC} v${SCRIPT_VERSION} — Gestion d'inventaire infrastructure Proxmox

${BOLD}USAGE${NC}
    ${SCRIPT_NAME} <commande> [options]

${BOLD}COMMANDES${NC}
    ${CYAN}list${NC}                            Afficher toutes les machines
    ${CYAN}search${NC}  <terme>                  Rechercher (hostname, IP, OS, type...)
    ${CYAN}add${NC}     [host ip port user os type]  Ajouter une machine (interactif si sans args)
    ${CYAN}remove${NC}  <hostname|IP>             Supprimer une entrée
    ${CYAN}export${NC}  [--format md|csv]         Exporter (défaut: markdown)
    ${CYAN}stats${NC}                            Statistiques de l'infrastructure
    ${CYAN}check${NC}                            Vérifier la connectivité SSH
    ${CYAN}help${NC}                             Afficher cette aide

${BOLD}EXEMPLES${NC}
    ${SCRIPT_NAME} list
    ${SCRIPT_NAME} search nginx
    ${SCRIPT_NAME} search 192.168.1
    ${SCRIPT_NAME} search lxc
    ${SCRIPT_NAME} add
    ${SCRIPT_NAME} add lxc-nginx-prod 10.0.0.50 2222 sysadmin "Debian 12" lxc
    ${SCRIPT_NAME} remove lxc-nginx-prod
    ${SCRIPT_NAME} export --format md
    ${SCRIPT_NAME} stats
    ${SCRIPT_NAME} check

${BOLD}CONFIGURATION${NC}
    INVENTORY_FILE    Chemin du CSV (défaut: /root/inventaire.csv)
    EXPORT_DIR        Dossier d'export (défaut: /root/exports)

EOF
    exit 0
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    local command="${1:-help}"
    shift || true

    case "${command}" in
        list|ls)        cmd_list "$@" ;;
        search|find|s)  cmd_search "$@" ;;
        add|a)          cmd_add "$@" ;;
        remove|rm|del)  cmd_remove "$@" ;;
        export|exp)     cmd_export "$@" ;;
        stats|st)       cmd_stats "$@" ;;
        check|chk)      cmd_check "$@" ;;
        help|--help|-h) show_help ;;
        *)              die "Commande inconnue : ${command}. Utilisez '${SCRIPT_NAME} help'." ;;
    esac
}

main "$@"