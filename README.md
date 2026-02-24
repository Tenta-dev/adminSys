# 🔒 AdminSys — Scripts d'administration serveur

Boîte à outils d'administration système pour infrastructure **Proxmox VE** (Dell PowerEdge T430).

Scripts de hardening, audit et maintenance conçus pour être exécutés sur des conteneurs LXC et machines virtuelles fraîchement déployés via les [Proxmox Community Scripts](https://github.com/community-scripts/ProxmoxVE).

---

## 📋 Scripts disponibles

| Script | Description | Cible |
|--------|-------------|-------|
| `post-install-hardening.sh` | Hardening post-installation complet | LXC / VM (Debian, Ubuntu) |
| `inventory.sh` | Gestion centralisée de l'inventaire | Host Proxmox |
| `security-audit.sh` | Audit de sécurité périodique | LXC / VM / Host Proxmox |

---

## 🚀 post-install-hardening.sh

Applique une baseline de sécurité uniforme sur chaque conteneur ou VM après déploiement. Le script détecte automatiquement l'environnement (LXC ou VM) et adapte son comportement.

### Ce qu'il fait concrètement

**Mise à jour système** — Met à jour tous les paquets et installe les outils essentiels manquants sur les LXC minimalistes (curl, htop, dnsutils, openssh-server, sudo...).

**Création d'un utilisateur admin** — Crée un utilisateur dédié avec sudo NOPASSWD, verrouille l'authentification par mot de passe et dépose ta clé publique SSH. L'accès se fait exclusivement par clé. Les clés sont dédoublonnées si le script est relancé.

**Hardening SSH** — Génère un fichier `/etc/ssh/sshd_config.d/99-hardening.conf` qui interdit le login root, désactive l'authentification par mot de passe, limite les sessions à 2 et les tentatives à 3, désactive X11/TCP/agent forwarding et TCPKeepAlive, configure un timeout d'inactivité de 5 minutes, et restreint l'accès SSH à l'utilisateur admin uniquement. Gère automatiquement la désactivation de `ssh.socket` sur Ubuntu 24.04.

**Fail2ban** — Après 3 tentatives échouées en 10 minutes, l'IP est bannie 1 heure. Le réseau local est en whitelist.

**UFW** *(VMs uniquement)* — Firewall en mode "deny incoming / allow outgoing", seul le port SSH est ouvert. Ignoré sur les LXC où le firewall est géré par le host Proxmox.

**Mises à jour de sécurité automatiques** — Configure `unattended-upgrades` pour appliquer les patchs de sécurité quotidiennement, avec reboot automatique à 4h du matin si nécessaire.

**Hardening sysctl** *(VMs uniquement)* — Protection SYN flood, anti-spoofing (reverse path filtering), désactivation des redirections ICMP, ASLR complet, restriction ptrace et dmesg, buffers TCP optimisés. Ignoré sur les LXC qui partagent le kernel du host.

**Désactivation des services inutiles** — Désactive avahi-daemon (mDNS), cups (impression), bluetooth et ModemManager s'ils sont présents.

**Configuration journald** — Limite les logs à 200 Mo avec rétention d'un mois et compression. Évite que les logs remplissent le disque.

**Hardening avancé (Lynis)** — Module d'amélioration du score Lynis :
- Installation de paquets de sécurité : `libpam-tmpdir`, `needrestart`, `debsums`, `apt-show-versions`, `rkhunter`, `sysstat`, `acct`
- Bannière légale dans `/etc/issue` et `/etc/issue.net`
- Politique de mots de passe renforcée (`login.defs` : UMASK 027, PASS_MIN_DAYS, PASS_MAX_DAYS, SHA_ROUNDS 5000)
- Désactivation des protocoles réseau inutiles (dccp, sctp, rds, tipc) et du stockage USB/FireWire via `modprobe.d`
- Permissions restrictives sur les fichiers sensibles (`/etc/crontab`, `/etc/ssh/sshd_config`, `/etc/shadow`)
- Restriction de l'accès aux compilateurs (gcc, g++, cc) à root uniquement

**Enregistrement dans l'inventaire** — Enregistre la machine dans le CSV centralisé sur le host Proxmox (via `--proxmox-host`) ou en local en fallback. Les entrées sont mises à jour si le script est relancé (pas de doublons).

**Notification Telegram** *(optionnel)* — Envoie un résumé du hardening avec hostname, IP, utilisateur et port SSH.

### Installation rapide

```bash
# 1. Toujours tester en dry-run d'abord
curl -fsSL https://raw.githubusercontent.com/Tenta-dev/adminSys/main/post-install-hardening.sh \
  | bash -s -- --dry-run -u sysadmin -k https://github.com/Tenta-dev.keys -p 2222

# 2. Exécution réelle
curl -fsSL https://raw.githubusercontent.com/Tenta-dev/adminSys/main/post-install-hardening.sh \
  | bash -s -- -u sysadmin -k https://github.com/Tenta-dev.keys -p 2222

# 3. Avec inventaire centralisé sur le host Proxmox
curl -fsSL https://raw.githubusercontent.com/Tenta-dev/adminSys/main/post-install-hardening.sh \
  | bash -s -- -u sysadmin -k https://github.com/Tenta-dev.keys -p 2222 --proxmox-host 192.168.1.1
```

> **Note** : Le paramètre `-k` accepte une URL GitHub qui expose tes clés SSH publiques (`https://github.com/<username>.keys`), un fichier local (`~/.ssh/id_ed25519.pub`) ou n'importe quelle URL retournant une clé publique.

### Options

| Option | Description | Défaut |
|--------|-------------|--------|
| `-u, --username <user>` | Utilisateur admin à créer | `admin` |
| `-k, --ssh-key <path\|url>` | Clé publique SSH (fichier local ou URL GitHub) | — |
| `-p, --ssh-port <port>` | Port SSH personnalisé | `22` |
| `-h, --hostname <n>` | Nom d'hôte à configurer | — |
| `-i, --inventory <path>` | Chemin du fichier d'inventaire CSV (mode local) | `/root/infrastructure-inventory.csv` |
| `--proxmox-host <IP\|host>` | IP du host Proxmox pour inventaire centralisé | — |
| `-t, --telegram` | Activer la notification Telegram | désactivé |
| `--no-fail2ban` | Ne pas installer fail2ban | — |
| `--no-ufw` | Ne pas configurer UFW | — |
| `--no-unattended` | Ne pas configurer unattended-upgrades | — |
| `--dry-run` | Mode simulation (aucune modification) | — |
| `--help` | Afficher l'aide | — |

### Comportement adaptatif LXC / VM

| Fonctionnalité | VM (KVM/QEMU) | Conteneur LXC |
|----------------|:---:|:---:|
| Mise à jour système | ✅ | ✅ |
| Paquets essentiels | ✅ | ✅ |
| Création utilisateur admin | ✅ | ✅ |
| Hardening SSH | ✅ | ✅ |
| Désactivation ssh.socket (Ubuntu 24.04) | ✅ | ✅ |
| Fail2ban | ✅ | ✅ |
| UFW | ✅ | ⏭️ Ignoré (géré par le host) |
| Unattended-upgrades | ✅ | ✅ |
| Hardening sysctl | ✅ | ⏭️ Ignoré (géré par le host) |
| Hardening avancé (Lynis) | ✅ | ✅ |
| Désactivation services inutiles | ✅ | ✅ |
| Configuration journald | ✅ | ✅ |

---

## 📦 inventory.sh

Script de gestion d'inventaire centralisé à installer sur le host Proxmox. Permet de lister, rechercher, ajouter, supprimer et exporter les machines durcies.

### Installation

```bash
curl -fsSLo /usr/local/bin/inventory \
  https://raw.githubusercontent.com/Tenta-dev/adminSys/main/inventory.sh
chmod +x /usr/local/bin/inventory
```

### Commandes

| Commande | Description |
|----------|-------------|
| `inventory list` | Tableau coloré de toutes les machines |
| `inventory search <terme>` | Recherche par hostname, IP, OS, type, sous-réseau... |
| `inventory add` | Ajout interactif d'une machine |
| `inventory add <host> <ip> <port> <user> <os> <type>` | Ajout en une ligne |
| `inventory remove <hostname\|IP>` | Suppression avec confirmation |
| `inventory export --format md` | Export Markdown |
| `inventory export --format csv` | Export CSV |
| `inventory stats` | Statistiques (répartition LXC/VM, OS, ports SSH) |
| `inventory check` | Vérification de la connectivité SSH sur toutes les machines |
| `inventory help` | Aide |

### Configuration

| Variable | Description | Défaut |
|----------|-------------|--------|
| `INVENTORY_FILE` | Chemin du fichier CSV | `/root/inventaire.csv` |
| `EXPORT_DIR` | Dossier d'export | `/root/exports` |

---

## 🔍 security-audit.sh

Script d'audit de sécurité pour conteneurs LXC et VMs. Peut être lancé localement sur une machine ou depuis le host Proxmox sur tout l'inventaire.

### Installation

```bash
curl -fsSLo /usr/local/bin/security-audit \
  https://raw.githubusercontent.com/Tenta-dev/adminSys/main/security-audit.sh
chmod +x /usr/local/bin/security-audit
```

### Usage

```bash
# Audit local sur une machine
security-audit

# Depuis le host Proxmox : audit de tout l'inventaire
security-audit --all

# Avec notification Telegram et export
security-audit --telegram --export /root/reports/

# En cron quotidien (7h du matin)
echo "0 7 * * * root /usr/local/bin/security-audit --telegram --export /root/reports/" \
  > /etc/cron.d/security-audit
```

### Ce qu'il vérifie

| Module | Vérifications |
|--------|---------------|
| **Mises à jour** | Patchs de sécurité en attente, unattended-upgrades actif, date dernière MAJ |
| **SSH** | Port custom, root désactivé, password désactivé, MaxAuthTries, AllowUsers |
| **Fail2ban** | Service actif, jail SSH, IP bannies |
| **Ports ouverts** | Listing complet avec classification (SSH, Web, BDD...), déduplication IPv4/IPv6 |
| **Utilisateurs** | UID 0 multiples, fichiers SUID suspects, fichiers world-writable dans /etc |
| **Disque** | Usage par partition + inodes (seuils 80%/90%) |
| **Services** | Services systemd en échec |
| **Docker** | Conteneurs en restart loop, images orphelines, volumes dangling, mode privileged |
| **Certificats TLS** | Expiration Let's Encrypt et certificats custom |
| **Tâches planifiées** | Crontabs, timers systemd |
| **Lynis** | Score global, warnings, suggestions |

### Options

| Option | Description |
|--------|-------------|
| `--all` | Auditer toutes les machines de l'inventaire (depuis le host Proxmox) |
| `--telegram` | Envoyer le rapport par Telegram |
| `--export <dir>` | Exporter le rapport en Markdown |
| `--summary-only` | Afficher uniquement le résumé (pour mode --all) |
| `--inventory <path>` | Chemin du fichier inventaire |
| `--help` | Aide |

### Codes de sortie

Le code de sortie permet l'intégration dans du monitoring : `0` = OK, `1` = warnings, `2` = critiques.

---

## 🔄 Workflow recommandé

```
Community Script (Proxmox)          post-install-hardening.sh          security-audit.sh
┌──────────────────────┐           ┌──────────────────────┐          ┌─────────────────┐
│  Crée le LXC / VM   │ ────────► │  Hardening complet   │ ───────► │  Audit continu   │
│  Installe le service │           │  + Lynis avancé      │          │  via cron        │
│  (Docker, Nginx...)  │           │  + inventaire auto   │          │  ou --all        │
└──────────────────────┘           └──────────────────────┘          └─────────────────┘
```

1. **Créer** le conteneur/VM avec un community-script Proxmox
2. **Durcir** avec `post-install-hardening.sh` via curl
3. **Vérifier** avec `inventory list` et `inventory check` sur le host Proxmox
4. **Auditer** régulièrement avec `security-audit` (local ou `--all`)

---

## 🔧 Mise à jour des scripts

Sur le host Proxmox, un helper permet de tout mettre à jour d'un coup :

```bash
# Ajouter à ~/.bashrc (une seule fois)
cat >> ~/.bashrc << 'EOF'
update-scripts() {
    echo "Mise à jour des scripts adminSys..."
    curl -fsSLo /usr/local/bin/security-audit "https://raw.githubusercontent.com/Tenta-dev/adminSys/main/security-audit.sh?$(date +%s)"
    curl -fsSLo /usr/local/bin/inventory "https://raw.githubusercontent.com/Tenta-dev/adminSys/main/inventory.sh?$(date +%s)"
    chmod +x /usr/local/bin/security-audit /usr/local/bin/inventory
    echo "OK"
}
EOF
source ~/.bashrc

# Utilisation
update-scripts
```

---

## ⚠️ Points d'attention

- **Toujours lancer `--dry-run` en premier** sur une nouvelle configuration
- **Garder la session SSH ouverte** après exécution et vérifier la connexion avec le nouvel utilisateur avant de fermer
- Si **Docker** tourne sur la machine, le sysctl désactive `ip_forward` par défaut — il faudra le réactiver (`net.ipv4.ip_forward = 1`) pour le réseau bridge Docker
- Les notifications **Telegram** nécessitent les variables d'environnement `TELEGRAM_BOT_TOKEN` et `TELEGRAM_CHAT_ID`
- Le script de hardening est **idempotent** : il peut être relancé sans casser l'existant (clés SSH dédoublonnées, inventaire mis à jour sans doublons)
- Le `--proxmox-host` nécessite que la clé SSH root du conteneur soit autorisée sur le host Proxmox (sinon un mot de passe sera demandé)

---

## 🧰 Prérequis

- **OS supportés** : Debian 12 (Bookworm), Debian 13 (Trixie), Ubuntu 22.04 / 24.04 LTS
- **Accès** : root
- **Réseau** : accès internet pour l'installation des paquets
- **inventory.sh** : `nc` (netcat) recommandé pour la commande `check`, fallback sur `/dev/tcp` sinon

---

## 📂 Structure du repo

```
adminSys/
├── README.md
├── post-install-hardening.sh
├── inventory.sh
├── security-audit.sh
└── scripts/                    # Futurs scripts
    └── ...
```

---

## 📄 Licence

MIT