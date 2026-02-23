# 🔒 AdminSys — Scripts d'administration serveur

Boîte à outils d'administration système pour infrastructure **Proxmox VE**.

Scripts de hardening, monitoring et maintenance conçus pour être exécutés sur des conteneurs LXC et machines virtuelles fraîchement déployés via les [Proxmox Community Scripts](https://github.com/community-scripts/ProxmoxVE).

---

## 📋 Scripts disponibles

| Script | Description | Cible |
|--------|-------------|-------|
| `post-install-hardening.sh` | Hardening post-installation complet | LXC / VM (Debian, Ubuntu) |
| `inventory.sh` | Gestion centralisée de l'inventaire | Host Proxmox |

---

## 🚀 post-install-hardening.sh

Applique une baseline de sécurité uniforme sur chaque conteneur ou VM après déploiement. Le script détecte automatiquement l'environnement (LXC ou VM) et adapte son comportement.

### Ce qu'il fait concrètement

**Mise à jour système** — Met à jour tous les paquets et installe les outils essentiels manquants sur les LXC minimalistes (curl, htop, dnsutils, openssh-server, sudo...).

**Création d'un utilisateur admin** — Crée un utilisateur dédié avec sudo NOPASSWD, verrouille l'authentification par mot de passe et dépose ta clé publique SSH. L'accès se fait exclusivement par clé.

**Hardening SSH** — Génère un fichier `/etc/ssh/sshd_config.d/99-hardening.conf` qui interdit le login root, désactive l'authentification par mot de passe, limite les tentatives de connexion à 3, désactive le X11/TCP/agent forwarding, configure un timeout d'inactivité de 5 minutes, et restreint l'accès SSH à l'utilisateur admin uniquement. Gère automatiquement la désactivation de `ssh.socket` sur Ubuntu 24.04.

**Fail2ban** — Après 3 tentatives échouées en 10 minutes, l'IP est bannie 1 heure. Le réseau local est en whitelist.

**UFW** *(VMs uniquement)* — Firewall en mode "deny incoming / allow outgoing", seul le port SSH est ouvert. Ignoré sur les LXC où le firewall est géré par le host Proxmox.

**Mises à jour de sécurité automatiques** — Configure `unattended-upgrades` pour appliquer les patchs de sécurité quotidiennement, avec reboot automatique à 4h du matin si nécessaire.

**Hardening sysctl** *(VMs uniquement)* — Protection SYN flood, anti-spoofing (reverse path filtering), désactivation des redirections ICMP, ASLR complet, restriction ptrace et dmesg, buffers TCP optimisés. Ignoré sur les LXC qui partagent le kernel du host.

**Désactivation des services inutiles** — Désactive avahi-daemon (mDNS), cups (impression), bluetooth et ModemManager s'ils sont présents.

**Configuration journald** — Limite les logs à 200 Mo avec rétention d'un mois et compression. Évite que les logs remplissent le disque.

**Enregistrement dans l'inventaire** — Enregistre la machine dans le CSV centralisé sur le host Proxmox (via `--proxmox-host`) ou en local en fallback.

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

### Exemples

```bash
# Hardening complet avec clé SSH GitHub, port custom et inventaire centralisé
./post-install-hardening.sh -u sysadmin -k https://github.com/Tenta-dev.keys -p 2222 --proxmox-host 192.168.1.1

# Hardening minimal sans firewall ni fail2ban
./post-install-hardening.sh -u admin -k ~/.ssh/id_ed25519.pub --no-ufw --no-fail2ban

# Avec notification Telegram
export TELEGRAM_BOT_TOKEN="123456:ABC-DEF..."
export TELEGRAM_CHAT_ID="-100123456789"
./post-install-hardening.sh -u sysadmin -k https://github.com/Tenta-dev.keys -t

# Hardening + hostname personnalisé
./post-install-hardening.sh -u sysadmin \
  -k https://github.com/Tenta-dev.keys \
  -p 2222 \
  -h lxc-nginx-prod \
  --proxmox-host 192.168.1.1
```

### Comportement adaptatif LXC / VM

Le script détecte automatiquement l'environnement et adapte ses actions :

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

### Exemples

```bash
# Lister toutes les machines
inventory list

# Rechercher par nom, IP ou type
inventory search nginx
inventory search 192.168.1
inventory search lxc

# Ajouter une machine manuellement
inventory add lxc-nginx-prod 10.0.0.50 2222 sysadmin "Debian 12" lxc

# Ajout interactif (le script pose les questions)
inventory add

# Supprimer une entrée
inventory remove lxc-nginx-prod

# Exporter en Markdown (sauvegardé dans /root/exports/)
inventory export --format md

# Statistiques de l'infrastructure
inventory stats

# Vérifier que toutes les machines répondent en SSH
inventory check
```

### Configuration

| Variable | Description | Défaut |
|----------|-------------|--------|
| `INVENTORY_FILE` | Chemin du fichier CSV | `/root/inventaire.csv` |
| `EXPORT_DIR` | Dossier d'export | `/root/exports` |

---

## 🔄 Workflow recommandé

```
Community Script (Proxmox)          post-install-hardening.sh          inventory.sh
┌──────────────────────┐           ┌──────────────────────┐          ┌─────────────────┐
│  Crée le LXC / VM   │ ────────► │  Applique le         │ ───────► │  Machine visible │
│  Installe le service │           │  hardening système   │          │  dans inventory  │
│  (Docker, Nginx...)  │           │  de manière uniforme │          │  list / check    │
└──────────────────────┘           └──────────────────────┘          └─────────────────┘
```

1. **Créer** le conteneur/VM avec un community-script Proxmox
2. **Durcir** avec `post-install-hardening.sh` via curl
3. **Vérifier** avec `inventory list` et `inventory check` sur le host Proxmox

---

## ⚠️ Points d'attention

- **Toujours lancer `--dry-run` en premier** sur une nouvelle configuration
- **Garder la session SSH ouverte** après exécution et vérifier la connexion avec le nouvel utilisateur avant de fermer
- Si **Docker** tourne sur la machine, le sysctl désactive `ip_forward` par défaut — il faudra le réactiver (`net.ipv4.ip_forward = 1`) pour le réseau bridge Docker
- Les notifications **Telegram** nécessitent les variables d'environnement `TELEGRAM_BOT_TOKEN` et `TELEGRAM_CHAT_ID`
- Le script de hardening est **idempotent** : il peut être relancé sans casser l'existant (la clé SSH sera dupliquée dans authorized_keys, sans impact fonctionnel)

---

## 🧰 Prérequis

- **OS supportés** : Debian 12 (Bookworm), Ubuntu 22.04 / 24.04 LTS
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
└── scripts/                    # Futurs scripts
    └── ...
```

---

## 📄 Licence

MIT