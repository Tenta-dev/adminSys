# 🔒 AdminSys — Scripts d'administration serveur

Boîte à outils d'administration système pour infrastructure **Proxmox VE**.

Scripts de hardening, monitoring et maintenance conçus pour être exécutés sur des conteneurs LXC et machines virtuelles fraîchement déployés via les [Proxmox Community Scripts](https://github.com/community-scripts/ProxmoxVE).

---

## 📋 Scripts disponibles

| Script | Description | Cible |
|--------|-------------|-------|
| `post-install-hardening.sh` | Hardening post-installation complet | LXC / VM (Debian, Ubuntu) |

---

## 🚀 post-install-hardening.sh

Applique une baseline de sécurité uniforme sur chaque conteneur ou VM après déploiement.

### Ce qu'il fait

- **Mise à jour système** complète
- **Création d'un utilisateur admin** avec authentification par clé SSH uniquement
- **Hardening SSH** : root désactivé, password désactivé, tentatives limitées, timeout configuré
- **Fail2ban** sur le port SSH
- **UFW** (VMs uniquement — détection automatique LXC)
- **Unattended-upgrades** pour les patchs de sécurité automatiques
- **Hardening sysctl** (VMs uniquement) : anti-spoofing, SYN flood, ASLR, restriction ptrace/dmesg
- **Désactivation des services inutiles** (avahi, cups, bluetooth, ModemManager)
- **Configuration journald** (rotation 200M, rétention 1 mois)
- **Enregistrement** dans un fichier d'inventaire CSV
- **Notification Telegram** optionnelle

### Utilisation rapide

```bash
# 1. Toujours tester en dry-run d'abord
curl -fsSL https://raw.githubusercontent.com/Tenta-dev/adminSys/main/post-install-hardening.sh \
  | bash -s -- --dry-run -u sysadmin -k https://github.com/ton-user.keys -p 2222

# 2. Exécution réelle
curl -fsSL https://raw.githubusercontent.com/Tenta-dev/adminSys/main/post-install-hardening.sh \
  | bash -s -- -u sysadmin -k https://github.com/ton-user.keys -p 2222
```

### Options

| Option | Description | Défaut |
|--------|-------------|--------|
| `-u, --username <user>` | Nom de l'utilisateur admin à créer | `admin` |
| `-k, --ssh-key <path\|url>` | Clé publique SSH (fichier local ou URL GitHub) | — |
| `-p, --ssh-port <port>` | Port SSH personnalisé | `22` |
| `-h, --hostname <name>` | Nom d'hôte à configurer | — |
| `-i, --inventory <path>` | Chemin du fichier d'inventaire CSV | `/root/infrastructure-inventory.csv` |
| `-t, --telegram` | Activer la notification Telegram | désactivé |
| `--no-fail2ban` | Ne pas installer fail2ban | — |
| `--no-ufw` | Ne pas configurer UFW | — |
| `--no-unattended` | Ne pas configurer unattended-upgrades | — |
| `--dry-run` | Mode simulation (aucune modification) | — |
| `--help` | Afficher l'aide | — |

### Exemples

```bash
# Hardening complet avec clé SSH GitHub et port custom
./post-install-hardening.sh -u sysadmin -k https://github.com/Tenta-dev.keys -p 2222

# Hardening minimal sans firewall ni fail2ban
./post-install-hardening.sh -u admin -k ~/.ssh/id_ed25519.pub --no-ufw --no-fail2ban

# Avec notification Telegram
export TELEGRAM_BOT_TOKEN="123456:ABC-DEF..."
export TELEGRAM_CHAT_ID="-100123456789"
./post-install-hardening.sh -u sysadmin -k https://github.com/Tenta-dev.keys -t

# Hardening + hostname + inventaire custom
./post-install-hardening.sh -u sysadmin \
  -k https://github.com/Tenta-dev.keys \
  -p 2222 \
  -h lxc-nginx-prod \
  -i /root/inventaire.csv
```

### Comportement adaptatif

Le script détecte automatiquement l'environnement d'exécution et adapte ses actions :

| Fonctionnalité | VM (KVM/QEMU) | Conteneur LXC |
|----------------|:-:|:-:|
| Mise à jour système | ✅ | ✅ |
| Création utilisateur admin | ✅ | ✅ |
| Hardening SSH | ✅ | ✅ |
| Fail2ban | ✅ | ✅ |
| UFW | ✅ | ⏭️ Ignoré (géré par le host) |
| Hardening sysctl | ✅ | ⏭️ Ignoré (géré par le host) |
| Unattended-upgrades | ✅ | ✅ |
| Désactivation services | ✅ | ✅ |

### Workflow recommandé

```
Community Script (Proxmox)     Ce script
┌──────────────────────┐      ┌──────────────────────┐
│  Crée le LXC / VM   │ ───► │  Applique le         │
│  Installe le service │      │  hardening système   │
│  (Docker, Nginx...)  │      │  de manière uniforme │
└──────────────────────┘      └──────────────────────┘
```

---

## ⚠️ Points d'attention

- **Toujours lancer `--dry-run` en premier** sur une nouvelle configuration
- **Garder la session SSH ouverte** après exécution et vérifier la connexion avec le nouvel utilisateur **avant** de fermer
- Si Docker tourne sur la machine, vérifier que `ip_forward` est bien activé (le sysctl le désactive par défaut — ne s'applique qu'aux VMs)
- Les notifications Telegram nécessitent les variables d'environnement `TELEGRAM_BOT_TOKEN` et `TELEGRAM_CHAT_ID`

---

## 📂 Structure du repo

```
adminSys/
├── README.md
├── post-install-hardening.sh
└── scripts/                    # Futurs scripts
    └── ...
```

---

## 🧰 Prérequis

- **OS supportés** : Debian 12 (Bookworm), Ubuntu 22.04 / 24.04 LTS
- **Accès** : root (ou sudo)
- **Réseau** : accès internet pour l'installation des paquets

---

## 📝 Inventaire

Le script enregistre chaque machine durcie dans un fichier CSV :

```csv
hostname,ip,ssh_port,admin_user,os,type,date_hardening
lxc-nginx-prod,10.0.0.50,2222,sysadmin,Debian GNU/Linux 12 (bookworm),lxc,2025-06-15 14:30:00
vm-postgres-prod,10.0.0.60,2222,sysadmin,Ubuntu 24.04 LTS,kvm,2025-06-15 15:00:00
```

---

## 📄 Licence

MIT