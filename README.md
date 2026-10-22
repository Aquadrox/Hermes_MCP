# hermes-ngrok-mcp

Serveur [MCP](https://modelcontextprotocol.io) qui permet à l'agent
[Hermes](https://hermes-agent.nousresearch.com) d'ouvrir **à la demande**, depuis Telegram et en
langage naturel, un tunnel [ngrok](https://ngrok.com) temporaire vers un port local d'un VPS
non exposé à Internet. Chaque ouverture est protégée par un **code TOTP** généré par
**Proton Authenticator** (ou toute application compatible).

```
Toi (Telegram) ──► Hermes ──► hermes-ngrok-mcp ──► ngrok ──► https://xxx.ngrok-free.app
   « ouvre-moi un tunnel     (service dédié,            ▲
     sur le port 8080 »       127.0.0.1:8765)           │
   « 482 913 »  (code MFA)                              │ relais local qui mesure l'usage
                                                        ▼
                                              ton service sur 127.0.0.1:8080
```

## Fonctionnalités

- **Ouverture en langage naturel** : « ouvre-moi un tunnel sur le port 3000 », « j'ai besoin
  d'un accès SSH », « le tunnel sert encore ? », « prolonge-le », « ferme tout ».
- **MFA TOTP obligatoire** pour ouvrir et pour prolonger : 6 chiffres, 30 s, SHA-1, compatible
  Proton Authenticator. Un code ne sert qu'une fois (anti-rejeu). Après 5 codes faux, la
  vérification est verrouillée 15 min, puis le double à chaque récidive, et tu reçois une alerte.
- **Configuration du MFA par Hermes lui-même** : le QR code et la clé te sont envoyés
  directement sur Telegram par le serveur, sans passer par le modèle de langage. Le message est
  protégé contre le transfert, puis supprimé une fois l'enrôlement validé.
- **Vérification de bout en bout** : à l'ouverture, le serveur appelle sa propre URL publique
  et contrôle que la requête revient bien jusqu'au VPS.
- **Mesure de l'usage réel** : connexions, octets échangés, dernière activité.
- **Fermeture automatique** (tous les délais sont paramétrables) :
  - après **10 min sans activité** ;
  - au plus tard après **20 min**, avec une **alerte Telegram à 15 min** ; tu peux alors
    prolonger avec un nouveau code MFA.
- **Accès HTTP protégé** : un identifiant et un mot de passe aléatoires sont générés pour chaque
  tunnel (basic auth appliquée par ngrok) et envoyés uniquement sur Telegram. Ils sont
  désactivables au cas par cas.
- **HTTP et TCP** (SSH, bases de données…).
- **Isolation** : service systemd durci, exécuté sous un utilisateur Unix dédié. Hermes ne peut
  lire ni le secret MFA ni le token ngrok.

## Sommaire

1. [Prérequis](#prérequis)
2. [Installation](#installation)
3. [Configurer le MFA avec Proton Authenticator](#configurer-le-mfa-avec-proton-authenticator)
4. [Utilisation au quotidien](#utilisation-au-quotidien)
5. [Configuration](#configuration)
6. [Outils MCP exposés](#outils-mcp-exposés)
7. [Administration](#administration)
8. [Dépannage](#dépannage)
9. [Sécurité](#sécurité)
10. [Développement](#développement)

## Prérequis

- Un VPS Linux avec **systemd** (Debian 12+, Ubuntu 22.04+…) et un accès root (une seule fois,
  pour l'installation).
- **Python ≥ 3.12**, ou [`uv`](https://docs.astral.sh/uv/) installé pour root, qui fournit
  Python si besoin :
  `curl -LsSf https://astral.sh/uv/install.sh | sudo env UV_INSTALL_DIR=/usr/local/bin sh`
- Un compte [ngrok](https://dashboard.ngrok.com) et son
  [authtoken](https://dashboard.ngrok.com/get-started/your-authtoken). Le plan gratuit
  suffit pour HTTP ; les tunnels **TCP** exigent une carte bancaire enregistrée sur le compte
  ngrok (elle n'est pas débitée).
- Hermes configuré avec **Telegram** (`TELEGRAM_BOT_TOKEN`, `TELEGRAM_ALLOWED_USERS`).
- Proton Authenticator sur ton téléphone.

Aucun binaire ngrok n'est nécessaire : le SDK officiel est embarqué.

## Installation

> Tu peux confier le dépôt à Hermes : `AGENTS.md` lui explique la procédure. Il te donnera les
> deux commandes root ci-dessous, à exécuter en SSH.

**1. Installer le service (root)**, depuis un clone appartenant à root : root ne doit jamais
exécuter du code qu'Hermes aurait pu modifier.

```bash
sudo git clone https://github.com/Aquadrox/Hermes_MCP.git /usr/local/src/hermes-ngrok-mcp
sudo /usr/local/src/hermes-ngrok-mcp/deploy/install.sh --hermes-user <utilisateur-unix-de-hermes>
```

Si le dépôt est privé, clone-le avec un jeton d'accès GitHub, ou copie-le dans
`/usr/local/src/hermes-ngrok-mcp` avec `sudo cp -r`.

L'installeur est idempotent. Il :

- crée l'utilisateur système `hermes-ngrok` ;
- installe l'application dans `/opt/hermes-ngrok-mcp`, avec les versions exactes du lockfile ;
- crée `/etc/hermes-ngrok-mcp/hermes-ngrok-mcp.env` (root:hermes-ngrok, 0640) et génère le
  jeton d'API partagé avec Hermes ;
- écrit `HERMES_NGROK_MCP_TOKEN` dans `~/.hermes/.env` de l'utilisateur Hermes, et reprend
  `TELEGRAM_BOT_TOKEN` et ton identifiant Telegram depuis ce même fichier ;
- installe et démarre l'unité systemd, puis vérifie qu'elle répond.

**2. Renseigner l'authtoken ngrok**

```bash
sudo nano /etc/hermes-ngrok-mcp/hermes-ngrok-mcp.env     # NGROK_AUTHTOKEN=...
sudo systemctl restart hermes-ngrok-mcp
sudo hermes-ngrok-admin check                            # doit finir sans « ERROR »
sudo hermes-ngrok-admin notify-test                      # message de test sur Telegram
```

**3. Déclarer le serveur dans Hermes** (`~/.hermes/config.yaml`, sous la clé `mcp_servers:`
existante le cas échéant). Hermes sait le faire lui-même.

```yaml
mcp_servers:
  ngrok:
    url: "http://127.0.0.1:8765/mcp"
    headers:
      Authorization: "Bearer ${HERMES_NGROK_MCP_TOKEN}"
    timeout: 120
    connect_timeout: 30
    sampling:
      enabled: false
```

**4. Installer le skill** qui apprend à Hermes à utiliser les outils, puis redémarrer :

```bash
mkdir -p ~/.hermes/skills/devops
cp -r /usr/local/src/hermes-ngrok-mcp/skills/ngrok-tunnels ~/.hermes/skills/devops/
hermes gateway restart
```

**Mise à jour** : `sudo git -C /usr/local/src/hermes-ngrok-mcp pull`, puis relance
`install.sh`. La configuration et le secret MFA sont conservés ; les tunnels ouverts sont
fermés au redémarrage.

**Désinstallation** : `sudo /usr/local/src/hermes-ngrok-mcp/deploy/uninstall.sh`, avec
`--purge` pour supprimer aussi la configuration, le secret MFA et l'utilisateur.

## Configurer le MFA avec Proton Authenticator

Sur Telegram, écris à Hermes : **« configure le MFA pour les tunnels »**.

1. Le bot t'envoie un QR code et une clé (message protégé, valable 10 min).
2. Dans Proton Authenticator : **+**, puis :
   - **saisie manuelle** si tu lis Telegram sur ce même téléphone : appuie sur la clé dans
     Telegram pour la copier, puis colle-la. Émetteur `Hermes ngrok`, type TOTP, SHA-1,
     6 chiffres, 30 s (valeurs par défaut) ;
   - ou **scan du QR code** si Telegram est ouvert sur un autre écran.
3. Envoie à Hermes le code à 6 chiffres affiché. Le MFA est actif ; le message contenant la
   clé est supprimé.

**Changer de téléphone** : demande à Hermes de « changer d'authentificateur ». Il te demandera
un code de l'**ancien** appareil, puis la procédure ci-dessus recommence.

**Téléphone perdu** : seul l'administrateur peut réinitialiser, en SSH :
`sudo hermes-ngrok-admin mfa reset`, puis reconfigure via Hermes. Tu peux aussi tout faire
depuis le terminal, sans passer par Telegram : `sudo hermes-ngrok-admin mfa setup` affiche le
QR code dans la console.

## Utilisation au quotidien

| Tu écris à Hermes | Ce qui se passe |
|---|---|
| « Ouvre-moi un tunnel sur le port 8080 » | Hermes te demande ton code MFA, ouvre le tunnel HTTP, le vérifie, puis le bot t'envoie l'URL, l'identifiant et le mot de passe. |
| « J'ai besoin d'un accès SSH » | Tunnel TCP vers le port 22 ; le bot t'envoie l'hôte, le port et la commande `ssh -p …`. |
| « Expose le port 3000 sans mot de passe » | Tunnel HTTP sans basic auth (si la politique l'autorise). |
| « Le tunnel est utilisé ? » | Connexions, octets, dernière activité, temps restant avant fermeture. |
| *(alerte à 15 min)* « Prolonge le tunnel » | Hermes demande un nouveau code et ajoute 20 min. |
| « Ferme le tunnel » / « ferme tout » | Fermeture immédiate, sans code. |

Les notifications automatiques (accès, alerte avant expiration, fermeture pour inactivité ou
expiration, alerte de sécurité) arrivent dans la même conversation Telegram, envoyées par le bot.

Bon à savoir :

- Est considéré comme « utilisé » un tunnel qui transporte des données. Pour un tunnel TCP, une
  connexion ouverte (une session SSH par exemple) compte aussi.
- Sur le plan gratuit, ngrok affiche une page d'avertissement au premier accès depuis un
  navigateur : clique sur « Visit Site ».
- Le plan gratuit n'a qu'un domaine : un seul tunnel HTTP à la fois.

## Configuration

Fichier : `/etc/hermes-ngrok-mcp/hermes-ngrok-mcp.env`. Après modification :
`sudo systemctl restart hermes-ngrok-mcp`. Les durées s'écrivent en secondes ou sous la forme
`45s`, `10m`, `1h30m`. Le modèle complet et commenté est dans
[`deploy/hermes-ngrok-mcp.env.example`](deploy/hermes-ngrok-mcp.env.example).

| Variable | Défaut | Rôle |
|---|---|---|
| `NGROK_AUTHTOKEN` | — | Authtoken ngrok (**obligatoire**). |
| `HERMES_NGROK_DOMAIN` | — | Domaine ngrok réservé pour les tunnels HTTP. |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | — | Notifications et remise directe des secrets (recommandé). |
| `HERMES_NGROK_IDLE_TIMEOUT` | `10m` | Fermeture sans activité (`0` = jamais). |
| `HERMES_NGROK_MAX_LIFETIME` | `20m` | Durée de vie maximale (`0` = illimitée). |
| `HERMES_NGROK_EXPIRY_WARNING` | `5m` | Délai de l'alerte avant expiration. |
| `HERMES_NGROK_EXTENSION` | `20m` | Durée ajoutée par prolongation. |
| `HERMES_NGROK_MAX_TUNNELS` | `3` | Tunnels simultanés. |
| `HERMES_NGROK_ALLOWED_PORTS` / `HERMES_NGROK_DENIED_PORTS` | `1-65535` / — | Ports exposables, ex. `80,8000-8999`. |
| `HERMES_NGROK_TARGET_HOST` | `127.0.0.1` | Hôte vers lequel les tunnels redirigent. |
| `HERMES_NGROK_BASIC_AUTH` | `true` | Mot de passe généré pour les tunnels HTTP. |
| `HERMES_NGROK_ALLOW_UNPROTECTED_HTTP` | `true` | Autoriser « sans mot de passe » sur demande. |
| `HERMES_NGROK_SHARE_CREDENTIALS_WITH_AGENT` | `false` | Donner aussi le mot de passe à Hermes. |
| `HERMES_NGROK_VERIFY_TUNNELS` | `true` | Vérification de bout en bout à l'ouverture. |
| `HERMES_NGROK_MFA_MAX_FAILURES` / `_FAILURE_WINDOW` / `_LOCKOUT` | `5` / `5m` / `15m` | Verrouillage (doublé à chaque récidive, 24 h max). |
| `HERMES_NGROK_MFA_ALLOW_INLINE_ENROLLMENT` | `true` | Sans Telegram, autoriser l'envoi du QR via Hermes. |
| `HERMES_NGROK_HOST` / `HERMES_NGROK_PORT` | `127.0.0.1` / `8765` | Écoute du serveur MCP. |
| `HERMES_NGROK_API_TOKEN` | généré | Jeton Bearer attendu de Hermes. |
| `HERMES_NGROK_LANGUAGE` / `HERMES_NGROK_TIMEZONE` | `fr` / `UTC` | Langue et fuseau des notifications. |

## Outils MCP exposés

Dans Hermes, ils apparaissent sous le nom `mcp_ngrok_<outil>`.

| Outil | Rôle | Code MFA |
|---|---|---|
| `mfa_status` | État du MFA (configuré, verrouillé, enrôlement en cours). | non |
| `mfa_setup_start` | Démarre l'enrôlement ; QR code envoyé sur Telegram. | seulement pour remplacer un appareil |
| `mfa_setup_confirm` | Valide l'enrôlement. | oui (nouvel appareil) |
| `tunnel_open` | Ouvre, vérifie et décrit un tunnel (`port`, `protocol` http/tcp, `protect`, `label`). | **oui** |
| `tunnel_status` | Tunnels ouverts, usage, délais ; `verify=true` les reteste depuis Internet. | non |
| `tunnel_extend` | Prolonge un tunnel et remet à zéro son minuteur d'inactivité. | **oui** |
| `tunnel_close` | Ferme un tunnel ou tous. | non |

## Administration

```bash
sudo hermes-ngrok-admin check          # validation de la configuration
sudo hermes-ngrok-admin mfa status     # état du MFA
sudo hermes-ngrok-admin mfa setup      # enrôlement depuis le terminal
sudo hermes-ngrok-admin mfa reset      # réinitialisation (téléphone perdu)
sudo hermes-ngrok-admin notify-test    # test Telegram
journalctl -u hermes-ngrok-mcp -f      # journaux (ouvertures, fermetures, échecs MFA)
systemd-analyze security hermes-ngrok-mcp
```

## Dépannage

| Symptôme | Cause probable / solution |
|---|---|
| Les outils n'apparaissent pas dans Hermes | Indentation YAML, `HERMES_NGROK_MCP_TOKEN` absent de `~/.hermes/.env`, gateway non redémarrée (`hermes gateway restart`). |
| `401 unauthorized` | Jeton différent entre `~/.hermes/.env` et `HERMES_NGROK_API_TOKEN` : relance `install.sh --hermes-user …`. |
| « Invalid MFA code » alors que le code est bon | Horloge du VPS décalée : `timedatectl` doit indiquer `System clock synchronized: yes`. |
| « This MFA code was already used » | Chaque code ne sert qu'une fois : attends le suivant (30 s). |
| « Nothing is listening on 127.0.0.1:… » | Le service à exposer n'est pas démarré, ou écoute sur une autre adresse (`ss -ltnp`). |
| `ERR_NGROK_105` / `107` | Authtoken ngrok invalide. |
| `ERR_NGROK_108` | Un autre agent ngrok tourne déjà avec ce compte (une seule session sur le plan gratuit). |
| `ERR_NGROK_334` | Le domaine est déjà utilisé par un autre tunnel : ferme-le d'abord. |
| `ERR_NGROK_8013` | Les tunnels TCP exigent une carte bancaire sur le compte ngrok. |
| « could not be verified » | Le VPS n'arrive pas à joindre sa propre URL publique (pare-feu sortant ?). En dernier recours : `HERMES_NGROK_VERIFY_TUNNELS=false`. |
| Pas de notification Telegram | `sudo hermes-ngrok-admin notify-test`, puis vérifie `TELEGRAM_CHAT_ID` (ton identifiant numérique). |
| Hermes passe par un proxy HTTP | Ajoute `127.0.0.1` à `NO_PROXY` dans l'environnement de Hermes. |

## Sécurité

Le résumé ci-dessous est détaillé dans [SECURITY.md](SECURITY.md).

- Hermes s'authentifie auprès du serveur avec un jeton Bearer. Ouvrir ou prolonger un tunnel
  exige en plus un code TOTP que seul ton téléphone produit. Un agent manipulé (prompt
  injection) ne peut donc rien exposer sans toi.
- Le secret TOTP et le token ngrok appartiennent à l'utilisateur `hermes-ngrok`. Hermes ne
  peut pas les lire, même avec son accès shell.
- Quand Telegram est configuré, les secrets (clé MFA, mots de passe des tunnels) te sont remis
  directement, jamais à l'agent. Si l'envoi échoue, l'opération est annulée plutôt que de
  retomber sur l'agent.
- Les tunnels sont courts, vérifiés, mesurés et fermés automatiquement ; le port du serveur MCP
  ne peut jamais être exposé.
- Le service tourne dans un bac à sable systemd : pas de privilèges, système de fichiers en
  lecture seule, appels système filtrés.

## Développement

```bash
uv sync                 # dépendances (versions figées par uv.lock)
make check              # ruff + mypy --strict + pytest
make lock               # après un changement de dépendances (uv.lock + deploy/requirements.lock)
uv run hermes-ngrok-mcp --env-file dev.env serve --transport stdio   # test local avec un client MCP
```

Architecture (`src/hermes_ngrok_mcp/`) :

| Module | Rôle |
|---|---|
| `server.py` | Outils MCP et leurs descriptions pour l'agent. |
| `asgi.py` | Transport HTTP « streamable », authentification Bearer, `/healthz`. |
| `mfa.py` | TOTP : enrôlement, vérification, anti-rejeu, verrouillage. |
| `storage.py` | État JSON verrouillé (`flock`) et écrit de façon atomique (0600). |
| `tunnels/manager.py` | Cycle de vie : contrôles, ouverture, inactivité, expiration, prolongation. |
| `tunnels/proxy.py` | Relais TCP local qui mesure l'usage réel. |
| `tunnels/probe.py` | Vérification de bout en bout via l'URL publique. |
| `tunnels/backends.py` | SDK ngrok (session partagée, Traffic Policy basic-auth). |
| `notify.py`, `messages.py` | Notifications Telegram (FR/EN). |
| `config.py`, `cli.py` | Configuration et ligne de commande. |

Les tests (`tests/`) n'ont besoin ni de compte ngrok ni de Telegram : un faux « edge » ngrok
local, une horloge simulée et un notificateur factice couvrent tout le cycle de vie.

## Licence

[MIT](LICENSE).
