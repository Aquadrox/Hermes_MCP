# Changelog

Format : [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/), versions :
[SemVer](https://semver.org/lang/fr/).

## [1.1.1] - 2026-10-25

### Corrigé

- `nas_open` échouait sur le plan ngrok gratuit (`ERR_NGROK_2263` : `add-headers` est une action
  payante). Le NAS vérifie désormais lui-même l'identifiant et le mot de passe du tunnel, que le
  serveur MCP lui remet à l'ouverture et révoque à la fermeture : aucune Traffic Policy n'est
  envoyée à ngrok pour le NAS.
- PROXY protocol désactivé par défaut (`ERR_NGROK_9014` sur le plan gratuit) ; messages d'aide
  pour les erreurs ngrok 9014 et 2263.

### Ajouté

- Anti brute-force sur le NAS (20 échecs en 5 min → 15 min de blocage) et audit des mots de
  passe faux (`nas.auth_failed`, `nas.auth_locked`), avec l'IP du client.

## [1.1.0] - 2026-10-25

### Ajouté

- **Gestionnaire de fichiers NAS** : service `hermes-nas` séparé (utilisateur dédié, activation
  par socket systemd sur 127.0.0.1, aucun accès réseau, écriture limitée au dossier partagé,
  arrêt sur inactivité) avec une interface web sans dépendance externe : navigation, envoi
  (progression, file d'attente, dossiers entiers par glisser-déposer), téléchargement avec
  reprise (`Range`), création de dossiers, aperçus image/vidéo/audio/texte, mobile, thème sombre,
  raccourcis clavier. Aucun écrasement ni suppression ; liens symboliques jamais suivis.
- Outils MCP `nas_status` et `nas_open` : tunnel HTTP toujours protégé par basic auth, et clé
  d'accès injectée par ngrok (Traffic Policy `remove-headers` + `add-headers`) que le NAS exige.
- **Journal d'audit** JSON Lines avec rotation (`audit.jsonl`) : tunnels, chaque connexion
  cliente, tentatives MFA, appels d'outils, requêtes refusées ; outil `audit_log` (lecture seule)
  et commandes `hermes-ngrok-admin audit` / `nas audit`.
- Adresse IP réelle des clients grâce au PROXY protocol de ngrok (`HERMES_NGROK_PROXY_PROTOCOL`),
  exposée dans `tunnel_status` (`last_client_ip`, `distinct_client_ips`).
- Installeur : options `--nas-dir` et `--nas-owner` (utilisateur `hermes-nas`, ACL, clé partagée).

### Modifié

- Toute erreur inattendue d'un outil est journalisée et renvoyée proprement à l'agent (`isError`).
- `nas_open` vérifie que le NAS répond avant de consommer un code MFA.

## [1.0.0] - 2026-10-22

### Ajouté

- Serveur MCP (transport HTTP « streamable » avec jeton Bearer, ou stdio) exposant
  `mfa_status`, `mfa_setup_start`, `mfa_setup_confirm`, `tunnel_open`, `tunnel_status`,
  `tunnel_extend` et `tunnel_close`.
- MFA TOTP compatible Proton Authenticator : enrôlement via Telegram, anti-rejeu, verrouillage
  progressif persistant, rotation protégée par le code courant, réinitialisation locale.
- Tunnels ngrok HTTP et TCP via le SDK embarqué, avec basic auth générée (Traffic Policy),
  vérification de bout en bout et mesure de l'usage par un relais local.
- Fermeture automatique après inactivité, durée de vie maximale, alerte avant expiration et
  prolongation avec un nouveau code (délais paramétrables).
- Notifications Telegram en français et en anglais.
- Service systemd durci sous un utilisateur dédié, installeur idempotent, désinstalleur,
  commande `hermes-ngrok-admin`.
- Skill Hermes `ngrok-tunnels` et instructions d'installation pour l'agent (`AGENTS.md`).
