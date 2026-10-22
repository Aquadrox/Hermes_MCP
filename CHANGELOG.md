# Changelog

Format : [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/), versions :
[SemVer](https://semver.org/lang/fr/).

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
