# Sécurité

## Ce qu'on protège

Le VPS n'est pas joignable depuis Internet. Ouvrir un tunnel crée une porte d'entrée : seul le
propriétaire doit pouvoir le décider, pour une durée courte, vers un service précis.

## Modèle de menace

| Menace | Contre-mesure |
|---|---|
| Un tiers écrit au bot Telegram, ou ton compte Telegram est compromis | Ouvrir ou prolonger exige un code TOTP de ton téléphone. Les codes faux entraînent un verrouillage croissant et une alerte Telegram. |
| Prompt injection : Hermes est poussé à ouvrir un tunnel tout seul | Même chose : sans code MFA fourni par toi, aucune ouverture. Les outils exigent le code et leur description interdit de l'inventer. |
| Hermes (accès shell) essaie de lire le secret MFA ou le token ngrok | Le service tourne sous l'utilisateur `hermes-ngrok`. Secret dans `/var/lib/hermes-ngrok-mcp` (0700), configuration en `root:hermes-ngrok` 0640. |
| Hermes essaie d'obtenir un secret en faisant échouer Telegram (il connaît le token du bot) | Quand Telegram est configuré, aucun secret n'est jamais renvoyé à l'agent : en cas d'échec d'envoi, l'enrôlement est annulé et le tunnel refermé. |
| Hermes essaie de transférer le message contenant le secret (il connaît le token du bot) | Les messages sensibles sont envoyés avec `protect_content` (ni transfert ni copie par l'API) ; le QR code est supprimé après validation. |
| Rejeu d'un code intercepté | Un code n'est accepté qu'une fois : le pas de temps utilisé est mémorisé. |
| Brute-force du code à 6 chiffres | 5 essais par fenêtre de 5 min, puis verrouillage de 15 min doublé à chaque récidive (24 h max), persistant au redémarrage. |
| URL publique devinée (domaine fixe du plan gratuit) | Basic auth générée pour chaque tunnel HTTP (24 caractères aléatoires), appliquée par ngrok avant d'atteindre le VPS. |
| Tunnel oublié ouvert | Fermeture après 10 min sans trafic, durée de vie de 20 min, prolongation uniquement avec un nouveau code. |
| Exposition du serveur MCP lui-même | Son port est refusé quelle que soit la configuration ; il n'écoute que sur 127.0.0.1 et exige le jeton Bearer. |
| Processus local qui appelle le serveur MCP | Jeton Bearer (≥ 32 caractères, comparaison à temps constant) ; protection contre le DNS rebinding (en-tête `Host` vérifié). |
| Compromission du service | Bac à sable systemd : `NoNewPrivileges`, aucune capability, `ProtectSystem=strict`, `ProtectHome`, filtre d'appels système, familles d'adresses limitées. |
| Installeur détourné pour exécuter du code en root | L'installeur n'exécute que des binaires `uv` contrôlés par root et avertit si les sources ne le sont pas ; la documentation impose un clone appartenant à root. |
| Fuite de secrets dans les journaux | Codes, secrets, mots de passe et tokens ne sont jamais journalisés ; le token du bot est masqué dans les erreurs ; les URL de requêtes httpx ne sont pas journalisées. |

## Risques résiduels

- **Bootstrap du MFA** : tant que le MFA n'est pas configuré, quiconque passe par Hermes peut
  lancer l'enrôlement. Avec Telegram configuré, le QR code n'arrive pourtant que chez toi.
  Configure le MFA juste après l'installation, ou fais-le depuis le terminal
  (`sudo hermes-ngrok-admin mfa setup`).
- **Sans Telegram**, le secret MFA et les mots de passe transitent par l'agent et par le
  fournisseur du modèle de langage. Pour l'éviter : configure Telegram, ou mets
  `HERMES_NGROK_MFA_ALLOW_INLINE_ENROLLMENT=false` et enrôle depuis le terminal.
- **Hermes connaît le token du bot** : il pourrait t'envoyer de faux messages au nom du bot.
  Ne donne un code MFA que pour une action que tu as toi-même demandée.
- **Pendant qu'un tunnel est ouvert**, le service exposé est joignable par quiconque possède
  l'URL et le mot de passe. Il doit avoir sa propre authentification s'il est sensible, et les
  tunnels « sans mot de passe » sont à réserver à ce cas.
- **sudo sans mot de passe pour Hermes** : si l'utilisateur Hermes peut devenir root,
  l'isolation par utilisateur ne tient plus.
- **Fournisseur** : le trafic transite par ngrok (TLS terminé chez ngrok pour HTTP).

## Bonnes pratiques

- Garde l'horloge du VPS synchronisée (NTP) : TOTP en dépend.
- Supprime les messages contenant un secret s'ils ont été envoyés via l'agent.
- Vérifie périodiquement `journalctl -u hermes-ngrok-mcp` et
  `systemd-analyze security hermes-ngrok-mcp`.
- Restreins les ports exposables avec `HERMES_NGROK_ALLOWED_PORTS` si tu n'en utilises que
  quelques-uns.

## Signaler une vulnérabilité

Ouvre une « security advisory » privée sur le dépôt GitHub plutôt qu'une issue publique.
