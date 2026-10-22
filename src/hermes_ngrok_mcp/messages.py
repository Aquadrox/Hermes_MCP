"""User-facing Telegram texts (French and English).

Tool results are written in English for the language model; these messages go straight
to the user, so they follow ``HERMES_NGROK_LANGUAGE``. Every interpolated value is
HTML-escaped because messages are sent with ``parse_mode=HTML``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from html import escape
from zoneinfo import ZoneInfo

from hermes_ngrok_mcp.durations import format_duration


@dataclass(frozen=True)
class TunnelFacts:
    """What a message needs to know about a tunnel."""

    tunnel_id: str
    protocol: str
    local_port: int
    label: str | None
    public_url: str
    username: str | None = None
    password: str | None = None
    expires_at: float | None = None
    idle_timeout: int = 0


_CLOSE_REASONS = {
    "fr": {
        "idle": "aucune activité depuis {idle}",
        "expired": "durée de vie maximale atteinte",
        "shutdown": "arrêt du service",
        "manual": "fermeture demandée",
        "verification_failed": "vérification échouée",
        "error": "erreur",
    },
    "en": {
        "idle": "no activity for {idle}",
        "expired": "maximum lifetime reached",
        "shutdown": "service shutdown",
        "manual": "closed on request",
        "verification_failed": "verification failed",
        "error": "error",
    },
}


class Messages:
    def __init__(self, language: str, tz: ZoneInfo) -> None:
        self.lang = "fr" if language == "fr" else "en"
        self.tz = tz

    def _fr(self) -> bool:
        return self.lang == "fr"

    def clock_time(self, epoch: float) -> str:
        moment = datetime.fromtimestamp(epoch, tz=self.tz)
        return moment.strftime("%H:%M") + ("" if self.tz.key == "UTC" else f" ({self.tz.key})")

    def _title(self, facts: TunnelFacts) -> str:
        label = ""
        if facts.label:
            label = f" « {escape(facts.label)} »" if self._fr() else f" “{escape(facts.label)}”"
        endpoint = f"<b>{escape(facts.protocol.upper())} :{facts.local_port}</b>"
        return f"{endpoint}{label} <code>{escape(facts.tunnel_id)}</code>"

    # --- MFA --------------------------------------------------------------------------------------
    def enrollment_caption(
        self, *, issuer: str, account: str, secret: str, expires_in: int, rotation: bool
    ) -> str:
        ttl = format_duration(expires_in)
        if self._fr():
            head = "🔐 <b>Nouvelle clé MFA</b>" if rotation else "🔐 <b>Configuration du MFA</b>"
            return (
                f"{head} — tunnels ngrok\n\n"
                "1. Ouvre <b>Proton Authenticator</b> → <b>+</b> → scanne ce QR code, "
                "ou choisis la saisie manuelle avec la clé ci-dessous (appuie dessus pour la copier) :\n"
                f"<code>{escape(secret)}</code>\n"
                f"   Émetteur : <i>{escape(issuer)}</i> · Compte : <i>{escape(account)}</i>\n"
                "   Type TOTP · SHA-1 · 6 chiffres · 30 s\n"
                "2. Envoie à Hermes le code à 6 chiffres affiché pour valider.\n\n"
                f"⏳ À valider dans les {ttl}. Ce message sera supprimé après validation ; "
                "ne le transfère pas."
            )
        head = "🔐 <b>New MFA key</b>" if rotation else "🔐 <b>MFA setup</b>"
        return (
            f"{head} — ngrok tunnels\n\n"
            "1. Open <b>Proton Authenticator</b> → <b>+</b> → scan this QR code, or enter the key "
            "manually (tap it to copy):\n"
            f"<code>{escape(secret)}</code>\n"
            f"   Issuer: <i>{escape(issuer)}</i> · Account: <i>{escape(account)}</i>\n"
            "   TOTP · SHA-1 · 6 digits · 30 s\n"
            "2. Send Hermes the 6-digit code shown in the app to confirm.\n\n"
            f"⏳ Confirm within {ttl}. This message is deleted once confirmed; do not forward it."
        )

    def mfa_enabled(self, *, rotation: bool) -> str:
        if self._fr():
            what = "La nouvelle clé MFA est active" if rotation else "Le MFA est activé"
            return f"✅ {what}. L'ouverture et la prolongation des tunnels exigeront un code."
        what = "The new MFA key is active" if rotation else "MFA is enabled"
        return f"✅ {what}. Opening and extending tunnels now requires a code."

    def mfa_locked(self, *, retry_after: int) -> str:
        duration = format_duration(retry_after)
        if self._fr():
            return (
                "🚨 <b>Alerte sécurité</b> : trop de codes MFA invalides. "
                f"La vérification est bloquée pendant {duration}. "
                "Si ce n'était pas toi, vérifie qui a accès à Hermes."
            )
        return (
            "🚨 <b>Security alert</b>: too many invalid MFA codes. "
            f"Verification is locked for {duration}. If this wasn't you, check who can reach Hermes."
        )

    # --- tunnels ----------------------------------------------------------------------------------------
    def tunnel_opened(self, facts: TunnelFacts) -> str:
        lines = [("🔓 Tunnel ouvert : " if self._fr() else "🔓 Tunnel open: ") + self._title(facts), ""]
        if facts.protocol == "tcp":
            host, _, port = facts.public_url.removeprefix("tcp://").rpartition(":")
            lines.append(f"<b>{'Hôte' if self._fr() else 'Host'}</b> : <code>{escape(host)}</code>")
            lines.append(f"<b>Port</b> : <code>{escape(port)}</code>")
            if facts.local_port == 22:
                lines.append(f"<code>ssh -p {escape(port)} USER@{escape(host)}</code>")
        else:
            lines.append(f"<b>URL</b> : {escape(facts.public_url)}")
            if facts.username and facts.password:
                login = "Identifiant" if self._fr() else "Username"
                password = "Mot de passe" if self._fr() else "Password"
                lines.append(f"<b>{login}</b> : <code>{escape(facts.username)}</code>")
                lines.append(f"<b>{password}</b> : <code>{escape(facts.password)}</code>")
        lines.append("")
        lines.extend(self._lifetime_lines(facts))
        return "\n".join(lines)

    def _lifetime_lines(self, facts: TunnelFacts) -> list[str]:
        lines: list[str] = []
        if facts.idle_timeout:
            idle = format_duration(facts.idle_timeout)
            lines.append(
                f"⏱️ Fermeture automatique après {idle} sans activité."
                if self._fr()
                else f"⏱️ Closes automatically after {idle} without activity."
            )
        if facts.expires_at is not None:
            when = self.clock_time(facts.expires_at)
            lines.append(
                f"⌛ Expire à {when} (prolongeable avec un code MFA)."
                if self._fr()
                else f"⌛ Expires at {when} (can be extended with an MFA code)."
            )
        return lines

    def expiry_warning(self, facts: TunnelFacts, *, remaining: float) -> str:
        left = format_duration(remaining)
        when = self.clock_time(facts.expires_at) if facts.expires_at else "?"
        if self._fr():
            return (
                f"⏰ Le tunnel {self._title(facts)} se ferme dans <b>{left}</b> (à {when}).\n"
                f"{escape(facts.public_url)}\n\n"
                "Pour le prolonger, écris à Hermes « prolonge le tunnel » avec un code MFA."
            )
        return (
            f"⏰ Tunnel {self._title(facts)} closes in <b>{left}</b> (at {when}).\n"
            f"{escape(facts.public_url)}\n\n"
            "To keep it, ask Hermes to “extend the tunnel” and give an MFA code."
        )

    def tunnel_closed(self, facts: TunnelFacts, *, reason: str) -> str:
        template = _CLOSE_REASONS[self.lang].get(reason, reason)
        why = template.format(idle=format_duration(facts.idle_timeout))
        if self._fr():
            return (
                f"🔒 Tunnel fermé : {self._title(facts)}\n{escape(facts.public_url)}\nMotif : {escape(why)}."
            )
        return f"🔒 Tunnel closed: {self._title(facts)}\n{escape(facts.public_url)}\nReason: {escape(why)}."

    def test_message(self, hostname: str) -> str:
        if self._fr():
            return (
                f"👋 Test de notification depuis <b>hermes-ngrok-mcp</b> sur <code>{escape(hostname)}</code>."
            )
        return f"👋 Test notification from <b>hermes-ngrok-mcp</b> on <code>{escape(hostname)}</code>."
