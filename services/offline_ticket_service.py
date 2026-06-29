import os
import hmac
import json
import hashlib
import base64
from datetime import datetime, timedelta


OFFLINE_TICKET_SECRET = os.getenv("OFFLINE_TICKET_SECRET")


if not OFFLINE_TICKET_SECRET:
    raise RuntimeError("OFFLINE_TICKET_SECRET não configurada no .env")


def _assinar_payload(payload: dict) -> str:
    dados = json.dumps(payload, sort_keys=True, separators=(",", ":"))

    assinatura = hmac.new(
        OFFLINE_TICKET_SECRET.encode("utf-8"),
        dados.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    pacote = {
        "payload": payload,
        "signature": assinatura
    }

    return base64.urlsafe_b64encode(
        json.dumps(pacote).encode("utf-8")
    ).decode("utf-8")


def gerar_ticket_offline(
    usuario_id: int,
    email: str,
    plano: str,
    status: str,
    device_id: str,
    fingerprint: str | None,
    license_expires_at: datetime
) -> dict:
    agora = datetime.utcnow()
    offline_ate = agora + timedelta(hours=12)

    payload = {
        "usuario_id": usuario_id,
        "email": email,
        "plano": plano,
        "status": status,
        "device_id": device_id,
        "fingerprint": fingerprint,
        "license_expires_at": license_expires_at.isoformat(),
        "last_online_check": agora.isoformat(),
        "offline_valid_until": offline_ate.isoformat(),
        "offline_grace_hours": 12,
        "max_offline_drop_minutes": 3
    }

    return {
        "offline_ticket": _assinar_payload(payload),
        "offline_valid_until": offline_ate.isoformat(),
        "offline_grace_hours": 12,
        "max_offline_drop_minutes": 3
    }

def validar_ticket_offline(ticket: str) -> dict | None:
    try:
        pacote_json = base64.urlsafe_b64decode(ticket.encode("utf-8")).decode("utf-8")
        pacote = json.loads(pacote_json)

        payload = pacote.get("payload")
        assinatura_recebida = pacote.get("signature")

        if not payload or not assinatura_recebida:
            return None

        dados = json.dumps(payload, sort_keys=True, separators=(",", ":"))

        assinatura_correta = hmac.new(
            OFFLINE_TICKET_SECRET.encode("utf-8"),
            dados.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(assinatura_recebida, assinatura_correta):
            return None

        return payload

    except Exception:
        return None



