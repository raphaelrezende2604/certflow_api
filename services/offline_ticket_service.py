import base64
import json
import uuid
from datetime import datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


PRIVATE_KEY_PATH = Path("keys/offline_ticket_private.pem")
PUBLIC_KEY_PATH = Path("keys/offline_ticket_public.pem")


def _carregar_chave_privada():
    private_bytes = PRIVATE_KEY_PATH.read_bytes()
    return serialization.load_pem_private_key(
        private_bytes,
        password=None
    )


def _carregar_chave_publica():
    public_bytes = PUBLIC_KEY_PATH.read_bytes()
    return serialization.load_pem_public_key(public_bytes)


def _serializar_payload(payload: dict) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")


def _assinar_payload(payload: dict) -> str:
    private_key = _carregar_chave_privada()
    dados = _serializar_payload(payload)

    assinatura = private_key.sign(dados)

    pacote = {
        "payload": payload,
        "signature": base64.urlsafe_b64encode(assinatura).decode("utf-8")
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
        "ticket_id": str(uuid.uuid4()),
        "usuario_id": usuario_id,
        "email": email,
        "plano": plano,
        "status": status,
        "device_id": device_id,
        "fingerprint": fingerprint,
        "license_expires_at": license_expires_at.isoformat(),
        "issued_at": agora.isoformat(),
        "last_online_check": agora.isoformat(),
        "offline_valid_until": offline_ate.isoformat(),
        "offline_grace_hours": 12,
        "max_offline_drop_minutes": 3
    }

    return {
        "offline_ticket": _assinar_payload(payload),
        "ticket_id": payload["ticket_id"],
        "offline_valid_until": offline_ate.isoformat(),
        "offline_grace_hours": 12,
        "max_offline_drop_minutes": 3
    }


def validar_ticket_offline(ticket: str) -> dict | None:
    try:
        pacote_json = base64.urlsafe_b64decode(ticket.encode("utf-8")).decode("utf-8")
        pacote = json.loads(pacote_json)

        payload = pacote.get("payload")
        assinatura_b64 = pacote.get("signature")

        if not payload or not assinatura_b64:
            return None

        dados = _serializar_payload(payload)
        assinatura = base64.urlsafe_b64decode(assinatura_b64.encode("utf-8"))

        public_key = _carregar_chave_publica()
        public_key.verify(assinatura, dados)

        return payload

    except (InvalidSignature, Exception):
        return None



