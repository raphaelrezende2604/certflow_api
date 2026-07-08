import json
from typing import Any

from sqlalchemy.orm import Session

from models import AuditLog


def registrar_auditoria(
    db: Session,
    event: tuple[str, str],
    message: str,
    usuario_id: int | None = None,
    email: str | None = None,
    ip: str | None = None,
    device_id: str | None = None,
    fingerprint: str | None = None,
    metadata: dict[str, Any] | None = None
):
    event_code, event_type = event

    log = AuditLog(
        usuario_id=usuario_id,
        email=email,
        event_code=event_code,
        event_type=event_type,
        message=message,
        ip=ip,
        device_id=device_id,
        fingerprint=fingerprint,
        metadata_json=json.dumps(metadata) if metadata else None
    )

    db.add(log)
    db.commit()

    return log