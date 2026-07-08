from datetime import datetime

from sqlalchemy.orm import Session

from models import OfflineTicket
from services.offline_ticket_service import gerar_ticket_offline
from services.audit_service import registrar_auditoria
from services.audit_events import AuditEvents


def emitir_ticket_offline(
    db: Session,
    usuario_id: int,
    email: str,
    plano: str,
    status: str,
    device_id: str,
    fingerprint: str | None,
    license_expires_at
) -> dict:
    ticket = gerar_ticket_offline(
        usuario_id=usuario_id,
        email=email,
        plano=plano,
        status=status,
        device_id=device_id,
        fingerprint=fingerprint,
        license_expires_at=license_expires_at
    )

    registro = OfflineTicket(
        ticket_id=ticket["ticket_id"],
        usuario_id=usuario_id,
        device_id=device_id,
        fingerprint=fingerprint,
        valido_ate=datetime.fromisoformat(ticket["offline_valid_until"])
    )

    db.add(registro)
    db.commit()



    registrar_auditoria(
    db=db,
    event=AuditEvents.OFFLINE_TICKET_CREATED,
    message="Ticket offline emitido com sucesso.",
    usuario_id=usuario_id,
    email=email,
    device_id=device_id,
    fingerprint=fingerprint,
    metadata={
        "ticket_id": ticket["ticket_id"],
        "valido_ate": ticket["offline_valid_until"],
        "plano": plano,
        "status": status
    }
)


    return ticket
