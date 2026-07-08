from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from database import SessionLocal
from models import Usuario, Licenca, Dispositivo
from schemas.heartbeat_schema import HeartbeatRequest
from services.audit_service import registrar_auditoria
from services.audit_events import AuditEvents


router = APIRouter(tags=["Heartbeat"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_client_ip(request: Request) -> str | None:
    ip_cliente = request.headers.get("x-forwarded-for")
    if ip_cliente:
        return ip_cliente.split(",")[0].strip()
    return request.client.host if request.client else None


@router.post("/heartbeat")
def heartbeat(
    request: Request,
    data: HeartbeatRequest,
    db: Session = Depends(get_db)
):
    ip_cliente = get_client_ip(request)

    usuario = db.query(Usuario).filter(Usuario.email == data.email).first()

    if not usuario:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")

    if not usuario.ativo:
        raise HTTPException(status_code=403, detail="Usuário bloqueado.")

    licenca = db.query(Licenca).filter(Licenca.usuario_id == usuario.id).first()

    if not licenca:
        raise HTTPException(status_code=403, detail="Licença não encontrada.")

    dispositivo = db.query(Dispositivo).filter(
        Dispositivo.usuario_id == usuario.id,
        Dispositivo.device_id == data.device_id,
        Dispositivo.ativo == True
    ).first()

    if not dispositivo:
        raise HTTPException(status_code=403, detail="Dispositivo não autorizado.")

    if dispositivo.fingerprint and data.fingerprint:
        if dispositivo.fingerprint != data.fingerprint:
            registrar_auditoria(
                db=db,
                event=AuditEvents.FINGERPRINT_MISMATCH,
                message="Heartbeat com fingerprint diferente.",
                usuario_id=usuario.id,
                email=usuario.email,
                ip=ip_cliente,
                device_id=data.device_id,
                fingerprint=data.fingerprint,
                metadata={
                    "fingerprint_cadastrado": dispositivo.fingerprint,
                    "app_version": data.app_version,
                    "sistema": data.sistema
                }
            )

            raise HTTPException(
                status_code=403,
                detail="Fingerprint da máquina não confere."
            )

    dispositivo.ultimo_ip = ip_cliente
    dispositivo.ultimo_acesso = datetime.utcnow()

    db.commit()

    ativo = (
        licenca.status == "active"
        and licenca.expira_em > datetime.utcnow()
    )

    registrar_auditoria(
        db=db,
        event=AuditEvents.HEARTBEAT_RECEIVED,
        message="Heartbeat recebido do cliente.",
        usuario_id=usuario.id,
        email=usuario.email,
        ip=ip_cliente,
        device_id=data.device_id,
        fingerprint=data.fingerprint,
        metadata={
            "app_version": data.app_version,
            "sistema": data.sistema,
            "licenca_ativa": ativo
        }
    )

    return {
        "status": "ok",
        "license_active": ativo,
        "license_status": licenca.status,
        "plan": licenca.plano,
        "server_time": datetime.utcnow().isoformat(),
        "requires_online": not ativo
    }
