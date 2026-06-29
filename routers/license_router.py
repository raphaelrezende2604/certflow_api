from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from database import SessionLocal
from models import Usuario, Licenca, Dispositivo
from schemas.auth_schema import LoginRequest
from services.offline_ticket_service import gerar_ticket_offline


router = APIRouter(tags=["License"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post("/license/check")
def check_license(
    request: Request,
    data: LoginRequest,
    db: Session = Depends(get_db)
):
    usuario = db.query(Usuario).filter(
        Usuario.email == data.email
    ).first()

    if not usuario:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")

    if not usuario.ativo:
        raise HTTPException(status_code=403, detail="Usuário bloqueado.")

    licenca = db.query(Licenca).filter(
        Licenca.usuario_id == usuario.id
    ).first()

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
            raise HTTPException(
                status_code=403,
                detail="Fingerprint da máquina não confere."
            )

    ip_cliente = request.headers.get("x-forwarded-for")
    if ip_cliente:
        ip_cliente = ip_cliente.split(",")[0].strip()
    else:
        ip_cliente = request.client.host if request.client else None

    dispositivo.ultimo_ip = ip_cliente
    dispositivo.ultimo_acesso = datetime.utcnow()
    db.commit()

    ativo = (
        licenca.status == "active"
        and licenca.expira_em > datetime.utcnow()
    )




    ticket_offline = gerar_ticket_offline(
    usuario_id=usuario.id,
    email=usuario.email,
    plano=licenca.plano,
    status=licenca.status,
    device_id=data.device_id,
    fingerprint=data.fingerprint,
    license_expires_at=licenca.expira_em)



    return {
        "active": ativo,
        "plan": licenca.plano,
        "status": licenca.status,
        "expires_at": licenca.expira_em.isoformat(),
        "devices_limit": licenca.limite_dispositivos,
        "offline": ticket_offline,
        "device_authorized": True,
        "offline_grace_hours": 12,
        "max_offline_drop_minutes": 3
    }
    

    