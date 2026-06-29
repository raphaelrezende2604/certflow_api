from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Header
from sqlalchemy.orm import Session

from database import SessionLocal
from models import Usuario, Licenca, Dispositivo
from auth import validar_token
from schemas.admin_schema import AtivarPagoRequest, EmailRequest, DeviceRequest


router = APIRouter(prefix="/admin", tags=["Admin"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def exigir_admin(
    authorization: str | None = Header(default=None),
    x_admin_secret: str | None = Header(default=None)
):
    from os import getenv

    ADMIN_SECRET = getenv("ADMIN_SECRET")

    if x_admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Acesso administrativo negado.")

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token administrativo ausente.")

    token = authorization.replace("Bearer ", "")
    payload = validar_token(token)

    if not payload:
        raise HTTPException(status_code=401, detail="Token inválido ou expirado.")

    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Usuário não possui permissão administrativa.")

    return payload


@router.get("/dashboard")
def admin_dashboard(
    admin=Depends(exigir_admin),
    db: Session = Depends(get_db)
):
    total_usuarios = db.query(Usuario).count()
    usuarios_ativos = db.query(Usuario).filter(Usuario.ativo == True).count()
    total_licencas = db.query(Licenca).count()
    licencas_ativas = db.query(Licenca).filter(Licenca.status == "active").count()
    total_dispositivos = db.query(Dispositivo).count()
    dispositivos_ativos = db.query(Dispositivo).filter(Dispositivo.ativo == True).count()

    return {
        "total_usuarios": total_usuarios,
        "usuarios_ativos": usuarios_ativos,
        "total_licencas": total_licencas,
        "licencas_ativas": licencas_ativas,
        "total_dispositivos": total_dispositivos,
        "dispositivos_ativos": dispositivos_ativos
    }


@router.get("/users")
def admin_users(
    admin=Depends(exigir_admin),
    db: Session = Depends(get_db)
):
    usuarios = db.query(Usuario).order_by(Usuario.id.desc()).all()

    return [
        {
            "id": u.id,
            "nome": u.nome,
            "email": u.email,
            "ativo": u.ativo,
            "criado_em": u.criado_em.isoformat() if u.criado_em else None
        }
        for u in usuarios
    ]
    

@router.get("/licenses")
def admin_licenses(
    admin=Depends(exigir_admin),
    db: Session = Depends(get_db)
):
    licencas = db.query(Licenca).order_by(Licenca.id.desc()).all()

    return [
        {
            "id": l.id,
            "usuario_id": l.usuario_id,
            "email": l.usuario.email if l.usuario else None,
            "plano": l.plano,
            "status": l.status,
            "limite_dispositivos": l.limite_dispositivos,
            "expira_em": l.expira_em.isoformat() if l.expira_em else None
        }
        for l in licencas
    ]  


@router.get("/devices")
def admin_devices(
    admin=Depends(exigir_admin),
    db: Session = Depends(get_db)
):
    dispositivos = db.query(Dispositivo).order_by(Dispositivo.id.desc()).all()

    return [
        {
            "id": d.id,
            "usuario_id": d.usuario_id,
            "email": d.usuario.email if d.usuario else None,
            "device_id": d.device_id,
            "nome_maquina": d.nome_maquina,
            "sistema": d.sistema,
            "fingerprint": d.fingerprint,
            "ultimo_ip": d.ultimo_ip,
            "ultimo_acesso": d.ultimo_acesso.isoformat() if d.ultimo_acesso else None,
            "ativo": d.ativo,
            "criado_em": d.criado_em.isoformat() if d.criado_em else None
        }
        for d in dispositivos
    ]



@router.post("/block-user")
def admin_block_user(
    data: EmailRequest,
    admin=Depends(exigir_admin),
    db: Session = Depends(get_db)
):
    usuario = db.query(Usuario).filter(Usuario.email == data.email).first()

    if not usuario:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")

    usuario.ativo = False
    db.commit()

    return {"message": "Usuário bloqueado com sucesso.", "email": data.email}


@router.post("/unblock-user")
def admin_unblock_user(
    data: EmailRequest,
    admin=Depends(exigir_admin),
    db: Session = Depends(get_db)
):
    usuario = db.query(Usuario).filter(Usuario.email == data.email).first()

    if not usuario:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")

    usuario.ativo = True
    db.commit()

    return {"message": "Usuário desbloqueado com sucesso.", "email": data.email}


@router.post("/deactivate-license")
def admin_deactivate_license(
    data: EmailRequest,
    admin=Depends(exigir_admin),
    db: Session = Depends(get_db)
):
    usuario = db.query(Usuario).filter(Usuario.email == data.email).first()

    if not usuario:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")

    licenca = db.query(Licenca).filter(Licenca.usuario_id == usuario.id).first()

    if not licenca:
        raise HTTPException(status_code=404, detail="Licença não encontrada.")

    licenca.status = "inactive"
    db.commit()

    return {"message": "Licença desativada.", "email": data.email}


@router.post("/remove-device")
def admin_remove_device(
    data: DeviceRequest,
    admin=Depends(exigir_admin),
    db: Session = Depends(get_db)
):
    dispositivo = db.query(Dispositivo).filter(
        Dispositivo.device_id == data.device_id
    ).first()

    if not dispositivo:
        raise HTTPException(status_code=404, detail="Dispositivo não encontrado.")

    dispositivo.ativo = False
    db.commit()

    return {"message": "Dispositivo removido/bloqueado.", "device_id": data.device_id}



@router.post("/ativar-pago")
def ativar_pago(
    data: AtivarPagoRequest,
    admin=Depends(exigir_admin),
    db: Session = Depends(get_db)
):
    usuario = db.query(Usuario).filter(
        Usuario.email == data.email
    ).first()

    if not usuario:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")

    licenca = db.query(Licenca).filter(
        Licenca.usuario_id == usuario.id
    ).first()

    if not licenca:
        raise HTTPException(status_code=404, detail="Licença não encontrada.")

    if data.plano == "empresa":
        licenca.plano = "empresa"
        licenca.limite_dispositivos = 4
    else:
        licenca.plano = "individual"
        licenca.limite_dispositivos = 1

    licenca.status = "active"
    licenca.expira_em = datetime.utcnow() + timedelta(days=30)

    db.commit()

    return {
        "message": "Licença ativada com sucesso.",
        "email": data.email,
        "plano": licenca.plano,
        "expira_em": licenca.expira_em.isoformat()
    }