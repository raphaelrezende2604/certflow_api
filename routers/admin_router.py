from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Header
from sqlalchemy.orm import Session
from database import SessionLocal
from models import Usuario, Licenca, Dispositivo, OfflineTicket, AuditLog
from auth import validar_token
from schemas.admin_schema import AtivarPagoRequest, EmailRequest, DeviceRequest
from services.audit_service import registrar_auditoria
from services.audit_events import AuditEvents
from models import AppUpdate
from schemas.update_schema import UpdateCreateRequest
from schemas.update_schema import UpdateCreateRequest, UpdateStatusRequest
from datetime import datetime, timedelta



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
    email: str | None = None,
    ativo: bool | None = None,
    limit: int = 100,
    admin=Depends(exigir_admin),
    db: Session = Depends(get_db)
):
    if limit > 500:
        limit = 500

    query = db.query(Usuario)

    if email:
        query = query.filter(Usuario.email == email)

    if ativo is not None:
        query = query.filter(Usuario.ativo == ativo)

    usuarios = query.order_by(Usuario.id.desc()).limit(limit).all()

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
    email: str | None = None,
    plano: str | None = None,
    status: str | None = None,
    limit: int = 100,
    admin=Depends(exigir_admin),
    db: Session = Depends(get_db)
):
    if limit > 500:
        limit = 500

    query = db.query(Licenca).join(Usuario, Licenca.usuario_id == Usuario.id)

    if email:
        query = query.filter(Usuario.email == email)

    if plano:
        query = query.filter(Licenca.plano == plano)

    if status:
        query = query.filter(Licenca.status == status)

    licencas = query.order_by(Licenca.id.desc()).limit(limit).all()

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
    email: str | None = None,
    device_id: str | None = None,
    ativo: bool | None = None,
    limit: int = 100,
    admin=Depends(exigir_admin),
    db: Session = Depends(get_db)
):
    if limit > 500:
        limit = 500

    query = db.query(Dispositivo).join(Usuario, Dispositivo.usuario_id == Usuario.id)

    if email:
        query = query.filter(Usuario.email == email)

    if device_id:
        query = query.filter(Dispositivo.device_id == device_id)

    if ativo is not None:
        query = query.filter(Dispositivo.ativo == ativo)

    dispositivos = query.order_by(Dispositivo.id.desc()).limit(limit).all()

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

    tickets_revogados = db.query(OfflineTicket).filter(
        OfflineTicket.device_id == data.device_id,
        OfflineTicket.revogado == False
    ).all()

    for ticket in tickets_revogados:
        ticket.revogado = True
        ticket.revogado_em = datetime.utcnow()
        ticket.motivo_revogacao = "Dispositivo removido/bloqueado pelo administrador."

    registrar_auditoria(
        db=db,
        event=AuditEvents.DEVICE_BLOCKED,
        message="Dispositivo bloqueado pelo administrador.",
        usuario_id=dispositivo.usuario_id,
        email=dispositivo.usuario.email if dispositivo.usuario else None,
        device_id=data.device_id,
        fingerprint=dispositivo.fingerprint,
        metadata={
            "tickets_revogados": len(tickets_revogados)
        }
    )

    registrar_auditoria(
        db=db,
        event=AuditEvents.OFFLINE_TICKET_REVOKED,
        message="Tickets offline revogados por bloqueio de dispositivo.",
        usuario_id=dispositivo.usuario_id,
        email=dispositivo.usuario.email if dispositivo.usuario else None,
        device_id=data.device_id,
        fingerprint=dispositivo.fingerprint,
        metadata={
            "tickets_revogados": len(tickets_revogados)
        }
    )

    db.commit()

    return {
        "message": "Dispositivo removido/bloqueado e tickets revogados.",
        "device_id": data.device_id,
        "tickets_revogados": len(tickets_revogados)
    }





@router.post("/restore-device")
def admin_restore_device(
    data: DeviceRequest,
    admin=Depends(exigir_admin),
    db: Session = Depends(get_db)
):
    dispositivo = db.query(Dispositivo).filter(
        Dispositivo.device_id == data.device_id
    ).first()

    if not dispositivo:
        raise HTTPException(status_code=404, detail="Dispositivo não encontrado.")

    dispositivo.ativo = True

    registrar_auditoria(
        db=db,
        event=AuditEvents.DEVICE_AUTHORIZED,
        message="Dispositivo reativado pelo administrador.",
        usuario_id=dispositivo.usuario_id,
        email=dispositivo.usuario.email if dispositivo.usuario else None,
        device_id=data.device_id,
        fingerprint=dispositivo.fingerprint
    )

    db.commit()

    return {
        "message": "Dispositivo reativado com sucesso.",
        "device_id": data.device_id
    }


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



@router.get("/audit-logs")
def admin_audit_logs(
    email: str | None = None,
    event_type: str | None = None,
    event_code: str | None = None,
    device_id: str | None = None,
    limit: int = 100,
    admin=Depends(exigir_admin),
    db: Session = Depends(get_db)
):
    if limit > 500:
        limit = 500

    query = db.query(AuditLog)

    if email:
        query = query.filter(AuditLog.email == email)

    if event_type:
        query = query.filter(AuditLog.event_type == event_type)

    if event_code:
        query = query.filter(AuditLog.event_code == event_code)

    if device_id:
        query = query.filter(AuditLog.device_id == device_id)

    logs = query.order_by(AuditLog.id.desc()).limit(limit).all()

    return [
        {
            "id": log.id,
            "usuario_id": log.usuario_id,
            "email": log.email,
            "event_code": log.event_code,
            "event_type": log.event_type,
            "message": log.message,
            "ip": log.ip,
            "device_id": log.device_id,
            "fingerprint": log.fingerprint,
            "metadata": log.metadata_json,
            "criado_em": log.criado_em.isoformat() if log.criado_em else None
        }
        for log in logs
    ]


@router.get("/offline-tickets")
def admin_offline_tickets(
    device_id: str | None = None,
    usuario_id: int | None = None,
    revogado: bool | None = None,
    limit: int = 100,
    admin=Depends(exigir_admin),
    db: Session = Depends(get_db)
):
    if limit > 500:
        limit = 500

    query = db.query(OfflineTicket)

    if device_id:
        query = query.filter(OfflineTicket.device_id == device_id)

    if usuario_id:
        query = query.filter(OfflineTicket.usuario_id == usuario_id)

    if revogado is not None:
        query = query.filter(OfflineTicket.revogado == revogado)

    tickets = query.order_by(OfflineTicket.id.desc()).limit(limit).all()

    return [
        {
            "id": t.id,
            "ticket_id": t.ticket_id,
            "usuario_id": t.usuario_id,
            "device_id": t.device_id,
            "fingerprint": t.fingerprint,
            "emitido_em": t.emitido_em.isoformat() if t.emitido_em else None,
            "valido_ate": t.valido_ate.isoformat() if t.valido_ate else None,
            "revogado": t.revogado,
            "revogado_em": t.revogado_em.isoformat() if t.revogado_em else None,
            "motivo_revogacao": t.motivo_revogacao
        }
        for t in tickets
    ]


@router.post("/updates")
def admin_create_update(
    data: UpdateCreateRequest,
    admin=Depends(exigir_admin),
    db: Session = Depends(get_db)
):
    update = AppUpdate(
        app_name=data.app_name,
        version=data.version,
        min_required_version=data.min_required_version,
        download_url=data.download_url,
        changelog=data.changelog,
        obrigatorio=data.obrigatorio,
        ativo=True
    )

    db.add(update)
    db.commit()
    db.refresh(update)

    return {
        "message": "Atualização cadastrada com sucesso.",
        "id": update.id,
        "app_name": update.app_name,
        "version": update.version,
        "obrigatorio": update.obrigatorio
    }



@router.get("/updates")
def admin_list_updates(
    admin=Depends(exigir_admin),
    db: Session = Depends(get_db)
):
    updates = db.query(AppUpdate).order_by(AppUpdate.id.desc()).all()

    return [
        {
            "id": u.id,
            "app_name": u.app_name,
            "version": u.version,
            "min_required_version": u.min_required_version,
            "download_url": u.download_url,
            "changelog": u.changelog.splitlines() if u.changelog else [],
            "ativo": u.ativo,
            "obrigatorio": u.obrigatorio,
            "criado_em": u.criado_em.isoformat() if u.criado_em else None
        }
        for u in updates
    ]



@router.post("/updates/deactivate")
def admin_deactivate_update(
    data: UpdateStatusRequest,
    admin=Depends(exigir_admin),
    db: Session = Depends(get_db)
):
    update = db.query(AppUpdate).filter(AppUpdate.id == data.update_id).first()

    if not update:
        raise HTTPException(status_code=404, detail="Atualização não encontrada.")

    update.ativo = False
    db.commit()

    return {
        "message": "Atualização desativada com sucesso.",
        "id": update.id,
        "version": update.version,
        "ativo": update.ativo
    }


@router.post("/updates/require")
def admin_require_update(
    data: UpdateStatusRequest,
    admin=Depends(exigir_admin),
    db: Session = Depends(get_db)
):
    update = db.query(AppUpdate).filter(AppUpdate.id == data.update_id).first()

    if not update:
        raise HTTPException(status_code=404, detail="Atualização não encontrada.")

    update.obrigatorio = True
    db.commit()

    return {
        "message": "Atualização marcada como obrigatória.",
        "id": update.id,
        "version": update.version,
        "obrigatorio": update.obrigatorio
    }

@router.get("/dashboard/stats")
def admin_dashboard_stats(
    admin=Depends(exigir_admin),
    db: Session = Depends(get_db)
):
    agora = datetime.utcnow()
    ultima_hora = agora - timedelta(hours=1)

    total_usuarios = db.query(Usuario).count()
    usuarios_ativos = db.query(Usuario).filter(Usuario.ativo == True).count()

    total_licencas = db.query(Licenca).count()
    licencas_ativas = db.query(Licenca).filter(Licenca.status == "active").count()

    total_dispositivos = db.query(Dispositivo).count()
    dispositivos_ativos = db.query(Dispositivo).filter(Dispositivo.ativo == True).count()
    dispositivos_bloqueados = db.query(Dispositivo).filter(Dispositivo.ativo == False).count()

    total_tickets = db.query(OfflineTicket).count()
    tickets_revogados = db.query(OfflineTicket).filter(OfflineTicket.revogado == True).count()
    tickets_ativos = db.query(OfflineTicket).filter(
        OfflineTicket.revogado == False,
        OfflineTicket.valido_ate > agora
    ).count()

    heartbeats_ultima_hora = db.query(AuditLog).filter(
        AuditLog.event_type == "HEARTBEAT_RECEIVED",
        AuditLog.criado_em >= ultima_hora
    ).count()

    eventos_seguranca = db.query(AuditLog).filter(
        AuditLog.event_code.like("SEC%")
    ).count()

    atualizacoes_ativas = db.query(AppUpdate).filter(
        AppUpdate.ativo == True
    ).count()

    return {
        "usuarios": {
            "total": total_usuarios,
            "ativos": usuarios_ativos
        },
        "licencas": {
            "total": total_licencas,
            "ativas": licencas_ativas
        },
        "dispositivos": {
            "total": total_dispositivos,
            "ativos": dispositivos_ativos,
            "bloqueados": dispositivos_bloqueados
        },
        "tickets_offline": {
            "total": total_tickets,
            "ativos": tickets_ativos,
            "revogados": tickets_revogados
        },
        "monitoramento": {
            "heartbeats_ultima_hora": heartbeats_ultima_hora,
            "eventos_seguranca": eventos_seguranca
        },
        "atualizacoes": {
            "ativas": atualizacoes_ativas
        }
    }