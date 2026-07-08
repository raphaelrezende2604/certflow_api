from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from models import Usuario, Licenca, Dispositivo, OfflineTicket

from database import SessionLocal
from models import Usuario, Licenca, Dispositivo
from auth import gerar_hash_senha, verificar_senha, criar_token
from schemas.auth_schema import RegisterRequest, LoginRequest, AdminLoginRequest
from services.ticket_service import emitir_ticket_offline
from services.audit_service import registrar_auditoria
from services.audit_events import AuditEvents




router = APIRouter(tags=["Auth"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/register")
def register(
    request: Request,
    data: RegisterRequest,
    db: Session = Depends(get_db)
):
    usuario_existente = db.query(Usuario).filter(
        Usuario.email == data.email
    ).first()

    if usuario_existente:
        raise HTTPException(status_code=400, detail="E-mail já cadastrado.")

    usuario = Usuario(
        nome=data.nome,
        email=data.email,
        senha_hash=gerar_hash_senha(data.senha),
        ativo=True
    )

    db.add(usuario)
    db.commit()
    db.refresh(usuario)

    licenca = Licenca(
        usuario_id=usuario.id,
        plano="trial",
        status="trial",
        limite_dispositivos=1,
        expira_em=datetime.utcnow() + timedelta(days=1)
    )

    dispositivo = Dispositivo(
        usuario_id=usuario.id,
        device_id=data.device_id,
        nome_maquina=data.nome_maquina,
        sistema=data.sistema,
        fingerprint=getattr(data, "fingerprint", None),
        ativo=True
    )

    db.add(licenca)
    db.add(dispositivo)
    db.commit()

    token = criar_token({
        "sub": usuario.email,
        "usuario_id": usuario.id,
        "role": "user"
    })


    ticket_offline = gerar_ticket_offline(
    usuario_id=usuario.id,
    email=usuario.email,
    plano=licenca.plano,
    status=licenca.status,
    device_id=data.device_id,
    fingerprint=data.fingerprint,
    license_expires_at=licenca.expira_em)

    offline_registro = OfflineTicket(
    ticket_id=ticket_offline["ticket_id"],
    usuario_id=usuario.id,
    device_id=data.device_id,
    fingerprint=data.fingerprint,
    valido_ate=datetime.fromisoformat(ticket_offline["offline_valid_until"])
    )

    db.add(offline_registro)
    db.commit()



    return {
        "token": token,
        "usuario": {
            "id": usuario.id,
            "nome": usuario.nome,
            "email": usuario.email,
            "offline": ticket_offline
        }
    }


@router.post("/login")
def login(
    request: Request,
    data: LoginRequest,
    db: Session = Depends(get_db)
):
    usuario = db.query(Usuario).filter(
        Usuario.email == data.email
    ).first()

    if not usuario or not verificar_senha(data.senha, usuario.senha_hash):
        registrar_auditoria(
            db=db,
            event=AuditEvents.LOGIN_FAILED,
            message="Tentativa de login com credenciais inválidas.",
            email=data.email,
            device_id=data.device_id,
            fingerprint=data.fingerprint
    )
        raise HTTPException(status_code=401, detail="E-mail ou senha inválidos.")

    if not usuario.ativo:
        raise HTTPException(status_code=403, detail="Usuário bloqueado.")

    licenca = db.query(Licenca).filter(
        Licenca.usuario_id == usuario.id
    ).first()

    if not licenca:
        raise HTTPException(status_code=403, detail="Licença não encontrada.")

    dispositivos_ativos = db.query(Dispositivo).filter(
        Dispositivo.usuario_id == usuario.id,
        Dispositivo.ativo == True
    ).all()

    dispositivo_atual = None

    for d in dispositivos_ativos:
        if d.device_id == data.device_id:
            dispositivo_atual = d
            break

    ip_cliente = request.headers.get("x-forwarded-for")
    if ip_cliente:
        ip_cliente = ip_cliente.split(",")[0].strip()
    else:
        ip_cliente = request.client.host if request.client else None

    if dispositivo_atual:
        if dispositivo_atual.fingerprint and data.fingerprint:
            if dispositivo_atual.fingerprint != data.fingerprint:
                raise HTTPException(
                    status_code=403,
                    detail="Fingerprint da máquina não confere com o dispositivo autorizado."
                )

        if not dispositivo_atual.fingerprint and data.fingerprint:
            dispositivo_atual.fingerprint = data.fingerprint

        dispositivo_atual.nome_maquina = data.nome_maquina
        dispositivo_atual.sistema = data.sistema
        dispositivo_atual.ultimo_ip = ip_cliente
        dispositivo_atual.ultimo_acesso = datetime.utcnow()

    else:
        if len(dispositivos_ativos) >= licenca.limite_dispositivos:
            raise HTTPException(
                status_code=403,
                detail="Limite de dispositivos atingido para este plano."
            )

        novo_dispositivo = Dispositivo(
            usuario_id=usuario.id,
            device_id=data.device_id,
            nome_maquina=data.nome_maquina,
            sistema=data.sistema,
            fingerprint=data.fingerprint,
            ultimo_ip=ip_cliente,
            ultimo_acesso=datetime.utcnow(),
            ativo=True
        )

        db.add(novo_dispositivo)

    db.commit()

    token = criar_token({
        "sub": usuario.email,
        "usuario_id": usuario.id,
        "role": "user"
    })

    ticket_offline = emitir_ticket_offline(
        db=db,
        usuario_id=usuario.id,
        email=usuario.email,
        plano=licenca.plano,
        status=licenca.status,
        device_id=data.device_id,
        fingerprint=data.fingerprint,
        license_expires_at=licenca.expira_em
    )

    registrar_auditoria(
    db=db,
    event=AuditEvents.LOGIN_SUCCESS,
    message="Login realizado com sucesso.",
    usuario_id=usuario.id,
    email=usuario.email,
    ip=ip_cliente,
    device_id=data.device_id,
    fingerprint=data.fingerprint,
    metadata={
        "plano": licenca.plano,
        "status": licenca.status
    }
)



    return {
        "token": token,
        "usuario": {
            "id": usuario.id,
            "nome": usuario.nome,
            "email": usuario.email
        },
        "licenca": {
            "plano": licenca.plano,
            "status": licenca.status,
            "expira_em": licenca.expira_em.isoformat(),
            "limite_dispositivos": licenca.limite_dispositivos
        },
        "offline": ticket_offline
    }