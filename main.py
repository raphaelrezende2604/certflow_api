import os
from datetime import datetime, timedelta
from schemas.auth_schema import RegisterRequest, LoginRequest, AdminLoginRequest
from schemas.admin_schema import AtivarPagoRequest, EmailRequest, DeviceRequest
from routers.admin_router import router as admin_router

from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr

from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from database import Base, engine, SessionLocal
from models import Usuario, Licenca, Dispositivo
from auth import gerar_hash_senha, verificar_senha, criar_token, validar_token


load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ADMIN_SECRET = os.getenv("ADMIN_SECRET")
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*")

if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY não configurada no .env")

if not ADMIN_SECRET:
    raise RuntimeError("ADMIN_SECRET não configurada no .env")


Base.metadata.create_all(bind=engine)

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="CertFlow API",
    docs_url=None,
    redoc_url=None,
    openapi_url=None
)


app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

origins = (
    ["*"]
    if ALLOWED_ORIGINS == "*"
    else [origin.strip() for origin in ALLOWED_ORIGINS.split(",")]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type", "X-Admin-Secret"],
)

app.include_router(admin_router)




@app.exception_handler(RateLimitExceeded)
def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    raise HTTPException(
        status_code=429,
        detail="Muitas requisições. Tente novamente em alguns minutos."
    )


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
    if x_admin_secret != ADMIN_SECRET:
        raise HTTPException(
            status_code=403,
            detail="Acesso administrativo negado."
        )

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Token administrativo ausente."
        )

    token = authorization.replace("Bearer ", "")
    payload = validar_token(token)

    if not payload:
        raise HTTPException(
            status_code=401,
            detail="Token inválido ou expirado."
        )

    if payload.get("role") != "admin":
        raise HTTPException(
            status_code=403,
            detail="Usuário não possui permissão administrativa."
        )

    return payload



@app.get("/")
def home():
    return {
        "status": "CertFlow API online",
        "environment": os.getenv("ENVIRONMENT", "development"),
        "version": os.getenv("API_VERSION", "1.0")
    }


@app.post("/register")
@limiter.limit("10/minute")
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

    return {
        "token": token,
        "usuario": {
            "id": usuario.id,
            "nome": usuario.nome,
            "email": usuario.email
        }
    }


@app.post("/login")
@limiter.limit("10/minute")
def login(
    request: Request,
    data: LoginRequest,
    db: Session = Depends(get_db)
):
    usuario = db.query(Usuario).filter(
        Usuario.email == data.email
    ).first()

    if not usuario or not verificar_senha(data.senha, usuario.senha_hash):
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

    if not dispositivo_atual:
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
            ativo=True
        )

        db.add(novo_dispositivo)
        db.commit()

    token = criar_token({
        "sub": usuario.email,
        "usuario_id": usuario.id,
        "role": "user"
    })

    return {
        "token": token,
        "usuario": {
            "id": usuario.id,
            "nome": usuario.nome,
            "email": usuario.email
        }
    }


@app.post("/admin/login")
@limiter.limit("5/minute")
def admin_login(
    request: Request,
    data: AdminLoginRequest,
    db: Session = Depends(get_db)
):
    usuario = db.query(Usuario).filter(
        Usuario.email == data.email
    ).first()

    if not usuario or not verificar_senha(data.senha, usuario.senha_hash):
        raise HTTPException(status_code=401, detail="Credenciais inválidas.")

    if usuario.email not in [
        "raphaelrezende490@gmail.com",
        "reezenderaphael@gmail.com"
    ]:
        raise HTTPException(status_code=403, detail="Usuário não é administrador.")

    token = criar_token({
        "sub": usuario.email,
        "usuario_id": usuario.id,
        "role": "admin"
    })

    return {
        "token": token,
        "admin": {
            "id": usuario.id,
            "nome": usuario.nome,
            "email": usuario.email
        }
    }


@app.post("/license/check")
@limiter.limit("30/minute")
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

    ativo = licenca.expira_em > datetime.utcnow()

    return {
        "active": ativo,
        "plan": licenca.plano,
        "status": licenca.status,
        "expires_at": licenca.expira_em.isoformat(),
        "devices_limit": licenca.limite_dispositivos,
        "device_authorized": True
    }


@app.post("/admin/ativar-pago")
@limiter.limit("10/minute")
def ativar_pago(
    request: Request,
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

@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "certflow-api",
        "environment": os.getenv("ENVIRONMENT", "production"),
        "version": os.getenv("API_VERSION", "1.0")
    }





@app.get("/admin/devices")
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
            "ativo": d.ativo,
            "criado_em": d.criado_em.isoformat() if d.criado_em else None
        }
        for d in dispositivos
    ]


@app.post("/admin/block-user")
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


@app.post("/admin/unblock-user")
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


@app.post("/admin/deactivate-license")
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


@app.post("/admin/remove-device")
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



