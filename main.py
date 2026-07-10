import os
from datetime import datetime, timedelta
from schemas.auth_schema import RegisterRequest, LoginRequest, AdminLoginRequest
from schemas.admin_schema import AtivarPagoRequest, EmailRequest, DeviceRequest
from routers.admin_router import router as admin_router
from routers.auth_router import router as auth_router
from routers.license_router import router as license_router
from routers.update_router import router as update_router


from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
from routers.heartbeat_router import router as heartbeat_router

from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from database import SessionLocal
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


##Base.metadata.create_all(bind=engine)

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
app.include_router(auth_router)
app.include_router(license_router)
app.include_router(heartbeat_router)
app.include_router(update_router)



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

