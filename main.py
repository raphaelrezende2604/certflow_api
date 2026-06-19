from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta

from database import Base, engine, SessionLocal
from models import Usuario, Licenca, Dispositivo
from auth import gerar_hash_senha, verificar_senha, criar_token


Base.metadata.create_all(bind=engine)

app = FastAPI(title="CertFlow API")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class RegisterRequest(BaseModel):
    nome: str
    email: EmailStr
    senha: str
    device_id: str
    nome_maquina: str
    sistema: str


class LoginRequest(BaseModel):
    email: EmailStr
    senha: str
    device_id: str
    nome_maquina: str
    sistema: str


@app.get("/")
def home():
    return {"status": "CertFlow API online"}


@app.post("/register")
def register(data: RegisterRequest, db: Session = Depends(get_db)):
    usuario_existente = db.query(Usuario).filter(Usuario.email == data.email).first()

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

    token = criar_token({"sub": usuario.email, "usuario_id": usuario.id})

    return {
        "token": token,
        "usuario": {
            "id": usuario.id,
            "nome": usuario.nome,
            "email": usuario.email
        }
    }


@app.post("/login")
def login(data: LoginRequest, db: Session = Depends(get_db)):
    usuario = db.query(Usuario).filter(Usuario.email == data.email).first()

    if not usuario or not verificar_senha(data.senha, usuario.senha_hash):
        raise HTTPException(status_code=401, detail="E-mail ou senha inválidos.")

    licenca = db.query(Licenca).filter(Licenca.usuario_id == usuario.id).first()

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

    token = criar_token({"sub": usuario.email, "usuario_id": usuario.id})

    return {
        "token": token,
        "usuario": {
            "id": usuario.id,
            "nome": usuario.nome,
            "email": usuario.email
        }
    }


@app.post("/license/check")
def check_license(data: LoginRequest, db: Session = Depends(get_db)):
    usuario = db.query(Usuario).filter(Usuario.email == data.email).first()

    if not usuario:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")

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
def ativar_pago(email: EmailStr, plano: str = "individual", db: Session = Depends(get_db)):
    usuario = db.query(Usuario).filter(Usuario.email == email).first()

    if not usuario:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")

    licenca = db.query(Licenca).filter(Licenca.usuario_id == usuario.id).first()

    if not licenca:
        raise HTTPException(status_code=404, detail="Licença não encontrada.")

    if plano == "empresa":
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
        "email": email,
        "plano": licenca.plano,
        "expira_em": licenca.expira_em.isoformat()
    }

    