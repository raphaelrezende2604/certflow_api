from pydantic import BaseModel, EmailStr


class RegisterRequest(BaseModel):
    nome: str
    email: EmailStr
    senha: str
    device_id: str
    nome_maquina: str
    sistema: str
    fingerprint: str | None = None

class LoginRequest(BaseModel):
    email: EmailStr
    senha: str
    device_id: str
    nome_maquina: str
    sistema: str
    fingerprint: str | None = None

class AdminLoginRequest(BaseModel):
    email: EmailStr
    senha: str
