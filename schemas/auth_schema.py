from pydantic import BaseModel, EmailStr


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


class AdminLoginRequest(BaseModel):
    email: EmailStr
    senha: str
