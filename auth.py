
import hmac
import os
import hashlib
import binascii
from datetime import datetime, timedelta

from dotenv import load_dotenv
from jose import jwt, JWTError


load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))


if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY não configurada no .env")


def gerar_hash_senha(senha: str) -> str:
    senha = senha[:72]
    salt = os.urandom(16)

    senha_hash = hashlib.pbkdf2_hmac(
        "sha256",
        senha.encode("utf-8"),
        salt,
        200000
    )

    return binascii.hexlify(salt).decode() + ":" + binascii.hexlify(senha_hash).decode()


def verificar_senha(senha: str, senha_hash_salvo: str) -> bool:
    try:
        senha = senha[:72]
        salt_hex, hash_hex = senha_hash_salvo.split(":")
        salt = binascii.unhexlify(salt_hex)
        hash_salvo = binascii.unhexlify(hash_hex)

        novo_hash = hashlib.pbkdf2_hmac(
            "sha256",
            senha.encode("utf-8"),
            salt,
            200000
        )

        return hmac.compare_digest(novo_hash, hash_salvo)

    except Exception:
        return False


def criar_token(dados: dict) -> str:
    payload = dados.copy()
    expira = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload.update({"exp": expira})

    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def validar_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None
