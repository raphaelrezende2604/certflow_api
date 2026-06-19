import os
import hashlib
import binascii
from datetime import datetime, timedelta

from jose import jwt


SECRET_KEY = "TROQUE_ESSA_CHAVE_POR_UMA_CHAVE_GRANDE_E_SECRETA"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440


def gerar_hash_senha(senha: str) -> str:
    senha = senha[:72]
    salt = os.urandom(16)

    senha_hash = hashlib.pbkdf2_hmac(
        "sha256",
        senha.encode("utf-8"),
        salt,
        150000
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
            150000
        )

        return hashlib.compare_digest(novo_hash, hash_salvo)

    except Exception:
        return False


def criar_token(dados: dict) -> str:
    payload = dados.copy()
    expira = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload.update({"exp": expira})

    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)



    


