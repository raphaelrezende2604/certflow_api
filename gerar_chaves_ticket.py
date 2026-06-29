from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

KEYS_DIR = Path("keys")
KEYS_DIR.mkdir(exist_ok=True)

private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()

private_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

public_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

(KEYS_DIR / "offline_ticket_private.pem").write_bytes(private_bytes)
(KEYS_DIR / "offline_ticket_public.pem").write_bytes(public_bytes)

print("Chaves geradas com sucesso.")
print("Privada: keys/offline_ticket_private.pem")
print("Pública: keys/offline_ticket_public.pem")
