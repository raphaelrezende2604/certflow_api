from pydantic import BaseModel, EmailStr


class HeartbeatRequest(BaseModel):
    email: EmailStr
    device_id: str
    fingerprint: str | None = None
    app_version: str | None = None
    sistema: str | None = None
