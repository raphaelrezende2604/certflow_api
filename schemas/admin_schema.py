from pydantic import BaseModel, EmailStr


class AtivarPagoRequest(BaseModel):
    email: EmailStr
    plano: str = "individual"


class EmailRequest(BaseModel):
    email: EmailStr


class DeviceRequest(BaseModel):
    device_id: str
