from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime

from database import Base


class Usuario(Base):
    __tablename__ = "usuarios"

    id = Column(Integer, primary_key=True, index=True)
    nome = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    senha_hash = Column(String, nullable=False)
    ativo = Column(Boolean, default=True)
    criado_em = Column(DateTime, default=datetime.utcnow)

    licenca = relationship(
        "Licenca",
        back_populates="usuario",
        uselist=False
    )

    dispositivos = relationship(
        "Dispositivo",
        back_populates="usuario"
    )


class Licenca(Base):
    __tablename__ = "licencas"

    id = Column(Integer, primary_key=True, index=True)

    usuario_id = Column(
        Integer,
        ForeignKey("usuarios.id")
    )

    plano = Column(String, default="trial")
    status = Column(String, default="trial")

    limite_dispositivos = Column(Integer, default=1)

    expira_em = Column(
        DateTime,
        nullable=False
    )

    usuario = relationship(
        "Usuario",
        back_populates="licenca"
    )


class Dispositivo(Base):
    __tablename__ = "dispositivos"

    id = Column(Integer, primary_key=True, index=True)

    usuario_id = Column(
        Integer,
        ForeignKey("usuarios.id")
    )

    device_id = Column(String, nullable=False)

    nome_maquina = Column(String)
    sistema = Column(String)

    ativo = Column(Boolean, default=True)
    fingerprint = Column(String)
    ultimo_ip = Column(String)
    ultimo_acesso = Column(DateTime)
    
    criado_em = Column(
        DateTime,
        default=datetime.utcnow
    )

    usuario = relationship(
        "Usuario",
        back_populates="dispositivos"
    )


class OfflineTicket(Base):
    __tablename__ = "offline_tickets"

    id = Column(Integer, primary_key=True, index=True)

    ticket_id = Column(String, unique=True, index=True, nullable=False)

    usuario_id = Column(
        Integer,
        ForeignKey("usuarios.id")
    )

    device_id = Column(String, nullable=False)
    fingerprint = Column(String)

    emitido_em = Column(DateTime, default=datetime.utcnow)
    valido_ate = Column(DateTime, nullable=False)

    revogado = Column(Boolean, default=False)
    revogado_em = Column(DateTime)
    motivo_revogacao = Column(String)   

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)

    usuario_id = Column(Integer, nullable=True)
    email = Column(String, nullable=True)

    event_code = Column(String, nullable=False)
    event_type = Column(String, nullable=False)
    message = Column(String, nullable=False)

    ip = Column(String, nullable=True)
    device_id = Column(String, nullable=True)
    fingerprint = Column(String, nullable=True)

    metadata_json = Column(String, nullable=True)

    criado_em = Column(DateTime, default=datetime.utcnow)


class AppUpdate(Base):
    __tablename__ = "app_updates"

    id = Column(Integer, primary_key=True, index=True)

    app_name = Column(String, default="certflow-desktop")
    version = Column(String, nullable=False)
    min_required_version = Column(String, nullable=False)

    download_url = Column(String, nullable=False)
    changelog = Column(String)

    ativo = Column(Boolean, default=True)
    obrigatorio = Column(Boolean, default=False)

    criado_em = Column(DateTime, default=datetime.utcnow)


    