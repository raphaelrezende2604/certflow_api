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

    criado_em = Column(
        DateTime,
        default=datetime.utcnow
    )

    usuario = relationship(
        "Usuario",
        back_populates="dispositivos"
    )

    






    