from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import SessionLocal
from models import AppUpdate
from schemas.update_schema import UpdateCheckRequest


router = APIRouter(tags=["Updates"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def version_to_tuple(version: str):
    return tuple(int(part) for part in version.split("."))


@router.post("/updates/check")
def check_update(
    data: UpdateCheckRequest,
    db: Session = Depends(get_db)
):
    update = (
        db.query(AppUpdate)
        .filter(
            AppUpdate.app_name == data.app_name,
            AppUpdate.ativo == True
        )
        .order_by(AppUpdate.id.desc())
        .first()
    )

    if not update:
        return {
            "app_name": data.app_name,
            "current_version": data.current_version,
            "latest_version": data.current_version,
            "min_required_version": data.current_version,
            "update_available": False,
            "force_update": False,
            "download_url": None,
            "changelog": [],
            "message": "Nenhuma atualização cadastrada."
        }

    current = version_to_tuple(data.current_version)
    latest = version_to_tuple(update.version)
    minimum = version_to_tuple(update.min_required_version)

    update_available = current < latest
    force_update = current < minimum or update.obrigatorio

    return {
        "app_name": data.app_name,
        "current_version": data.current_version,
        "latest_version": update.version,
        "min_required_version": update.min_required_version,
        "update_available": update_available,
        "force_update": force_update,
        "download_url": update.download_url if update_available else None,
        "changelog": update.changelog.splitlines() if update.changelog else [],
        "message": (
            "Atualização obrigatória disponível."
            if force_update
            else "Atualização disponível."
            if update_available
            else "Você já está usando a versão mais recente."
        )
    }