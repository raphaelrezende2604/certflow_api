from pydantic import BaseModel


class UpdateCheckRequest(BaseModel):
    app_name: str = "certflow-desktop"
    current_version: str
    sistema: str | None = None




from pydantic import BaseModel


class UpdateCreateRequest(BaseModel):
    app_name: str = "certflow-desktop"
    version: str
    min_required_version: str
    download_url: str
    changelog: str
    obrigatorio: bool = False


class UpdateStatusRequest(BaseModel):
    update_id: int