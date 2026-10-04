"""FastAPI-приложение."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from dsc_vfs_solvent import __version__
from dsc_vfs_solvent.api.deps import bootstrap
from dsc_vfs_solvent.api.routes import router
from dsc_vfs_solvent.log import get_logger, setup_logging
from dsc_vfs_solvent.settings import AppSettings

log = get_logger(__name__)

_WEB_DIR = Path(__file__).resolve().parent / "web"


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging(AppSettings.load().log_level)
    bootstrap(AppSettings.load())
    log.info("dsc-vfs-solvent v%s запущен", __version__)
    yield


app = FastAPI(
    title="dsc-vfs-solvent API",
    description="REST API клиента децентрализованного хранения данных",
    version=__version__,
    lifespan=lifespan,
)

app.include_router(router)


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(_WEB_DIR / "index.html")


if _WEB_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=_WEB_DIR), name="static")