from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text

from app.database import Base, SessionLocal, engine, ensure_schema
from app.routers import alerts, email, ioc, logs, auth, detect, reports, sigma, playbooks, providers, mitre

BASE_DIR = Path(__file__).resolve().parent
Base.metadata.create_all(bind=engine)
ensure_schema()

app = FastAPI(title="SOC Analyst Toolkit", version="1.0.0")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
app.include_router(ioc.router)
app.include_router(email.router)
app.include_router(logs.router)
app.include_router(alerts.router)
app.include_router(auth.router)
app.include_router(detect.router)
app.include_router(reports.router)
app.include_router(sigma.router)
app.include_router(playbooks.router)
app.include_router(providers.router)
app.include_router(mitre.router)


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(
        BASE_DIR / "static" / "index.html",
        headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"},
    )


@app.get("/health")
def health() -> dict[str, str]:
    with SessionLocal() as db:
        db.execute(text("SELECT 1"))
    return {"status": "ok", "database": "ok"}
