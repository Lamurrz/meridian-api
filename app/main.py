from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from app.config import settings
from app.db.neo4j import get_driver, close_driver, verify_connectivity
from app.models.schemas import HealthResponse
from app.routers import assets, attack_paths, techniques, actors, controls


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    await close_driver()


app = FastAPI(
    title="Meridian Risk Scoring API",
    description=(
        "REST query layer over the Meridian MITRE ATLAS/ATT&CK knowledge graph. "
        "Exposes asset risk scores, attack paths, technique details, threat actor exposure, "
        "and control gap analysis from a Neo4j property graph."
    ),
    version="0.1.0",
    contact={
        "name": "Lori Murray, Ph.D.",
        "url": "https://github.com/Lamurrz",
    },
    license_info={"name": "MIT"},
    lifespan=lifespan,
)

app.include_router(assets.router)
app.include_router(attack_paths.router)
app.include_router(techniques.router)
app.include_router(actors.router)
app.include_router(controls.router)


@app.get("/health", response_model=HealthResponse, tags=["health"], summary="API and Neo4j connectivity check")
async def health():
    from app.config import settings
    print(f"DEBUG URI: {settings.neo4j_uri}")
    print(f"DEBUG PASS: {settings.neo4j_password[:8]}")
    connected = await verify_connectivity()
    status_code = 200 if connected else 503
    return JSONResponse(
        status_code=status_code,
        content=HealthResponse(
            status="ok" if connected else "degraded",
            neo4j_connected=connected,
        ).model_dump(),
    )


@app.get("/", include_in_schema=False)
async def root():
    return {
        "service": "Meridian Risk Scoring API",
        "version": "0.1.0",
        "docs": "/docs",
        "health": "/health",
    }
