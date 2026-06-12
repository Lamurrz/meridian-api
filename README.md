# Meridian Risk Scoring API

A FastAPI REST layer over the [Meridian MITRE ATLAS/ATT&CK Knowledge Graph](https://github.com/Lamurrz/meridian),
exposing asset risk scores, attack paths, technique intelligence, threat actor exposure,
and control gap analysis via a queryable HTTP API with auto-generated Swagger UI.

## Why this exists

The Meridian graph answers complex security questions — but only if you can write Cypher.
This API makes the graph consumable by dashboards, CI/CD pipelines, external tools,
and downstream projects (AI CSF Profiler, CyberGraph-AD) without requiring direct
Neo4j access or graph query expertise.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | API and Neo4j connectivity check |
| `GET` | `/assets` | List all assets with current risk scores |
| `GET` | `/assets/{id}/risk` | Full risk breakdown for one asset |
| `GET` | `/assets/{id}/attack-paths` | All threat actor → technique → asset paths |
| `GET` | `/techniques/{id}` | Technique detail with mitigations and exposed assets |
| `GET` | `/actors/{name}/assets` | All assets exposed to a specific threat actor |
| `GET` | `/controls/gaps` | Techniques targeting assets with no mitigating control |

Swagger UI is available at `http://localhost:8000/docs` after startup.

## Quick start

**Prerequisites:** Python 3.11+, Neo4j 5.x running with the Meridian graph loaded.

```bash
git clone https://github.com/Lamurrz/meridian-api.git
cd meridian-api

python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install -r requirements.txt

cp .env.example .env               # then edit .env with your Neo4j credentials

python run.py
```

Open `http://localhost:8000/docs` — the Swagger UI lists all endpoints
with request/response schemas and a live "Try it out" button.

## Configuration

All settings are loaded from `.env` (see `.env.example`):

| Variable | Default | Description |
|----------|---------|-------------|
| `NEO4J_URI` | `bolt://localhost:7687` | Neo4j connection URI |
| `NEO4J_USER` | `neo4j` | Neo4j username |
| `NEO4J_PASSWORD` | — | Neo4j password |
| `API_HOST` | `127.0.0.1` | Bind address |
| `API_PORT` | `8000` | Listen port |
| `LOG_LEVEL` | `info` | Uvicorn log level |

## Example queries

```bash
# Health check
curl http://localhost:8000/health

# List all assets sorted by risk score
curl http://localhost:8000/assets

# Full risk breakdown for the fraud inference API
curl http://localhost:8000/assets/api-fraud-inference/risk

# All attack paths to that asset
curl http://localhost:8000/assets/api-fraud-inference/attack-paths

# What does APT41 have access to?
curl http://localhost:8000/actors/APT41/assets

# Prompt injection technique detail
curl http://localhost:8000/techniques/AML.T0051

# Control gap report — techniques with no mitigating control
curl http://localhost:8000/controls/gaps
```

## Running tests

```bash
pytest tests/ -v
```

## Project structure

```
meridian-api/
├── app/
│   ├── main.py          # FastAPI app, router registration, lifespan
│   ├── config.py        # Settings loaded from .env
│   ├── db/
│   │   └── neo4j.py     # Async Neo4j driver and session management
│   ├── models/
│   │   └── schemas.py   # Pydantic request/response models
│   └── routers/
│       ├── assets.py        # GET /assets, GET /assets/{id}/risk
│       ├── attack_paths.py  # GET /assets/{id}/attack-paths
│       ├── techniques.py    # GET /techniques/{id}
│       ├── actors.py        # GET /actors/{name}/assets
│       └── controls.py      # GET /controls/gaps
├── tests/
│   └── test_api.py      # Pytest suite with mocked Neo4j sessions
├── run.py               # Local dev entry point (uvicorn with reload)
├── requirements.txt
└── .env.example
```

## Roadmap

- [ ] Docker + docker-compose (API + Neo4j in one `docker compose up`)
- [ ] What-if control simulation — POST a proposed control, get back delta risk scores
- [ ] Pagination on list endpoints
- [ ] Actor name autocomplete endpoint
- [ ] Integration with CyberGraph-AD anomaly scores (Detect subcategory evidence)
- [ ] Integration with AI CSF Profiler (CSF subcategory auto-population)

## Related projects

- [Meridian](https://github.com/Lamurrz/meridian) — the MITRE ATLAS/ATT&CK knowledge graph this API queries
- [OCSF Transformer](https://github.com/Lamurrz/ocsf-transformer) — vendor log normalization layer
- [ArchLens](https://github.com/Lamurrz/arch-lens) — DoDAF security architecture generator

## Background

This project is part of a portfolio demonstrating end-to-end AI security engineering:
normalize security telemetry (OCSF Transformer) → detect behavioral anomalies (CyberGraph-AD)
→ assess threat exposure (Meridian + this API) → evaluate framework compliance (AI CSF Profiler).
