# Meridian Risk Scoring API

A FastAPI REST layer over the [Meridian MITRE ATLAS/ATT&CK Knowledge Graph](https://github.com/Lamurrz/meridian-atlas-attack-kg),
exposing asset risk scores, attack paths, technique intelligence, threat actor exposure,
control gap analysis, and empirical anomaly evidence via a queryable HTTP API with
auto-generated Swagger UI.

## Why this exists

The Meridian graph answers complex security questions — but only if you can write Cypher.
This API makes the graph consumable by dashboards, CI/CD pipelines, external tools,
and downstream projects (AI CSF Profiler, CyberGraph-AD) without requiring direct
Neo4j access or graph query expertise.

It also serves as the integration point for the Meridian Bridge — receiving empirical
anomaly evidence from CyberGraph-AD and adjusting theoretical risk scores with observed
behavioral signal.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | API and Neo4j connectivity check |
| `GET` | `/assets` | List all assets with current risk scores |
| `GET` | `/assets/{id}/risk` | Full risk breakdown for one asset |
| `GET` | `/assets/{id}/attack-paths` | All threat actor → technique → asset paths |
| `POST` | `/assets/{id}/anomaly-evidence` | Submit CyberGraph-AD anomaly evidence to adjust risk score |
| `GET` | `/assets/{id}/anomaly-evidence` | Retrieve current anomaly evidence for an asset |
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

# Submit anomaly evidence from CyberGraph-AD
curl -X POST http://localhost:8000/assets/api-fraud-inference/anomaly-evidence \
  -H "Content-Type: application/json" \
  -d '{"max_anomaly_score": 7.2, "anomaly_types": ["lateral_movement"], "finding_count": 3}'

# Retrieve stored anomaly evidence
curl http://localhost:8000/assets/api-fraud-inference/anomaly-evidence

# What does APT41 have access to?
curl http://localhost:8000/actors/APT41/assets

# Prompt injection technique detail
curl http://localhost:8000/techniques/AML.T0051

# Control gap report — techniques with no mitigating control
curl http://localhost:8000/controls/gaps
```

## Anomaly evidence and risk score adjustment

The `/assets/{id}/anomaly-evidence` endpoint accepts detection findings from
CyberGraph-AD and adjusts the asset's theoretical risk score using an empirical
anomaly multiplier:

```
R_adjusted = R_theoretical × (1 + anomaly_weight × max_anomaly_score / 10)
```

**Default `anomaly_weight = 0.5`** — a maximum anomaly score of 10.0 doubles the
theoretical risk score. A score of 5.0 increases it by 25%.

The theoretical score (from threat intelligence) is preserved on the `RiskScore` node
alongside the adjusted score so both are available for comparison and audit.

**Example:** An `InferenceAPI` asset with theoretical risk 8.49 and a CyberGraph-AD
anomaly score of 7.2 (lateral movement detection) adjusts to:

```
8.49 × (1 + 0.5 × 7.2/10) = 8.49 × 1.36 = 11.55 → capped at 10.0 (Critical)
```

## Meridian Bridge

`meridian_bridge.py` and `run_bridge.py` in the repo root provide a standalone
bridge that runs CyberGraph-AD → Meridian integration automatically:

```bash
# Dry-run: see what assets would be updated
python run_bridge.py --dry-run

# Run with CyberGraph-AD findings
python run_bridge.py --findings-dir ../cybergraph-ad/data/findings --output enriched_findings.json
```

The bridge performs three operations:

1. **Asset cross-reference** — maps CyberGraph-AD flagged entities to Meridian asset
   nodes by anomaly type → asset type matching
2. **Risk score adjustment** — POSTs anomaly evidence to `/assets/{id}/anomaly-evidence`
3. **TTP enrichment** — attaches ATLAS/ATT&CK technique context from Meridian back to
   each Detection Finding, adding an `enrichment_note` such as:
   `"lateral_movement consistent with: AML.T0043, AML.T0005"`

## Running tests

```bash
pytest tests/ -v
```

## Project structure

```
meridian-api/
├── app/
│   ├── main.py              # FastAPI app, router registration, lifespan
│   ├── config.py            # Settings loaded from .env
│   ├── db/
│   │   └── neo4j.py         # Async Neo4j driver and session management
│   ├── models/
│   │   └── schemas.py       # Pydantic request/response models
│   └── routers/
│       ├── assets.py        # GET/POST /assets, anomaly-evidence endpoints
│       ├── attack_paths.py  # GET /assets/{id}/attack-paths
│       ├── techniques.py    # GET /techniques/{id}
│       ├── actors.py        # GET /actors/{name}/assets
│       └── controls.py      # GET /controls/gaps
├── tests/
│   └── test_api.py          # Pytest suite with mocked Neo4j sessions
├── meridian_bridge.py       # CyberGraph-AD → Meridian integration bridge
├── run_bridge.py            # Bridge CLI entry point
├── run.py                   # Local dev entry point (uvicorn with reload)
├── requirements.txt
└── .env.example
```

## Roadmap

- [ ] Docker + docker-compose (API + Neo4j in one `docker compose up`)
- [ ] What-if control simulation — POST a proposed control, get back delta risk scores
- [ ] Pagination on list endpoints
- [ ] Actor name autocomplete endpoint
- [x] Integration with CyberGraph-AD anomaly scores — anomaly-evidence endpoints + bridge
- [ ] Integration with AI CSF Profiler (CSF subcategory auto-population)

## Related projects

- [Meridian KG](https://github.com/Lamurrz/meridian-atlas-attack-kg) — the MITRE ATLAS/ATT&CK knowledge graph this API queries
- [CyberGraph-AD](https://github.com/Lamurrz/cybergraph-ad) — behavioral anomaly detector that feeds this API
- [OCSF Transformer](https://github.com/Lamurrz/ocsf-transformer) — vendor log normalization layer
- [AI CSF Profiler](https://github.com/Lamurrz/ai-csf-profiler) — compliance layer that consumes this API
- [ArchLens](https://github.com/Lamurrz/arch-lens) — DoDAF security architecture generator

## Background

This project is part of a portfolio demonstrating end-to-end AI security engineering:
normalize security telemetry (OCSF Transformer) → detect behavioral anomalies (CyberGraph-AD)
→ assess threat exposure (Meridian KG + this API) → evaluate framework compliance (AI CSF Profiler)
→ validate detection coverage (Meridian Emulation).
