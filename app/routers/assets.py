from fastapi import APIRouter, HTTPException

from app.db.neo4j import get_session
from app.models.schemas import AssetSummary, AssetRiskDetail, RiskPath

router = APIRouter(prefix="/assets", tags=["assets"])


@router.get("", response_model=list[AssetSummary], summary="List all assets with current risk scores")
async def list_assets():
    query = """
    MATCH (a)
    WHERE a:AIModel OR a:InferenceAPI OR a:TrainingData
       OR a:MLPipeline OR a:ModelRegistry
    OPTIONAL MATCH (a)-[:SCORED_BY]->(r:RiskScore)
    RETURN
        a.asset_id        AS asset_id,
        a.name            AS name,
        labels(a)[0]      AS asset_type,
        r.score           AS risk_score,
        a.criticality_multiplier AS criticality_multiplier,
        a.exposure_level  AS exposure_level
    ORDER BY r.score DESC, a.name ASC
    """
    async with get_session() as session:
        result = await session.run(query)
        records = await result.data()

    return [
        AssetSummary(
            asset_id=r["asset_id"] or "",
            name=r["name"] or "",
            asset_type=r["asset_type"] or "",
            risk_score=round(r["risk_score"], 3) if r["risk_score"] is not None else None,
            criticality_multiplier=r["criticality_multiplier"],
            exposure_level=r["exposure_level"],
        )
        for r in records
    ]


@router.get("/{asset_id}/risk", response_model=AssetRiskDetail, summary="Full risk breakdown for one asset")
async def get_asset_risk(asset_id: str):
    detail_query = """
    MATCH (a {asset_id: $asset_id})
    WHERE a:AIModel OR a:InferenceAPI OR a:TrainingData
       OR a:MLPipeline OR a:ModelRegistry
    OPTIONAL MATCH (a)-[:SCORED_BY]->(r:RiskScore)
    RETURN
        a.asset_id   AS asset_id,
        a.name       AS name,
        labels(a)[0] AS asset_type,
        r.score               AS risk_score,
        r.contributing_paths  AS contributing_paths
    """

    techniques_query = """
    MATCH (t:Technique)-[:TARGETS]->(a {asset_id: $asset_id})
    RETURN t.external_id AS technique_id, t.name AS technique_name
    ORDER BY t.external_id
    LIMIT 10
    """

    controls_query = """
    MATCH (mc:MitigationControl)-[:MITIGATES]->(t:Technique)-[:TARGETS]->(a {asset_id: $asset_id})
    RETURN DISTINCT mc.name AS control_name
    ORDER BY mc.name
    """

    paths_query = """
    MATCH (actor:ThreatActor)-[:USES_TECHNIQUE]->(t:Technique)-[:TARGETS]->(a {asset_id: $asset_id})
    OPTIONAL MATCH (mc:MitigationControl)-[:MITIGATES]->(t)
    OPTIONAL MATCH (t)-[:EXPLOITS]->(v:Vulnerability)
    RETURN
        actor.name          AS actor_name,
        t.external_id       AS technique_id,
        t.name              AS technique_name,
        t.attack_vector     AS attack_vector,
        v.exploit_maturity  AS exploit_maturity,
        collect(DISTINCT mc.name) AS mitigations
    ORDER BY actor.name, t.external_id
    """

    async with get_session() as session:
        detail_result = await session.run(detail_query, asset_id=asset_id)
        detail_records = await detail_result.data()

    if not detail_records:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found")

    async with get_session() as session:
        techniques_result = await session.run(techniques_query, asset_id=asset_id)
        techniques_records = await techniques_result.data()

    async with get_session() as session:
        controls_result = await session.run(controls_query, asset_id=asset_id)
        controls_records = await controls_result.data()

    async with get_session() as session:
        paths_result = await session.run(paths_query, asset_id=asset_id)
        paths_records = await paths_result.data()

    d = detail_records[0]
    risk_score = round(d["risk_score"], 3) if d["risk_score"] is not None else 0.0

    risk_paths = [
        RiskPath(
            actor_name=p["actor_name"],
            technique_id=p["technique_id"],
            technique_name=p["technique_name"],
            attack_vector=p["attack_vector"] or "unknown",
            path_probability=0.0,
            exploit_maturity=p["exploit_maturity"],
            mitigations_applied=p["mitigations"] or [],
        )
        for p in paths_records
    ]

    return AssetRiskDetail(
        asset_id=d["asset_id"],
        name=d["name"],
        asset_type=d["asset_type"],
        risk_score=risk_score,
        contributing_paths=d["contributing_paths"] or len(risk_paths),
        top_techniques=[r["technique_id"] for r in techniques_records],
        active_controls=[r["control_name"] for r in controls_records],
        risk_paths=risk_paths,
    )
