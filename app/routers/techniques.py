from fastapi import APIRouter, HTTPException

from app.db.neo4j import get_session
from app.models.schemas import TechniqueDetail, MitigationSummary, ExposedAsset

router = APIRouter(prefix="/techniques", tags=["techniques"])


@router.get(
    "/{technique_id}",
    response_model=TechniqueDetail,
    summary="Technique detail with mitigations and exposed assets",
)
async def get_technique(technique_id: str):
    detail_query = """
    MATCH (t:Technique {external_id: $technique_id})
    OPTIONAL MATCH (tac:Tactic)<-[:BELONGS_TO_TACTIC]-(t)
    RETURN
        t.external_id   AS technique_id,
        t.name          AS name,
        t.description   AS description,
        tac.name        AS tactic,
        t.is_atlas      AS is_atlas
    """

    mitigations_query = """
    MATCH (mc:MitigationControl)-[rel:MITIGATES]->(t:Technique {external_id: $technique_id})
    RETURN
        mc.name             AS name,
        rel.effectiveness   AS effectiveness
    ORDER BY mc.name
    """

    assets_query = """
    MATCH (t:Technique {external_id: $technique_id})-[:TARGETS]->(a)
    WHERE a:AIModel OR a:InferenceAPI OR a:TrainingData
       OR a:MLPipeline OR a:ModelRegistry
    OPTIONAL MATCH (a)-[:SCORED_BY]->(r:RiskScore)
    RETURN
        a.asset_id      AS asset_id,
        a.name          AS name,
        labels(a)[0]    AS asset_type,
        r.score         AS risk_score
    ORDER BY r.score DESC, a.name ASC
    """

    async with get_session() as session:
        detail_result = await session.run(detail_query, technique_id=technique_id)
        detail_records = await detail_result.data()

    if not detail_records:
        raise HTTPException(status_code=404, detail=f"Technique '{technique_id}' not found")

    async with get_session() as session:
        mit_result = await session.run(mitigations_query, technique_id=technique_id)
        mit_records = await mit_result.data()

    async with get_session() as session:
        assets_result = await session.run(assets_query, technique_id=technique_id)
        assets_records = await assets_result.data()

    d = detail_records[0]

    return TechniqueDetail(
        technique_id=d["technique_id"],
        name=d["name"],
        description=d["description"],
        tactic=d["tactic"],
        is_atlas=d["is_atlas"] or False,
        mitigations=[
            MitigationSummary(
                name=m["name"],
                effectiveness=round(m["effectiveness"], 3) if m["effectiveness"] is not None else None,
            )
            for m in mit_records
        ],
        exposed_assets=[
            ExposedAsset(
                asset_id=a["asset_id"],
                name=a["name"],
                asset_type=a["asset_type"],
                risk_score=round(a["risk_score"], 3) if a["risk_score"] is not None else None,
            )
            for a in assets_records
        ],
    )
