from fastapi import APIRouter

from app.db.neo4j import get_session
from app.models.schemas import ActorAsset, ActorAssetsResponse

router = APIRouter(prefix="/actors", tags=["threat-actors"])


@router.get(
    "/{actor_name}/assets",
    response_model=ActorAssetsResponse,
    summary="All assets exposed to a specific threat actor",
)
async def get_actor_assets(actor_name: str):
    query = """
    MATCH (actor:ThreatActor)-[:USES_TECHNIQUE]->(t:Technique)-[:TARGETS]->(a)
    WHERE toLower(actor.name) = toLower($actor_name)
      AND (a:AIModel OR a:InferenceAPI OR a:TrainingData
           OR a:MLPipeline OR a:ModelRegistry)
    OPTIONAL MATCH (a)-[:SCORED_BY]->(r:RiskScore)
    RETURN
        a.asset_id      AS asset_id,
        a.name          AS name,
        labels(a)[0]    AS asset_type,
        t.external_id   AS technique_id,
        t.name          AS technique_name,
        r.score         AS risk_score
    ORDER BY r.score DESC, a.name ASC
    """

    async with get_session() as session:
        result = await session.run(query, actor_name=actor_name)
        records = await result.data()

    assets = [
        ActorAsset(
            asset_id=r["asset_id"],
            name=r["name"],
            asset_type=r["asset_type"],
            technique_id=r["technique_id"],
            technique_name=r["technique_name"],
            risk_score=round(r["risk_score"], 3) if r["risk_score"] is not None else None,
        )
        for r in records
    ]

    return ActorAssetsResponse(
        actor_name=actor_name,
        total_exposed_assets=len({a.asset_id for a in assets}),
        assets=assets,
    )
