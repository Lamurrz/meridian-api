from fastapi import APIRouter, HTTPException

from app.db.neo4j import get_session
from app.models.schemas import AttackPath, AttackPathsResponse

router = APIRouter(prefix="/assets", tags=["attack-paths"])


@router.get(
    "/{asset_id}/attack-paths",
    response_model=AttackPathsResponse,
    summary="All active threat actor -> technique -> asset paths for one asset",
)
async def get_attack_paths(asset_id: str):
    check_query = """
    MATCH (a {asset_id: $asset_id})
    WHERE a:AIModel OR a:InferenceAPI OR a:TrainingData
       OR a:MLPipeline OR a:ModelRegistry
    RETURN a.name AS name
    """

    paths_query = """
    MATCH (actor:ThreatActor)-[:USES_TECHNIQUE]->(t:Technique)-[:TARGETS]->(a {asset_id: $asset_id})
    RETURN
        actor.name      AS actor_name,
        t.external_id   AS technique_id,
        t.name          AS technique_name,
        t.attack_vector AS attack_vector
    ORDER BY actor.name, t.external_id
    """

    async with get_session() as session:
        check_result = await session.run(check_query, asset_id=asset_id)
        check_records = await check_result.data()

    if not check_records:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found")

    async with get_session() as session:
        paths_result = await session.run(paths_query, asset_id=asset_id)
        paths_records = await paths_result.data()

    paths = [
        AttackPath(
            actor_name=p["actor_name"],
            technique_id=p["technique_id"],
            technique_name=p["technique_name"],
            attack_vector=p["attack_vector"],
        )
        for p in paths_records
    ]

    return AttackPathsResponse(
        asset_id=asset_id,
        asset_name=check_records[0]["name"],
        total_paths=len(paths),
        paths=paths,
    )
