from fastapi import APIRouter

from app.db.neo4j import get_session
from app.models.schemas import ControlGap, ControlGapsResponse

router = APIRouter(prefix="/controls", tags=["controls"])


@router.get(
    "/gaps",
    response_model=ControlGapsResponse,
    summary="Techniques that target assets but have no mitigating control",
)
async def get_control_gaps():
    query = """
    MATCH (t:Technique)-[:TARGETS]->(a)
    WHERE (a:AIModel OR a:InferenceAPI OR a:TrainingData
           OR a:MLPipeline OR a:ModelRegistry)
      AND NOT t.is_revoked
      AND NOT (:MitigationControl)-[:MITIGATES]->(t)
    OPTIONAL MATCH (t)-[:BELONGS_TO_TACTIC]->(tac:Tactic)
    RETURN
        t.external_id   AS technique_id,
        t.name          AS technique_name,
        tac.name        AS tactic,
        t.is_atlas      AS is_atlas,
        count(DISTINCT a) AS assets_exposed
    ORDER BY assets_exposed DESC, t.external_id ASC
    """

    async with get_session() as session:
        result = await session.run(query)
        records = await result.data()

    gaps = [
        ControlGap(
            technique_id=r["technique_id"],
            technique_name=r["technique_name"],
            tactic=r["tactic"],
            is_atlas=r["is_atlas"] or False,
            assets_exposed=r["assets_exposed"],
        )
        for r in records
    ]

    return ControlGapsResponse(total_gaps=len(gaps), gaps=gaps)
