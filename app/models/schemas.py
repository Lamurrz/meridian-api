from typing import Optional
from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str
    neo4j_connected: bool
    version: str = "0.1.0"


class AssetSummary(BaseModel):
    asset_id: str
    name: str
    asset_type: str
    risk_score: Optional[float] = None
    criticality_multiplier: Optional[float] = None
    exposure_level: Optional[str] = None


class RiskPath(BaseModel):
    actor_name: str
    technique_id: str
    technique_name: str
    attack_vector: str
    path_probability: float
    exploit_maturity: Optional[str] = None
    mitigations_applied: list[str] = []


class AssetRiskDetail(BaseModel):
    asset_id: str
    name: str
    asset_type: str
    risk_score: float
    contributing_paths: int
    top_techniques: list[str]
    active_controls: list[str]
    risk_paths: list[RiskPath]


class AttackPath(BaseModel):
    actor_name: str
    technique_id: str
    technique_name: str
    attack_vector: Optional[str] = None


class AttackPathsResponse(BaseModel):
    asset_id: str
    asset_name: str
    total_paths: int
    paths: list[AttackPath]


class MitigationSummary(BaseModel):
    name: str
    effectiveness: Optional[float] = None


class ExposedAsset(BaseModel):
    asset_id: str
    name: str
    asset_type: str
    risk_score: Optional[float] = None


class TechniqueDetail(BaseModel):
    technique_id: str
    name: str
    description: Optional[str] = None
    tactic: Optional[str] = None
    is_atlas: bool = False
    mitigations: list[MitigationSummary]
    exposed_assets: list[ExposedAsset]


class ActorAsset(BaseModel):
    asset_id: str
    name: str
    asset_type: str
    technique_id: str
    technique_name: str
    risk_score: Optional[float] = None


class ActorAssetsResponse(BaseModel):
    actor_name: str
    total_exposed_assets: int
    assets: list[ActorAsset]


class ControlGap(BaseModel):
    technique_id: str
    technique_name: str
    tactic: Optional[str] = None
    assets_exposed: int
    is_atlas: bool = False


class ControlGapsResponse(BaseModel):
    total_gaps: int
    gaps: list[ControlGap]
