from typing import Optional
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime, timezone


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
"""
Two Pydantic models for the anomaly evidence endpoint.
"""

class AnomalyEvidenceRequest(BaseModel):
    """
    Anomaly evidence payload from CyberGraph-AD.
    POSTed to /assets/{asset_id}/anomaly-evidence by meridian_bridge.py.
    """
    max_anomaly_score: float = Field(
        ...,
        ge=0.0,
        le=10.0,
        description="Highest normalized anomaly score (0-10) across all findings for this asset",
    )
    anomaly_types: list[str] = Field(
        default_factory=list,
        description="Anomaly types observed (e.g. brute_force, lateral_movement)",
    )
    finding_count: int = Field(
        default=1,
        ge=1,
        description="Number of CyberGraph-AD findings implicating this asset",
    )
    adjusted_risk_score: Optional[float] = Field(
        default=None,
        description="Pre-computed adjusted score from bridge (optional — Meridian will recompute)",
    )
    anomaly_weight: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Weight of anomaly evidence in risk adjustment (0=ignore, 1=double at max score)",
    )
    observed_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO-8601 timestamp when anomaly was observed",
    )


class AnomalyEvidenceResponse(BaseModel):
    """
    Response from /assets/{asset_id}/anomaly-evidence POST.
    """
    asset_id: str
    theoretical_risk_score: float = Field(
        description="Original Meridian risk score from threat intelligence",
    )
    adjusted_risk_score: float = Field(
        description="Empirically adjusted risk score after anomaly evidence",
    )
    max_anomaly_score: float
    anomaly_types: list[str]
    finding_count: int
    risk_increase: float = Field(
        description="Absolute increase in risk score (adjusted - theoretical)",
    )
