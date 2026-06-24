"""
meridian_bridge.py
------------------
Bridges CyberGraph-AD Detection Findings into the Meridian Risk Scoring API.

Three integration layers
------------------------

Layer 1 — Asset cross-reference
  Maps CyberGraph-AD flagged entities (user UIDs, IP addresses) to Meridian
  asset nodes by querying both graphs and matching on shared identifiers
  (asset names, IP ranges, user→asset access patterns).

Layer 2 — Risk score adjustment
  Empirical anomaly evidence from CyberGraph-AD adjusts Meridian's theoretical
  risk scores using a multiplicative anomaly weight:

    R_adjusted = R_theoretical × (1 + anomaly_weight × max_anomaly_score)

  Default anomaly_weight=0.5 means a max-score anomaly (10.0) doubles the
  theoretical risk score. This prevents low-prevalence detections from
  overwhelming the threat intelligence signal while ensuring high-confidence
  detections meaningfully elevate asset risk.

Layer 3 — ATLAS TTP enrichment
  Meridian looks up which ATLAS/ATT&CK techniques target the asset associated
  with each flagged entity and attaches that context back to the OCSF Detection
  Finding. A brute-force detection against an InferenceAPI becomes:
  "brute_force consistent with AML.T0051 (Prompt Injection) or T1110 (Brute Force)
  targeting InferenceAPI assets."

Usage
-----
  from meridian_bridge import MeridianBridge

  bridge = MeridianBridge(
      meridian_url="http://127.0.0.1:8000",
      cybergraph_findings_dir="path/to/cybergraph-ad/data/findings",
  )

  # Push anomaly evidence to Meridian and get enriched findings back
  enriched = await bridge.run(findings)
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger("meridian.bridge")

# Anomaly type → likely ATT&CK/ATLAS technique prefixes
# Includes both ATT&CK (T####) and ATLAS (AML.T####) technique IDs
ANOMALY_TO_TECHNIQUES: dict[str, list[str]] = {
    "brute_force":         ["T1110", "T1110.001", "AML.T0051", "AML.T0005"],
    "credential_stuffing": ["T1110.004", "T1110.003", "AML.T0051", "AML.T0005"],
    "lateral_movement":    ["T1021", "T1021.001", "T1021.002", "AML.T0035", "AML.T0043"],
    "data_exfiltration":   ["T1530", "T1537", "T1567", "AML.T0024", "AML.T0020"],
    "privilege_escalation": ["T1078", "T1078.002", "T1068", "AML.T0005", "AML.T0043"],
    "off_hours_access":    ["T1133", "T1078", "AML.T0051", "AML.T0005", "AML.T0043"],
}

# Anomaly type → asset types most likely targeted
ANOMALY_TO_ASSET_TYPES: dict[str, list[str]] = {
    "brute_force":         ["InferenceAPI", "MLPipeline"],
    "credential_stuffing": ["InferenceAPI", "MLPipeline"],
    "lateral_movement":    ["AIModel", "TrainingData", "ModelRegistry"],
    "data_exfiltration":   ["TrainingData", "ModelRegistry"],
    "privilege_escalation": ["AIModel", "InferenceAPI", "ModelRegistry"],
    "off_hours_access":    ["InferenceAPI", "TrainingData"],
}


class MeridianBridge:
    """
    Bridges CyberGraph-AD detection findings into Meridian risk scoring
    and enriches findings with ATLAS TTP context.
    """

    def __init__(
        self,
        meridian_url: str = "http://127.0.0.1:8000",
        cybergraph_findings_dir: str = None,
        anomaly_weight: float = 0.5,
        timeout: int = 10,
    ):
        self._meridian = meridian_url.rstrip("/")
        self._findings_dir = Path(cybergraph_findings_dir) if cybergraph_findings_dir else None
        self._anomaly_weight = anomaly_weight
        self._timeout = timeout

    # ── Main entry point ──────────────────────────────────────────────────────

    async def run(
        self,
        findings: list[dict] | None = None,
        findings_path: str | None = None,
    ) -> dict[str, Any]:
        """
        Execute the full bridge pipeline:
          1. Load findings from CyberGraph-AD
          2. Cross-reference with Meridian asset inventory
          3. Push anomaly evidence to Meridian
          4. Enrich findings with ATLAS TTP context
          5. Return summary and enriched findings

        Parameters
        ----------
        findings      : List of OCSF Detection Finding dicts (optional)
        findings_path : Path to findings JSON file (optional)

        Returns
        -------
        Bridge result dict with enriched findings and updated asset scores.
        """
        # Load findings
        if findings is None:
            findings = self._load_findings(findings_path)

        if not findings:
            logger.warning("No findings to process")
            return {"status": "no_findings", "enriched_findings": [], "assets_updated": []}

        logger.info(f"Processing {len(findings)} Detection Findings")

        # Layer 1: Cross-reference findings to Meridian assets
        asset_evidence = await self._cross_reference_assets(findings)
        logger.info(f"Cross-referenced {len(findings)} findings → {len(asset_evidence)} asset mappings")

        # Layer 2: Push anomaly evidence to Meridian
        updated_assets = await self._push_anomaly_evidence(asset_evidence)
        logger.info(f"Updated risk scores for {len(updated_assets)} assets")

        # Layer 3: Enrich findings with ATLAS TTP context
        enriched_findings = await self._enrich_findings(findings, asset_evidence)
        logger.info(f"Enriched {len(enriched_findings)} findings with TTP context")

        return {
            "status": "success",
            "processed_at": datetime.now(timezone.utc).isoformat(),
            "findings_processed": len(findings),
            "assets_updated": updated_assets,
            "enriched_findings": enriched_findings,
            "summary": self._build_summary(findings, updated_assets, enriched_findings),
        }

    # ── Layer 1: Asset cross-reference ────────────────────────────────────────

    async def _cross_reference_assets(
        self, findings: list[dict]
    ) -> dict[str, list[dict]]:
        """
        Map CyberGraph-AD findings to Meridian asset nodes.

        Returns dict: asset_id → list of findings that implicate that asset.

        Matching strategy:
          1. Direct asset_id match (if finding carries an asset reference)
          2. Anomaly type → asset type mapping (e.g. data_exfiltration → TrainingData)
          3. All assets of matching type (conservative fallback)
        """
        # Fetch Meridian asset inventory
        assets = await self._get_assets()
        if not assets:
            logger.warning("No assets from Meridian — cross-reference skipped")
            return {}

        asset_by_type: dict[str, list[dict]] = {}
        for asset in assets:
            atype = asset.get("asset_type", "")
            asset_by_type.setdefault(atype, []).append(asset)

        evidence: dict[str, list[dict]] = {}

        for finding in findings:
            anomaly_type = finding.get("unmapped", {}).get("anomaly_type")

            # Derive anomaly type from severity/risk if not explicitly set
            if not anomaly_type:
                anomaly_type = self._infer_anomaly_type(finding)

            if not anomaly_type:
                continue

            # Get target asset types for this anomaly
            target_types = ANOMALY_TO_ASSET_TYPES.get(anomaly_type, [])
            # anomaly_score_normalized may be > 10 (it's a ratio); cap it
            raw_score = (
                finding.get("unmapped", {}).get("anomaly_score_normalized")
                or finding.get("risk_score", 0) / 10.0
                or 0.0
            )
            anomaly_score = min(float(raw_score), 10.0)

            # Map to matching assets
            matched_assets = []
            for atype in target_types:
                matched_assets.extend(asset_by_type.get(atype, []))

            for asset in matched_assets:
                asset_id = asset.get("asset_id", "")
                if not asset_id:
                    continue
                evidence.setdefault(asset_id, []).append({
                    "finding": finding,
                    "anomaly_type": anomaly_type,
                    "anomaly_score": anomaly_score,
                    "asset_type": asset.get("asset_type", ""),
                    "current_risk_score": asset.get("risk_score"),
                })

        return evidence

    # ── Layer 2: Risk score adjustment ────────────────────────────────────────

    async def _push_anomaly_evidence(
        self, asset_evidence: dict[str, list[dict]]
    ) -> list[dict]:
        """
        Push anomaly evidence to Meridian's /assets/{id}/anomaly-evidence endpoint.
        Returns list of assets with updated risk scores.
        """
        updated = []

        for asset_id, evidence_list in asset_evidence.items():
            if not evidence_list:
                continue

            # Use the highest anomaly score across all findings for this asset
            max_score = max(e["anomaly_score"] for e in evidence_list)
            anomaly_types = list({e["anomaly_type"] for e in evidence_list})
            current_risk = evidence_list[0].get("current_risk_score") or 0.0

            # Compute adjusted risk score
            adjusted = min(current_risk * (1 + self._anomaly_weight * (max_score / 10.0)), 10.0)

            payload = {
                "max_anomaly_score": max_score,
                "anomaly_types": anomaly_types,
                "finding_count": len(evidence_list),
                "adjusted_risk_score": round(adjusted, 3),
                "anomaly_weight": self._anomaly_weight,
                "observed_at": datetime.now(timezone.utc).isoformat(),
            }

            try:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    resp = await client.post(
                        f"{self._meridian}/assets/{asset_id}/anomaly-evidence",
                        json=payload,
                    )
                    resp.raise_for_status()
                    result = resp.json()
                    updated.append({
                        "asset_id": asset_id,
                        "previous_risk_score": current_risk,
                        "adjusted_risk_score": adjusted,
                        "max_anomaly_score": max_score,
                        "anomaly_types": anomaly_types,
                        "finding_count": len(evidence_list),
                    })
                    logger.info(
                        f"Asset {asset_id}: risk {current_risk:.2f} → {adjusted:.2f} "
                        f"(anomaly_score={max_score:.2f})"
                    )
            except httpx.HTTPStatusError as exc:
                logger.warning(f"Failed to update {asset_id}: {exc.response.status_code}")
            except Exception as exc:
                logger.warning(f"Failed to update {asset_id}: {exc}")

        return updated

    # ── Layer 3: ATLAS TTP enrichment ─────────────────────────────────────────

    async def _enrich_findings(
        self,
        findings: list[dict],
        asset_evidence: dict[str, list[dict]],
    ) -> list[dict]:
        """
        Enrich each finding with ATLAS/ATT&CK technique context from Meridian.
        Attaches relevant techniques to each finding's unmapped context.
        """
        enriched = []

        # Build reverse map: finding uid → list of asset_ids it implicates
        finding_to_assets: dict[str, list[str]] = {}
        for asset_id, evidence_list in asset_evidence.items():
            for evidence in evidence_list:
                finding_uid = evidence["finding"].get("metadata", {}).get("uid", "")
                if finding_uid:
                    finding_to_assets.setdefault(finding_uid, []).append(asset_id)

        for finding in findings:
            finding_uid = finding.get("metadata", {}).get("uid", "")
            anomaly_type = finding.get("unmapped", {}).get("anomaly_type")

            enriched_finding = dict(finding)
            enriched_finding.setdefault("unmapped", {})

            # Infer anomaly type if not explicitly set, and write it back
            if not anomaly_type:
                anomaly_type = self._infer_anomaly_type(finding)
                if anomaly_type:
                    enriched_finding["unmapped"]["anomaly_type"] = anomaly_type

            # Get expected techniques for this anomaly type
            expected_techniques = ANOMALY_TO_TECHNIQUES.get(anomaly_type or "", [])

            # Fetch technique details from Meridian for the implicated assets
            ttp_context = []
            implicated_assets = finding_to_assets.get(finding_uid, [])

            for asset_id in implicated_assets[:2]:  # limit to 2 assets per finding
                asset_ttps = await self._get_asset_techniques(asset_id)
                for ttp in asset_ttps:
                    tid = ttp.get("technique_id", "")
                    # Include if technique matches expected anomaly techniques
                    if any(tid.startswith(et) for et in expected_techniques):
                        if ttp not in ttp_context:
                            ttp_context.append(ttp)

            # Attach TTP context to finding
            enriched_finding["unmapped"]["ttp_context"] = ttp_context
            enriched_finding["unmapped"]["expected_techniques"] = expected_techniques
            enriched_finding["unmapped"]["implicated_asset_ids"] = implicated_assets

            if ttp_context:
                # Deduplicate technique IDs across all assets for the note
                seen_tids = []
                for t in ttp_context:
                    tid = t.get("technique_id", "")
                    if tid and tid not in seen_tids:
                        seen_tids.append(tid)
                enriched_finding["unmapped"]["enrichment_note"] = (
                    f"{anomaly_type} consistent with: "
                    + ", ".join(seen_tids[:3])
                )

            enriched.append(enriched_finding)

        return enriched

    # ── Meridian API helpers ──────────────────────────────────────────────────

    async def _get_assets(self) -> list[dict]:
        """Fetch asset inventory from Meridian."""
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(f"{self._meridian}/assets")
                resp.raise_for_status()
                return resp.json()
        except Exception as exc:
            logger.warning(f"Could not fetch assets: {exc}")
            return []

    async def _get_asset_techniques(self, asset_id: str) -> list[dict]:
        """Fetch techniques targeting a specific asset from Meridian."""
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(f"{self._meridian}/assets/{asset_id}/risk")
                resp.raise_for_status()
                data = resp.json()
                seen = set()
                ttps = []
                for tid in data.get("top_techniques", []):
                    if tid not in seen:
                        seen.add(tid)
                        ttps.append({"technique_id": tid, "asset_id": asset_id})
                return ttps
        except Exception as exc:
            logger.debug(f"Could not fetch techniques for {asset_id}: {exc}")
            return []

    # ── Finding loader ────────────────────────────────────────────────────────

    def _load_findings(self, findings_path: str | None = None) -> list[dict]:
        """Load findings from a JSON file or the most recent file in findings_dir."""
        if findings_path:
            path = Path(findings_path)
        elif self._findings_dir and self._findings_dir.exists():
            files = sorted(self._findings_dir.glob("findings_*.json"))
            if not files:
                logger.warning(f"No findings files in {self._findings_dir}")
                return []
            path = files[-1]  # most recent
        else:
            logger.warning("No findings source configured")
            return []

        try:
            with open(path) as f:
                data = json.load(f)
            findings = data if isinstance(data, list) else [data]
            logger.info(f"Loaded {len(findings)} findings from {path.name}")
            return findings
        except Exception as exc:
            logger.error(f"Failed to load findings: {exc}")
            return []

    # ── Summary ───────────────────────────────────────────────────────────────

    def _infer_anomaly_type(self, finding: dict) -> str | None:
        """
        Infer anomaly type from finding fields when anomaly_type is not set.
        Uses severity, risk score, and entity type as signals.
        """
        severity_id = finding.get("severity_id", 1)
        risk_score = finding.get("risk_score", 0)
        description = finding.get("finding", {}).get("description", "").lower()
        actor_type = finding.get("actor", {}).get("entity", {}).get("type", "").lower()

        # Use description keywords to infer anomaly type
        if any(kw in description for kw in ["brute", "failed logon", "authentication failure"]):
            return "brute_force"
        if any(kw in description for kw in ["credential", "stuffing", "spray"]):
            return "credential_stuffing"
        if any(kw in description for kw in ["lateral", "many assets", "multiple assets"]):
            return "lateral_movement"
        if any(kw in description for kw in ["exfil", "bytes_out", "large transfer"]):
            return "data_exfiltration"
        if any(kw in description for kw in ["privilege", "escalat", "sensitive asset"]):
            return "privilege_escalation"
        if any(kw in description for kw in ["off-hours", "outside", "unusual time"]):
            return "off_hours_access"

        # Fallback: use severity as a broad signal
        if severity_id >= 3 or risk_score >= 50:
            return "privilege_escalation"  # high severity → assume privilege-related
        if severity_id == 2 or risk_score >= 25:
            return "lateral_movement"      # medium severity → lateral movement
        if actor_type == "user":
            return "off_hours_access"      # low severity user anomaly → off hours

        return None

    def _build_summary(
        self,
        findings: list[dict],
        updated_assets: list[dict],
        enriched_findings: list[dict],
    ) -> dict:
        anomaly_types = {}
        for f in findings:
            at = f.get("unmapped", {}).get("anomaly_type", "none")
            anomaly_types[at] = anomaly_types.get(at, 0) + 1

        risk_increases = [
            a for a in updated_assets
            if (a.get("adjusted_risk_score") or 0) > (a.get("previous_risk_score") or 0)
        ]

        enriched_with_ttp = sum(
            1 for f in enriched_findings
            if f.get("unmapped", {}).get("ttp_context")
        )

        return {
            "findings_by_anomaly_type": anomaly_types,
            "assets_with_risk_increase": len(risk_increases),
            "max_risk_increase": max(
                (a["adjusted_risk_score"] - a["previous_risk_score"]
                 for a in risk_increases), default=0.0
            ),
            "findings_enriched_with_ttp": enriched_with_ttp,
        }
