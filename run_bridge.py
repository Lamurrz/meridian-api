"""
run_bridge.py
-------------
CLI entry point for the Meridian bridge.

Usage
-----
# Run bridge with most recent CyberGraph-AD findings
python run_bridge.py

# Run with a specific findings file
python run_bridge.py --findings path/to/findings.json

# Run and save enriched findings
python run_bridge.py --output enriched_findings.json

# Dry-run: show what would be updated without pushing to Meridian
python run_bridge.py --dry-run
"""

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("bridge")


async def main(args):
    from meridian_bridge import MeridianBridge

    bridge = MeridianBridge(
        meridian_url=args.meridian_url,
        cybergraph_findings_dir=args.findings_dir,
        anomaly_weight=args.anomaly_weight,
    )

    # Load findings
    findings = None
    if args.findings:
        with open(args.findings) as f:
            data = json.load(f)
        findings = data if isinstance(data, list) else [data]
        logger.info(f"Loaded {len(findings)} findings from {args.findings}")

    if args.dry_run:
        logger.info("DRY-RUN mode — cross-referencing assets without pushing to Meridian")
        assets = await bridge._get_assets()
        if not assets:
            print("No assets available from Meridian — is the API running?")
            sys.exit(1)

        print(f"\nMeridian assets: {len(assets)}")
        for a in assets:
            print(f"  {a.get('asset_id','?'):30} {a.get('asset_type','?'):15} "
                  f"risk={a.get('risk_score') or '—'}")

        if findings:
            evidence = await bridge._cross_reference_assets(findings)
            print(f"\nFindings would update {len(evidence)} assets:")
            for asset_id, ev_list in evidence.items():
                max_score = max(e["anomaly_score"] for e in ev_list)
                types = {e["anomaly_type"] for e in ev_list}
                print(f"  {asset_id}: max_score={max_score:.2f}  types={types}")
        return

    # Full run
    result = await bridge.run(findings=findings)

    # Print summary
    summary = result.get("summary", {})
    print(f"\n{'='*50}")
    print(f"  Meridian Bridge — {result.get('status', 'unknown').upper()}")
    print(f"{'='*50}")
    print(f"  Findings processed:      {result.get('findings_processed', 0)}")
    print(f"  Assets updated:          {len(result.get('assets_updated', []))}")
    print(f"  Enriched with TTP:       {summary.get('findings_enriched_with_ttp', 0)}")
    print(f"  Assets with risk increase: {summary.get('assets_with_risk_increase', 0)}")

    updated = result.get("assets_updated", [])
    if updated:
        print(f"\n  Risk score updates:")
        for a in updated:
            delta = a["adjusted_risk_score"] - a["previous_risk_score"]
            print(f"    {a['asset_id']:30} "
                  f"{a['previous_risk_score']:.2f} → {a['adjusted_risk_score']:.2f} "
                  f"(+{delta:.2f})")

    # Save enriched findings
    if args.output:
        output_path = Path(args.output)
        with open(output_path, "w") as f:
            json.dump(result.get("enriched_findings", []), f, indent=2)
        print(f"\n  Enriched findings → {output_path}")

    print(f"{'='*50}\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Meridian Bridge — CyberGraph-AD → Meridian")
    parser.add_argument("--meridian-url", default="http://127.0.0.1:8000",
                        help="Meridian Risk API URL")
    parser.add_argument("--findings", default=None,
                        help="Path to CyberGraph-AD findings JSON file")
    parser.add_argument("--findings-dir", default=None,
                        help="Directory containing CyberGraph-AD findings files")
    parser.add_argument("--anomaly-weight", type=float, default=0.5,
                        help="Anomaly weight for risk adjustment (0-1, default: 0.5)")
    parser.add_argument("--output", default=None,
                        help="Save enriched findings to this path")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be updated without pushing to Meridian")

    args = parser.parse_args()
    asyncio.run(main(args))
