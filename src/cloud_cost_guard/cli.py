import argparse, sys
import boto3
from botocore.exceptions import BotoCoreError, ClientError
from .assessor import AwsCostAssessor
from .reporting import write_reports

def main():
    parser = argparse.ArgumentParser(description="Read-only AWS cost and governance assessment")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("assess")
    p.add_argument("--region")
    p.add_argument("--regions")
    p.add_argument("--profile")
    p.add_argument("--lookback-days", type=int, default=14)
    p.add_argument("--low-cpu-threshold", type=float, default=5.0)
    p.add_argument("--old-snapshot-days", type=int, default=90)
    p.add_argument("--required-tags", default="Environment,Owner,CostCenter")
    p.add_argument("--output-dir", default="reports")
    args = parser.parse_args()
    regions = [x.strip() for x in args.regions.split(",") if x.strip()] if args.regions else []
    if not regions and args.region:
        regions = [args.region]
    if not regions:
        parser.error("provide --region or --regions")
    session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()
    required = tuple(x.strip() for x in args.required_tags.split(",") if x.strip())
    for region in regions:
        try:
            report = AwsCostAssessor(session, region, args.lookback_days,
                args.low_cpu_threshold, args.old_snapshot_days, required).assess()
            out = args.output_dir if len(regions) == 1 else f"{args.output_dir}/{region}"
            write_reports(report, out)
            print(f"{region}: {report['summary']['resource_count']} resources, "
                  f"{report['summary']['finding_count']} findings -> {out}")
        except (ClientError, BotoCoreError, ValueError) as exc:
            print(f"Assessment failed for {region}: {exc}", file=sys.stderr)
            return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
