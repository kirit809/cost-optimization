# Cloud Cost Guard

A read-only CLI that scans an AWS account for common cost leaks and tagging gaps.

## What it checks
- EC2 instances with low average CPU (from CloudWatch, over a configurable lookback)
- Unattached EBS volumes
- Unassociated Elastic IPs
- EBS snapshots older than a set number of days
- Resources missing required tags

Results are written as JSON, CSV and a short text summary. The tool never modifies anything in your account, and it doesn't guess at dollar savings.

## Setup
Requires Python 3.10+ and AWS credentials (a profile or an instance/workload role).

```bash
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

## Usage
```bash
cloud-cost-guard assess --region us-east-2 --profile my-readonly-profile
```

Several regions at once:
```bash
cloud-cost-guard assess --regions us-east-1,us-east-2 --lookback-days 14 --output-dir reports
```

Custom tag policy:
```bash
cloud-cost-guard assess --region us-east-2 --required-tags Environment,Owner,CostCenter,Application
```

Each run writes `assessment.json`, `findings.csv` and `summary.txt` to the output directory.

## Notes
- Low CPU is just a hint. Check memory, disk, network, schedules and how critical the workload is before resizing anything.
- Confirm owners and retention requirements before removing volumes, IPs or snapshots.
- There are no stop, resize, detach, delete or modify calls anywhere in the code.
- Run it with a dedicated read-only role, and never commit access keys.

## IAM policy
A minimal read-only policy is in `examples/readonly-policy.json`. Adjust it to fit your organization.

## Ideas / TODO
- Pull real amortized cost from Cost Explorer or CUR instead of only flagging resources
- Discover accounts through AWS Organizations (with an allowlist)
- Deliver reports to an encrypted S3 bucket
- More tests and a CI pipeline

## Running tests
```bash
pip install pytest
pytest
```
