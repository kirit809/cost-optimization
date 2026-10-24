import csv, json
from pathlib import Path

FIELDS = ["severity", "rule_id", "resource_type", "resource_id", "title", "evidence", "recommendation"]

def write_reports(report, output_dir):
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "assessment.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    with (out / "findings.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows({key: row.get(key, "") for key in FIELDS} for row in report["findings"])
    summary = report["summary"]
    meta = report["metadata"]
    text = [
        "Cloud Cost Guard — Assessment Summary", f"Generated: {meta['generated_at']}",
        f"Region: {meta['region']}", f"Mode: {meta['mode']}", "",
        f"Resources assessed: {summary['resource_count']}", f"Findings: {summary['finding_count']}",
        *(f"{level.title()}: {count}" for level, count in summary["by_severity"].items()),
        "", "No resources were modified. Findings require human review."]
    (out / "summary.txt").write_text("\n".join(text) + "\n", encoding="utf-8")
