from datetime import datetime, timedelta, timezone
from .rules import tags_to_dict, missing_tags

class AwsCostAssessor:
    def __init__(self, session, region, lookback_days=14, low_cpu_threshold=5.0,
                 old_snapshot_days=90, required_tags=("Environment", "Owner", "CostCenter")):
        if not 1 <= lookback_days <= 90:
            raise ValueError("lookback_days must be between 1 and 90")
        if not 0 <= low_cpu_threshold <= 100:
            raise ValueError("low_cpu_threshold must be between 0 and 100")
        self.region = region
        self.lookback_days = lookback_days
        self.low_cpu_threshold = low_cpu_threshold
        self.old_snapshot_days = old_snapshot_days
        self.required_tags = tuple(required_tags)
        self.ec2 = session.client("ec2", region_name=region)
        self.cw = session.client("cloudwatch", region_name=region)

    @staticmethod
    def finding(rule, severity, resource_type, resource_id, title, evidence, recommendation):
        return dict(rule_id=rule, severity=severity, resource_type=resource_type,
                    resource_id=resource_id, title=title, evidence=evidence,
                    recommendation=recommendation)

    def tag_findings(self, resource_type, resource_id, tags):
        absent = missing_tags(tags, self.required_tags)
        if not absent:
            return []
        return [self.finding("MISSING_REQUIRED_TAGS", "LOW", resource_type, resource_id,
            "Resource is missing required governance tags", "Missing tags: " + ", ".join(absent),
            "Confirm ownership and apply approved tags using the organization's tagging standard.")]

    def average_cpu(self, instance_id, end):
        response = self.cw.get_metric_statistics(
            Namespace="AWS/EC2", MetricName="CPUUtilization",
            Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
            StartTime=end - timedelta(days=self.lookback_days), EndTime=end,
            Period=3600, Statistics=["Average"])
        points = response.get("Datapoints", [])
        return sum(p["Average"] for p in points) / len(points) if points else None

    def assess(self):
        now = datetime.now(timezone.utc)
        resources, findings = [], []

        for page in self.ec2.get_paginator("describe_instances").paginate():
            for reservation in page.get("Reservations", []):
                for item in reservation.get("Instances", []):
                    rid = item["InstanceId"]
                    tags = tags_to_dict(item.get("Tags"))
                    state = item.get("State", {}).get("Name", "unknown")
                    cpu = self.average_cpu(rid, now) if state == "running" else None
                    local = self.tag_findings("ec2_instance", rid, tags)
                    if cpu is not None and cpu < self.low_cpu_threshold:
                        local.append(self.finding("EC2_LOW_AVERAGE_CPU", "MEDIUM", "ec2_instance", rid,
                            "Review low-average-CPU instance for rightsizing",
                            f"Average CPU was {cpu:.2f}% over {self.lookback_days} days.",
                            "Validate memory, disk, network, latency, batch windows, and workload criticality; test changes in non-production first."))
                    resources.append(dict(resource_type="ec2_instance", resource_id=rid, region=self.region,
                        state=state, instance_type=item.get("InstanceType"), vpc_id=item.get("VpcId"),
                        subnet_id=item.get("SubnetId"), tags=tags,
                        average_cpu_percent=round(cpu, 2) if cpu is not None else None, findings=local))

        for page in self.ec2.get_paginator("describe_volumes").paginate():
            for item in page.get("Volumes", []):
                rid, tags = item["VolumeId"], tags_to_dict(item.get("Tags"))
                local = self.tag_findings("ebs_volume", rid, tags)
                if not item.get("Attachments"):
                    local.append(self.finding("EBS_UNATTACHED_VOLUME", "MEDIUM", "ebs_volume", rid,
                        "Review unattached EBS volume", f"Volume state: {item.get('State')}.",
                        "Confirm owner, recovery requirements, and retention before snapshotting or deleting."))
                resources.append(dict(resource_type="ebs_volume", resource_id=rid, region=self.region,
                    state=item.get("State"), size_gib=item.get("Size"), volume_type=item.get("VolumeType"),
                    encrypted=item.get("Encrypted"), attachments=item.get("Attachments", []),
                    tags=tags, findings=local))

        for item in self.ec2.describe_addresses().get("Addresses", []):
            rid = item.get("AllocationId") or item.get("PublicIp", "unknown")
            tags = tags_to_dict(item.get("Tags"))
            associated = bool(item.get("AssociationId") or item.get("NetworkInterfaceId"))
            local = self.tag_findings("elastic_ip", rid, tags)
            if not associated:
                local.append(self.finding("EIP_UNASSOCIATED", "LOW", "elastic_ip", rid,
                    "Review unassociated Elastic IP", "No network-interface association was found.",
                    "Check failover and deployment plans before releasing the address."))
            resources.append(dict(resource_type="elastic_ip", resource_id=rid, region=self.region,
                public_ip=item.get("PublicIp"), associated=associated, tags=tags, findings=local))

        for page in self.ec2.get_paginator("describe_snapshots").paginate(OwnerIds=["self"]):
            for item in page.get("Snapshots", []):
                rid, tags = item["SnapshotId"], tags_to_dict(item.get("Tags"))
                start = item.get("StartTime")
                age = (now - start.astimezone(timezone.utc)).days if start else None
                local = self.tag_findings("ebs_snapshot", rid, tags)
                if age is not None and age > self.old_snapshot_days:
                    local.append(self.finding("OLD_EBS_SNAPSHOT", "LOW", "ebs_snapshot", rid,
                        "Review snapshot lifecycle", f"Snapshot age is {age} days.",
                        "Validate retention, recovery objectives, AMI dependencies, and backup policy before changing lifecycle."))
                resources.append(dict(resource_type="ebs_snapshot", resource_id=rid, region=self.region,
                    volume_id=item.get("VolumeId"), size_gib=item.get("VolumeSize"), age_days=age,
                    start_time=start.isoformat() if start else None, tags=tags, findings=local))

        for resource in resources:
            findings.extend(resource["findings"])
        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
        findings.sort(key=lambda x: (order.get(x["severity"], 9), x["resource_id"], x["rule_id"]))
        return {
            "metadata": {"tool": "Cloud Cost Guard", "generated_at": now.isoformat(),
                "region": self.region, "lookback_days": self.lookback_days,
                "low_cpu_threshold_percent": self.low_cpu_threshold,
                "old_snapshot_days": self.old_snapshot_days,
                "required_tags": list(self.required_tags), "mode": "read-only; no resources modified"},
            "summary": {"resource_count": len(resources), "finding_count": len(findings),
                "by_severity": {s: sum(1 for f in findings if f["severity"] == s)
                                for s in ("HIGH", "MEDIUM", "LOW", "INFO")}},
            "resources": resources, "findings": findings}
