"""The IaCGuard rule set.

A rule inspects one parsed Terraform block and returns a short detail string
when the block violates it, or None when it does not. Rules are registered by
decorator so adding one never means touching the engine.
"""

import re
from dataclasses import dataclass, field
from typing import Callable, Optional

CRITICAL, HIGH, MEDIUM, LOW = "CRITICAL", "HIGH", "MEDIUM", "LOW"

OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
DB_PORTS = {3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB",
            6379: "Redis", 1433: "MSSQL", 9200: "Elasticsearch"}
SECRET_KEYS = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|private[_-]?key|"
    r"access[_-]?key|credential)", re.I
)
# A value that is clearly a reference or lookup, not a literal secret.
INTERPOLATED = re.compile(r"\$\{|^(var|local|data|aws_|module)\.")


@dataclass
class Rule:
    id: str
    severity: str
    title: str
    rationale: str
    applies_to: str
    check: Callable = field(repr=False)


RULES: list[Rule] = []


def rule(id, severity, title, rationale, applies_to):
    def wrap(fn):
        RULES.append(Rule(id, severity, title, rationale, applies_to, fn))
        return fn
    return wrap


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def truthy(value) -> bool:
    """HCL booleans arrive as real bools or as the strings 'true'/'false'."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return False


def blocks(body: dict, key: str) -> list[dict]:
    """Nested blocks may be a single dict or a list of dicts."""
    value = body.get(key)
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    return []


def as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def is_open(cidrs) -> bool:
    return any(str(c) in OPEN_CIDRS for c in as_list(cidrs))


def port_range(block: dict) -> tuple[int, int]:
    def num(key):
        try:
            return int(block.get(key, 0))
        except (TypeError, ValueError):
            return 0
    return num("from_port"), num("to_port")


def covers(block: dict, port: int) -> bool:
    lo, hi = port_range(block)
    return lo <= port <= hi


def companion(doc, type_: str, owner: str) -> bool:
    """True when a separate resource of `type_` references `owner`.

    Modern Terraform splits S3 settings into sibling resources, so a missing
    inline attribute is only a finding if no sibling supplies it either.
    """
    for res in doc.resources:
        if res["type"] != type_:
            continue
        if owner in str(res["body"].get("bucket", "")):
            return True
    return False


def policy_text(body: dict) -> str:
    """Flatten whatever carries an IAM policy document into searchable text."""
    parts = [body.get(k) for k in ("policy", "assume_role_policy",
                                   "policy_document", "inline_policy")]
    return " ".join(str(p) for p in parts if p)


def grants_wildcard(text: str, key: str) -> bool:
    """True when `key` is set to "*" in an IAM policy document.

    A policy reaches us in one of two shapes. A heredoc or file() gives real
    JSON (``"Action": "*"``), while jsonencode() survives HCL parsing as an
    interpolation holding HCL syntax (``Action = "*"``). Both spellings, and
    the single-element list form, mean the same thing, so one regex covers
    assignment by either ':' or '=' and an optional surrounding list.

    A JSON document embedded in an HCL string arrives still escaped
    (``\\"Action\\"``), so backslashes are dropped before matching rather
    than being accounted for in the pattern.
    """
    text = text.replace("\\", "")
    pattern = (
        r'["\']?' + key + r'["\']?'   # Action / "Action"
        r'\s*[:=]\s*'                    # : or =
        r'(?:\[\s*)?'                    # optional [
        r'["\']\*["\']'               # "*"
    )
    return re.search(pattern, text, re.I) is not None


# --------------------------------------------------------------------------
# S3
# --------------------------------------------------------------------------

@rule("IAC001", CRITICAL, "S3 bucket is world-readable",
      "A public ACL exposes every object in the bucket to the open internet, "
      "which is the single most common cause of cloud data breaches.",
      "aws_s3_bucket")
def _(res, doc):
    acl = str(res["body"].get("acl", ""))
    if acl in ("public-read", "public-read-write", "authenticated-read"):
        return f"acl = \"{acl}\""
    return None


@rule("IAC002", HIGH, "S3 bucket has no server-side encryption",
      "Objects are stored unencrypted at rest, so anyone who obtains the "
      "underlying storage or a stale backup can read them directly.",
      "aws_s3_bucket")
def _(res, doc):
    if res["body"].get("server_side_encryption_configuration"):
        return None
    if companion(doc, "aws_s3_bucket_server_side_encryption_configuration",
                 res["name"]):
        return None
    return "no server_side_encryption_configuration"


@rule("IAC003", MEDIUM, "S3 bucket versioning is disabled",
      "Without versioning, an accidental delete or a ransomware overwrite is "
      "unrecoverable.",
      "aws_s3_bucket")
def _(res, doc):
    for block in blocks(res["body"], "versioning"):
        if truthy(block.get("enabled")):
            return None
    if companion(doc, "aws_s3_bucket_versioning", res["name"]):
        return None
    return "versioning not enabled"


@rule("IAC004", HIGH, "S3 bucket has no public access block",
      "The account-level guardrail that refuses public ACLs and policies is "
      "absent, so a later change can silently make the bucket public.",
      "aws_s3_bucket")
def _(res, doc):
    if companion(doc, "aws_s3_bucket_public_access_block", res["name"]):
        return None
    return "no aws_s3_bucket_public_access_block for this bucket"


@rule("IAC005", LOW, "S3 bucket access logging is disabled",
      "Without access logs there is no record of who read or wrote objects, "
      "which blocks any later incident investigation.",
      "aws_s3_bucket")
def _(res, doc):
    if res["body"].get("logging") or companion(
            doc, "aws_s3_bucket_logging", res["name"]):
        return None
    return "no logging configuration"


@rule("IAC006", HIGH, "Public access block does not block everything",
      "Leaving any of the four flags false defeats the guardrail; all four "
      "should be true unless the bucket is deliberately a public website.",
      "aws_s3_bucket_public_access_block")
def _(res, doc):
    flags = ("block_public_acls", "ignore_public_acls",
             "block_public_policy", "restrict_public_buckets")
    weak = [f for f in flags if not truthy(res["body"].get(f))]
    return f"not enabled: {', '.join(weak)}" if weak else None


# --------------------------------------------------------------------------
# Security groups
# --------------------------------------------------------------------------

@rule("IAC010", CRITICAL, "SSH is open to the entire internet",
      "Port 22 reachable from 0.0.0.0/0 invites continuous automated "
      "credential-stuffing; SSH should come through a bastion or SSM.",
      "aws_security_group")
def _(res, doc):
    for ing in blocks(res["body"], "ingress"):
        if is_open(ing.get("cidr_blocks")) and covers(ing, 22):
            return "ingress 22 from 0.0.0.0/0"
    return None


@rule("IAC011", CRITICAL, "RDP is open to the entire internet",
      "Port 3389 exposed publicly is a primary ransomware entry point.",
      "aws_security_group")
def _(res, doc):
    for ing in blocks(res["body"], "ingress"):
        if is_open(ing.get("cidr_blocks")) and covers(ing, 3389):
            return "ingress 3389 from 0.0.0.0/0"
    return None


@rule("IAC012", HIGH, "Security group allows all ports from the internet",
      "An unrestricted ingress rule removes the security group as a control "
      "entirely, exposing every service on the instance.",
      "aws_security_group")
def _(res, doc):
    for ing in blocks(res["body"], "ingress"):
        if not is_open(ing.get("cidr_blocks")):
            continue
        lo, hi = port_range(ing)
        if str(ing.get("protocol")) in ("-1", "all") or (lo == 0 and hi >= 65535):
            return "ingress all ports/protocols from 0.0.0.0/0"
    return None


@rule("IAC013", HIGH, "Database port is open to the internet",
      "Databases should only be reachable from the application tier; public "
      "exposure allows direct brute-force against the database engine.",
      "aws_security_group")
def _(res, doc):
    for ing in blocks(res["body"], "ingress"):
        if not is_open(ing.get("cidr_blocks")):
            continue
        for port, name in DB_PORTS.items():
            if covers(ing, port):
                return f"ingress {port} ({name}) from 0.0.0.0/0"
    return None


@rule("IAC014", LOW, "Security group allows unrestricted egress",
      "Wide-open egress lets a compromised host exfiltrate data or reach a "
      "command-and-control server without obstruction.",
      "aws_security_group")
def _(res, doc):
    for eg in blocks(res["body"], "egress"):
        if is_open(eg.get("cidr_blocks")) and str(eg.get("protocol")) in ("-1", "all"):
            return "egress all traffic to 0.0.0.0/0"
    return None


# --------------------------------------------------------------------------
# IAM
# --------------------------------------------------------------------------

@rule("IAC020", CRITICAL, "IAM policy grants Action:* on Resource:*",
      "This is full administrative access. Any principal or workload holding "
      "it can do anything in the account, so one leaked credential is total "
      "compromise.",
      ("aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy",
       "aws_iam_group_policy"))
def _(res, doc):
    text = policy_text(res["body"])
    if grants_wildcard(text, "Action") and grants_wildcard(text, "Resource"):
        return "Action:* on Resource:*"
    return None


@rule("IAC021", HIGH, "AdministratorAccess is attached directly",
      "Attaching the AWS-managed admin policy skips least privilege; scope a "
      "custom policy to the actions the workload actually needs.",
      "aws_iam_role_policy_attachment")
def _(res, doc):
    if "AdministratorAccess" in str(res["body"].get("policy_arn", "")):
        return "policy_arn ends in AdministratorAccess"
    return None


@rule("IAC022", HIGH, "Long-lived IAM access key is created in code",
      "Static access keys do not rotate and often end up in source control; "
      "prefer IAM roles or IRSA so credentials are short-lived.",
      "aws_iam_access_key")
def _(res, doc):
    return "static access key resource declared"


@rule("IAC023", CRITICAL, "Role can be assumed by any principal",
      "A wildcard Principal in the trust policy lets any AWS account assume "
      "the role, which is a direct path into your account.",
      "aws_iam_role")
def _(res, doc):
    text = policy_text(res["body"])
    if grants_wildcard(text, "Principal") or grants_wildcard(text, "AWS"):
        return "trust policy Principal is *"
    return None


# --------------------------------------------------------------------------
# RDS
# --------------------------------------------------------------------------

@rule("IAC030", CRITICAL, "RDS instance is publicly accessible",
      "The database gets a public IP and can be reached from the internet, "
      "exposing it to direct attack regardless of the application's security.",
      "aws_db_instance")
def _(res, doc):
    if truthy(res["body"].get("publicly_accessible")):
        return "publicly_accessible = true"
    return None


@rule("IAC031", HIGH, "RDS storage is not encrypted",
      "Database files and automated snapshots are written in plaintext, so "
      "storage-level access bypasses every database permission.",
      "aws_db_instance")
def _(res, doc):
    if not truthy(res["body"].get("storage_encrypted")):
        return "storage_encrypted is not true"
    return None


@rule("IAC032", MEDIUM, "RDS has no backup retention",
      "A retention of zero disables automated backups, so there is no "
      "recovery point after corruption or a bad migration.",
      "aws_db_instance")
def _(res, doc):
    try:
        days = int(res["body"].get("backup_retention_period", 0))
    except (TypeError, ValueError):
        return None
    return f"backup_retention_period = {days}" if days < 1 else None


@rule("IAC033", MEDIUM, "RDS deletion protection is off",
      "A single mistaken terraform destroy or console click can delete the "
      "production database irrecoverably.",
      "aws_db_instance")
def _(res, doc):
    if not truthy(res["body"].get("deletion_protection")):
        return "deletion_protection is not true"
    return None


@rule("IAC034", LOW, "RDS skips the final snapshot on deletion",
      "Deleting the instance discards the data with no last backup taken.",
      "aws_db_instance")
def _(res, doc):
    if truthy(res["body"].get("skip_final_snapshot")):
        return "skip_final_snapshot = true"
    return None


# --------------------------------------------------------------------------
# EC2 / EBS
# --------------------------------------------------------------------------

@rule("IAC040", MEDIUM, "EC2 instance gets a public IP",
      "A public address puts the host directly on the internet; instances "
      "should normally sit in a private subnet behind a load balancer.",
      "aws_instance")
def _(res, doc):
    if truthy(res["body"].get("associate_public_ip_address")):
        return "associate_public_ip_address = true"
    return None


@rule("IAC041", HIGH, "Instance metadata service allows IMDSv1",
      "IMDSv1 is vulnerable to SSRF: a server-side request forgery bug in the "
      "application can read the instance's IAM credentials. IMDSv2 requires a "
      "session token, which blocks that.",
      "aws_instance")
def _(res, doc):
    for meta in blocks(res["body"], "metadata_options"):
        if str(meta.get("http_tokens", "")).lower() == "required":
            return None
        return "http_tokens is not \"required\""
    return "no metadata_options block (defaults to IMDSv1 allowed)"


@rule("IAC042", HIGH, "EBS volume is not encrypted",
      "Volume data and its snapshots are stored in plaintext.",
      "aws_ebs_volume")
def _(res, doc):
    if not truthy(res["body"].get("encrypted")):
        return "encrypted is not true"
    return None


@rule("IAC043", CRITICAL, "EBS snapshot is shared publicly",
      "Sharing a snapshot with 'all' publishes a full copy of the disk, "
      "including any credentials or customer data on it, to every AWS user.",
      "aws_snapshot_create_volume_permission")
def _(res, doc):
    if "all" in [str(a) for a in as_list(res["body"].get("account_id"))]:
        return "snapshot shared with all accounts"
    return None


# --------------------------------------------------------------------------
# DynamoDB / Lambda
# --------------------------------------------------------------------------

@rule("IAC050", MEDIUM, "DynamoDB point-in-time recovery is disabled",
      "Without PITR the table cannot be rolled back to a moment before a bad "
      "write or deletion.",
      "aws_dynamodb_table")
def _(res, doc):
    for pitr in blocks(res["body"], "point_in_time_recovery"):
        if truthy(pitr.get("enabled")):
            return None
    return "point_in_time_recovery not enabled"


@rule("IAC051", LOW, "DynamoDB table uses only AWS-owned encryption",
      "A customer-managed KMS key gives you auditable key usage and the "
      "ability to revoke access independently of AWS.",
      "aws_dynamodb_table")
def _(res, doc):
    for sse in blocks(res["body"], "server_side_encryption"):
        if truthy(sse.get("enabled")):
            return None
    return "no customer-managed server_side_encryption"


@rule("IAC060", MEDIUM, "Lambda environment variables are not KMS-encrypted",
      "Environment variables often hold secrets and are visible in plaintext "
      "to anyone with lambda:GetFunction unless a KMS key is set.",
      "aws_lambda_function")
def _(res, doc):
    if not blocks(res["body"], "environment"):
        return None
    if res["body"].get("kms_key_arn"):
        return None
    return "environment block without kms_key_arn"


@rule("IAC061", LOW, "Lambda has no X-Ray tracing",
      "Without tracing there is no latency or error breakdown for the "
      "function, which slows down debugging in production.",
      "aws_lambda_function")
def _(res, doc):
    for trace in blocks(res["body"], "tracing_config"):
        if str(trace.get("mode", "")).lower() in ("active", "passthrough"):
            return None
    return "no tracing_config block"


# --------------------------------------------------------------------------
# CloudTrail / KMS / ELB / EKS
# --------------------------------------------------------------------------

@rule("IAC070", HIGH, "CloudTrail is not multi-region",
      "Activity in unmonitored regions is invisible, and attackers routinely "
      "operate in a region nobody watches.",
      "aws_cloudtrail")
def _(res, doc):
    if not truthy(res["body"].get("is_multi_region_trail")):
        return "is_multi_region_trail is not true"
    return None


@rule("IAC071", MEDIUM, "CloudTrail log file validation is off",
      "Without validation digests you cannot prove the audit log was not "
      "tampered with after the fact.",
      "aws_cloudtrail")
def _(res, doc):
    if not truthy(res["body"].get("enable_log_file_validation")):
        return "enable_log_file_validation is not true"
    return None


@rule("IAC080", MEDIUM, "KMS key rotation is disabled",
      "Annual automatic rotation limits how much data a single compromised "
      "key version can decrypt.",
      "aws_kms_key")
def _(res, doc):
    if not truthy(res["body"].get("enable_key_rotation")):
        return "enable_key_rotation is not true"
    return None


@rule("IAC090", HIGH, "Load balancer listener uses plaintext HTTP",
      "Traffic including session cookies and credentials crosses the network "
      "unencrypted and can be read or modified in transit.",
      "aws_lb_listener")
def _(res, doc):
    proto = str(res["body"].get("protocol", "")).upper()
    if proto in ("HTTP", "TCP"):
        return f"protocol = \"{proto}\""
    return None


@rule("IAC100", HIGH, "EKS API server is publicly reachable",
      "A public control plane endpoint without CIDR restrictions exposes the "
      "Kubernetes API to the internet.",
      "aws_eks_cluster")
def _(res, doc):
    for vpc in blocks(res["body"], "vpc_config"):
        if truthy(vpc.get("endpoint_public_access")) and is_open(
                vpc.get("public_access_cidrs")):
            return "endpoint_public_access with 0.0.0.0/0"
    return None


# --------------------------------------------------------------------------
# Hardcoded secrets
# --------------------------------------------------------------------------

def _literal_secret(body: dict) -> Optional[str]:
    for key, value in body.items():
        if not SECRET_KEYS.search(str(key)):
            continue
        if not isinstance(value, str) or not value.strip():
            continue
        if INTERPOLATED.search(value):
            continue
        return f"{key} is set to a literal value"
    return None


@rule("IAC110", CRITICAL, "Hardcoded secret in a variable default",
      "A default value for a secret lives in source control forever, "
      "including in every clone and every past commit. Pass it at runtime "
      "from Secrets Manager or SSM Parameter Store instead.",
      "variable")
def _(res, doc):
    name, body = res["name"], res["body"]
    if not SECRET_KEYS.search(name):
        return None
    default = body.get("default")
    if isinstance(default, str) and default.strip() and not INTERPOLATED.search(default):
        return f"variable \"{name}\" has a literal default"
    return None


@rule("IAC111", CRITICAL, "Hardcoded secret in a resource attribute",
      "The credential is committed in plaintext alongside the code that uses "
      "it, so anyone with repository access has the secret.",
      "*")
def _(res, doc):
    if res["type"] in ("aws_secretsmanager_secret", "aws_ssm_parameter"):
        return None
    return _literal_secret(res["body"])
