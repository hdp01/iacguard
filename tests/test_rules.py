"""Rule-engine tests. These need no AWS credentials and no deployment."""

import pytest

import engine
from rules import RULES


def ids(source: str) -> set[str]:
    return {f["rule_id"] for f in engine.scan_source(source, "test.tf")}


# ---------------------------------------------------------------------------
# parser behaviour
# ---------------------------------------------------------------------------

def test_quotes_are_stripped_from_labels_and_values():
    """python-hcl2 v8 leaves literal quotes in place; if normalisation
    regresses, every rule silently stops matching."""
    from parser import Document

    doc = Document('resource "aws_s3_bucket" "b" {\n  acl = "private"\n}', "t")
    resource = doc.resources[0]
    assert resource["type"] == "aws_s3_bucket"
    assert resource["name"] == "b"
    assert resource["body"]["acl"] == "private"


def test_line_numbers_are_reported():
    source = '\n\nresource "aws_ebs_volume" "v" {\n  size = 10\n}\n'
    finding = engine.scan_source(source, "t.tf")[0]
    assert finding["line"] == 3


def test_snippet_captures_the_whole_block():
    source = (
        'resource "aws_security_group" "s" {\n'
        '  ingress {\n'
        '    from_port   = 22\n'
        '    to_port     = 22\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        '  }\n'
        '}\n'
    )
    finding = engine.scan_source(source, "t.tf")[0]
    assert finding["snippet"].count("{") == finding["snippet"].count("}")
    assert "0.0.0.0/0" in finding["snippet"]


# ---------------------------------------------------------------------------
# positive detections
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("rule_id,source", [
    ("IAC001", 'resource "aws_s3_bucket" "b" { acl = "public-read" }'),
    ("IAC006", 'resource "aws_s3_bucket_public_access_block" "p" {\n'
               '  bucket = "x"\n  block_public_acls = false\n}'),
    ("IAC010", 'resource "aws_security_group" "s" {\n  ingress {\n'
               '    from_port = 22\n    to_port = 22\n'
               '    cidr_blocks = ["0.0.0.0/0"]\n  }\n}'),
    ("IAC011", 'resource "aws_security_group" "s" {\n  ingress {\n'
               '    from_port = 3389\n    to_port = 3389\n'
               '    cidr_blocks = ["0.0.0.0/0"]\n  }\n}'),
    ("IAC012", 'resource "aws_security_group" "s" {\n  ingress {\n'
               '    from_port = 0\n    to_port = 65535\n    protocol = "-1"\n'
               '    cidr_blocks = ["0.0.0.0/0"]\n  }\n}'),
    ("IAC013", 'resource "aws_security_group" "s" {\n  ingress {\n'
               '    from_port = 3306\n    to_port = 3306\n'
               '    cidr_blocks = ["0.0.0.0/0"]\n  }\n}'),
    ("IAC030", 'resource "aws_db_instance" "d" { publicly_accessible = true }'),
    ("IAC041", 'resource "aws_instance" "i" { ami = "ami-1" }'),
    ("IAC042", 'resource "aws_ebs_volume" "v" { size = 8 }'),
    ("IAC070", 'resource "aws_cloudtrail" "t" { name = "t" }'),
    ("IAC080", 'resource "aws_kms_key" "k" { description = "k" }'),
    ("IAC090", 'resource "aws_lb_listener" "l" { protocol = "HTTP" }'),
    ("IAC100", 'resource "aws_eks_cluster" "c" {\n  vpc_config {\n'
               '    endpoint_public_access = true\n'
               '    public_access_cidrs = ["0.0.0.0/0"]\n  }\n}'),
])
def test_rule_fires(rule_id, source):
    assert rule_id in ids(source)


def test_imdsv1_detected_when_tokens_optional():
    source = ('resource "aws_instance" "i" {\n  metadata_options {\n'
              '    http_tokens = "optional"\n  }\n}')
    assert "IAC041" in ids(source)


def test_imdsv2_passes():
    source = ('resource "aws_instance" "i" {\n  metadata_options {\n'
              '    http_tokens = "required"\n  }\n}')
    assert "IAC041" not in ids(source)


# ---------------------------------------------------------------------------
# IAM policies arrive in two different spellings
# ---------------------------------------------------------------------------

def test_admin_policy_detected_in_jsonencode_form():
    """jsonencode() survives HCL parsing as `Action = "*"`, not JSON."""
    source = '''
    resource "aws_iam_policy" "p" {
      policy = jsonencode({
        Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
      })
    }
    '''
    assert "IAC020" in ids(source)


def test_admin_policy_detected_in_raw_json_form():
    source = '''
    resource "aws_iam_policy" "p" {
      policy = "{\\"Statement\\":[{\\"Action\\":\\"*\\",\\"Resource\\":\\"*\\"}]}"
    }
    '''
    assert "IAC020" in ids(source)


def test_scoped_policy_is_not_flagged():
    source = '''
    resource "aws_iam_policy" "p" {
      policy = jsonencode({
        Statement = [{
          Effect   = "Allow"
          Action   = "s3:GetObject"
          Resource = "arn:aws:s3:::bucket/*"
        }]
      })
    }
    '''
    assert "IAC020" not in ids(source)


# ---------------------------------------------------------------------------
# secrets
# ---------------------------------------------------------------------------

def test_literal_secret_in_variable_default():
    source = 'variable "db_password" { default = "hunter2" }'
    assert "IAC110" in ids(source)


def test_variable_without_default_is_fine():
    source = 'variable "db_password" { type = string }'
    assert "IAC110" not in ids(source)


def test_secret_passed_by_reference_is_not_flagged():
    source = ('resource "aws_db_instance" "d" {\n'
              '  password = var.db_password\n  storage_encrypted = true\n'
              '  backup_retention_period = 7\n  deletion_protection = true\n}')
    assert "IAC111" not in ids(source)


def test_literal_secret_in_resource_attribute():
    source = 'resource "aws_db_instance" "d" { password = "Pl4intext!" }'
    assert "IAC111" in ids(source)


def test_secrets_manager_resources_are_exempt():
    """A secret stored in Secrets Manager is the correct pattern, not a
    finding, even though the attribute name matches."""
    source = ('resource "aws_secretsmanager_secret" "s" '
              '{ name = "db-password" }')
    assert "IAC111" not in ids(source)


# ---------------------------------------------------------------------------
# cross-resource awareness
# ---------------------------------------------------------------------------

def test_sibling_resources_satisfy_bucket_rules():
    """Modern Terraform splits S3 settings into sibling resources; a rule that
    only looked at inline attributes would false-positive on correct code."""
    source = '''
    resource "aws_s3_bucket" "b" { bucket = "mybucket" }
    resource "aws_s3_bucket_server_side_encryption_configuration" "e" {
      bucket = aws_s3_bucket.b.id
      rule { apply_server_side_encryption_by_default { sse_algorithm = "aws:kms" } }
    }
    resource "aws_s3_bucket_versioning" "v" {
      bucket = aws_s3_bucket.b.id
      versioning_configuration { status = "Enabled" }
    }
    resource "aws_s3_bucket_public_access_block" "p" {
      bucket = aws_s3_bucket.b.id
      block_public_acls = true
      block_public_policy = true
      ignore_public_acls = true
      restrict_public_buckets = true
    }
    resource "aws_s3_bucket_logging" "l" {
      bucket = aws_s3_bucket.b.id
      target_bucket = "logs"
      target_prefix = "p/"
    }
    '''
    assert ids(source) == set()


# ---------------------------------------------------------------------------
# scoring and engine robustness
# ---------------------------------------------------------------------------

def test_clean_file_scores_100():
    findings = engine.scan_source(
        'resource "aws_ebs_volume" "v" { encrypted = true }', "t.tf")
    assert engine.summarise(findings)["score"] == 100


def test_score_floors_at_zero():
    many = [{"severity": "CRITICAL"} for _ in range(20)]
    assert engine.score(many) == 0


def test_severity_ordering_is_worst_first():
    source = ('resource "aws_s3_bucket" "b" { acl = "public-read" }\n'
              'resource "aws_kms_key" "k" { description = "x" }')
    severities = [f["severity"]
                  for f in engine.scan_source(source, "t.tf")]
    assert severities[0] == "CRITICAL"
    assert severities[-1] in ("MEDIUM", "LOW")


def test_empty_file_produces_no_findings():
    assert engine.scan_source("", "t.tf") == []


def test_unknown_resources_are_ignored():
    source = 'resource "some_other_provider_thing" "x" { foo = "bar" }'
    assert ids(source) == set()


def test_every_rule_has_complete_metadata():
    """A rule missing its rationale would send an empty prompt to Nova."""
    for rule in RULES:
        assert rule.id.startswith("IAC")
        assert rule.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        assert len(rule.title) > 10
        assert len(rule.rationale) > 30


def test_rule_ids_are_unique():
    seen = [r.id for r in RULES]
    assert len(seen) == len(set(seen))
