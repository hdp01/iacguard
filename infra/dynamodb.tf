# On-demand billing: no capacity to plan, nothing to pay between scans. For a
# workload this bursty, provisioned capacity would cost more and still throttle.
resource "aws_dynamodb_table" "results" {
  name         = "${local.name}-results"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "scan_id"
  range_key    = "sk"

  attribute {
    name = "scan_id"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  # Single-table design: one META item holds the aggregate counters and one
  # FINDING# item per finding, so a whole report is a single Query.
  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.main.arn
  }
}
