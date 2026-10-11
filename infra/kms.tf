# A customer-managed key rather than the AWS-managed default: it gives
# auditable key usage in CloudTrail, automatic annual rotation, and the
# ability to revoke access to the data independently of IAM.
resource "aws_kms_key" "main" {
  description             = "${local.name} encryption key for S3 uploads and DynamoDB results"
  enable_key_rotation     = true
  deletion_window_in_days = 7
}

resource "aws_kms_alias" "main" {
  name          = "alias/${local.name}"
  target_key_id = aws_kms_key.main.key_id
}
