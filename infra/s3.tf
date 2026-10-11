resource "aws_s3_bucket" "uploads" {
  bucket = local.bucket_name
}

# All four flags on: the bucket can never be made public by a later ACL or
# bucket-policy change, even by accident.
resource "aws_s3_bucket_public_access_block" "uploads" {
  bucket                  = aws_s3_bucket.uploads.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.main.arn
    }
    # Caches the data key per object prefix, cutting KMS request charges by
    # roughly 99% on bulk uploads.
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Uploaded Terraform is only needed long enough to scan it. Expiring it keeps
# storage near zero and limits how long any sensitive IaC sits in the account.
resource "aws_s3_bucket_lifecycle_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  rule {
    id     = "expire-uploads"
    status = "Enabled"

    filter {
      prefix = "uploads/"
    }

    expiration {
      days = var.upload_expiry_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 1
    }
  }

  rule {
    id     = "abort-incomplete-uploads"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

# Refuse any request that did not arrive over TLS. Without this, encryption
# in transit is a client-side convention rather than something enforced.
resource "aws_s3_bucket_policy" "require_tls" {
  bucket = aws_s3_bucket.uploads.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyUnencryptedTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.uploads.arn,
          "${aws_s3_bucket.uploads.arn}/*",
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.uploads]
}

# This event is the entire trigger mechanism: no scheduler, no polling, and
# nothing running between scans.
resource "aws_s3_bucket_notification" "scan_trigger" {
  bucket = aws_s3_bucket.uploads.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.scanner.arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "uploads/"
    filter_suffix       = ".tf"
  }

  depends_on = [aws_lambda_permission.allow_s3]
}
