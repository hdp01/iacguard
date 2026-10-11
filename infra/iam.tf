data "aws_iam_policy_document" "lambda_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "scanner" {
  name               = "${local.name}-scanner-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

# Least privilege, written out statement by statement. Every action here is
# one the scanner actually performs; there is no wildcard action and no
# wildcard resource anywhere in this policy.
data "aws_iam_policy_document" "scanner" {
  statement {
    sid    = "WriteOwnLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.scanner.arn}:*"]
  }

  statement {
    sid       = "ReadUploadedTerraformOnly"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.uploads.arn}/uploads/*"]
  }

  statement {
    sid    = "WriteScanResults"
    effect = "Allow"
    actions = [
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
      "dynamodb:BatchWriteItem",
    ]
    resources = [aws_dynamodb_table.results.arn]
  }

  statement {
    sid     = "InvokeNovaOnly"
    effect  = "Allow"
    actions = ["bedrock:InvokeModel"]
    resources = [
      "arn:aws:bedrock:${var.aws_region}::foundation-model/${var.nova_model_id}",
      "arn:aws:bedrock:${var.aws_region}:${local.account_id}:inference-profile/*",
    ]
  }

  statement {
    sid    = "UseProjectKey"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey",
    ]
    resources = [aws_kms_key.main.arn]
  }

  # PutMetricData does not support resource-level permissions, so the grant is
  # constrained by namespace instead of being left open.
  statement {
    sid       = "PublishScanMetrics"
    effect    = "Allow"
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["IaCGuard"]
    }
  }
}

resource "aws_iam_role_policy" "scanner" {
  name   = "${local.name}-scanner-policy"
  role   = aws_iam_role.scanner.id
  policy = data.aws_iam_policy_document.scanner.json
}
