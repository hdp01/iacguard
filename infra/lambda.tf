# Created explicitly rather than letting Lambda create it implicitly, so that
# retention is managed and the IAM policy can scope to this exact log group.
resource "aws_cloudwatch_log_group" "scanner" {
  name              = "/aws/lambda/${local.name}-scanner"
  retention_in_days = var.log_retention_days
}

resource "aws_lambda_function" "scanner" {
  function_name = "${local.name}-scanner"
  role          = aws_iam_role.scanner.arn
  handler       = "handler.handler"
  runtime       = "python3.12"
  architectures = ["arm64"]

  filename         = local.lambda_zip
  source_code_hash = filebase64sha256(local.lambda_zip)

  memory_size                    = var.lambda_memory_mb
  timeout                        = var.lambda_timeout_seconds
  reserved_concurrent_executions = var.lambda_reserved_concurrency

  # Encrypted with the project CMK rather than Lambda's default key. Found by
  # IaCGuard's own rule IAC060 when it scanned this file.
  kms_key_arn = aws_kms_key.main.arn

  environment {
    variables = {
      TABLE_NAME       = aws_dynamodb_table.results.name
      NOVA_MODEL_ID    = var.nova_model_id
      METRIC_NAMESPACE = "IaCGuard"
      RESULT_TTL_DAYS  = tostring(var.result_ttl_days)
    }
  }

  depends_on = [
    aws_iam_role_policy.scanner,
    aws_cloudwatch_log_group.scanner,
  ]
}

resource "aws_lambda_permission" "allow_s3" {
  statement_id   = "AllowExecutionFromS3"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.scanner.function_name
  principal      = "s3.amazonaws.com"
  source_arn     = aws_s3_bucket.uploads.arn
  source_account = local.account_id
}

# S3 invokes Lambda asynchronously, so a burst larger than the account's
# concurrency limit is throttled rather than dropped: Lambda retries the
# queued events with backoff and they drain on their own. Making the retry
# policy explicit documents that behaviour instead of relying on defaults.
#
# A production deployment would put SQS between S3 and Lambda for a real
# buffer and a dead-letter queue. That was omitted on purpose to keep the
# project within its five-service budget.
resource "aws_lambda_function_event_invoke_config" "scanner" {
  function_name                = aws_lambda_function.scanner.function_name
  maximum_retry_attempts       = 2
  maximum_event_age_in_seconds = 3600
}
