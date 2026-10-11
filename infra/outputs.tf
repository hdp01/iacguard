output "bucket_name" {
  description = "Upload target. The CLI reads this from terraform output."
  value       = aws_s3_bucket.uploads.id
}

output "table_name" {
  value = aws_dynamodb_table.results.name
}

output "function_name" {
  value = aws_lambda_function.scanner.function_name
}

output "log_group" {
  value = aws_cloudwatch_log_group.scanner.name
}

output "dashboard_url" {
  value = "https://${var.aws_region}.console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards/dashboard/${aws_cloudwatch_dashboard.main.dashboard_name}"
}

output "kms_key_arn" {
  value = aws_kms_key.main.arn
}

output "region" {
  value = var.aws_region
}

output "cli_config" {
  description = "Values the CLI needs; written to .iacguard.json by 'make config'."
  value = {
    region   = var.aws_region
    bucket   = aws_s3_bucket.uploads.id
    table    = aws_dynamodb_table.results.name
    function = aws_lambda_function.scanner.function_name
  }
}
