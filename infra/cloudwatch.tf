# The dashboard is deliberately built from the custom IaCGuard metrics as well
# as Lambda's built-ins: Lambda's own metrics describe the function, while the
# custom ones describe the security posture the function is measuring.
resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "${local.name}-operations"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "Findings by severity"
          region = var.aws_region
          view   = "timeSeries"
          stat   = "Sum"
          period = 300
          metrics = [
            ["IaCGuard", "CriticalFindings", { label = "Critical", color = "#d13212" }],
            ["IaCGuard", "HighFindings", { label = "High", color = "#ff7f0e" }],
            ["IaCGuard", "FindingsTotal", { label = "Total", color = "#1f77b4" }],
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 6
        height = 6
        properties = {
          title  = "Posture score (100 = clean)"
          region = var.aws_region
          view   = "gauge"
          stat   = "Average"
          period = 300
          yAxis  = { left = { min = 0, max = 100 } }
          metrics = [
            ["IaCGuard", "PostureScore", { label = "Score" }],
          ]
        }
      },
      {
        type   = "metric"
        x      = 18
        y      = 0
        width  = 6
        height = 6
        properties = {
          title  = "Scans completed"
          region = var.aws_region
          view   = "singleValue"
          stat   = "Sum"
          period = 86400
          metrics = [
            ["IaCGuard", "ScansCompleted", { label = "Scans (24h)" }],
          ]
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6
        properties = {
          title  = "Scanner Lambda health"
          region = var.aws_region
          view   = "timeSeries"
          period = 300
          metrics = [
            ["AWS/Lambda", "Invocations", "FunctionName", aws_lambda_function.scanner.function_name, { stat = "Sum" }],
            ["AWS/Lambda", "Errors", "FunctionName", aws_lambda_function.scanner.function_name, { stat = "Sum", color = "#d13212" }],
            ["AWS/Lambda", "Throttles", "FunctionName", aws_lambda_function.scanner.function_name, { stat = "Sum" }],
            ["AWS/Lambda", "Duration", "FunctionName", aws_lambda_function.scanner.function_name, { stat = "p95", yAxis = "right" }],
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 6
        width  = 12
        height = 6
        properties = {
          title  = "Amazon Nova token consumption (cost driver)"
          region = var.aws_region
          view   = "timeSeries"
          stat   = "Sum"
          period = 300
          metrics = [
            ["IaCGuard", "NovaInputTokens", { label = "Input tokens" }],
            ["IaCGuard", "NovaOutputTokens", { label = "Output tokens" }],
          ]
        }
      },
    ]
  })
}

# Alarms carry no SNS action on purpose: adding a notification topic would
# push the project past its five-service budget. They still surface state in
# the console and via the CLI.
resource "aws_cloudwatch_metric_alarm" "scanner_errors" {
  alarm_name          = "${local.name}-scanner-errors"
  alarm_description   = "Scanner Lambda returned an error"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.scanner.function_name }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
}

resource "aws_cloudwatch_metric_alarm" "scanner_throttles" {
  alarm_name          = "${local.name}-scanner-throttles"
  alarm_description   = "Scans are being throttled by the reserved concurrency cap"
  namespace           = "AWS/Lambda"
  metric_name         = "Throttles"
  dimensions          = { FunctionName = aws_lambda_function.scanner.function_name }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
}

resource "aws_cloudwatch_metric_alarm" "critical_findings" {
  alarm_name          = "${local.name}-critical-findings"
  alarm_description   = "A scan found at least one CRITICAL misconfiguration"
  namespace           = "IaCGuard"
  metric_name         = "CriticalFindings"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
}
