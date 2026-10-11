variable "aws_region" {
  description = "Region for every resource. Nova Lite is available on-demand in us-east-1, which is why that is the default."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Prefix for all resource names."
  type        = string
  default     = "iacguard"
}

variable "nova_model_id" {
  description = "Bedrock model used for remediation advice."
  type        = string
  default     = "amazon.nova-lite-v1:0"
}

variable "lambda_memory_mb" {
  description = "Memory for the scanner. 512 MB is enough for HCL parsing and gives proportionally more CPU, which shortens the Bedrock fan-out."
  type        = number
  default     = 512
}

variable "lambda_timeout_seconds" {
  description = "Must comfortably exceed the slowest Bedrock fan-out."
  type        = number
  default     = 120
}

variable "lambda_reserved_concurrency" {
  description = <<-EOT
    Caps simultaneous scans so a runaway upload loop cannot run up a Bedrock bill.
    -1 means no reservation. AWS requires an account to retain at least 10
    unreserved executions, so on a new account whose total limit is 10 any
    reservation is rejected and this must stay -1. On an account with the
    default limit of 1000, set this to 5.
  EOT
  type        = number
  default     = -1

  validation {
    condition     = var.lambda_reserved_concurrency == -1 || var.lambda_reserved_concurrency >= 1
    error_message = "Use -1 for no reservation, or a positive number."
  }
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention. Short retention is the single biggest log cost lever."
  type        = number
  default     = 14
}

variable "result_ttl_days" {
  description = "How long scan results live in DynamoDB before TTL deletes them."
  type        = number
  default     = 30
}

variable "upload_expiry_days" {
  description = "How long uploaded Terraform files live in S3 before lifecycle expiry."
  type        = number
  default     = 7
}
