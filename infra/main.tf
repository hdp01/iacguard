data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  name       = var.project_name

  # Bucket names are globally unique, so the account id keeps this
  # deployable in any account without a variable override.
  bucket_name = "${var.project_name}-uploads-${local.account_id}"

  lambda_zip = "${path.module}/../build/lambda.zip"
}
