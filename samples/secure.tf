# The hardened counterpart to insecure.tf. Scanning this should report
# materially fewer findings, which is what makes the before/after demo work.

resource "aws_s3_bucket" "customer_data" {
  bucket = "acme-customer-exports"
}

resource "aws_s3_bucket_public_access_block" "customer_data" {
  bucket                  = aws_s3_bucket.customer_data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "customer_data" {
  bucket = aws_s3_bucket.customer_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_versioning" "customer_data" {
  bucket = aws_s3_bucket.customer_data.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "customer_data" {
  bucket        = aws_s3_bucket.customer_data.id
  target_bucket = "acme-access-logs"
  target_prefix = "customer-data/"
}

resource "aws_security_group" "app" {
  name        = "app-sg"
  description = "Application security group"

  ingress {
    description = "SSH from the bastion subnet only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.1.0/24"]
  }

  ingress {
    description = "Postgres from the application subnet only"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.2.0/24"]
  }

  egress {
    description = "HTTPS to the internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "main" {
  identifier                = "acme-prod"
  engine                    = "postgres"
  instance_class            = "db.t3.medium"
  allocated_storage         = 100
  username                  = "admin"
  password                  = var.db_password
  publicly_accessible       = false
  storage_encrypted         = true
  backup_retention_period   = 14
  deletion_protection       = true
  skip_final_snapshot       = false
  final_snapshot_identifier = "acme-prod-final"
}

resource "aws_instance" "web" {
  ami                         = "ami-0abcdef1234567890"
  instance_type               = "t3.micro"
  associate_public_ip_address = false

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }
}

resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = true
}

resource "aws_lb_listener" "front" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/x/y"
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = "arn:aws:acm:us-east-1:123456789012:certificate/abc"
}

resource "aws_cloudtrail" "audit" {
  name                          = "acme-trail"
  s3_bucket_name                = "acme-trail-logs"
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  include_global_service_events = true
}

resource "aws_kms_key" "app" {
  description             = "Application key"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

variable "db_password" {
  description = "Injected at apply time from Secrets Manager; never defaulted."
  type        = string
  sensitive   = true
}
