# Deliberately insecure Terraform, used to demonstrate IaCGuard.
# Every block here violates at least one rule. Do not deploy this.

resource "aws_s3_bucket" "customer_data" {
  bucket = "acme-customer-exports"
  acl    = "public-read"
}

resource "aws_security_group" "app" {
  name        = "app-sg"
  description = "Application security group"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Postgres"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "main" {
  identifier          = "acme-prod"
  engine              = "postgres"
  instance_class      = "db.t3.medium"
  allocated_storage   = 100
  username            = "admin"
  password            = "Pr0dPassw0rd!"
  publicly_accessible = true
  skip_final_snapshot = true
}

resource "aws_instance" "web" {
  ami                         = "ami-0abcdef1234567890"
  instance_type               = "t3.micro"
  associate_public_ip_address = true
}

resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
}

resource "aws_iam_policy" "app" {
  name = "app-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      },
    ]
  })
}

resource "aws_lb_listener" "front" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/x/y"
  port              = 80
  protocol          = "HTTP"
}

resource "aws_cloudtrail" "audit" {
  name           = "acme-trail"
  s3_bucket_name = "acme-trail-logs"
}

resource "aws_kms_key" "app" {
  description = "Application key"
}

variable "db_password" {
  description = "Production database password"
  type        = string
  default     = "Pr0dPassw0rd!"
}
