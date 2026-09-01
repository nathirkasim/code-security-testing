terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# KMS Key for S3 Bucket Encryption
resource "aws_kms_key" "storage_key" {
  description             = "KMS key for application storage encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# Secure S3 Bucket
resource "aws_s3_bucket" "secure_storage" {
  bucket        = "app-secure-data-storage-${var.environment}"
  force_destroy = false

  tags = {
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# Enable S3 Bucket Versioning
resource "aws_s3_bucket_versioning" "storage_versioning" {
  bucket = aws_s3_bucket.secure_storage.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Enable S3 Server-Side Encryption with KMS
resource "aws_s3_bucket_server_side_encryption_configuration" "storage_encryption" {
  bucket = aws_s3_bucket.secure_storage.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.storage_key.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# Block Public Access Entirely
resource "aws_s3_bucket_public_access_block" "storage_public_block" {
  bucket = aws_s3_bucket.secure_storage.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Restricted Security Group
resource "aws_security_group" "app_sg" {
  name        = "app-service-sg-${var.environment}"
  description = "Security group for application service with strict access rules"
  vpc_id      = "vpc-12345678"

  ingress {
    description = "Allow HTTPS from VPC internal network only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_ingress_cidrs
  }

  egress {
    description = "Allow outbound HTTPS to verified API endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_ingress_cidrs
  }

  tags = {
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# Least-Privilege IAM Policy
resource "aws_iam_policy" "app_read_policy" {
  name        = "AppS3ReadPolicy-${var.environment}"
  description = "Granular IAM policy allowing read access to specific bucket"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.secure_storage.arn,
          "${aws_s3_bucket.secure_storage.arn}/*"
        ]
      }
    ]
  })
}
