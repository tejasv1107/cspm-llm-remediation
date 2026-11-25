# Module: s3_bucket_encryption
# Description: Enable default server-side encryption (SSE-S3 or SSE-KMS) on an S3 bucket.
# Controls: Security Hub S3.4
# Resource-Types: AwsS3Bucket
# Keywords: s3 bucket server-side encryption sse not encrypted default encryption kms

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

variable "bucket_name" {
  description = "Name of the S3 bucket that must have default encryption enabled."
  type        = string

  validation {
    condition     = length(var.bucket_name) >= 3 && length(var.bucket_name) <= 63
    error_message = "bucket_name must be between 3 and 63 characters."
  }
}

variable "kms_key_arn" {
  description = "Customer-managed KMS key for SSE-KMS. Null uses SSE-S3 (AES256)."
  type        = string
  default     = null

  validation {
    condition     = var.kms_key_arn == null || can(regex("^arn:aws[a-z-]*:kms:", var.kms_key_arn))
    error_message = "kms_key_arn must be a KMS key ARN."
  }
}

variable "bucket_key_enabled" {
  description = "Use S3 Bucket Keys to reduce KMS request costs. Only meaningful with kms_key_arn set."
  type        = bool
  default     = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = var.bucket_name

  rule {
    bucket_key_enabled = var.kms_key_arn == null ? null : var.bucket_key_enabled

    apply_server_side_encryption_by_default {
      sse_algorithm     = var.kms_key_arn == null ? "AES256" : "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
  }
}

output "bucket_name" {
  description = "Bucket now encrypted by default."
  value       = var.bucket_name
}

output "sse_algorithm" {
  description = "Encryption algorithm applied."
  value       = var.kms_key_arn == null ? "AES256" : "aws:kms"
}
