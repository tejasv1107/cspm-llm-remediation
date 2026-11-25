# Module: s3_bucket_versioning
# Description: Enable versioning on an S3 bucket so objects can be recovered after accidental deletion or overwrite.
# Controls: Security Hub S3.14
# Resource-Types: AwsS3Bucket
# Keywords: s3 bucket versioning not enabled disabled object recovery

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
  description = "Name of the S3 bucket that must have versioning enabled."
  type        = string

  validation {
    condition     = length(var.bucket_name) >= 3 && length(var.bucket_name) <= 63
    error_message = "bucket_name must be between 3 and 63 characters."
  }
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = var.bucket_name

  versioning_configuration {
    status = "Enabled"
  }
}

output "bucket_name" {
  description = "Bucket that now has versioning enabled."
  value       = var.bucket_name
}

output "versioning_status" {
  description = "Versioning status applied to the bucket."
  value       = aws_s3_bucket_versioning.this.versioning_configuration[0].status
}
