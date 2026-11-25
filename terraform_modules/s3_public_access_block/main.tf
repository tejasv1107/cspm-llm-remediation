# Module: s3_public_access_block
# Description: Enable all four S3 Block Public Access settings on the given buckets and, optionally, for the whole account.
# Controls: CIS 2.1.1; Security Hub S3.1, S3.2, S3.3, S3.8
# Resource-Types: AwsS3Bucket, AwsS3AccountPublicAccessBlock
# Keywords: s3 bucket public access block acl policy publicly readable writable exposure

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

variable "bucket_names" {
  description = "Names of the S3 buckets that must block all public access."
  type        = set(string)
  default     = []

  validation {
    condition     = alltrue([for b in var.bucket_names : length(b) >= 3 && length(b) <= 63])
    error_message = "Every bucket name must be between 3 and 63 characters."
  }
}

variable "enable_account_level_block" {
  description = "Also enable Block Public Access at the account level (Security Hub S3.1)."
  type        = bool
  default     = true
}

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket_public_access_block" "this" {
  for_each = var.bucket_names

  bucket                  = each.value
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_account_public_access_block" "this" {
  count = var.enable_account_level_block ? 1 : 0

  account_id              = data.aws_caller_identity.current.account_id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

output "protected_bucket_names" {
  description = "Buckets on which Block Public Access is now enforced."
  value       = sort(keys(aws_s3_bucket_public_access_block.this))
}

output "account_level_block_enabled" {
  description = "Whether account-level Block Public Access is managed by this module."
  value       = var.enable_account_level_block
}
