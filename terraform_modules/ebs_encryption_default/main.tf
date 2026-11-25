# Module: ebs_encryption_default
# Description: Turn on EBS encryption by default in the current region, optionally with a customer-managed KMS key.
# Controls: CIS 2.2.1; Security Hub EC2.7
# Resource-Types: AwsEc2Volume, AwsAccount
# Keywords: ebs volume encryption default kms unencrypted snapshot data at rest

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

variable "enabled" {
  description = "Whether new EBS volumes in this region are encrypted by default."
  type        = bool
  default     = true
}

variable "kms_key_arn" {
  description = "Customer-managed KMS key used as the regional EBS default. Null keeps the AWS-managed aws/ebs key."
  type        = string
  default     = null

  validation {
    condition     = var.kms_key_arn == null || can(regex("^arn:aws[a-z-]*:kms:", var.kms_key_arn))
    error_message = "kms_key_arn must be a KMS key ARN."
  }
}

# EBS default encryption is a per-region setting: instantiate this module once per region
# (using provider aliases) for full coverage.
resource "aws_ebs_encryption_by_default" "this" {
  enabled = var.enabled
}

resource "aws_ebs_default_kms_key" "this" {
  count = var.kms_key_arn == null ? 0 : 1

  key_arn    = var.kms_key_arn
  depends_on = [aws_ebs_encryption_by_default.this]
}

output "ebs_encryption_enabled" {
  description = "Whether EBS encryption by default is enabled."
  value       = aws_ebs_encryption_by_default.this.enabled
}

output "default_kms_key_arn" {
  description = "Customer-managed default key, or null when the AWS-managed key is used."
  value       = var.kms_key_arn
}
