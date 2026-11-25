# Module: guardduty_enable
# Description: Enable the Amazon GuardDuty detector for the current account and region.
# Controls: Security Hub GuardDuty.1
# Resource-Types: AwsGuardDutyDetector, AwsAccount
# Keywords: guardduty threat detection not enabled disabled detector

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

variable "finding_publishing_frequency" {
  description = "How often GuardDuty exports findings: FIFTEEN_MINUTES, ONE_HOUR or SIX_HOURS."
  type        = string
  default     = "FIFTEEN_MINUTES"

  validation {
    condition     = contains(["FIFTEEN_MINUTES", "ONE_HOUR", "SIX_HOURS"], var.finding_publishing_frequency)
    error_message = "finding_publishing_frequency must be FIFTEEN_MINUTES, ONE_HOUR or SIX_HOURS."
  }
}

variable "enable_s3_protection" {
  description = "Enable GuardDuty's S3 data event protection."
  type        = bool
  default     = true
}

variable "tags" {
  description = "Tags applied to the detector."
  type        = map(string)
  default     = {}
}

# NOTE: an account/region may have at most one detector. If GuardDuty is already enabled here
# (e.g. via AWS Organizations delegated administration), applying this module will fail with
# "The request is rejected because a detector already exists". Check first if unsure.
resource "aws_guardduty_detector" "this" {
  enable                       = true
  finding_publishing_frequency = var.finding_publishing_frequency
  tags                         = var.tags

  datasources {
    s3_logs {
      enable = var.enable_s3_protection
    }
  }
}

output "detector_id" {
  description = "ID of the GuardDuty detector."
  value       = aws_guardduty_detector.this.id
}
