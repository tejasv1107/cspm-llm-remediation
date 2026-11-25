# Module: iam_password_policy
# Description: Enforce a strong IAM account password policy (length, complexity, rotation, reuse prevention).
# Controls: CIS 1.8, 1.9, 1.10, 1.11; Security Hub IAM.7, IAM.11, IAM.12, IAM.13, IAM.14, IAM.15, IAM.16, IAM.17
# Resource-Types: AwsIamUser, AwsAccount
# Keywords: iam password policy minimum length uppercase lowercase symbols numbers reuse expiry rotation

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

variable "minimum_password_length" {
  description = "Minimum password length."
  type        = number
  default     = 14

  validation {
    condition     = var.minimum_password_length >= 14 && var.minimum_password_length <= 128
    error_message = "minimum_password_length must be between 14 and 128."
  }
}

variable "password_reuse_prevention" {
  description = "Number of previous passwords users cannot reuse (IAM allows at most 24)."
  type        = number
  default     = 24

  validation {
    condition     = var.password_reuse_prevention >= 24
    error_message = "CIS requires remembering at least 24 previous passwords (24 is also the IAM maximum)."
  }
}

variable "max_password_age" {
  description = "Days before a password expires."
  type        = number
  default     = 90

  validation {
    condition     = var.max_password_age >= 1 && var.max_password_age <= 90
    error_message = "max_password_age must be between 1 and 90 days."
  }
}

variable "allow_users_to_change_password" {
  description = "Let IAM users change their own password."
  type        = bool
  default     = true
}

variable "hard_expiry" {
  description = "Prevent users from setting a new password after expiry without an admin reset."
  type        = bool
  default     = false
}

resource "aws_iam_account_password_policy" "this" {
  minimum_password_length        = var.minimum_password_length
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = var.allow_users_to_change_password
  password_reuse_prevention      = var.password_reuse_prevention
  max_password_age               = var.max_password_age
  hard_expiry                    = var.hard_expiry
}

output "minimum_password_length" {
  description = "Enforced minimum password length."
  value       = aws_iam_account_password_policy.this.minimum_password_length
}

output "max_password_age" {
  description = "Enforced maximum password age in days."
  value       = aws_iam_account_password_policy.this.max_password_age
}
