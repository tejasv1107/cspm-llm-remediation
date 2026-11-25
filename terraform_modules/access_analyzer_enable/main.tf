# Module: access_analyzer_enable
# Description: Enable an IAM Access Analyzer for the account to detect resources shared with external principals.
# Controls: Security Hub IAM.4 (AccessAnalyzer.1 in some Security Hub standards)
# Resource-Types: AwsAccount, AwsIamAccessAnalyzer
# Keywords: access analyzer not enabled external access findings disabled

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

variable "analyzer_name" {
  description = "Name for the Access Analyzer."
  type        = string
  default     = "cspm-account-analyzer"
}

variable "type" {
  description = "Zone of trust: ACCOUNT or ORGANIZATION."
  type        = string
  default     = "ACCOUNT"

  validation {
    condition     = contains(["ACCOUNT", "ORGANIZATION"], var.type)
    error_message = "type must be ACCOUNT or ORGANIZATION."
  }
}

variable "tags" {
  description = "Tags applied to the analyzer."
  type        = map(string)
  default     = {}
}

resource "aws_accessanalyzer_analyzer" "this" {
  analyzer_name = var.analyzer_name
  type          = var.type
  tags          = var.tags
}

output "analyzer_arn" {
  description = "ARN of the Access Analyzer."
  value       = aws_accessanalyzer_analyzer.this.arn
}
