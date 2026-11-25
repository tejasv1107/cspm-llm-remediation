# Module: default_security_group_lockdown
# Description: Remove all ingress and egress rules from a VPC's default security group so it allows no traffic.
# Controls: Security Hub EC2.2
# Resource-Types: AwsEc2SecurityGroup
# Keywords: default security group should not allow inbound outbound traffic unrestricted vpc

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

variable "vpc_id" {
  description = "ID of the VPC whose default security group must be locked down."
  type        = string

  validation {
    condition     = can(regex("^vpc-[0-9a-f]+$", var.vpc_id))
    error_message = "vpc_id must look like vpc-0123456789abcdef0."
  }
}

variable "tags" {
  description = "Tags applied to the default security group."
  type        = map(string)
  default     = {}
}

# aws_default_security_group adopts the VPC's existing default security group into Terraform
# (no terraform import needed). Omitting ingress/egress blocks removes every existing rule,
# leaving the group fully closed, which is exactly what EC2.2 requires.
resource "aws_default_security_group" "this" {
  vpc_id = var.vpc_id
  tags   = merge(var.tags, { Name = "default - locked down by cspm-llm-remediation" })
}

output "security_group_id" {
  description = "ID of the locked-down default security group."
  value       = aws_default_security_group.this.id
}
