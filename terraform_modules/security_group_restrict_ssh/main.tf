# Module: security_group_restrict_ssh
# Description: Replace world-open SSH (port 22) ingress on a security group with rules limited to approved CIDRs / security groups, then revoke the 0.0.0.0/0 and ::/0 rules.
# Controls: CIS 4.1; Security Hub EC2.13, EC2.53
# Resource-Types: AwsEc2SecurityGroup
# Keywords: security group ssh port 22 ingress 0.0.0.0/0 unrestricted remote administration open to the internet

terraform {
  required_version = ">= 1.5.0" # terraform_data needs >= 1.4

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

variable "security_group_id" {
  description = "ID of the security group that currently allows public SSH."
  type        = string

  validation {
    condition     = can(regex("^sg-[0-9a-f]+$", var.security_group_id))
    error_message = "security_group_id must look like sg-0123456789abcdef0."
  }
}

variable "aws_region" {
  description = "Region of the security group (used by the AWS CLI revoke step)."
  type        = string
}

variable "allowed_ipv4_cidrs" {
  description = "Approved IPv4 CIDRs allowed to SSH in (e.g. a corporate VPN range). Never 0.0.0.0/0."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for c in var.allowed_ipv4_cidrs : can(cidrhost(c, 0)) && c != "0.0.0.0/0"])
    error_message = "Each entry must be a valid IPv4 CIDR and must not be 0.0.0.0/0."
  }
}

variable "allowed_source_security_group_ids" {
  description = "Security groups (e.g. a bastion host group) allowed to SSH in."
  type        = list(string)
  default     = []
}

variable "revoke_public_ssh" {
  description = "Revoke the existing 0.0.0.0/0 and ::/0 port-22 rules after the approved rules exist. Requires the AWS CLI on the Terraform runner."
  type        = bool
  default     = true
}

resource "aws_vpc_security_group_ingress_rule" "ssh_from_cidr" {
  for_each = toset(var.allowed_ipv4_cidrs)

  security_group_id = var.security_group_id
  description       = "SSH from approved CIDR (managed by cspm-llm-remediation)"
  cidr_ipv4         = each.value
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "ssh_from_security_group" {
  for_each = toset(var.allowed_source_security_group_ids)

  security_group_id            = var.security_group_id
  description                  = "SSH from approved security group (managed by cspm-llm-remediation)"
  referenced_security_group_id = each.value
  from_port                    = 22
  to_port                      = 22
  ip_protocol                  = "tcp"
}

# Approved rules are created first (depends_on) so revoking the public rule cannot lock operators out.
resource "terraform_data" "revoke_public_ssh" {
  count = var.revoke_public_ssh ? 1 : 0

  triggers_replace = [var.security_group_id]

  provisioner "local-exec" {
    command = <<-EOT
      aws ec2 revoke-security-group-ingress --region ${var.aws_region} --group-id ${var.security_group_id} --protocol tcp --port 22 --cidr 0.0.0.0/0 || true
      aws ec2 revoke-security-group-ingress --region ${var.aws_region} --group-id ${var.security_group_id} --ip-permissions 'IpProtocol=tcp,FromPort=22,ToPort=22,Ipv6Ranges=[{CidrIpv6=::/0}]' || true
    EOT
  }

  depends_on = [
    aws_vpc_security_group_ingress_rule.ssh_from_cidr,
    aws_vpc_security_group_ingress_rule.ssh_from_security_group,
  ]
}

output "restricted_security_group_id" {
  description = "Security group whose SSH access is now restricted."
  value       = var.security_group_id
}

output "approved_ssh_sources" {
  description = "CIDRs and security groups now allowed to reach port 22."
  value       = concat(var.allowed_ipv4_cidrs, var.allowed_source_security_group_ids)
}
