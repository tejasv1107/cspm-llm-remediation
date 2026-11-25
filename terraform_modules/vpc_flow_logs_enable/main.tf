# Module: vpc_flow_logs_enable
# Description: Enable VPC Flow Logs for a VPC, delivering to a dedicated CloudWatch Logs group with its own IAM role.
# Controls: Security Hub EC2.6
# Resource-Types: AwsEc2Vpc, AwsEc2FlowLog
# Keywords: vpc flow logs network traffic logging disabled not enabled cloudwatch

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
  description = "ID of the VPC that must have flow logging enabled."
  type        = string

  validation {
    condition     = can(regex("^vpc-[0-9a-f]+$", var.vpc_id))
    error_message = "vpc_id must look like vpc-0123456789abcdef0."
  }
}

variable "traffic_type" {
  description = "Traffic to log: ACCEPT, REJECT or ALL."
  type        = string
  default     = "ALL"

  validation {
    condition     = contains(["ACCEPT", "REJECT", "ALL"], var.traffic_type)
    error_message = "traffic_type must be ACCEPT, REJECT or ALL."
  }
}

variable "retention_days" {
  description = "Days to retain flow log records in CloudWatch Logs."
  type        = number
  default     = 365

  validation {
    condition     = var.retention_days >= 90
    error_message = "Retain flow logs for at least 90 days."
  }
}

variable "tags" {
  description = "Tags applied to the log group, IAM role and flow log."
  type        = map(string)
  default     = {}
}

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/vpc/flow-logs/${var.vpc_id}"
  retention_in_days = var.retention_days
  tags              = var.tags
}

data "aws_iam_policy_document" "flow_logs_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "flow_logs_publish" {
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
    ]
    resources = ["${aws_cloudwatch_log_group.flow_logs.arn}:*"]
  }
}

resource "aws_iam_role" "flow_logs" {
  name               = "vpc-flow-logs-${var.vpc_id}"
  assume_role_policy = data.aws_iam_policy_document.flow_logs_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy" "flow_logs_publish" {
  name   = "publish-to-cloudwatch"
  role   = aws_iam_role.flow_logs.id
  policy = data.aws_iam_policy_document.flow_logs_publish.json
}

resource "aws_flow_log" "this" {
  vpc_id          = var.vpc_id
  traffic_type    = var.traffic_type
  log_destination = aws_cloudwatch_log_group.flow_logs.arn
  iam_role_arn    = aws_iam_role.flow_logs.arn
  tags            = var.tags
}

output "flow_log_id" {
  description = "ID of the created VPC flow log."
  value       = aws_flow_log.this.id
}

output "log_group_name" {
  description = "CloudWatch Logs group receiving the flow log records."
  value       = aws_cloudwatch_log_group.flow_logs.name
}
