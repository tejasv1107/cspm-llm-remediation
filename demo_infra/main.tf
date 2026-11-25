// Intentionally misconfigured demo resource for the viva: an S3 bucket with no public-access
// block, so AWS Config/Security Hub flags it as S3.8 -- a control this project already has a
// proven reference module (terraform_modules/s3_public_access_block) and live PR history for.
// Clearly named and tagged so it is never mistaken for real infrastructure.

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.0"
    }
  }
}

provider "aws" {
  region = "us-west-2"
}

resource "random_id" "suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "demo_misconfigured" {
  bucket = "cspm-demo-viva-s3-public-access-${random_id.suffix.hex}"

  tags = {
    Project   = "cspm-llm-remediation"
    Purpose   = "intentional-demo-misconfiguration-for-viva"
    ManagedBy = "terraform"
    SafeToDelete = "true"
  }
}

// Deliberately no aws_s3_bucket_public_access_block resource here -- that absence is exactly
// what trips Security Hub control S3.8.

output "bucket_name" {
  value = aws_s3_bucket.demo_misconfigured.bucket
}

output "bucket_arn" {
  value = aws_s3_bucket.demo_misconfigured.arn
}
