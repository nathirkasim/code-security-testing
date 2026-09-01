variable "aws_region" {
  type        = string
  default     = "us-east-1"
  description = "AWS deployment region"
}

variable "environment" {
  type        = string
  default     = "production"
  description = "Deployment environment name"
}

variable "vpc_cidr" {
  type        = string
  default     = "10.0.0.0/16"
  description = "CIDR block for the application VPC"
}

variable "allowed_ingress_cidrs" {
  type        = list(string)
  default     = ["10.0.0.0/16"]
  description = "Allowed CIDR blocks for ingress access"
}
