variable "project_prefix" {
  description = "Prefix for all resource names"
  type        = string
  default     = "sm-nc2-flow"
}

variable "vpc_region" {
  description = "Region for VPC"
  type        = string
  default     = "us-east-2"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "172.18.0.0/16"
}

variable "vpc_az" {
  description = "Availability zone for VPC"
  type        = string
  default     = "us-east-2b"
} 