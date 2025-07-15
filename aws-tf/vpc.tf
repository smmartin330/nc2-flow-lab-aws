# VPC
resource "aws_vpc" "vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.project_prefix}-vpc"
  }
}

# Default route table
resource "aws_default_route_table" "vpc_default" {
  default_route_table_id = aws_vpc.vpc.default_route_table_id

  tags = {
    Name = "${var.project_prefix}-vpc-default-rt"
  }
}

# Public Subnet
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 0)
  availability_zone       = var.vpc_az
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.project_prefix}-public-subnet"
  }
}

# Private Subnets
resource "aws_subnet" "private_metal" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, 1)
  availability_zone = var.vpc_az

  tags = {
    Name = "${var.project_prefix}-private-metal-subnet"
  }
}

resource "aws_subnet" "private_pc" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, 2)
  availability_zone = var.vpc_az

  tags = {
    Name = "${var.project_prefix}-private-pc-subnet"
  }
}

resource "aws_subnet" "private_flow" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, 3)
  availability_zone = var.vpc_az

  tags = {
    Name = "${var.project_prefix}-private-flow-subnet"
  }
} 