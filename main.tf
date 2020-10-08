//variable "env" {}
//
provider "aws" {
  region = "ap-northeast-1"
}
//
//data "template_file" "httpd_user_data" {
//  template = file("./user_data.sh.tpl")
//  vars = {
//    package = "httpd"
//  }
//}
//
//resource "aws_instance" "example" {
//  ami = "ami-0f9ae750e8274075b"
//  instance_type = var.env == "prod" ? "m5.large" : "t3.micro"
//  vpc_security_group_ids = [aws_security_group.example_ec2.id]
//  user_data = data.template_file.httpd_user_data.rendered
//}
//
//output "example_public_dns" {
//  value = aws_instance.example.public_dns
//}
//
//resource "aws_security_group" "example_ec2" {
//  name = "example-ec"
//  ingress {
//    from_port = 80
//    protocol = "tcp"
//    to_port = 80
//    cidr_blocks = ["0.0.0.0/0"]
//  }
//  egress {
//    from_port = 0
//    protocol = "-1"
//    to_port = 0
//    cidr_blocks = ["0.0.0.0/0"]
//  }
//}

module "dev_server" {
  source = "./http_server"
  instance_type = "t3.micro"
}

output "public_dns" {
  value = module.dev_server.public_dns
}

module "describe_regions_for_ec2" {
  source = "./iam_role"
  name = "describe_regions_for_ec2"
  identifier = "ec2.amazon.com"
  policy = data.aws_iam_policy_document.allow_describe_regions.json
}

data "aws_iam_policy_document" "allow_describe_regions" {
  statement {
    effect = "Allow"
    actions = ["ec2:DescribeRegions"]
    resources = ["*"]
  }
}

resource "aws_s3_bucket" "private" {
  bucket = "private-pragmatic-terraform-on-aws"
  versioning {
    enabled = true
  }
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "private" {
  bucket = aws_s3_bucket.private.id
  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "public" {
  bucket = "public-pragmatic-terraform-on-aws"
  acl = "public-read"

  cors_rule {
    allowed_methods = ["GET"]
    allowed_origins = ["https;//example.com"]
    allowed_headers = ["*"]
    max_age_seconds = 3000
  }
}

resource "aws_s3_bucket" "alb_log" {
  bucket = "alb-log-pragmatic-terraform-on-aws"
  lifecycle_rule {
    enabled = true
    expiration {
      days = "180"
    }
  }
}

resource "aws_s3_bucket_policy" "alb_log" {
  bucket = aws_s3_bucket.alb_log.id
  policy = ""
}

data "aws_iam_policy_document" "alb_log" {
  statement {

  }
}