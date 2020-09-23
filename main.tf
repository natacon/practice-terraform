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

data "aws_iam_policy_document" "allow_describe_regions" {
  statement {
    effect = "Allow"
    actions = ["ec2:DescribeRegions"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "example" {
  name = "example"
  policy = data.aws_iam_policy_document.allow_describe_regions.json
}

data "aws_iam_policy_document" "ec2_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      identifiers = ["ec2.amazonaws.com"]
      type = "Service"
    }
  }
}

resource "aws_iam_role" "example" {
  name = "example"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json
}

resource "aws_iam_role_policy_attachment" "example" {
  policy_arn = aws_iam_policy.example.arn
  role = aws_iam_role.example.name
}

