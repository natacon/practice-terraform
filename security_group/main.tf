variable "name" {}
variable "vpc_id" {}
variable "port" {}

variable "cidr_blocks" {
  type = list(string)
}

resource "aws_security_group" "default" {
  name = var.name
  vpc_id = var.vpc_id
}

resource "aws_security_group_rule" "ingress" {
  from_port = var.port
  protocol = "tcp"
  security_group_id = aws_security_group.default.id
  to_port = var.port
  type = "ingress"
  cidr_blocks = var.cidr_blocks
}

resource "aws_security_group_rule" "egress" {
  from_port = 0
  protocol = "-1"
  security_group_id = aws_security_group.default.id
  to_port = 0
  type = "egress"
  cidr_blocks = var.cidr_blocks
}

output "aws_security_group_id" {
  value = aws_security_group.default.id
}