resource "aws_security_group" "open_sg" {
  name        = "open-sg"
  description = "Overly permissive security group"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "logs_bucket" {
  bucket = "compliance-agent-demo-bucket"
}

data "aws_iam_policy_document" "wildcard" {
  statement {
    actions   = ["*"]
    resources = ["*"]
  }
}

resource "aws_iam_role" "wildcard_role" {
  name               = "wildcard-role"
  assume_role_policy = data.aws_iam_policy_document.wildcard.json
}
