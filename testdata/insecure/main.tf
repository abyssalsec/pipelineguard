resource "aws_security_group" "bad" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "public" {
  associate_public_ip_address = true
}

resource "aws_s3_bucket" "public" {
  acl = "public-read"
}
