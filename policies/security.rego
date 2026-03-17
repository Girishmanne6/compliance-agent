package security

# Deny hardcoded passwords
deny[msg] {
  contains(input.code, "password =")
  msg := "Hardcoded password detected"
}

# Deny hardcoded API keys, tokens, and secrets
deny[msg] {
  contains(input.code, "api_key =")
  msg := "Hardcoded secret detected"
}

deny[msg] {
  contains(input.code, "token =")
  msg := "Hardcoded secret detected"
}

deny[msg] {
  contains(input.code, "sk-")
  msg := "Hardcoded secret detected"
}

# Deny use of eval
deny[msg] {
  contains(input.code, "eval(")
  msg := "Use of eval() is a security risk"
}

# Deny use of exec
deny[msg] {
  contains(input.code, "exec(")
  msg := "Use of exec() is a security risk"
}

# Deny open CIDR in Terraform
deny[msg] {
  contains(input.code, "0.0.0.0/0")
  msg := "Open security group detected in IaC"
}

# Deny pickle usage
deny[msg] {
  contains(input.code, "pickle.loads")
  msg := "Unsafe deserialization with pickle detected"
}

# Deny S3 buckets without encryption
deny[msg] {
  contains(input.code, "resource \"aws_s3_bucket\"")
  not contains(input.code, "server_side_encryption_configuration")
  msg := "S3 bucket encryption is missing"
}

# Deny wildcard IAM permissions
deny[msg] {
  contains(input.code, "actions")
  contains(input.code, "\"*\"")
  msg := "Wildcard IAM permissions detected"
}
