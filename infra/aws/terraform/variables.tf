variable "aws_region" {
  description = "AWS region for deployment."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project and ECR repository name."
  type        = string
  default     = "ai-security-alert-investigation-agent"
}
