# AWS Deployment Setup

This folder keeps the project AWS-ready without creating any paid resources.

Nothing here costs money unless you run Terraform or deploy the generated resources in an AWS account.

## Included Templates

- `terraform/` provisions an ECS/Fargate-style service shape, ECR repository, CloudWatch log group, and security variables.
- `task-definition.json` is an ECS task definition template for the FastAPI container.
- `github-actions-deploy.example.yml` is a copy/paste deployment workflow template.

## Safe Usage

Review costs before running:

```bash
cd infra/aws/terraform
terraform init
terraform plan
```

Do not run `terraform apply` unless you intentionally want to create AWS resources.
