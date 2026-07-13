# Deployment assets

The foundation ships the root Dockerfile and Compose stack. Phase-specific
folders will contain Bicep for Microsoft resources, CloudFormation/CDK for AWS,
Terraform for Google, optional cross-cloud Terraform, and Helm only after their
generators and policy-validation tests exist.

