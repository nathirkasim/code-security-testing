output "s3_bucket_arn" {
  value       = aws_s3_bucket.secure_storage.arn
  description = "The ARN of the secure S3 bucket"
}

output "kms_key_arn" {
  value       = aws_kms_key.storage_key.arn
  description = "The ARN of the KMS customer managed key"
}

output "security_group_id" {
  value       = aws_security_group.app_sg.id
  description = "The ID of the hardened security group"
}
