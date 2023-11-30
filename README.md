# serverless

README.md for Lambda Function
Overview
This Lambda function is designed to handle assignment submissions, process them, and notify users via email. It interacts with several AWS services like SNS, DynamoDB, Secrets Manager, and integrates with Google Cloud Storage (GCS) and Mailgun for email notifications.

Features
SNS Message Parsing: Processes messages from an SNS topic, extracting key information like submission URLs, user emails, etc.
Error Handling: Detects and logs various error conditions (e.g., missing data, incorrect file formats).
DynamoDB Logging: Records event details in a DynamoDB table.
File Processing: Downloads files from provided URLs and uploads them to a GCS bucket.
Email Notifications: Sends success or failure notifications to users using Mailgun.
Prerequisites
AWS account with access to Lambda, SNS, DynamoDB, and Secrets Manager.
A configured GCS bucket and a service account with permissions.
A Mailgun account for sending emails.
Environment Variables
The Lambda function requires the following environment variables:

GCS_BUCKET_SECRET_ARN: ARN of the secret containing the GCS bucket name.
DYNAMODB_TABLE_SECRET_ARN: ARN of the secret containing the DynamoDB table name.
GCP_SERVICE_ACCOUNT_SECRET_ARN: ARN of the secret containing GCP service account credentials.
MAILGUN_API_KEY_SECRET_ARN: ARN of the secret containing the Mailgun API key.
MAILGUN_DOMAIN_SECRET_ARN: ARN of the secret containing the Mailgun domain.
Key Functions
getsecret(secret_arn)
Fetches a secret value from AWS Secrets Manager.

send_email_with_mailgun(email_address, subject, body)
Sends an email using Mailgun. Parameters include the recipient's email address, email subject, and body.

log_dynamodb(request_id, user_email, status, info)
Logs events to a specified DynamoDB table.

handler_lambda(event, context)
The main Lambda function handler. It orchestrates the process flow, including parsing SNS messages, error handling, file processing, sending emails, and logging.

Error Handling
The function includes comprehensive error handling to log and notify about various failure scenarios, such as download issues, file format mismatches, and issues in sending emails.

Deployment
Deploy this Lambda function using AWS CLI, AWS Lambda console, or infrastructure as code tools like AWS CloudFormation or Terraform.

Usage
Trigger this function by publishing messages to the configured SNS topic. The function expects messages in a specific JSON format containing details like SubmissionURL, UserEmail, UserId, AssignmentId, and SubmissionId.

Security
Ensure that the IAM role associated with this Lambda function has necessary permissions for SNS, DynamoDB, Secrets Manager, and CloudWatch Logs. Use secure practices for managing environment variables and secrets.