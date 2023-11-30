import boto3
import json
import os
import requests
import base64
from contextlib import closing
import shutil
from google.cloud import storage
from google.oauth2 import service_account
from botocore.exceptions import ClientError

# Initialize AWS clients
client_sns = boto3.client('sns')
dynamodb = boto3.resource('dynamodb')
client_secretsmanager = boto3.client('secretsmanager')

def getsecret(secret_arn):
    try:
        response = client_secretsmanager.get_secret_value(SecretId=secret_arn)
        # Check if the secret uses the 'SecretString' field, else assume binary and decode it
        if 'SecretString' in response:
            return response['SecretString']
        else:
            decoded_binary_secret = base64.b64decode(
                response['SecretBinary']).decode('utf-8')
            return decoded_binary_secret
    except ClientError as e:
        raise e


# Fetching secrets from AWS Secrets Manager gcs_bucket_name
secret = getsecret(os.environ['GCS_BUCKET_SECRET_ARN'])
secret_dict = json.loads(secret)
GCS_BUCKET_NAME = secret_dict['gcs_bucket_name']
DYNAMODB_TABLE = getsecret(os.environ['DYNAMODB_TABLE_SECRET_ARN'])
GCP_SERVICE_ACCOUNT_CREDENTIALS_JSON = getsecret(
    os.environ['GCP_SERVICE_ACCOUNT_SECRET_ARN'])
mailgun_api_key = getsecret(os.environ['MAILGUN_API_KEY_SECRET_ARN'])
mailgun_domain = getsecret(os.environ['MAILGUN_DOMAIN_SECRET_ARN'])

# Parse JSON string to dictionary for GCP service account credentials
GCP_SERVICE_ACCOUNT_CREDENTIALS = json.loads(
    GCP_SERVICE_ACCOUNT_CREDENTIALS_JSON)

import requests

# def send_email_with_mailgun(mailgun_api_key, mailgun_domain, to, subject, text):
#     url = f"https://api.mailgun.net/v3/{mailgun_domain}/messages"
#     auth = ("api", mailgun_api_key)
#     data = {
#         "from": f"Excited User <mailgun@{mailgun_domain}>",
#         "to": to,
#         "subject": subject,
#         "text": text
#     }
    
#     response = requests.post(url, auth=auth, data=data)
#     return response


def send_email_with_mailgun(email_address, subject, body):
    api_key = mailgun_api_key
    domain = mailgun_domain
    sender_email = "no-reply@demo.webappcloud.me"

    url = f'https://api.mailgun.net/v3/{domain}/messages'
    data = {
        'from': sender_email,
        'to': email_address,
        'subject': subject,
        'text': body
    }

    response = requests.post(url, auth=('api', api_key), data=data)
    
    if response.status_code == 200:
        print("Email sent successfully")
        return True, response.json()  # Email sent successfully, return response
    else:
        print(f"Error sending email: {response.text}")
        return False, response.json() if response.status_code != 404 else None 

# Define a helper function to log events to DynamoDB
def log_dynamodb(request_id, user_email, status, info):
    table = dynamodb.Table(DYNAMODB_TABLE)
    table.put_item(
        Item={
            'RequestId': request_id,
            'UserEmail': user_email,
            'Status': status,
            'Info': info
        }
    )

# Define the Lambda function handler
def handler_lambda(event, context):
    # Initialize default values for email subject and body
    email_subject = "Submission Notification"
    email_body = "Your submission has been processed."
    try:
        # Step 1: Parse SNS Message
        message = json.loads(event['Records'][0]['Sns']['Message'])
        github_url = message.get('SubmissionURL')
        user_email = message.get('UserEmail')
        user_id = message.get('UserId')
        assignment_id = message.get('AssignmentId')
        submission_id = message.get('SubmissionId')
        error_message = message.get('errorMessage')

        # Step 2: Handle error message
        if error_message:
            # Log the error to DynamoDB
            log_dynamodb(context.aws_request_id, message['userEmail'], "Failed", error_message)
            send_email_with_mailgun(
            user_email,
            "Assignment Submission Failure",
            email_body = f"Your assignment has been failed. {error_message}"
        )
            return {'statusCode': 200, 'body': json.dumps(f'{error_message} notification sent.')}
        
        error_subject = "Submission Error"
        error_body = ""

        if not github_url or not user_email:
            error_info = "SubmissionURL or User Email missing from the SNS message."
            print("Error:", error_info)
            log_dynamodb(context.aws_request_id, user_email, "Failed", error_info)
            return {'statusCode': 400, 'body': json.dumps('Bad Request: Missing data in SNS message.')}
            send_email_with_mailgun(
            user_email,
            "Assignment Submission Failure",
            email_body = f"Your assignment has been failed. {error_info}"
        )
            

        # Validate the URL to ensure it points to a .zip file
        if not github_url.lower().endswith('.zip'):
            error_info = "Submission URL does not point to a .zip file."
            print("Error:", error_info)
            send_email_with_mailgun(
            user_email,
            "Assignment Submission Failure",
            email_body = f"Your assignment has been failed. {error_info}"
        )
            return {'statusCode': 400, 'body': json.dumps('Bad Request: URL must be a .zip file.')}

        # Step 2: Download content from GitHub
        response = requests.get(github_url, stream=True)
        # Check for a valid response
        if response.status_code != 200:
            error_info = f"Failed to download the file. Status code: {response.status_code}"
            print("Error:", error_info)
            email_subject = "Incomplete Submission Details"
            error_body = f"Your submission could not be processed because {error_info}"
            log_dynamodb(context.aws_request_id, user_email, "Failed", error_info)
            send_email_with_mailgun(
            user_email,
            "Assignment Submission Failure",
            email_body = f"Your assignment has been failed. {error_info}"
        )
            return {'statusCode': response.status_code, 'body': json.dumps('Bad Request: Could not download the file.')}

        # Check for a chunked response or content length
        is_chunked = response.headers.get('Transfer-Encoding') == 'chunked'
        content_length = response.headers.get('Content-Length', '0')  

        if not is_chunked and int(content_length) <= 0:
            error_info = "The file is empty."
            print("Error:", error_info)
            email_subject = "Incomplete Submission Details"
            error_body = f"Your submission could not be processed because {error_info}"
            log_dynamodb(context.aws_request_id, user_email, "Failed", error_info)
            send_email_with_mailgun(
            user_email,
            "Assignment Submission Failure",
            email_body = f"Your assignment has been failed. {error_info}"
            )   
            return {'statusCode': 400, 'body': json.dumps('Bad Request: The file is empty.')}

        content_type = response.headers.get('Content-Type', '')
        if 'application/zip' not in content_type:
            error_info = "URL did not point to a zip file."
            print("Error:", error_info)
            email_subject = "Incomplete Submission Details"
            error_body = f"Your submission could not be processed because {error_info}"
            log_dynamodb(context.aws_request_id, user_email, "Failed", error_info)
            send_email_with_mailgun(
            user_email,
            "Assignment Submission Failure",
            email_body = f"Your assignment has been failed. {error_info}"
            )
            return {'statusCode': 400, 'body': json.dumps('Bad Request: URL must point to a .zip file.')}

        # Extract the filename from the URL or use a default one
        filename = github_url.split('/')[-1] if '/' in github_url else 'submission.zip'
        blob_name = f"{assignment_id}/{user_id}/{submission_id}/{filename}"

        # Step 3: Stream content to GCS
        credentials = service_account.Credentials.from_service_account_info(GCP_SERVICE_ACCOUNT_CREDENTIALS)
        gcs_client = storage.Client(credentials=credentials)
        bucket = gcs_client.bucket(GCS_BUCKET_NAME)
        blob = bucket.blob(blob_name)
        
        with closing(response), blob.open('wb') as blob_file:
            shutil.copyfileobj(response.raw, blob_file)

        print("File was successfully downloaded and uploaded to GCS.")

        # Construct the submission link for the file in GCS
        submission_link = f"https://storage.googleapis.com/{GCS_BUCKET_NAME}/{blob_name}"


       # Step 6: Send Email via SES with submission link
        send_email_with_mailgun(
            user_email,
            "Assignment Submission Successful",
            email_body = f"Your assignment has been successfully uploaded. {submission_link}"
        )
        
        # Step 7: Log successful submission to DynamoDB with submission link
        log_dynamodb(
            request_id=context.aws_request_id,
            user_email=user_email,
            status="Success",
            info=f"File uploaded to GCS. Submission link: {submission_link}"
        )
    
    except json.JSONDecodeError as e:
        print("Error decoding the SNS message:", e)
        return {'statusCode': 400, 'body': json.dumps('Bad Request: Invalid JSON in SNS message.')}
    except ClientError as e:
        print("An error occurred while sending the email:", e)
        log_dynamodb(context.aws_request_id, user_email, "Error", "Failed to send email.")
        raise e  # Re-raise the exception to make the Lambda function fail
    except Exception as e:
        print("An error occurred:", e)
        return {'statusCode': 500, 'body': json.dumps('Internal Server Error')}

    return {
        'statusCode': 200,
        'body': json.dumps('Process completed successfully.')
    }
