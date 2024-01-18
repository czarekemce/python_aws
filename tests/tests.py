import boto3
from datetime import datetime
import os


dt = datetime.now()
formatted_date = dt.strftime("%Y%m%d%H%M%S")
timestamp = formatted_date[0:8]

file_path = '/home/runner/work/python_aws/python_aws/resources/policy_arn_name.txt'
with open(file_path, 'r') as file:
    read = file.readlines()
    arn_name = read[0].strip()
    file.close()

policy_arn_name = arn_name

def verify_resources():
    bucket_name = (f"new-test-bucket{timestamp}")
    user_name = "new-test-python-user"
    role_name = "new-python-role"

    aws_access_key_id = os.environ.get('AWS_ACCESS_KEY_ID')
    aws_secret_access_key = os.environ.get('AWS_SECRET_KEY_ID')

    aws_session = boto3.Session(
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key
    )    
    s3_client = aws_session.client('s3')

    try:
        response = s3_client.list_buckets()
        bucket_names = [bucket['Name'] for bucket in response['Buckets']]
        matching_bucket = [b for b in bucket_names if bucket_name in b]
        if matching_bucket:
            print(f"Bucket {bucket_name} exists")
        else:
            print(f"{bucket_name} not found")
    except Exception as e:
        print(f"Bucket '{bucket_name}' does not exist. Error: {e}")

    iam_client = boto3.client('iam')
    try:
        response_user = iam_client.get_user(UserName=user_name)
        print(f"IAM user'{user_name}' exists.")
    except iam_client.exceptions.NoSuchEntityException:
        print(f"IAM user'{user_name}' does not exist.")

    try:
        response_role = iam_client.get_role(RoleName=role_name)
        print(f"IAM role'{role_name}' exists.")
    except iam_client.exceptions.NoSuchEntityException:
        print(f"IAM role'{role_name}' does not exists.")

    iam_client = boto3.client('iam')
    try:
        response_user = iam_client.get_policy(PolicyArn=policy_arn_name)
        print(f"Policy'{policy_arn_name}' exists.")
    except iam_client.exceptions.NoSuchEntityException:
        print(f"Policy'{policy_arn_name}' does not exist.")

if __name__ == '__main__':
    verify_resources()
    