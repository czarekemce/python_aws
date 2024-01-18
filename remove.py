import logging
import boto3
from botocore.exceptions import ClientError
from datetime import datetime
import os

dt = datetime.now()
formatted_date = dt.strftime("%Y%m%d%H%M%S")
timestamp = formatted_date[0:8]


logger = logging.getLogger(__name__)
user_name = "new-test-python-user"
bucket_name = (f"new-test-bucket{timestamp}")
role_name = "new-python-role"
policy_name = 'test_python_policy'
file_path = 'policy_arn_name.txt'

with open(file_path, 'r') as file:
    read = file.readlines()
    arn_name = read[0].strip()
    file.close()
    os.remove(file_path)

policy_arn_name = arn_name

aws_access_key_id = os.environ.get('AWS_ACCESS_KEY_ID')
aws_secret_access_key = os.environ.get('AWS_SECRET_KEY_ID')
aws_session = boto3.Session(
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key
)

iam_client = aws_session.resource("iam")


def detach_from_user():

    iam_client = boto3.client('iam')

        

    try:
        iam_client.detach_user_policy(
            UserName=user_name,
            PolicyArn=policy_arn_name
)
        logger.info("Detached policy %s from user %s.", policy_arn_name, user_name)
    except ClientError:
        logger.exception(
            "Couldn't detach policy %s from user %s.", policy_arn_name, user_name
        )
        raise

def delete_policy():

    try:
        iam_client.Policy(policy_arn_name).delete()
        logger.info("Deleted policy %s.", policy_arn_name)
    except ClientError:
        logger.exception("Couldn't delete policy %s.", policy_arn_name)
        raise

def delete_role():

    try:
        iam_client.Role(role_name).delete()
        logger.info("Deleted role %s.", role_name)
    except ClientError:
        logger.exception("Couldn't delete role %s.", role_name)
        raise


def delete_user():

    try:
        iam_client.User(user_name).delete()
        logger.info("Deleted user %s.", user_name)
    except ClientError:
        logger.exception("Couldn't delete user %s.", user_name)
        raise


def delete_bucket():

    s3 = boto3.resource('s3')
    bucket = s3.Bucket(bucket_name)

    try:
        bucket.delete()
        logger.info("Deleted user %s.", user_name)
    except ClientError:
        logger.exception("Couldn't delete user %s.", user_name)
        raise

delete_bucket()
detach_from_user()
delete_role()
delete_policy()
delete_user()
