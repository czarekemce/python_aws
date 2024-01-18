import logging
import time
import json
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
region = 'eu-central-1'
role_name = "new-python-role"
policy_name = 'test_python_policy'

aws_access_key_id = os.environ.get('AWS_ACCESS_KEY_ID')
aws_secret_access_key = os.environ.get('AWS_SECRET_KEY_ID')
aws_session = boto3.Session(
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key
)

iam_client = aws_session.resource("iam")

def create_s3_bucket():

    s3_client = boto3.client('s3')

    try:
        s3_client.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region})
        s3_client.get_waiter('bucket_exists').wait(Bucket=bucket_name)
        logger.info("Created bucket '%s' in region=%s", bucket_name, region)
    except ClientError as error:
        logger.exception(
            "Couldn't create bucket named '%s' in region=%s.",
            bucket_name,
            region,
        )
        raise error


def create_service_account():
    # get_user is not included in aws_session.resource
    iam_client = boto3.client('iam')

    iam_client.create_user(UserName=user_name)
    response = iam_client.get_user(UserName=user_name)

    full_user_arn = response['User']['Arn']

    user_arn_parts = full_user_arn.split(':')
    user_arn_number = user_arn_parts[4]

    return {
        'UserName': user_name,
        'UserArn': user_arn_number
    }

new_user_info = create_service_account()
user_policy_arn = f"{new_user_info['UserArn']}"


def create_s3_read_policy():

    path='/'
    description='BOTO3 role'

    trust_policy={
        "Version": "2012-10-17",
        "Statement": [
            {
            "Sid": "",
            "Effect": "Allow",
            "Principal": {
                "Service": "s3.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
            }
        ]
    }

    iam_client.create_role(
        Path=path,
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Description=description,
        MaxSessionDuration=3600
    )

    managed_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "S3ReadOnly",
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:ListBucket"
                ],
                "Resource": [
                f"arn:aws:s3:::{bucket_name}/*",
                f"arn:aws:s3:::{bucket_name}",
                ]
            },
        ]
    }

    iam_client.create_policy(
        PolicyName= policy_name,
        PolicyDocument=json.dumps(managed_policy)
    )
    time.sleep(2)

def attach_policy(arn, user):
    # attach_user_policy is not included in aws_session.resource
    iam_client = boto3.client('iam')
    policy_Arn=f"arn:aws:iam::{arn}:policy/{policy_name}"

    with open('policy_arn_name.txt', 'w') as file:
        file.write(policy_Arn)

    try:
        iam_client.attach_user_policy(UserName=user, PolicyArn=policy_Arn)
        logger.info("Attached policy %s to user %s.", policy_Arn, user)
    except ClientError:
        logger.exception("Couldn't attach policy %s to user %s.", policy_Arn, user)
        raise


create_s3_bucket()
create_s3_read_policy()
attach_policy(user_policy_arn, user_name)