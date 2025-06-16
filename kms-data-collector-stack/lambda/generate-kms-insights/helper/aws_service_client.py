import boto3
import botocore
from datetime import datetime
from helper.logger import logger

class AWSServiceClient:
    def __init__(self, account_id: str):
        self.account_id = account_id

    def _get_assumed_role_session(self, role_name: str) -> boto3.Session:
        """
        Create AWS session with assumed role.

        Args:
            role_name: The name of the role to assume

        Returns:
            boto3.Session: AWS Session with assumed role credentials
        
        Raises:
            Exception: If role assumption fails
        """
        try:
            role_arn = f"arn:aws:iam::{self.account_id}:role/{role_name}"
            sts_client = boto3.client('sts')
            
            logger.debug(f"Attempting to assume role: {role_arn}")
            response = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=f"KMSAnalyzer-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
            )
            
            credentials = response['Credentials']
            return boto3.Session(
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                logger.error(f"""
                    Access Denied assuming role {role_arn}. 
                    Please check:
                    1. The role exists in account {self.account_id}
                    2. Your IAM user/role has sts:AssumeRole permission
                    3. The role's trust policy allows your account/role to assume it
                    Error: {str(e)}
                """)
            logger.error(f"Failed to assume role {role_name} in {self.account_id}")
            raise
        except Exception as e:
            logger.error(f"Other Exception - Failed to assume role: {str(e)}")
            raise