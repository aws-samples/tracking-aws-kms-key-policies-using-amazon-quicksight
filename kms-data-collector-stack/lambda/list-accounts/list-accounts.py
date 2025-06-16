import boto3
import os
import logging
import re
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()

# TODO: Read from parameter
logger.setLevel(logging.INFO)

def get_active_accounts():
    """
    Retrieves a list of active accounts in AWS Organizations.
    
    Uses pagination to handle large numbers of accounts. Logs the number of active accounts retrieved.
    """
    try:
        session = boto3.session.Session()
        client = session.client('organizations')
        paginator = client.get_paginator('list_accounts')
        
        active_accounts = []
        
        # Paginate through accounts and fetch active ones
        for page in paginator.paginate():
            for account in page['Accounts']:
                if account['Status'] == 'ACTIVE':
                    active_accounts.append(account['Id'])

        logger.info(f"Retrieved {len(active_accounts)} active accounts.")
        return active_accounts
    except ClientError as e:
        logger.error(f"AWS client error retrieving active accounts: {e}")
    except Exception as e:
        logger.error(f"Unexpected error retrieving active accounts: {e}")

    return []

def handler(event, context):
    """
    Lambda function handler that processes the event and retrieves active accounts and regions.
    
    Returns a combination of each active account and region.
    """

    sts = boto3.client('sts')

    try:
        # Get environment variables with a fallback default
        default_region = boto3.session.Session().region_name
        regions = os.getenv("REGIONS_TO_SCAN", default_region).split(",")

        logger.info(f"Regions configured: {regions}")
        
        # Fetch active accounts
        active_accounts = []
        deployment_type = os.getenv("DEPLOYMENT_TYPE", "local")
        if deployment_type == "org":
            logger.info("Deployment type is 'org'. Retrieving active accounts.")
            active_accounts = get_active_accounts()
            if not active_accounts:
                logger.error("No accounts found in AWS Organization.")
        elif deployment_type == "local":
            logger.info("Deployment type is 'local'. Using the current account only.")
            active_accounts = [sts.get_caller_identity()['Account']]
        else:
            logger.info("Deployment type is 'account list'.")
            accounts = deployment_type.split(",")
            invalid_accounts = [acc.strip() for acc in accounts if not re.match(r'^\d{12}$', acc.strip())]
            if invalid_accounts:
                logger.error(f"Invalid account(s) {invalid_accounts} in input detected. Please check the provided AWS account list!")
            else:
                logger.info("Deployment type is 'list'. Processing the provided active accounts.")
                active_accounts = accounts

        # Create combinations of account IDs and regions
        output = [{"accountId": account_id, "region": region} for account_id in active_accounts for region in regions]
        
        logger.info(f"Processing of {len(output)} account-region combinations.")
        return output
    except Exception as e:
        logger.error(f"Error in lambda handler: {e}")
        raise