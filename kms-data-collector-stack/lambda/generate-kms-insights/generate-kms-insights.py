"""
AWS Lambda function that:
1. Tracks KMS (encryption key) usage from CloudTrail logs
2. Analyzes KMS key policies
"""

from helper.logger import logger
from datetime import datetime

from helper.aws_s3_client import S3Client
from helper.aws_kms_client import KMSClient
from helper.aws_cloud_trail_client import CloudTrailClient
from helper.aws_key_policy_extractor import KMSPolicyExtractor
from helper.aws_key_policy_analyzer import KMSPolicyAnalyzer



def handler(event, context):

    logger.info(f"Processing event: {event}")
    
    account_number = event.get("accountId")
    account_region = event.get("region")
    funcStatus = event

    s3_client = S3Client()

    # Part 1: Process KMS usage events from CloudTrail
    try:
        cloudtrail_client = CloudTrailClient(account_number, account_region)
        kms_events = cloudtrail_client.get_kms_events(hours=24)

        for key_id, event_data in kms_events.items():

            event_time = datetime.strptime(event_data["EventTime"], '%Y-%m-%d %H:%M:%S%z')
            date_path = event_time.strftime("%Y/%m/%d")

            # folder for historical record
            s3_client.upload_data(
                data=[event_data],
                file_path=f"kms/key_last_used/{date_path}/last_used/",
                file_name=f"kms_last_used_data_{key_id}.gz"
            )

            # folder for 'latest' state
            s3_client.upload_data(
                data=[event_data],
                file_path="kms/key_last_used/latest/",
                file_name=f"kms_last_used_data_{key_id}.gz"
            )
    except Exception as e:
        logger.error(f"Failed processing KMS CloudTrail events: {str(e)}")
        raise

    # Part 2: Analyze KMS keys and the key policies
    try:
        kms_client = KMSClient(account_number, account_number, account_region)
        keys = kms_client.get_key_inventory()

        kms_policy_extractor = KMSPolicyExtractor(account_number, account_number, account_region)
        keys_with_policies = kms_policy_extractor.split_key_policies(key_map=keys)

        kms_policy_analyzer = KMSPolicyAnalyzer(account_number)
        policy_analysis = kms_policy_analyzer.process_policy_insights(keys_with_policies)

        today = datetime.now().strftime("%Y/%m/%d")

        # folder for historical record
        s3_client.upload_data(
            data=policy_analysis,
            file_path=f"kms/key_data/{today}/",
            file_name=f"kms_insight_data_{account_number}{account_region}.gz"
        )

    except Exception as e:
        logger.error(f"Failed processing KMS policies: {str(e)}")
        raise


    funcStatus['funcState'] = "complete"
    return funcStatus

# For local testing
if __name__ == "__main__":
    logger.info("<<<<<<<<<< KMSReadLambda >>>>>>>>>>")
    test_event = {
        "accountId": "477673582600",
        "region": "eu-west-2"
    }
    handler(test_event, None)