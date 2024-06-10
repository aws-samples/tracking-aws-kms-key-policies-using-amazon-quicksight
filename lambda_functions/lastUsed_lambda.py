# DAP241 - re:Inforce 2024 - June 10th-12th 2024
# lastUsed_lambda function:
# This function is used to read CloudTrail for KMS Events using a filter of
#  EventSource = kms.amazonaws.com. Find the most recent events for each key.
# Write them to DynamoDB

import json
import logging
import os
from datetime import datetime, timedelta

import boto3
import botocore

# Logging
logger = logging.getLogger(__name__)
FORMAT = (
    "[%(asctime)s:%(levelname)s:%(filename)s:%(lineno)s - %(funcName)10s()] %(message)s"
)

logger.setLevel(logging.INFO)
logging.basicConfig(format=FORMAT)

# Globals
# Which region are we scanning?  If no env varaible set, default to us-east-1
regionToScan = str(os.getenv("REGIONTOSCAN", "us-east-1"))
# Name of the DynamoDB Table containing lastUsed data.  Default to 'lastUsedTable'
dynamoDBTable = str(os.getenv("DYNAMODBTABLE", "lastUsedTable"))
# Account number containing the DynamoDB Table containing lastUsed.
dynamoDBAccount = str(os.getenv("DYNAMODBACCOUNT", "123456789012"))
# IAM Role assumed by Lambdas in member accounts to be able to PUT to DynamoDB table.
dynamoDBRole = str(os.getenv("DYNAMODBROLE", "putToDynamoRole"))
# Region containing the DynamoDB Table containing lastUsed.
dynamoDBRegion = str(os.getenv("DYNAMODBREGION", "us-east-1"))
# Maximum number of results returng in a paging operation to CloudTrail.
maxResults = int(os.getenv("MAXRESULTS", 100))
# Number of hours to search back in CloudTrail. Default to 24. Set to 2160 for 90 days
numberOfHours = int(os.getenv("NUMBEROFHOURS", 24))


def getLambdaRegion(context):
    region = context.invoked_function_arn.split(":")[3]
    return region


def populateTheObject(event, keyID):
    kms_event_object = {}

    kms_event_object["keyID"] = keyID

    if "EventTime" in event:
        event["EventTime"] = str(event["EventTime"])  # Convert from datetime to string
        kms_event_object["EventTime"] = str(event["EventTime"])

    if "Username" in event:
        kms_event_object["Username"] = event["Username"]

    if "EventName" in event:
        kms_event_object["EventName"] = event["EventName"]

    if "resources" in event:
        kms_event_object["resources"] = event["resources"]

    if "CloudTrailEvent" in event:
        # Turn the JSON into a dictionary
        cloudTrailEventDictFromJson = json.loads(event["CloudTrailEvent"])

        if "requestParameters" in cloudTrailEventDictFromJson:
            if "encryptionContext" in cloudTrailEventDictFromJson["requestParameters"]:
                kms_event_object["encryptionContext"] = str(
                    cloudTrailEventDictFromJson["requestParameters"][
                        "encryptionContext"
                    ]
                )
        if "resources" in cloudTrailEventDictFromJson:
            if "arn" in cloudTrailEventDictFromJson["resources"]:
                kms_event_object["resourcesArn"] = cloudTrailEventDictFromJson[
                    "resources"
                ]["arn"]
                kms_event_object["resourcesType"] = cloudTrailEventDictFromJson[
                    "resources"
                ]["type"]
                kms_event_object["resourcesAccountId"] = cloudTrailEventDictFromJson[
                    "resources"
                ]["accountId"]

        if "eventSource" in cloudTrailEventDictFromJson:
            kms_event_object["eventSource"] = cloudTrailEventDictFromJson["eventSource"]

        if "userIdentity" in cloudTrailEventDictFromJson:
            if "type" in cloudTrailEventDictFromJson["userIdentity"]:
                kms_event_object["userIdentityType"] = cloudTrailEventDictFromJson[
                    "userIdentity"
                ]["type"]
            if "invokedBy" in cloudTrailEventDictFromJson["userIdentity"]:
                kms_event_object["userIdentityInvokedBy"] = cloudTrailEventDictFromJson[
                    "userIdentity"
                ]["invokedBy"]

        if "sourceIPAddress" in cloudTrailEventDictFromJson:
            kms_event_object["sourceIPAddress"] = cloudTrailEventDictFromJson[
                "sourceIPAddress"
            ]

    return kms_event_object


def grabKMSCTEvents(numberOfHours, region):
    timeNow = datetime.now()
    logger.info(f"Now: {timeNow}")

    # Get the time.  Defaults to 24 hours ago
    timeToGoBack = timeNow - timedelta(hours=int(numberOfHours))
    logger.info(f"timeToGoBack: {timeToGoBack}")

    cloudtrail = boto3.client("cloudtrail", region_name=region)

    paginator = cloudtrail.get_paginator("lookup_events")
    page_iterator = paginator.paginate(
        LookupAttributes=[
            {"AttributeKey": "EventSource", "AttributeValue": "kms.amazonaws.com"}
        ],
        StartTime=timeToGoBack,
        MaxResults=int(maxResults),  # Is this really used?  Defaults to 50
    )

    # What are our definitions of KMS key "last used"?
    validActions = [
        "Decrypt",
        "Encrypt",
        "GenerateDataKeyWithoutPlaintext",
    ]
    lastUsedEvents = {}

    # kms_events = []
    page_count = 1  # Count how many pages of results there are
    events_count = 1  # How many KMS Cloud Trail events did we find?

    logger.info(f"Starting pagination...")

    # Loop through all the pages of CloudTrail events
    for page in page_iterator:
        logger.info(f"Page Count: {page_count}")
        page_count += 1
        for event in page["Events"]:
            events_count += 1

            # If this is a valid action, then process it
            if event["EventName"] in validActions:
                # Is there an actual CloudTrailEvent(almost definitely yes)
                if "CloudTrailEvent" in event:
                    # Turn the JSON into a dictionary
                    cloudTrailEventDictFromJson = json.loads(event["CloudTrailEvent"])

                    # Grab the ARN, resource type and AccountID about the resource(key) from the CloudTrail event
                    if "resources" in cloudTrailEventDictFromJson:
                        keyID = cloudTrailEventDictFromJson["resources"][0]["ARN"]
                        # Split out to return the keyID from the ARN
                        keyID = keyID.split("/")[1]

                    # Get the EventTime
                    if "EventTime" in event:
                        EventTime = str(event["EventTime"])

                    ### Now lookup if this is already keyed in the hashmap

                    # Do we already have the keyID in the dictionary
                    if keyID in lastUsedEvents:
                        # Do we already have a 'lastUsed' time for that keyID?
                        if "EventTime" in lastUsedEvents[keyID]:
                            # Is the EventTime newer than the existing one?
                            if EventTime > lastUsedEvents[keyID]["EventTime"]:
                                # Create the object in preparation to store in the array and DynamoDB
                                lastUsedEventObject = populateTheObject(
                                    event=event, keyID=keyID
                                )
                                # Store the object in the array to finally load into DynamoDB
                                lastUsedEvents[keyID] = lastUsedEventObject

                    else:
                        # Key not found before.
                        # Let's create the object ready to store in the array to finally load into DynamoDB
                        lastUsedEventObject = populateTheObject(
                            event=event, keyID=keyID
                        )
                        # Store the object in the array to finally load into DynamoDB
                        lastUsedEvents[keyID] = lastUsedEventObject

    logger.info(f"Events Processed: {events_count}")
    return lastUsedEvents


# Function to assume role
def getAssumedRoleSession(aws_account: str, role_name: str):
    role_to_assume_arn = "arn:aws:iam::" + aws_account + ":role/" + role_name
    sts_client = boto3.client("sts")

    try:
        response = sts_client.assume_role(
            RoleArn=role_to_assume_arn, RoleSessionName=role_name
        )
        creds = response["Credentials"]
        session = boto3.session.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
        return session
    except Exception as e:
        logger.error(f"Unable to assume role in account {aws_account}: {e}")


def pushToDynamoDB(
    dynamoDB_json: json,
    dynamoDBAccount: str,
    dynamoDBTable: str,
    dynamoDBRole: str,
    dynamoDBRegion: str = "us-east-1",
):
    numberOfEntriesSuccessfullyAddedToDynamoDB = 0

    try:
        session = getAssumedRoleSession(dynamoDBAccount, dynamoDBRole)

        dynamodb_resource = session.resource("dynamodb", region_name=dynamoDBRegion)

        table = dynamodb_resource.Table(dynamoDBTable)
        for item in dynamoDB_json:

            response = add_cloudtrail_item_to_dynamodb(table, dynamoDB_json[item])
            if response["ResponseMetadata"]["HTTPStatusCode"] == 200:
                numberOfEntriesSuccessfullyAddedToDynamoDB += 1
        logger.info(
            f"{numberOfEntriesSuccessfullyAddedToDynamoDB} records successfully added to arn:aws:dynamodb:{dynamoDBRegion}:{dynamoDBAccount}:table/{dynamoDBTable}"
        )
        return numberOfEntriesSuccessfullyAddedToDynamoDB

    except botocore.exceptions.ClientError as err:
        logger.error(
            "Couldn't add item %s to table %s. Here's why: %s: %s",
            item,
            table,
            err.response["Error"]["Code"],
            err.response["Error"]["Message"],
        )
        raise


def add_cloudtrail_item_to_dynamodb(table, item):
    try:
        return table.put_item(Item=item)
    except botocore.exceptions.ClientError as err:
        logger.error(
            "Couldn't add item %s to table %s. Here's why: %s: %s",
            item,
            table,
            err.response["Error"]["Code"],
            err.response["Error"]["Message"],
        )
        raise


def lambda_handler(event, context):
    # Gather relevant details
    region = getLambdaRegion(context)
    logger.info(f"Region: {region}")

    kms_events = {}
    kms_events = grabKMSCTEvents(numberOfHours, region)

    kms_event_count = len(kms_events)
    logger.info(f"{kms_event_count} events found")

    logger.info(
        f"Now loading {kms_event_count} events into Dynamo: arn:aws:dynamodb:{dynamoDBRegion}:{dynamoDBAccount}:table/{dynamoDBTable}"
    )

    successfulRecordCount = pushToDynamoDB(
        dynamoDB_json=kms_events,
        dynamoDBAccount=dynamoDBAccount,
        dynamoDBTable=dynamoDBTable,
        dynamoDBRegion=dynamoDBRegion,
        dynamoDBRole=dynamoDBRole,
    )

    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "message": f"{kms_event_count} events found.  {successfulRecordCount} records successfully added to arn:aws:dynamodb:{dynamoDBRegion}:{dynamoDBAccount}:table/{dynamoDBTable}"
            }
        ),
    }


if __name__ == "__main__":
    # Reads regionToScan variable (defaults to 'us-east-1')
    kms_events = {}
    kms_events = grabKMSCTEvents(numberOfHours, regionToScan)

    kms_event_count = len(kms_events)
    logger.info(f"{kms_event_count} events found")

    logger.info(
        f"Now loading {kms_event_count} events into Dynamo: arn:aws:dynamodb:{dynamoDBRegion}:{dynamoDBAccount}:table/{dynamoDBTable}"
    )

    # print(f"kms_events: {kms_events}")
    successfulRecordCount = pushToDynamoDB(
        dynamoDB_json=kms_events,
        dynamoDBAccount=dynamoDBAccount,
        dynamoDBTable=dynamoDBTable,
        dynamoDBRegion=dynamoDBRegion,
        dynamoDBRole=dynamoDBRole,
    )
