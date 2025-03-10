# KMSRead_lambda function:
# This function reads down the list of accounts in the 'accounts' DynamoDB table.
# For every account is tries to AssumeRole into that account and then read the KMS keys
# For every key it finds it then reads their aliases, tags, creation date via the KMS APIs
#  and stores them in a big JSON object.
# It then augments this with the details of when the key was lastUsed from the
#  'lastUsedTable' DynamoDB table
# Once all this is done, each key policy __statement__ is written as a separate line in a CSV
# This is done to make it clearer when 'Concerns' are raised and which policy
#  statement they relate to.
# Once all this is complete, the final CSV file is pushed up to S3 with a file
#  name of the account and region

import csv
import json
import logging
import os
from datetime import date, datetime

# Define Imports
import boto3
import botocore
from botocore.exceptions import ClientError

# Logging
logger = logging.getLogger(__name__)
FORMAT = (
    "[%(asctime)s:%(levelname)s:%(filename)s:%(lineno)s - %(funcName)10s()] %(message)s"
)

logger.setLevel(logging.INFO)
logging.basicConfig(format=FORMAT)


# Globals
# DynamoDB table containing list of accounts and mapping IDs
# Table name of accounts.  Defaults to 'accounts'
accountsDynamoDBTable = str(os.getenv("ACCOUNTSDYNAMODBTABLE", "accounts"))

# Account number containing the DynamoDB Table containing 'accounts' table
accountsDynamoDBAccount = str(os.getenv("ACCOUNTSDYNAMODBACCOUNT", "123456789012"))

# IAM Role assumed by this lambda function with permissions to read 'accounts' DynamoDB table
accountsDynamoDBRole = str(os.getenv("ACCOUNTSDYNAMODBROLE", "ReadDynamoDBRole"))

# Region containing the DynamoDB Table containing 'accounts' table
accountsDynamoDBRegion = str(os.getenv("ACCOUNTSDYNAMODBREGION", "us-east-1"))

# DynamoDB table containing the last used data
lastUsedDynamoDBTable = str(os.getenv("LASTUSEDDYNAMODBTABLE", "lastUsedTable"))

# Account number containing the DynamoDB Table containing 'lastUsedTable' table
lastUsedDynamoDBAccount = str(os.getenv("LASTUSEDDYNAMODBACCOUNT", "123456789012"))

# IAM Role assumed by this lambda function with permissions to read 'lastUsedTable' table
lastUsedDynamoDBRole = str(os.getenv("LASTUSEDDYNAMODBROLE", "ReadDynamoDBRole"))

# Region containing the DynamoDB Table containing 'lastUsedTable' table
lastUsedDynamoDBRegion = str(os.getenv("LASTUSEDDYNAMODBREGION", "us-east-1"))

# Cross-account role assumed by this lambda function in each memeber account.
#  This role is deployed by the member-account-kmsread-role.yaml CloudFormation
#  and has permissions to read and gather details of KMS keys.
xaKMSReadRole = str(os.getenv("XAKMSREADROLE", "XA-KMSRead-Role"))


# Read S3 bucket name containing the CSV files
destination_s3_bucket = str(
    os.getenv("DEST_BUCKET", "kms-read-policy-123456789012-us-east-1")
)

# Read active regions from env variable to loop through once we assume into
#  member account
regions_string = str(os.getenv("REGIONS", "eu-west-1,eu-west-2,us-east-1"))


# Gather all the keys.  These are used to drive the policy and alias searches
def getKeys(kms):
    response = kms.list_keys()
    return response["Keys"]


# Gather the list of policies containing all the key policy statements
def getKeyPolicies(kms, keyid):
    try:
        response = kms.list_key_policies(KeyId=keyid)
        return response["PolicyNames"]
    except botocore.exceptions.ClientError as error:
        if error.response["Error"]["Code"] == "AccessDeniedException":
            logger.warning(
                f"Unable to get Policies: {error.response['Error']['Message']}"
            )
        else:
            logger.error(f"ERROR RESPONSE: {error.response}")
            raise error


# Read all the account from the 'accounts' table so we know what to
#  loop through
def get_accounts(
    accountsDynamoDBAccount: str,
    accountsDynamoDBRole: str = "ReadDynamoDBRole",
    accountsDynamoDBTable: str = "accounts",
    region: str = "us-east-1",
):
    # Get assumed role credentials for dynamodb read
    try:
        session = getAssumedRoleSession(accountsDynamoDBAccount, accountsDynamoDBRole)

        dynamodb = session.resource("dynamodb", region_name=region)
        table = dynamodb.Table(accountsDynamoDBTable)

        accounts = table.scan(ProjectionExpression="accountId, accountName")

        return accounts["Items"]

    except Exception as e:
        logger.error("Issue assuming the XA role: " + str(e))


# Gather key policies based on initial list of keys
# Pass in the 'kms' session so we don't need to re-assume any roles anywhere
def getPolicy(kms, keyId, policy):
    response = kms.get_key_policy(KeyId=keyId, PolicyName=policy)
    return json.loads(response["Policy"])


# Get the creation date of the key
def getCreationDate(kms, keyId):
    response = kms.describe_key(KeyId=keyId)
    return response["KeyMetadata"]["CreationDate"].strftime("%Y-%m-%d %H:%M:%S")


# Get all the tags for the keys
def getTag(kms, keyId):
    try:
        response = kms.list_resource_tags(KeyId=keyId)
        return response["Tags"]
    except botocore.exceptions.ClientError as error:
        if error.response["Error"]["Code"] == "AccessDeniedException":
            logger.warning(f"Unable to get Tags: {error.response['Error']['Message']}")
        else:
            logger.error(f"ERROR RESPONSE: {error.response}")
            raise error


# Get the alias the kms key
def getAliases(kms, keyId):
    response = kms.list_aliases(KeyId=keyId)
    return response["Aliases"]


# Get the last used dates from lastUsedTable
def getLastUsed(
    keyid,
    lastUsedDynamoDBAccount,
    lastUsedDynamoDBRole,
    lastUsedDynamoDBTable,
    lastUsedDynamoDBRegion,
):
    try:
        session = getAssumedRoleSession(lastUsedDynamoDBAccount, lastUsedDynamoDBRole)
        dynamodb = session.resource("dynamodb", region_name=lastUsedDynamoDBRegion)
        table = dynamodb.Table(lastUsedDynamoDBTable)
        response = table.get_item(Key={"keyID": keyid})
        if "Item" in response:
            return response["Item"]
        else:
            return None

    except Exception as e:
        logger.error("Issue getting the last used events: " + str(e))

    return None


# The main orchestrator function.  This pulls everything together
def getEverythingJson(kms):
    kms_keys = getKeys(kms)

    keyMap = {"kms_keys": []}

    for kms_key in kms_keys:
        # Create an empty dict to hold everything
        kms_key_object = {}
        # Create a key using the KMS keyId
        kms_key_object["KeyId"] = kms_key["KeyId"]
        # Create an empty list for all the aliases just in case
        #  we don't find any.

        # Create a temporary list to hold the aliaes
        list_of_aliases = []
        # Create a temporary list to hold the policies
        list_of_policies = []

        keyid = kms_key["KeyId"]

        # Now grab all the aliases passing in our kms session and the keyId
        kms_aliases = getAliases(kms, keyid)

        # Did we find any aliases?
        if kms_aliases:
            # Loop through all the aliases that we found (might just be one)
            for ind in range(len(kms_aliases)):
                # Add the alias to the list of aliases
                list_of_aliases.append(kms_aliases[ind]["AliasName"])

        # Add them to the key object (even if list_of_aliases is empty)
        kms_key_object["Aliases"] = list_of_aliases

        # Now grab all the policies passing in our kms session and the keyId
        kms_key_policies = getKeyPolicies(kms, keyid)

        # Did we find any key policies?
        # At this stage we just want all the policies.  We're not digging
        #  into them yet.
        if kms_key_policies:
            # If so, grab the policy details for the specificed keyId
            for policy in kms_key_policies:
                key_policy = getPolicy(kms, keyid, policy)
                # Append this policy to the list of policies
                list_of_policies.append(key_policy)

        kms_key_object["Policies"] = list_of_policies

        creation_date = getCreationDate(kms, keyid)
        kms_key_object["CreationDate"] = creation_date

        key_tag = getTag(kms, keyid)
        kms_key_object["Tags"] = key_tag

        # Now grab the lastUsedDate of the KMS Key from the 'lastUsedTable' DynamoDB table
        #  NOTE: this table is populated separately by the 'lastUsed_lambda'
        kms_last_used = getLastUsed(
            kms_key["KeyId"],
            lastUsedDynamoDBAccount,
            lastUsedDynamoDBRole,
            lastUsedDynamoDBTable,
            lastUsedDynamoDBRegion,
        )

        # Did we find any lastUsed entries in the DynamoDB table?
        if kms_last_used:
            # If we did then grab the relevant values from the lastUsed DynamoDB record
            if "EventTime" in kms_last_used:
                kms_key_object["LastUsedTime"] = kms_last_used["EventTime"]
            if "EventName" in kms_last_used:
                kms_key_object["LastUsedAction"] = kms_last_used["EventName"]
            if "encryptionContext" in kms_last_used:
                kms_key_object["LastUsedEncryptionContext"] = kms_last_used[
                    "encryptionContext"
                ]
            if "sourceIPAddress" in kms_last_used:
                kms_key_object["LastUsedSourceIPAddress"] = kms_last_used[
                    "sourceIPAddress"
                ]
            if "Username" in kms_last_used:
                kms_key_object["LastUsedUsername"] = kms_last_used["Username"]

        # Now we have all entries for the kms_key_object including:
        #  ["KeyId"], ["Aliases"], ["Policies"], ["Tags"], ["CreationDate"], ["LastUsedTime"] etc.

        #  The kms_key_object now contains everything we need for the CSV

        # Add this key to the big list of keys
        keyMap["kms_keys"].append(kms_key_object)
    return keyMap


# Function to assume role
def getAssumedRoleSession(aws_account, role_name="XA-KMSRead-Role"):
    role_to_assume_arn = "arn:aws:iam::" + aws_account + ":role/" + role_name
    sts_client = boto3.client("sts")

    logged_on_arn = sts_client.get_caller_identity()["Arn"]
    logger.debug(
        f"Logged on user: '{logged_on_arn}' assuming role '{role_to_assume_arn}"
    )

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
        logger.error(
            f"Unable to assume role '{role_name}' in account  in '{aws_account}': {e}"
        )


# Now generate a CSV based on the keyMap file
def getEverythingToCSV(
    accountNumber: str, accountName: str, filename: str, keyMap: dict, region: str
):
    logger.info(f"{len(keyMap['kms_keys'])} KMS keys found in [{region}]")
    filename = "/tmp/" + filename

    kmsKeysWithPolicies = []

    for key in keyMap["kms_keys"]:
        # This is where the create the multiple lines for each policy statement
        #  but repeat the core data such as KeyID, creationDate, last used etc.

        if "Policies" in key:

            # Grab the KeyId
            keyId = key["KeyId"]

            # Grab the 1st alias
            keyAlias = None
            if "Aliases" in key:
                logger.debug(f"{len(key['Aliases'])} aliases found for {keyId}.")
                # If there are any aliases found, then take the first
                if len(key["Aliases"]) > 0:
                    keyAlias = key["Aliases"][0]

            # Grab the last used details
            keyLastUsedTime = None
            if "LastUsedTime" in key:
                keyLastUsedTime = key["LastUsedTime"]

            keyLastUsedAction = None
            if "LastUsedAction" in key:
                keyLastUsedAction = key["LastUsedAction"]

            keyLastUsedEncryptionContext = None
            if "LastUsedEncryptionContext" in key:
                keyLastUsedEncryptionContext = key["LastUsedEncryptionContext"]

            keyLastUsedSourceIPAddress = None
            if "LastUsedSourceIPAddress" in key:
                keyLastUsedSourceIPAddress = key["LastUsedSourceIPAddress"]

            keyLastUsedUsername = None
            if "LastUsedUsername" in key:
                keyLastUsedUsername = key["LastUsedUsername"]

            # Process the policies
            # NOTE: A key may have multiple statements in a policy.  A unique line
            #  is created for each policy. The aliases and last useds are duplicated for those lines
            #  but this means that concerns can be generated for each statement rather than a policy overall
            for x in range(
                len(key["Policies"])
            ):  # Probably always one Policy - so x will almost always be 0
                # This is where we loop through each Statement in the policy but duplicate the records
                for line in grabPolicyStatementDetailsList(
                    accountNumber,
                    accountName,
                    region,
                    keyId,
                    keyAlias,
                    key["Policies"][x]["Statement"],
                    key["Tags"],
                    key["CreationDate"],
                    keyLastUsedTime,
                    keyLastUsedAction,
                    keyLastUsedEncryptionContext,
                    keyLastUsedSourceIPAddress,
                    keyLastUsedUsername,
                ):
                    kmsKeysWithPolicies.append(line)

        # Write to CSV
        header = [
            "Date",
            "AccountNumber",
            "AccountName",
            "Region",
            "KeyId",
            "Alias",
            "Sid",
            "Effect",
            "Principal",
            "Principal Service",
            "Action",
            "Condition",
            "Concern",
            "Resource",
            "Tags",
            "CreationDate",
            "LastUsedTime",
            "LastUsedAction",
            "LastUsedEncryptionContext",
            "LastUsedSourceIPAddress",
            "LastUsedUsername",
        ]

        # Write the actual file from the kmsKeysWithPolicies JSON object
        with open(filename, "w") as file:
            writer = csv.DictWriter(file, fieldnames=header)
            writer.writeheader()
            writer.writerows(kmsKeysWithPolicies)


# Function to grab the Policy Statement Details
# It will handle multiple statements in the policy
# This function is what generates the actual contents (columns) to
#  populate a line of the CSV
def grabPolicyStatementDetailsList(
    accountNumber: str,
    accountName: str,
    region: str,
    keyId: str,
    keyAlias: str,
    policyStatements: json,
    Tags: list,
    CreationDate: date,
    keyLastUsedTime: str,
    keyLastUsedAction: str,
    keyLastUsedEncryptionContext: str,
    keyLastUsedSourceIPAddress: str,
    keyLastUsedUsername: str,
) -> list:

    # Lets create a list of lists!
    #  This is a collection of entries which will become all of the lines for
    #  the CSV for the single keyId.
    keyListOfLists = []

    # try:
    # Are there some statements in the JSON of the Key Policy?
    if policyStatements:
        # If there are, loop through them all and create a 'keyList' object which will become
        #  the line of the CSV
        for each in range(len(policyStatements)):
            # Add the variables we know exist
            keyList = {
                "AccountNumber": accountNumber,
                "AccountName": accountName,
                "Region": region,
                "KeyId": keyId,
                "Alias": keyAlias,
            }
            # Add the others that might exist
            if "Sid" in policyStatements[each]:
                keyList["Sid"] = policyStatements[each]["Sid"]
            if "Effect" in policyStatements[each]:
                keyList["Effect"] = policyStatements[each]["Effect"]

            # Grab the first Principal
            if "Principal" in policyStatements[each]:
                keyList["Principal"] = list(policyStatements[each]["Principal"].keys())[
                    0
                ]
                keyList["Principal Service"] = list(
                    policyStatements[each]["Principal"].values()
                )[0]

                # change to semi-colons to not mangle the CSV
                keyList["Principal Service"] = str(
                    keyList["Principal Service"]
                ).replace(",", ";")

            # Check the Actions and change to semi-colons to not mangle the CSV
            if "Action" in policyStatements[each]:
                keyList["Action"] = str(policyStatements[each]["Action"]).replace(
                    ",", ";"
                )
            if "Resource" in policyStatements[each]:
                keyList["Resource"] = policyStatements[each]["Resource"]
            if "Condition" in policyStatements[each]:
                condition = str(policyStatements[each]["Condition"])
                if isinstance(condition, str):
                    keyList["Condition"] = condition.replace(",", ";")
            keyList["Tags"] = Tags
            keyList["Tags"] = str(keyList["Tags"]).replace(",", ";")
            keyList["CreationDate"] = CreationDate
            keyList["LastUsedTime"] = keyLastUsedTime
            keyList["LastUsedAction"] = keyLastUsedAction
            keyList["LastUsedEncryptionContext"] = keyLastUsedEncryptionContext
            keyList["LastUsedSourceIPAddress"] = keyLastUsedSourceIPAddress
            keyList["LastUsedUsername"] = keyLastUsedUsername

            keyList["Date"] = str(datetime.now().strftime("%Y-%m-%d"))
            keyList["Concern"] = concernFiller(
                principal_service=keyList["Principal Service"],
                account_number=accountsDynamoDBAccount,
                current_account_number=accountNumber,
                action=keyList["Action"],
            )
            keyListOfLists.append(keyList)

    return keyListOfLists


# Function to push to S3
def pushToS3(filename: str, bucketName: str):
    # file to check
    file_path = "/tmp/" + filename

    flag = os.path.isfile(file_path)
    if flag:
        client = boto3.resource("s3")
        bucket = client.Bucket(bucketName)
        key = filename
        try:
            bucket.upload_file("/tmp/" + filename, key)
            logger.info(f"Successfully uploaded [{filename}] to s3://{bucketName}")
        # generate code to handle s3 botoexceptions

        except FileNotFoundError as error:
            logger.error(f"{filename} not found!")
        except botocore.exceptions.ClientError as error:
            logger.error(f"Error Dump: {error}")
            errorCode = error.response.get("Error", {}).get("Code")
            if errorCode == "AccessDeniedException":
                logger.error(
                    f"Access Denied PUTting {filename} to s3://{bucket}: {error.response['Error']['Message']}"
                )
            elif errorCode == "AccessDeniedException":
                logger.error(
                    f"Access Denied PUTting {filename} to s3://{bucket}: {error.response['Error']['Message']}"
                )
            elif errorCode == "FileNotFoundError":
                logger.error(
                    f"{filename} not found!: {error.response['Error']['Message']}"
                )
            elif errorCode == "S3UploadFailedError":
                logger.error(
                    f"S3UploadFailedError: S3 Upload Failed PUTting {filename} to s3://{bucket}: {error.response['Error']['Message']}"
                )
            elif errorCode == "ClientError":
                logger.error(
                    f"ClientError: S3 Upload Failed PUTting {filename} to s3://{bucket}: {error.response['Error']['Message']}"
                )

            else:
                logger.error(f"ERROR RESPONSE: {error.response}")
                raise error
        except client.meta.client.exceptions.BucketAlreadyExists as error:
            logger.error(
                f"Bucket {err.response['Error']['BucketName']} already exists!"
            )
            raise error
        except client.meta.client.exceptions.NoSuchBucket as error:
            logger.error(f"NoSuchBucket: No such bucket: {bucket}")
            raise error
        except ClientError as error:
            logger.error(f"Unexpected error: {error}")
            raise error

        except Exception as error:
            logger.error(f"Unexpected error: {error}")
            raise error

    else:
        logger.info(f"{file_path} not found. Probably because no keys found")


# Augment the findings with our own concerns / areas of interest
def concernFiller(
    principal_service: str,
    account_number: str,
    current_account_number: str,
    action: str,
):
    # These are the collection of concerns. This is where the 'Concern checks' are
    #  added to the Key policy statement.
    concern_list = []
    concern_list.append(checkManageableThroughIAM(principal_service=principal_service))
    concern_list.append(
        checkThirdPartyManaged(
            account_number=account_number, current_account_number=current_account_number
        )
    )
    concern_list.append(checkKmsPolicy(action=action))
    concern_list.append(checkManageableThroughKMS(principal_service=principal_service))
    return ";".join([x for x in concern_list if x != ""])


# Collection of 'Concern checks'.  Used by concernFiller()
def checkManageableThroughIAM(principal_service: str) -> str:
    if principal_service[-5:] == ":root":
        return "Principal is account"
    return ""


def checkThirdPartyManaged(account_number: str, current_account_number: str) -> str:
    if account_number != current_account_number:
        return "External account"
    return ""


def checkKmsPolicy(action: str) -> str:
    if "kms:*" in action:
        return "Key policy overly permissive"
    return ""


def checkManageableThroughKMS(principal_service: str) -> str:
    if ":user" in principal_service:
        return "Access provided to IAM user"
    return ""


# Key has permissions but cannot be read (locked down key policy)
def unreadableKey(principal_service: str) -> str:
    if principal_service == "":
        return "Unreadable key. Key permissions don't allow lambda to read details"
    return ""


def processAccount(
    account_number: str, account_name: str, session: boto3.Session, region: str
) -> list:
    # Create a KMS session...
    kms = session.client("kms", region_name=region)
    # Grab all the Keys and store them in a JSON object
    keyMap = getEverythingJson(kms)
    filename = account_number + "-" + region + "-kms-details.csv"
    getEverythingToCSV(account_number, account_name, filename, keyMap, region=region)
    pushToS3(filename, destination_s3_bucket)
    # return keyMap["kms_keys"]


def main():
    # Use global variables to avoid passing them around
    # regions has been read from environment variables at the beginning
    regions = [x.strip() for x in regions_string.strip("[]").split(",")]

    # dynamo_ variables have also been read from environment variables at the beginning
    account_ids = get_accounts(
        accountsDynamoDBAccount,
        accountsDynamoDBRole,
        accountsDynamoDBTable,
        accountsDynamoDBRegion,
    )
    logger.info(f"Accounts: {account_ids}")

    # If we found some accounts in the 'accounts' DynamoDB table...
    if account_ids:
        # then loop through each account...
        for account in account_ids:
            account_number = account["accountId"]
            account_name = account["accountName"]
            logger.info(f"Processing Account Number: {account_number}")
            # and assumerole into that account using the cross-account KMS Read Role
            session = getAssumedRoleSession(account_number, xaKMSReadRole)

            if session:
                # If we successfully AssumeRole into the target account...
                #  then loop through all the regions defined in the 'regions' env variable
                for region in regions:
                    processAccount(account_number, account_name, session, region)
            else:
                logger.error(f"Unable to create session for {account_number}")
    else:
        logger.error(f"No Account IDs found: account_ids={account_ids}")


# Run the Lambda
def lambda_handler(event, context):
    logging.info("<<<<<<<<<< KMSReadLambda >>>>>>>>>>")
    logging.info(f"OS Env Variables: {os.environ}")
    logging.info(f"Received Event: {event}")

    main()


# Run from CLI
if __name__ == "__main__":
    logging.info("<<<<<<<<<< KMSReadLambda >>>>>>>>>>")
    main()
