# Data Protection Insights - KMS

## Architecture

![Data Protection Insights Architecture](images/data-protection-insights-architecture.png)

## Overview
This solution provides a mechanism for building a data protection insights observability solution. Resources are deployed in one of two account types:

**Security Observability Account** - Hosts the central resources (e.g. Step Functions, Lambda functions and Quicksight)   
**Member Accounts** - IAM Role that allows the Lambda function to assume into   

This git repository contains a services of CloudFormation scripts for deploying into these two accounts types.

## Instructions
### 1. Security Observability Account
Deploy the following:
| Order | command/filename | Stack / Stackset | Single Region / Multi-Region|
| ----- | ----- | ----- | ----- |
| # 1 | ```sam build && sam deploy --guided --capabilities CAPABILITY_NAMED_IAM CAPABILITY_IAM CAPABILITY_AUTO_EXPAND``` | Stack | Single |


To deploy without the KMS analytics stack, use:
```sam build && sam deploy --guided --capabilities CAPABILITY_NAMED_IAM CAPABILITY_IAM CAPABILITY_AUTO_EXPAND --parameter-overrides DeployKMSAnalytics=n```

#### For local deployment
sam deploy --guided --parameter-overrides DeploymentType=local

#### For deployment that gets list of accounts from AWS Organizations
sam deploy --guided --parameter-overrides DeploymentType=org

#### For list deployment
sam deploy --guided --parameter-overrides DeploymentType=list listofaccounts="111111111111,222222222222"



### 2. All Member Accounts
Deploy the following as StackSets from your **`AWS Organizations Management`** account / [delegated CloudFormation account](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-orgs-delegated-admin.html):

| Order | command/filename | Stack / Stackset | Single Region / Multi-Region|
| ----- | ----- | ----- | ----- |
| # 1 | member-account-kmsread-role.yaml | Stackset | Multi |

### 3. Key in use definition
This list outlines which AWS KMS API calls determine whether a key is considered 'in use' by the solution. We have defined that a key is flagged as actively in use when associated with selected (Y) API calls, signaling its involvement in cryptographic tasks like encryption, decryption, or signing. The API actions can be configured here: [kms-data-collector-stack/lambda/generate-kms-insights/config.py](kms-data-collector-stack/lambda/generate-kms-insights/config.py)




| API                              | Key 'in use' Indicator? | Description                                                                 |
|----------------------------------|---------|-----------------------------------------------------------------------------|
| CancelKeyDeletion               | N       | Cancels a pending key deletion request.                                      |
| ConnectCustomKeyStore           | N       | Connects a custom key store to AWS KMS.                                      |
| CreateAlias                     | N       | Creates an alias for a KMS key.                                              |
| CreateCustomKeyStore            | N       | Creates a custom key store for AWS KMS.                                      |
| CreateGrant                      | N       | Creates a grant to permit specific actions on KMS keys.                      |
| CreateKey                        | N       | Creates a new KMS key.                                                       |
| Decrypt                         | Y       | Decrypts encrypted data using a KMS key.                                     |
| DeleteAlias                     | N       | Deletes a KMS alias.                                                         |
| DeleteCustomKeyStore            | N       | Deletes a custom key store from AWS KMS.                                     |
| DeleteImportedKeyMaterial       | N       | Deletes imported key material from a KMS key.                                |
| DeriveSharedSecret              | Y       | Derives a shared secret using Diffie-Hellman.                                |
| DescribeCustomKeyStores         | N       | Describes the custom key stores in AWS KMS.                                  |
| DescribeKey                     | N       | Provides information about a KMS key.                                        |
| DisableKey                      | N       | Disables a KMS key so it cannot be used for cryptographic operations.        |
| DisableKeyRotation              | N       | Disables automatic key rotation for a KMS key.                              |
| DisconnectCustomKeyStore        | N       | Disconnects a custom key store from AWS KMS.                                 |
| EnableKey                       | N       | Enables a KMS key to be used for cryptographic operations.                   |
| EnableKeyRotation               | N       | Enables automatic key rotation for a KMS key.                               |
| Encrypt                         | Y       | Encrypts plaintext into ciphertext using a KMS key.                          |
| GenerateDataKey                 | Y       | Generates a data encryption key.                                             |
| GenerateDataKeyPair             | Y       | Generates a public and private key pair for data encryption.                 |
| GenerateDataKeyPairWithoutPlaintext | Y   | Generates a data encryption key pair without returning the plaintext key.   |
| GenerateDataKeyWithoutPlaintext | Y       | Generates a data encryption key without returning the plaintext key.         |
| GenerateMac                      | Y       | Generates a message authentication code (MAC) for data integrity checks.    |
| GenerateRandom                  | N       | Generates a random byte sequence for various uses.                           |
| GetKeyPolicy                    | N       | Retrieves the key policy attached to a KMS key.                              |
| GetKeyRotationStatus            | N       | Retrieves the key rotation status of a KMS key.                              |
| GetParametersForImport          | N       | Retrieves parameters for importing key material into AWS KMS.                |
| GetPublicKey                    | Y       | Retrieves the public key associated with a KMS key.                          |
| ImportKeyMaterial               | N       | Imports key material into a KMS key for use with encryption operations.      |
| ListAliases                     | N       | Lists all aliases in AWS KMS.                                                |
| ListGrants                      | N       | Lists all grants associated with a KMS key.                                  |
| ListKeyPolicies                 | N       | Lists the key policies attached to KMS keys.                                 |
| ListKeyRotations                | N       | Lists the key rotation statuses for KMS keys.                                |
| ListKeys                        | N       | Lists all KMS keys in your account.                                          |
| ListResourceTags                | N       | Lists the tags attached to KMS resources.                                    |
| ListRetirableGrants             | N       | Lists grants that are eligible for retirement.                               |
| PutKeyPolicy                    | N       | Attaches or updates a key policy to a KMS key.                               |
| ReEncrypt                       | Y       | Re-encrypts data using a new KMS key.                                        |
| ReplicateKey                    | N       | Replicates a KMS key to another region.                                      |
| RetireGrant                     | N       | Retires a grant, preventing further use of the associated key.               |
| RevokeGrant                     | N       | Revokes a grant, preventing the use of the associated key.                   |
| RotateKeyOnDemand               | N       | Rotates a KMS key on-demand (for keys with manual rotation enabled).         |
| ScheduleKeyDeletion             | N       | Schedules a KMS key for deletion after a specified waiting period.           |
| Sign                             | Y       | Signs data using a KMS key for integrity verification.                       |
| TagResource                     | N       | Adds tags to a KMS resource.                                                 |
| UntagResource                   | N       | Removes tags from a KMS resource.                                            |
| UpdateAlias                     | N       | Updates the alias of a KMS key.                                              |
| UpdateCustomKeyStore            | N       | Updates properties of a custom key store.                                    |
| UpdateKeyDescription            | N       | Updates the description of a KMS key.                                        |
| UpdatePrimaryRegion             | N       | Updates the primary region of a KMS key.                                     |
| Verify                           | Y       | Verifies a signature using a KMS public key.                                 |
| VerifyMac                        | Y       | Verifies a message authentication code (MAC) using a KMS key.                |
