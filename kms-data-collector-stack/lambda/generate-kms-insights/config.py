import os
class Config:
    S3_BUCKET = os.environ['S3_BUCKET']
    KMS_ROLE = os.getenv('KMS_READ_ROLE', 'XA-KMSRead-Role')
    VALID_ACTIONS = ['Decrypt', 'DeriveSharedSecret', 'Encrypt', 'GenerateDataKey', 'GenerateDataKeyPair', 'GenerateDataKeyPairWithoutPlaintext', 'GenerateDataKeyWithoutPlaintext', 'GenerateMac', 'GetPublicKey', 'ReEncrypt', 'Sign', 'Verify', 'VerifyMac']