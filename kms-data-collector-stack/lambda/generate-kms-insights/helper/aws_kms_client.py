import botocore
import json
import boto3
from helper.logger import logger
from datetime import datetime
from config import Config
from helper.aws_service_client import AWSServiceClient
from typing import Dict, List, Any, Optional


class KMSClient(AWSServiceClient):
    def __init__(self, account_id: str, account_name: str, region: str):
        """
        Initialize KMSClient with boto3 session and region.
        
        Args:
            session: boto3 Session object
            region: AWS region name
        """
        self.account_id = account_id
        self.account_name = account_name
        self.region = region

        try:
            self.session = self._get_assumed_role_session()
            self.kms = self.session.client('kms', region_name=region)
        except Exception as e:
            logger.error(f"Failed to initialize KMS client in {self.region} for {self.account_id}: {str(e)}")
            raise

    def _get_assumed_role_session(self) -> boto3.Session:
        return super()._get_assumed_role_session(Config.KMS_ROLE)
        
    def get_key_inventory(self) -> Dict:
        """
        Collect comprehensive inventory of KMS keys and their details.
        
        Returns:
            Dictionary containing all KMS key information
        """
        try:
            kms_keys = self._get_keys()
            key_map = {"kms_keys": []}

            for kms_key in kms_keys:
                key_id = kms_key["KeyId"]
                key_object = self._build_key_object(key_id)
                if key_object:
                    key_map["kms_keys"].append(key_object)

            logger.info(f"Collected information for {len(key_map['kms_keys'])} keys")
            return key_map
        except Exception as e:
            logger.error(f"Error collecting key inventory: {str(e)}")
            raise

    def _get_keys(self) -> List:
        """
        Get list of all KMS keys in the account/region.
        
        Returns:
            List of KMS key metadata
        """
        try:
            response = self.kms.list_keys()
            return response["Keys"]
        except Exception as e:
            logger.error(f"Error listing keys: {str(e)}")
            return []

    def _build_key_object(self, key_id: str) -> Optional[Dict]:
        """
        Build comprehensive object containing all key details.
        
        Args:
            key_id: KMS key ID
            
        Returns:
            Dictionary containing key details or None if error
        """
        try:
            key_object = {"KeyId": key_id}

            # Get aliases
            aliases = self._get_aliases(key_id)
            key_object["Aliases"] = [alias["AliasName"] for alias in aliases]

            # Get policies
            policies = self._get_key_policies(key_id)
            key_object["Policies"] = policies

            # Get creation date
            creation_date = self._get_creation_date(key_id)
            key_object["CreationDate"] = creation_date

            # Get tags
            tags = self._get_tags(key_id)
            key_object["Tags"] = tags

            return key_object

        except Exception as e:
            logger.warning(f"Error building key object for {key_id}: {str(e)}")
            return None

    def _get_aliases(self, key_id: str) -> List:
        """
        Get aliases for a specific key.
        
        Args:
            key_id: KMS key ID
            
        Returns:
            List of key aliases
        """
        try:
            response = self.kms.list_aliases(KeyId=key_id)
            return response["Aliases"]
        except botocore.exceptions.ClientError as e:
            logger.warning(f"Error listing aliases for key {key_id}: {e}")
            return []

    def _get_key_policies(self, key_id: str) -> List:
        """
        Get all policies for a specific key.
        
        Args:
            key_id: KMS key ID
            
        Returns:
            List of key policies
        """
        try:
            policy_names = self.kms.list_key_policies(KeyId=key_id)["PolicyNames"]
            policies = []
            
            for policy_name in policy_names:
                policy = self.kms.get_key_policy(KeyId=key_id, PolicyName=policy_name)
                policies.append(json.loads(policy["Policy"]))
                
            return policies
        except botocore.exceptions.ClientError as e:
            logger.warning(f"Error getting policies for key {key_id}: {e}")
            return []

    def _get_creation_date(self, key_id: str) -> Optional[str]:
        """
        Get creation date for a specific key.
        
        Args:
            key_id: KMS key ID
            
        Returns:
            Creation date string or None if error
        """
        try:
            response = self.kms.describe_key(KeyId=key_id)
            return response["KeyMetadata"]["CreationDate"].strftime("%Y-%m-%d %H:%M:%S")
        except botocore.exceptions.ClientError as e:
            logger.warning(f"Error getting creation date for key {key_id}: {e}")
            return None

    def _get_tags(self, key_id: str) -> List:
        """
        Get tags for a specific key.
        
        Args:
            key_id: KMS key ID
            
        Returns:
            List of key tags
        """
        try:
            response = self.kms.list_resource_tags(KeyId=key_id)
            return response["Tags"]
        except botocore.exceptions.ClientError as e:
            logger.warning(f"Error listing tags for key {key_id}: {e}")
            return []

    def get_current_date_path(self) -> str:
        """
        Get current date folder path in YYYY/MM/DD format.
        
        Returns:
            String containing date path
        """
        return datetime.now().strftime("%Y/%m/%d")
