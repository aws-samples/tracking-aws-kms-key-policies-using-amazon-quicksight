from datetime import datetime
from typing import List, Dict, Any
from helper.logger import logger

class KMSPolicyExtractor:
    def __init__(self, account_number: str, account_name: str, region: str):
        """
        Initialize KMS Policy Extractor.
        
        Args:
            region: AWS region
            account_number: AWS account number
            account_name: AWS account name
        """
        self.region = region
        self.account_number = account_number
        self.account_name = account_name

    def split_key_policies(self, key_map: Dict) -> List[Dict]:
        """
        Split KMS key policies for detailed reporting.

        Args:
            key_map: Dictionary containing KMS keys and their policies

        Returns:
            List of dictionaries containing detailed policy information
        """
        try:
            kms_keys_with_policies = []
            logger.info(f"{len(key_map['kms_keys'])} KMS keys found in [{self.region}]")

            for key in key_map["kms_keys"]:
                if "Policies" not in key:
                    continue

                # Process each policy
                for policy in key["Policies"]:
                    if "Statement" not in policy:
                        continue

                    policy_entries = self._process_policy_statements(
                        key,
                        policy["Statement"]
                    )
                    kms_keys_with_policies.extend(policy_entries)

            return kms_keys_with_policies

        except Exception as e:
            logger.error(f"Error splitting key policies: {str(e)}")
            raise


    def _process_policy_statements(
        self,
        key: Dict,
        statements: List[Dict]
    ) -> List[Dict]:
        """
        Process individual policy statements.
        
        Args:
            key_id: KMS key ID
            key: Dictionary of key data
            statements: List of policy statements
            
        Returns:
            List of processed policy entries
        """
        entries = []

        for statement in statements:
            policy_entry = {
                "Date": datetime.now().strftime("%Y-%m-%d"),
                "AccountNumber": self.account_number,
                "AccountName": self.account_name,
                "Region": self.region,
                "KeyId": key.get("KeyId"),
                "Alias": key.get("alias"),
                "Tags": str(key.get("tags")).replace(",", ";"),
                "CreationDate": key.get("CreationDate"),
                "LastUsedTime": key.get("LastUsedTime"),
                "LastUsedAction": key.get("LastUsedAction"),
                "LastUsedEncryptionContext": key.get("LastUsedEncryptionContext"),
                "LastUsedSourceIPAddress": key.get("LastUsedSourceIPAddress"),
                "LastUsedUsername": key.get("LastUsedUsername")
            }

            # Add statement-specific details
            self._add_statement_details(policy_entry, statement)

            entries.append(policy_entry)

        return entries

    def _add_statement_details(self, policy_entry: Dict, statement: Dict) -> None:
        """
        Add statement-specific details to policy entry.
        
        Args:
            policy_entry: Dictionary to add details to
            statement: Policy statement to process
        """
        policy_entry["Sid"] = statement.get("Sid", "")
        policy_entry["Effect"] = statement.get("Effect", "")
        
        if "Principal" in statement:
            principal = statement["Principal"]
            if isinstance(principal, dict):
                policy_entry["Principal"] = list(principal.keys())[0]
                principal_service = list(principal.values())[0]
                if isinstance(principal_service, list):
                    principal_service = ";".join(principal_service)
                policy_entry["Principal Service"] = principal_service

        if "Action" in statement:
            action = statement["Action"]
            if isinstance(action, list):
                action = str(action).replace(",", ";")
            policy_entry["Action"] = str(action)

        policy_entry["Resource"] = statement.get("Resource", "")
        
        if "Condition" in statement:
            condition = str(statement["Condition"])
            policy_entry["Condition"] = condition.replace(",", ";")
