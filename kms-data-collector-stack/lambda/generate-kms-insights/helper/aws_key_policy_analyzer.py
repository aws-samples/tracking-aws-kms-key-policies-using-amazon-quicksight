from typing import List, Dict
from helper.logger import logger

"""
Class handling KMS policy insights and checks.
"""
class KMSPolicyAnalyzer:
    def __init__(self, account_number: str):
        """
        Initialize KMS Policy Extractor.
        
        Args:
            account_number: AWS account number
        """
        self.account_number = account_number
    def process_policy_insights(self, policy_analysis: List[Dict]) -> List[Dict]:
        """
        Process and add insights to policy analysis entries.
        
        Args:
            policy_analysis: List of policy analysis entries
            
        Returns:
            List of policy entries with added insights
        """
        for entry in policy_analysis:
            principal_service = entry.get("Principal Service", "")
            action = entry.get("Action", "")
            
            entry["Concern"] = self._insight_filler(
                principal_service=principal_service,
                account_number=self.account_number,
                current_account_number=self.account_number,
                action=action
            )
        
        return policy_analysis

    def _insight_filler(
        self,
        principal_service: str,
        account_number: str,
        current_account_number: str,
        action: str,
    ) -> str:
        """
        Aggregate all concern checks and return combined results.
        
        Args:
            principal_service: Principal service from policy
            account_number: AWS account number
            current_account_number: Current AWS account number
            action: Policy action
            
        Returns:
            Semicolon-separated string of insights
        """
        concern_list = []
        concern_list.append(self._check_manageable_through_iam(principal_service))
        concern_list.append(self._check_kms_policy(action))
        concern_list.append(self._check_manageable_through_kms(principal_service))
        concern_list.append(self._check_unreadable_key(principal_service))
        concern_list.append(
            self.check_third_party_managed(
                account_number, current_account_number
            )
        )
        
        return ";".join([x for x in concern_list if x != ""])

    def _check_manageable_through_iam(self, principal_service: str) -> str:
        """Check if principal is account root."""
        if principal_service.endswith(":root"):
            return "Principal is account"
        return ""

    def check_third_party_managed(self, account_number: str, current_account_number: str) -> str:
        """Check for external account access."""
        if account_number != current_account_number:
            return "External account"
        return ""

    def _check_kms_policy(self, action: str) -> str:
        """Check for overly permissive KMS policies."""
        if "kms:*" in action:
            return "Key policy overly permissive"
        return ""

    def _check_manageable_through_kms(self, principal_service: str) -> str:
        """Check for IAM user access."""
        if ":user" in principal_service:
            return "Access provided to IAM user"
        return ""

    def _check_unreadable_key(self, principal_service: str) -> str:
        """Check if key is unreadable due to permissions."""
        if not principal_service:
            return "Unreadable key. Key permissions don't allow lambda to read details"
        return ""
