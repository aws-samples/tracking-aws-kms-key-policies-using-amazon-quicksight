import boto3
import json
from helper.logger import logger
from helper.aws_service_client import AWSServiceClient

from config import Config
from datetime import datetime, timedelta
from typing import Dict, Optional

class CloudTrailClient(AWSServiceClient):

    def __init__(self, account_id: str, region: str):
        """
        Initialize KMS Manager with account and region.

        Args:
            account_id (str): AWS Account ID
            region (str): AWS Region
        """
        self.account_id = account_id
        self.region = region
        self.valid_actions = Config.VALID_ACTIONS
        
        try:
            self.session = self._get_assumed_role_session()
            self.cloudtrail = self.session.client('cloudtrail', region_name=region)
        except Exception as e:
            logger.error(f"Failed to initialize CloudTrail client in {self.region} for {self.account_id}: {str(e)}")
            raise
        
    def _get_assumed_role_session(self) -> boto3.Session:
        return super()._get_assumed_role_session(Config.KMS_ROLE)
        
    def get_kms_events(self, hours: int = 24, max_results: int = 100) -> Dict:
        """
        Retrieve KMS events from CloudTrail for specified time period.
        
        Args:
            hours: Number of hours to look back (default: 24)
            max_results: Maximum number of results to return (default: 100)
            
        Returns:
            Dictionary of KMS events keyed by key ID
        """
        try:
            time_now = datetime.now()
            time_to_go_back = time_now - timedelta(hours=int(hours))
            
            logger.info(f"Retrieving KMS events from {time_to_go_back} to {time_now}")
            
            return self._process_cloudtrail_events(time_to_go_back, max_results)
            
        except Exception as e:
            logger.error(f"Error retrieving KMS events: {str(e)}")
            raise

    def _process_cloudtrail_events(self, start_time: datetime, max_results: int) -> Dict:
        """
        Process CloudTrail events and extract KMS usage information.
        
        Args:
            start_time: Start time for event lookup
            max_results: Maximum number of results to return
            
        Returns:
            Dictionary of processed KMS events
        """
        paginator = self.cloudtrail.get_paginator("lookup_events")
        page_iterator = paginator.paginate(
            LookupAttributes=[
                {"AttributeKey": "EventSource", "AttributeValue": "kms.amazonaws.com"}
            ],
            StartTime=start_time,
            MaxResults=max_results
        )

        last_used_events = {}
        events_count = 0

        for page in page_iterator:
            for event in page["Events"]:
                events_count += 1
                
                if event["EventName"] not in self.valid_actions:
                    continue
                    
                event_data = self._extract_event_data(event)
                if event_data:
                    key_id = event_data["keyID"]
                    event_time = event_data["EventTime"]
                    
                    # Update if this is a newer event for this key
                    if (key_id not in last_used_events or 
                        event_time > last_used_events[key_id]["EventTime"]):
                        last_used_events[key_id] = event_data

        logger.info(f"Processed {events_count} CloudTrail events")
        return last_used_events

    def _extract_event_data(self, event: Dict) -> Optional[Dict]:
        """
        Extract relevant data from a CloudTrail event.
        
        Args:
            event: CloudTrail event dictionary
            
        Returns:
            Dictionary containing processed event data or None if invalid
        """
        try:
            if "CloudTrailEvent" not in event:
                return None
                
            ct_event = json.loads(event["CloudTrailEvent"])
            
            if "resources" not in ct_event or not ct_event["resources"]:
                return None
                
            key_id = ct_event["resources"][0]["ARN"].split("/")[1]
            
            event_data = {
                "keyID": key_id,
                "EventTime": str(event["EventTime"]),
                "EventName": event["EventName"]
            }

            # Add username if available
            if "Username" in event:
                event_data["Username"] = event["Username"]

            # Add encryption context if available
            if ("requestParameters" in ct_event and 
                "encryptionContext" in ct_event["requestParameters"]):
                event_data["encryptionContext"] = str(
                    ct_event["requestParameters"]["encryptionContext"]
                )

            # Add source IP if available
            if "sourceIPAddress" in ct_event:
                event_data["sourceIPAddress"] = ct_event["sourceIPAddress"]

            return event_data
            
        except Exception as e:
            logger.warning(f"Error processing event: {str(e)}")
            return None

