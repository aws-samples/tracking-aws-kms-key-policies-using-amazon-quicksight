import gzip
import json
import boto3
from config import Config
from helper.logger import logger

class S3Client:
    def __init__(self):
        self.bucket = Config.S3_BUCKET
        try:
            self.s3 = boto3.resource('s3')
        except Exception as e:
            logger.error(f"Failed to initialize S3 client: {str(e)}")
            raise

    def upload_data(self, data: list, file_path: str, file_name: str, max_retries=3):
        """Upload data to S3 with retry mechanism"""
        s3_key = file_path + file_name
        compressed_data = self._compress_data(data)

        for attempt in range(max_retries):
            try:
                self.s3.Bucket(self.bucket).put_object(
                    Key=s3_key, 
                    Body=compressed_data
                )
                logger.info(f"Successfully uploaded to s3://{self.bucket}/{s3_key}")
                return
            except Exception as e:
                if attempt == max_retries - 1:
                    logger.error(f"Failed to upload to S3 after {max_retries} attempts: {e}")
                    raise
                logger.warning(f"Upload attempt {attempt + 1} failed: {str(e)}")

    def _compress_data(self, data):
        json_str = "\n".join([json.dumps(item) for item in data])
        return gzip.compress(json_str.encode('utf-8'))
