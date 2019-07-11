import boto3
from botocore.exceptions import ClientError
from pip.utils import logging


class S3services:
    # this method is used to Create bucket
    def create_bucket(bucket_name, region=None):
        try:
            if region is None:
                s3_client = boto3.client('s3')
                s3_client.create_bucket(Bucket='fandoo-bucket')
            else:
                s3_client = boto3.client('s3', region_name='ap-south-1')
                location = {'LocationConstraint': region}
                s3_client.create_bucket(Bucket='fandoo-bucket',
                                        CreateBucketConfiguration=location)
        except ClientError as e:
            logging.error(e)
            return False
        return True

    # this method used to download file
    def DeleteFile(self, Bucket_name, File_name):
        try:
            # delete object from bucket by calling delete _object method
            self.s3.delete_object(Bucket=Bucket_name, Key=File_name)
        except ClientError as e:
            logging.error(e)
            return False
        # return if deleted
        return True