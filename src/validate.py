import logging
import os
import re
import tarfile
import traceback
from pathlib import Path
from shutil import rmtree

import bagit
import boto3
import pymupdf
from aws_assume_role_lib import assume_role
from PIL import Image, UnidentifiedImageError

logging.basicConfig(
    level=int(os.environ.get('LOGGING_LEVEL', logging.INFO)),
    format='%(filename)s::%(funcName)s::%(lineno)s %(message)s')
logging.getLogger("bagit").setLevel(logging.ERROR)

Image.MAX_IMAGE_PIXELS = 500000000  # accounts for oversized items.


class RefidError(Exception):
    pass


class ExtractError(Exception):
    pass


class AssetValidationError(Exception):
    pass


class FileFormatValidationError(Exception):
    pass


class AlreadyExistsError(Exception):
    pass


class OCRError(Exception):
    pass


class Validator(object):
    """Validates digitized audio and moving image assets."""

    def __init__(self, region, s3_role_arn, sns_role_arn, source_bucket,
                 destination_bucket, source_filename, tmp_dir, sns_topic):
        self.s3_role_arn = s3_role_arn
        self.sns_role_arn = sns_role_arn
        self.region = region
        self.source_bucket = source_bucket
        self.destination_bucket = destination_bucket
        self.source_filename = source_filename
        self.refid = Path(source_filename).stem.split('.')[0]
        self.tmp_dir = tmp_dir
        self.sns_topic = sns_topic
        self.service_name = 'digitized_image_validation'
        if not Path(self.tmp_dir).is_dir():
            Path(self.tmp_dir).mkdir(parents=True)
        logging.debug(self.__dict__)

    def run(self):
        """Main method which calls all other logic."""
        logging.debug(
            f'Validation process started for package {self.refid}.')
        try:
            extracted = Path(self.tmp_dir, self.refid)
            self.validate_refid(self.refid)
            downloaded = self.download_bag()
            self.extract_bag(downloaded)
            self.validate_bag(extracted)
            self.validate_assets(extracted)
            self.validate_file_formats(extracted)
            self.validate_ocr(extracted)
            self.move_to_destination(extracted)
            self.cleanup_binaries(extracted)
            self.deliver_success_notification()
            logging.info(
                f'Package {self.refid} successfully validated.')
        except Exception as e:
            logging.exception(e)
            self.cleanup_binaries(extracted, job_failed=True)
            self.deliver_failure_notification(e)

    def get_client_with_role(self, resource, role_arn):
        """Gets Boto3 client which authenticates with a specific IAM role."""
        session = boto3.Session()
        assumed_role_session = assume_role(session, role_arn)
        return assumed_role_session.client(resource)

    def validate_refid(self, refid):
        valid = re.compile(r"^[a-zA-Z0-9]{32}$")
        if not bool(valid.match(refid)):
            raise RefidError(f"{refid} is not a valid refid.")
        return True

    def download_bag(self):
        """Downloads a streaming file from S3.

        Returns:
            downloaded_path (pathlib.Path): path of the downloaded file.
        """
        downloaded_path = Path(self.tmp_dir, self.source_filename)
        client = self.get_client_with_role('s3', self.s3_role_arn)
        transfer_config = boto3.s3.transfer.TransferConfig(
            multipart_threshold=1024 * 25,
            max_concurrency=10,
            multipart_chunksize=1024 * 25,
            use_threads=True)
        client.download_file(
            self.source_bucket,
            self.source_filename,
            downloaded_path,
            Config=transfer_config)
        logging.debug(f'Package downloaded to {downloaded_path}.')
        return downloaded_path

    def extract_bag(self, file_path):
        """Extracts the contents of a TAR file.

        Args:
            file_path (pathlib.Path): path of compressed file to extract.
        """
        try:
            tf = tarfile.open(file_path, "r:*")
            tf.extractall(self.tmp_dir)
            tf.close()
            file_path.unlink()
            logging.debug(f'Package {file_path} extracted to {self.tmp_dir}.')
        except Exception as e:
            raise ExtractError("Error extracting TAR file: {}".format(e))

    def validate_bag(self, bag_path):
        """Validates a bag.

        Args:
            bag_path (pathlib.Path): path of bagit Bag to validate.

        Raises:
            bagit.BagValidationError with the error in the `details` property.
        """
        bag = bagit.Bag(str(bag_path))
        bag.validate()
        logging.debug(f'Bag {bag_path} validated.')

    def validate_directories(self, bag_path):
        """Checks for the presence of expected directories.

        Args:
            bag_path (pathlib.Path): path of bagit Bag containing assets.

        Raises:
            FileNotFoundError if not all directories are present.
        """
        for dir in ['master', 'master_edited', 'service_edited']:
            if not (bag_path / 'data' / dir).is_dir():
                raise FileNotFoundError(f"Expected directory {dir} is missing")

    def validate_file_counts(self, bag_path):
        """Asserts correct number of files is present in each directory."""
        with pymupdf.open(bag_path / 'data' / 'service_edited' / f'{self.refid}.pdf', filetype='pdf') as document:
            pdf_page_count = document.page_count
        master_file_count = len(list((bag_path / 'data' / 'master').glob(f'{self.refid}*.tif')))
        master_edited_file_count = len(
            list((bag_path / 'data' / 'master_edited').glob(f'{self.refid}*.tif')))
        if pdf_page_count != master_edited_file_count:
            raise Exception(
                f"PDF has {pdf_page_count} pages but found {master_edited_file_count} files in master_edited directory")
        if master_file_count < master_edited_file_count:
            raise Exception(
                f"{master_edited_file_count} files found in master_edited directory but only {master_file_count} in master directory")

    def validate_file_names(self, bag_path):
        """Ensures file names are valid.

        Args:
            bag_path (pathlib.Path): path of bagit Bag containing assets.
        """
        for dir in ['master', 'master_edited', 'service_edited']:
            for fp in (bag_path / 'data' / dir).iterdir():
                if " " in fp.name:
                    raise Exception(f"File name {str(fp)} contains space.")

    def validate_ocr(self, bag_path):
        """Ensures there is an OCR layer for each page of the PDF.

        Args:
            bag_path (pathlib.Path): path of bagit Bag containing assets.
        """
        with pymupdf.open(bag_path / 'data' / 'service_edited' / f'{self.refid}.pdf', filetype='pdf') as document:
            for page in document:
                if page.get_text("text"):
                    return True
        raise OCRError(f'No OCR detected in package {self.refid}')

    def validate_assets(self, bag_path):
        """Ensures that all expected directories and files are present.

        Args:
            bag_path (pathlib.Path): path of bagit Bag containing assets.

        Raises:
            AssetValidationError if files delivered do not match expected files.
        """
        try:
            self.validate_directories(bag_path)
            self.validate_file_counts(bag_path)
            self.validate_file_names(bag_path)
        except Exception as e:
            raise AssetValidationError(
                f"Package structure is invalid: {e}") from e
        logging.debug(f'Package {bag_path} contains all expected assets.')

    def validate_file_characteristics(self, image_path):
        with Image.open(image_path) as image:
            assert image.mode in ["L", "RGB"], f"Image format should be RGB or L, got {image.mode}."
            resolution = image.info.get('dpi', image.info.get('resolution'))
            assert resolution, "Image does not have embedded resolution information."
            assert resolution[0] >= 400 and resolution[1] >= 400, f"Image resolution should be at least 400dpi, got {image.info['dpi']}"

    def validate_file_formats(self, bag_path):
        """Ensures that files pass format validation rules.

        Args:
            bag_path (pathlib.Path): path of bagit Bag containing assets.
        """
        for dir in ['master', 'master_edited']:
            for fp in (bag_path / 'data' / dir).glob('*.tif'):
                try:
                    self.validate_file_characteristics(fp)
                except UnidentifiedImageError as e:
                    raise FileFormatValidationError(
                        f"Invalid TIFF file {str(fp)}: {e}")
                except AssertionError as e:
                    raise FileFormatValidationError(
                        f"TIFF file does not meet specs: {e}")
        logging.debug(f'All file formats in {bag_path} are valid.')

    def move_to_destination(self, bag_path):
        """"Moves validated assets to destination bucket.

        Args:
            bag_path (pathlib.Path): path of bagit Bag containing assets.
        """
        client = self.get_client_with_role('s3', self.s3_role_arn)
        existing = bool(client.list_objects_v2(Bucket=self.destination_bucket, Prefix=self.refid, MaxKeys=1)['KeyCount'])
        if existing:
            raise AlreadyExistsError(
                f'A package with refid {self.refid} is already waiting to be QCed.')

        for dirpath, _, files in (bag_path / 'data').walk():
            for f in files:
                source = dirpath / f
                destination = Path(self.refid, source.relative_to(bag_path / 'data'))
                client.upload_file(
                    str(source),
                    self.destination_bucket,
                    str(destination))

        logging.debug(
            f'All files in payload directory of {bag_path} moved to destination bucket {self.destination_bucket}.')

    def cleanup_binaries(self, bag_path, job_failed=False):
        """Removes binaries after completion of successful or failed job.

        Args:
            bag_path (pathlib.Path): path of bagit Bag containing assets.
        """
        client = self.get_client_with_role('s3', self.s3_role_arn)
        if bag_path.is_dir():
            try:
                rmtree(bag_path)
            except OSError:
                for p in bag_path.iterdir():
                    p.chmod(0o775)
                rmtree(bag_path)
        if job_failed:
            client = self.get_client_with_role('s3', self.s3_role_arn)
            paginator = client.get_paginator('list_objects_v2')
            pages = paginator.paginate(Bucket=self.destination_bucket, Prefix=self.refid)

            objects_to_delete = []
            for page in pages:
                if 'Contents' in page:
                    for obj in page['Contents']:
                        objects_to_delete.append({'Key': obj['Key']})

            if objects_to_delete:
                for i in range(0, len(objects_to_delete), 1000):
                    batch = objects_to_delete[i:i + 1000]
                    response = client.delete_objects(
                        Bucket=self.destination_bucket,
                        Delete={'Objects': batch, 'Quiet': True})
                    if 'Errors' in response:
                        errors = "\n".join([e["Key"] for e in response["errors"]])
                        raise Exception(f'Error deleting objects: {errors}')
        else:
            client.delete_object(
                Bucket=self.source_bucket,
                Key=self.source_filename)
        logging.debug('Binaries cleaned up.')

    def deliver_success_notification(self):
        """Sends notifications after successful run."""
        client = self.get_client_with_role('sns', self.sns_role_arn)
        client.publish(
            TopicArn=self.sns_topic,
            Message=f'Package {self.source_filename} successfully validated',
            MessageAttributes={
                'refid': {
                    'DataType': 'String',
                    'StringValue': self.refid,
                },
                'service': {
                    'DataType': 'String',
                    'StringValue': self.service_name,
                },
                'outcome': {
                    'DataType': 'String',
                    'StringValue': 'SUCCESS',
                }
            })
        logging.debug('Success notification sent.')

    def deliver_failure_notification(self, exception):
        """"Sends notifications when run fails.

        Args:
            exception (Exception): the exception that was thrown.
        """
        client = self.get_client_with_role('sns', self.sns_role_arn)
        tb = ''.join(traceback.format_exception(exception)[:-1])
        client.publish(
            TopicArn=self.sns_topic,
            Message=f'Package {self.source_filename} is invalid',
            MessageAttributes={
                'refid': {
                    'DataType': 'String',
                    'StringValue': self.refid,
                },
                'service': {
                    'DataType': 'String',
                    'StringValue': self.service_name,
                },
                'outcome': {
                    'DataType': 'String',
                    'StringValue': 'FAILURE',
                },
                'message': {
                    'DataType': 'String',
                    'StringValue': str(exception),
                },
                'traceback': {
                    'DataType': 'String',
                    'StringValue': tb
                },
            })
        logging.debug('Failure notification sent.')


if __name__ == '__main__':
    region = os.environ.get('AWS_REGION')
    s3_role_arn = os.environ.get('AWS_S3_ROLE_ARN')
    sns_role_arn = os.environ.get('AWS_SNS_ROLE_ARN')
    source_bucket = os.environ.get('AWS_SOURCE_BUCKET')
    source_filename = os.environ.get('SOURCE_FILENAME')
    tmp_dir = os.environ.get('TMP_DIR')
    destination_bucket = os.environ.get('DESTINATION_BUCKET')
    sns_topic = os.environ.get('AWS_SNS_TOPIC')

    logging.debug('Validator instantiated.')

    Validator(
        region,
        s3_role_arn,
        sns_role_arn,
        source_bucket,
        destination_bucket,
        source_filename,
        tmp_dir,
        sns_topic).run()
