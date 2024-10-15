import json
import random
from pathlib import Path
from shutil import copyfile, copytree, rmtree
from unittest.mock import patch

import bagit
import boto3
import pytest
from moto import mock_s3, mock_sns, mock_sqs, mock_sts
from moto.core import DEFAULT_ACCOUNT_ID
from PIL import UnidentifiedImageError

from src.validate import (AlreadyExistsError, AssetValidationError,
                          FileFormatValidationError, OCRError, RefidError,
                          Validator)

ARGS = [
    'us-east-1',
    'digitized-image-role-arn',
    'foo',
    '/qc',
    'b90862f3baceaae3b7418c78f9d50d52.tar.gz',
    '/validation',
    'topic']


@pytest.fixture(autouse=True)
def setup_and_teardown():
    """Fixture to create and tear down dir before and after a test is run"""
    dir_list = [ARGS[3], ARGS[5]]
    for dir in dir_list:
        dir_path = Path(dir)
        if not dir_path.is_dir():
            dir_path.mkdir()

    yield  # this is where the testing happens

    for dir in dir_list:
        rmtree(dir)


def test_init():
    """Asserts Validator init method sets attributes correctly."""
    validator = Validator(*ARGS)
    assert validator.source_bucket == 'foo'
    assert validator.destination_dir == '/qc'
    assert validator.source_filename == 'b90862f3baceaae3b7418c78f9d50d52.tar.gz'
    assert validator.tmp_dir == '/validation'
    assert validator.refid == 'b90862f3baceaae3b7418c78f9d50d52'

    invalid_args = [
        'us-east-1',
        'digitized-image-role-arn',
        'text',
        'foo',
        '/qc',
        'b90862f3baceaae3b7418c78f9d50d52.tar.gz',
        '/validation',
        'topic']
    with pytest.raises(Exception):
        Validator(*invalid_args)


@patch('src.validate.Validator.validate_refid')
@patch('src.validate.Validator.download_bag')
@patch('src.validate.Validator.extract_bag')
@patch('src.validate.Validator.validate_bag')
@patch('src.validate.Validator.validate_assets')
@patch('src.validate.Validator.validate_file_formats')
@patch('src.validate.Validator.validate_ocr')
@patch('src.validate.Validator.move_to_destination')
@patch('src.validate.Validator.cleanup_binaries')
@patch('src.validate.Validator.deliver_success_notification')
def test_run(mock_deliver, mock_cleanup, mock_move, mock_ocr, mock_validate_formats,
             mock_validate_assets, mock_validate_bag, mock_extract_bag, mock_download, mock_refid):
    """Asserts correct methods are called by run method."""
    validator = Validator(*ARGS)
    extracted_path = Path(validator.tmp_dir, validator.refid)
    download_path = "foo"
    mock_download.return_value = download_path
    validator.run()
    mock_deliver.assert_called_once_with()
    mock_cleanup.assert_called_once_with(extracted_path)
    mock_move.assert_called_once_with(extracted_path)
    mock_ocr.assert_called_once_with(extracted_path)
    mock_validate_formats.assert_called_once_with(extracted_path)
    mock_validate_assets.assert_called_once_with(extracted_path)
    mock_validate_bag.assert_called_once_with(extracted_path)
    mock_extract_bag.assert_called_once_with(download_path)
    mock_download.assert_called_once_with()
    mock_refid.assert_called_once_with(validator.refid)


@patch('src.validate.Validator.validate_refid')
@patch('src.validate.Validator.cleanup_binaries')
@patch('src.validate.Validator.deliver_failure_notification')
def test_run_with_exception(mock_deliver, mock_cleanup, mock_refid):
    """Asserts run method handles exceptions correctly."""
    validator = Validator(*ARGS)
    exception = Exception("Invalid refid.")
    mock_refid.side_effect = exception
    validator.run()
    mock_cleanup.assert_called_once()
    mock_deliver.assert_called_once_with(exception)


def test_validate_refid():
    """Asserts refID is validated."""
    validator = Validator(*ARGS)
    assert validator.validate_refid(validator.refid)
    with pytest.raises(RefidError):
        validator.validate_refid('b90862f3baceaae3b7418c78f9d50d5')


@mock_s3
@mock_sts
def test_download_bag():
    """Asserts file is downloaded correctly."""
    validator = Validator(*ARGS)
    bucket_name = validator.source_bucket
    expected_path = Path(validator.tmp_dir, validator.source_filename)
    s3 = boto3.client('s3', region_name='us-east-1')
    s3.create_bucket(Bucket=bucket_name)
    s3.put_object(Bucket=bucket_name, Key=validator.source_filename, Body='')

    downloaded = validator.download_bag()
    assert downloaded == expected_path
    assert expected_path.is_file()


def test_extract_bag():
    """Asserts bag is extracted correctly and downloaded file is removed."""
    validator = Validator(*ARGS)
    fixture_path = Path(
        "tests",
        "fixtures",
        "b90862f3baceaae3b7418c78f9d50d52.tar.gz")
    tmp_path = Path(validator.tmp_dir, validator.source_filename)
    copyfile(fixture_path, tmp_path)

    validator.extract_bag(tmp_path)
    assert Path(validator.tmp_dir, validator.refid).is_dir()
    assert not tmp_path.is_file()


def test_validate_bag():
    """Asserts bag validation is successful or raises expected exceptions on failure."""
    validator = Validator(*ARGS)
    fixture_path = Path(
        "tests",
        "fixtures",
        "b90862f3baceaae3b7418c78f9d50d52")
    tmp_path = Path(validator.tmp_dir, validator.refid)
    copytree(fixture_path, tmp_path)

    validator.validate_bag(tmp_path)

    rmtree(Path(tmp_path, 'data'))
    with pytest.raises(bagit.BagValidationError):
        validator.validate_bag(tmp_path)


def test_validate_assets():
    """Asserts assets are validated as expected."""
    validator = Validator(*ARGS)
    fixture_path = Path("tests", "fixtures", validator.refid)
    tmp_path = Path(validator.tmp_dir, validator.refid)
    copytree(fixture_path, tmp_path)

    validator.validate_assets(tmp_path)


def test_validate_directories_missing_dir():
    validator = Validator(*ARGS)
    fixture_path = Path("tests", "fixtures", validator.refid)
    tmp_path = Path(validator.tmp_dir, validator.refid)
    copytree(fixture_path, tmp_path)

    rmtree(tmp_path / 'data' / 'service_edited')

    with pytest.raises(AssetValidationError) as err:
        validator.validate_assets(tmp_path)
    assert err.typename == 'AssetValidationError'
    assert 'service_edited' in str(err.value)


def test_validate_file_count_missing_file():
    """Asserts exceptions encountered when validating assets are correctly handled."""
    validator = Validator(*ARGS)
    fixture_path = Path("tests", "fixtures", validator.refid)
    tmp_path = Path(validator.tmp_dir, validator.refid)
    copytree(fixture_path, tmp_path)

    files = list(tmp_path.glob('data/master/*'))
    random.choice(files).unlink()

    with pytest.raises(AssetValidationError):
        validator.validate_assets(tmp_path)


def test_validate_file_formats():
    """Asserts file formats are validated as expected."""
    validator = Validator(*ARGS)
    fixture_path = Path("tests", "fixtures", validator.refid)
    tmp_path = Path(validator.tmp_dir, validator.refid)
    copytree(fixture_path, tmp_path)

    validator.validate_file_formats(tmp_path)


@patch('src.validate.Validator.validate_file_characteristics')
def test_validate_file_formats_with_error(mock_characteristics):
    validator = Validator(*ARGS)
    fixture_path = Path("tests", "fixtures", validator.refid)
    tmp_path = Path(validator.tmp_dir, validator.refid)
    copytree(fixture_path, tmp_path)

    error_string = 'This is an error!'
    mock_characteristics.side_effect = AssertionError(error_string)
    with pytest.raises(FileFormatValidationError) as err:
        validator.validate_file_formats(tmp_path)
    assert error_string in (str(err.value))

    error_string = 'This is a different error!'
    mock_characteristics.side_effect = UnidentifiedImageError(error_string)
    with pytest.raises(FileFormatValidationError) as err:
        validator.validate_file_formats(tmp_path)
    assert error_string in (str(err.value))


def test_validate_ocr():
    """Asserts PDF is checked for OCR layer."""
    validator = Validator(*ARGS)
    fixture_path = Path(
        "tests",
        "fixtures",
        "b90862f3baceaae3b7418c78f9d50d52")
    tmp_path = Path(validator.tmp_dir, validator.refid)
    copytree(fixture_path, tmp_path)

    validator.validate_ocr(tmp_path)

    # Assert PDFs without OCR raise error.
    copyfile(
        Path("tests", "fixtures", "non-text-searchable.pdf"),
        tmp_path / 'data' / 'service_edited' / f'{validator.refid}.pdf')

    with pytest.raises(OCRError) as err:
        validator.validate_ocr(tmp_path)
    assert validator.refid in str(err.value)


def test_move_to_destination():
    """Asserts correct files are moved to correct location."""
    validator = Validator(*ARGS)
    fixture_path = Path(
        "tests",
        "fixtures",
        "b90862f3baceaae3b7418c78f9d50d52")
    tmp_path = Path(validator.tmp_dir, validator.refid)
    copytree(fixture_path, tmp_path)

    validator.move_to_destination(tmp_path)
    expected_paths = [
        f"{validator.destination_dir}/{validator.refid}/master",
        f"{validator.destination_dir}/{validator.refid}/master/{validator.refid}_0001.tif",
        f"{validator.destination_dir}/{validator.refid}/master/{validator.refid}_0002.tif",
        f"{validator.destination_dir}/{validator.refid}/master_edited",
        f"{validator.destination_dir}/{validator.refid}/master_edited/{validator.refid}_0001.tif",
        f"{validator.destination_dir}/{validator.refid}/master_edited/{validator.refid}_0002.tif",
        f"{validator.destination_dir}/{validator.refid}/service_edited",
        f"{validator.destination_dir}/{validator.refid}/service_edited/{validator.refid}.pdf",
    ]
    found = list(
        str(p) for p in Path(
            validator.destination_dir,
            validator.refid).rglob('*'))
    assert len(expected_paths) == len(found)
    assert sorted(expected_paths) == sorted(found)


@patch('src.validate.copytree')
def test_move_to_destination_with_exception(mock_copytree):
    """Asserts correct exception is raised by validator."""
    mock_copytree.side_effect = FileExistsError()
    validator = Validator(*ARGS)
    tmp_path = Path(validator.tmp_dir, validator.refid)
    with pytest.raises(AlreadyExistsError):
        validator.move_to_destination(tmp_path)


@mock_s3
@mock_sts
def test_cleanup_binaries():
    """Asserts that binaries are cleaned up properly."""
    validator = Validator(*ARGS)
    fixture_path = Path(
        "tests",
        "fixtures",
        "b90862f3baceaae3b7418c78f9d50d52")
    tmp_path = Path(validator.tmp_dir, validator.refid)
    s3 = boto3.client('s3', region_name='us-east-1')
    s3.create_bucket(Bucket=validator.source_bucket)

    copytree(fixture_path, tmp_path)
    s3.put_object(
        Bucket=validator.source_bucket,
        Key=validator.source_filename,
        Body='')

    validator.cleanup_binaries(tmp_path)
    assert not tmp_path.is_dir()
    found = s3.list_objects_v2(
        Bucket=validator.source_bucket,
        Prefix=validator.refid)['KeyCount']
    assert found == 0

    copytree(fixture_path, tmp_path)
    s3.put_object(
        Bucket=validator.source_bucket,
        Key=validator.source_filename,
        Body='')

    validator.cleanup_binaries(tmp_path, job_failed=True)
    assert not tmp_path.is_dir()
    found = s3.list_objects_v2(
        Bucket=validator.source_bucket,
        Prefix=validator.refid)['KeyCount']
    assert found == 1


@mock_sns
@mock_sqs
@mock_sts
@patch('src.validate.Validator.get_client_with_role')
def test_deliver_success_notification(mock_role):
    """Asserts success messages are delivered as expected."""
    sns = boto3.client('sns', region_name='us-east-1')
    mock_role.return_value = sns
    topic_arn = sns.create_topic(Name='my-topic')['TopicArn']
    sqs_conn = boto3.resource("sqs", region_name="us-east-1")
    sqs_conn.create_queue(QueueName="test-queue")
    sns.subscribe(
        TopicArn=topic_arn,
        Protocol="sqs",
        Endpoint=f"arn:aws:sqs:us-east-1:{DEFAULT_ACCOUNT_ID}:test-queue",
    )

    default_args = ARGS
    default_args[-1] = topic_arn
    validator = Validator(*default_args)

    validator.deliver_success_notification()

    queue = sqs_conn.get_queue_by_name(QueueName="test-queue")
    messages = queue.receive_messages(MaxNumberOfMessages=1)
    message_body = json.loads(messages[0].body)
    assert message_body['MessageAttributes']['outcome']['Value'] == 'SUCCESS'
    assert message_body['MessageAttributes']['refid']['Value'] == validator.refid


@mock_sns
@mock_sqs
@mock_sts
@patch('src.validate.Validator.get_client_with_role')
@patch('traceback.format_exception')
def test_deliver_failure_notification(mock_traceback, mock_role):
    """Asserts failure messages are delivered as expected."""
    sns = boto3.client('sns', region_name='us-east-1')
    mock_role.return_value = sns
    topic_arn = sns.create_topic(Name='my-topic')['TopicArn']
    sqs_conn = boto3.resource("sqs", region_name="us-east-1")
    sqs_conn.create_queue(QueueName="test-queue")
    sns.subscribe(
        TopicArn=topic_arn,
        Protocol="sqs",
        Endpoint=f"arn:aws:sqs:us-east-1:{DEFAULT_ACCOUNT_ID}:test-queue",
    )

    default_args = ARGS
    default_args[-1] = topic_arn
    validator = Validator(*default_args)
    exception_message = "foo"
    exception = Exception(exception_message)
    mock_traceback.return_value = ["baz", "buzz"]

    validator.deliver_failure_notification(exception)

    queue = sqs_conn.get_queue_by_name(QueueName="test-queue")
    messages = queue.receive_messages(MaxNumberOfMessages=1)
    message_body = json.loads(messages[0].body)
    assert message_body['MessageAttributes']['outcome']['Value'] == 'FAILURE'
    assert message_body['MessageAttributes']['refid']['Value'] == validator.refid
    assert exception_message in message_body['MessageAttributes']['message']['Value']
    assert message_body['MessageAttributes']['traceback']['Value'] == 'baz'
