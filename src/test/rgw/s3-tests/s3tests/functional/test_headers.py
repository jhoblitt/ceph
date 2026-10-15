import boto3
import pytest
import botocore.config
import requests

from botocore.auth import S3SigV4Auth
from botocore.auth import S3SigV4QueryAuth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.exceptions import ClientError

from email.utils import formatdate
import http.client
import time
import xml.etree.ElementTree as ET
from urllib.parse import urlencode
from urllib.parse import urlsplit
from botocore.auth import HmacV1Auth
from botocore.auth import HmacV1QueryAuth

from .utils import assert_raises
from .utils import _get_status_and_error_code
from .utils import _get_status

from . import (
    configfile,
    setup_teardown,
    get_client,
    get_config_endpoint,
    get_main_api_name,
    get_main_aws_access_key,
    get_main_aws_secret_key,
    get_new_bucket,
    get_new_bucket_name,
    get_v2_client,
    get_config_ssl_verify
    )

def _add_header_create_object(headers, client=None):
    """ Create a new bucket, add an object w/header customizations
    """
    bucket_name = get_new_bucket()
    if client == None:
        client = get_client()
    key_name = 'foo'

    # pass in custom headers before PutObject call
    add_headers = (lambda **kwargs: kwargs['params']['headers'].update(headers))
    client.meta.events.register('before-call.s3.PutObject', add_headers)
    client.put_object(Bucket=bucket_name, Key=key_name)

    return bucket_name, key_name


def _add_header_create_bad_object(headers, client=None):
    """ Create a new bucket, add an object with a header. This should cause a failure
    """
    bucket_name = get_new_bucket()
    if client == None:
        client = get_client()
    key_name = 'foo'

    # pass in custom headers before PutObject call
    add_headers = (lambda **kwargs: kwargs['params']['headers'].update(headers))
    client.meta.events.register('before-call.s3.PutObject', add_headers)
    e = assert_raises(ClientError, client.put_object, Bucket=bucket_name, Key=key_name, Body='bar')

    return e


def _remove_header_create_object(remove, client=None):
    """ Create a new bucket, add an object without a header
    """
    bucket_name = get_new_bucket()
    if client == None:
        client = get_client()
    key_name = 'foo'

    # remove custom headers before PutObject call
    def remove_header(**kwargs):
        if (remove in kwargs['params']['headers']):
            del kwargs['params']['headers'][remove]

    client.meta.events.register('before-call.s3.PutObject', remove_header)
    client.put_object(Bucket=bucket_name, Key=key_name)

    return bucket_name, key_name

def _remove_header_create_bad_object(remove, client=None):
    """ Create a new bucket, add an object without a header. This should cause a failure
    """
    bucket_name = get_new_bucket()
    if client == None:
        client = get_client()
    key_name = 'foo'

    # remove custom headers before PutObject call
    def remove_header(**kwargs):
        if (remove in kwargs['params']['headers']):
            del kwargs['params']['headers'][remove]

    client.meta.events.register('before-call.s3.PutObject', remove_header)
    e = assert_raises(ClientError, client.put_object, Bucket=bucket_name, Key=key_name, Body='bar')

    return e


def _add_header_create_bucket(headers, client=None):
    """ Create a new bucket, w/header customizations
    """
    bucket_name = get_new_bucket_name()
    if client == None:
        client = get_client()

    # pass in custom headers before PutObject call
    add_headers = (lambda **kwargs: kwargs['params']['headers'].update(headers))
    client.meta.events.register('before-call.s3.CreateBucket', add_headers)
    client.create_bucket(Bucket=bucket_name)

    return bucket_name


def _add_header_create_bad_bucket(headers=None, client=None):
    """ Create a new bucket, w/header customizations that should cause a failure
    """
    bucket_name = get_new_bucket_name()
    if client == None:
        client = get_client()

    # pass in custom headers before PutObject call
    add_headers = (lambda **kwargs: kwargs['params']['headers'].update(headers))
    client.meta.events.register('before-call.s3.CreateBucket', add_headers)
    e = assert_raises(ClientError, client.create_bucket, Bucket=bucket_name)

    return e


def _remove_header_create_bucket(remove, client=None):
    """ Create a new bucket, without a header
    """
    bucket_name = get_new_bucket_name()
    if client == None:
        client = get_client()

    # remove custom headers before PutObject call
    def remove_header(**kwargs):
        if (remove in kwargs['params']['headers']):
            del kwargs['params']['headers'][remove]

    client.meta.events.register('before-call.s3.CreateBucket', remove_header)
    client.create_bucket(Bucket=bucket_name)

    return bucket_name

def _remove_header_create_bad_bucket(remove, client=None):
    """ Create a new bucket, without a header. This should cause a failure
    """
    bucket_name = get_new_bucket_name()
    if client == None:
        client = get_client()

    # remove custom headers before PutObject call
    def remove_header(**kwargs):
        if (remove in kwargs['params']['headers']):
            del kwargs['params']['headers'][remove]

    client.meta.events.register('before-call.s3.CreateBucket', remove_header)
    e = assert_raises(ClientError, client.create_bucket, Bucket=bucket_name)

    return e

def _get_s3sigv4_signer():
    """ Return a Signer object based on default user/secret/region.
    """
    creds = Credentials(
        access_key=get_main_aws_access_key(),
        secret_key=get_main_aws_secret_key(),
    )
    return S3SigV4Auth(credentials=creds, service_name="s3", region_name=get_main_api_name())

def _get_s3sigv4_query_signer():
    """ Return a query-string (presigning) Signer based on default user/secret/region.
    """
    creds = Credentials(
        access_key=get_main_aws_access_key(),
        secret_key=get_main_aws_secret_key(),
    )
    return S3SigV4QueryAuth(credentials=creds, service_name="s3",
                            region_name=get_main_api_name(), expires=100000)

#
# common tests
#

@pytest.mark.auth_common
def test_object_create_bad_md5_invalid_short():
    e = _add_header_create_bad_object({'Content-MD5':'YWJyYWNhZGFicmE='})
    status, error_code = _get_status_and_error_code(e.response)
    assert status == 400
    assert error_code == 'InvalidDigest'

@pytest.mark.auth_common
def test_object_create_bad_md5_bad():
    e = _add_header_create_bad_object({'Content-MD5':'rL0Y20xC+Fzt72VPzMSk2A=='})
    status, error_code = _get_status_and_error_code(e.response)
    assert status == 400
    assert error_code == 'BadDigest'

@pytest.mark.auth_common
def test_object_create_bad_md5_empty():
    e = _add_header_create_bad_object({'Content-MD5':''})
    status, error_code = _get_status_and_error_code(e.response)
    assert status == 400
    assert error_code == 'InvalidDigest'

@pytest.mark.auth_common
def test_object_create_bad_md5_none():
    bucket_name, key_name = _remove_header_create_object('Content-MD5')
    client = get_client()
    client.put_object(Bucket=bucket_name, Key=key_name, Body='bar')

def _call_with_unknown_expectation(func, **kwargs):
    """ Call func, whose request carries an Expect other than 100-continue.
    RFC 9110 section 10.1.1 lets a server answer such an expectation with
    417 (Expectation Failed), so accept that as well as success
    """
    try:
        func(**kwargs)
    except ClientError as e:
        if _get_status(e.response) != 417:
            raise

@pytest.mark.auth_common
def test_object_create_bad_expect_mismatch():
    bucket_name = get_new_bucket()
    client = get_client()
    key_name = 'foo'

    headers = {'Expect': 200}
    add_headers = (lambda **kwargs: kwargs['params']['headers'].update(headers))
    client.meta.events.register('before-call.s3.PutObject', add_headers)
    _call_with_unknown_expectation(client.put_object, Bucket=bucket_name, Key=key_name)

    client = get_client()
    client.put_object(Bucket=bucket_name, Key=key_name, Body='bar')

@pytest.mark.auth_common
def test_object_create_bad_expect_empty():
    bucket_name, key_name = _add_header_create_object({'Expect': ''})
    client = get_client()
    client.put_object(Bucket=bucket_name, Key=key_name, Body='bar')

@pytest.mark.auth_common
def test_object_create_bad_expect_none():
    bucket_name, key_name = _remove_header_create_object('Expect')
    client = get_client()
    client.put_object(Bucket=bucket_name, Key=key_name, Body='bar')

@pytest.mark.auth_common
# TODO: remove 'fails_on_rgw' and once we have learned how to remove the content-length header
@pytest.mark.fails_on_rgw
def test_object_create_bad_contentlength_empty():
    e = _add_header_create_bad_object({'Content-Length':''})
    status, error_code = _get_status_and_error_code(e.response)
    assert status == 400

@pytest.mark.auth_common
@pytest.mark.fails_on_mod_proxy_fcgi
def test_object_create_bad_contentlength_negative():
    # to test Content-Length=-1, we have to prevent the checksum calculation
    # from switching to STREAMING-UNSIGNED-PAYLOAD-TRAILER
    config = botocore.config.Config(request_checksum_calculation = 'when_required')
    client = get_client(config)
    bucket_name = get_new_bucket()
    key_name = 'foo'
    e = assert_raises(ClientError, client.put_object, Bucket=bucket_name, Key=key_name, ContentLength=-1)
    status = _get_status(e.response)
    assert status == 400

@pytest.mark.auth_common
# TODO: remove 'fails_on_rgw' and once we have learned how to remove the content-length header
@pytest.mark.fails_on_rgw
def test_object_create_bad_contentlength_none():
    remove = 'Content-Length'
    e = _remove_header_create_bad_object('Content-Length')
    status, error_code = _get_status_and_error_code(e.response)
    assert status == 411
    assert error_code == 'MissingContentLength'

@pytest.mark.auth_common
def test_object_create_bad_contenttype_invalid():
    bucket_name, key_name = _add_header_create_object({'Content-Type': 'text/plain'})
    client = get_client()
    client.put_object(Bucket=bucket_name, Key=key_name, Body='bar')

@pytest.mark.auth_common
def test_object_create_bad_contenttype_empty():
    client = get_client()
    key_name = 'foo'
    bucket_name = get_new_bucket()
    client.put_object(Bucket=bucket_name, Key=key_name, Body='bar', ContentType='')

@pytest.mark.auth_common
def test_object_create_bad_contenttype_none():
    bucket_name = get_new_bucket()
    key_name = 'foo'
    client = get_client()
    # as long as ContentType isn't specified in put_object it isn't going into the request
    client.put_object(Bucket=bucket_name, Key=key_name, Body='bar')


@pytest.mark.auth_common
# TODO: remove 'fails_on_rgw' and once we have learned how to remove the authorization header
@pytest.mark.fails_on_rgw
def test_object_create_bad_authorization_empty():
    e = _add_header_create_bad_object({'Authorization': ''})
    status, error_code = _get_status_and_error_code(e.response)
    assert status == 403

@pytest.mark.auth_common
# TODO: remove 'fails_on_rgw' and once we have learned how to pass both the 'Date' and 'X-Amz-Date' header during signing and not 'X-Amz-Date' before
@pytest.mark.fails_on_rgw
def test_object_create_date_and_amz_date():
    date = formatdate(usegmt=True)
    bucket_name, key_name = _add_header_create_object({'Date': date, 'X-Amz-Date': date})
    client = get_client()
    client.put_object(Bucket=bucket_name, Key=key_name, Body='bar')

@pytest.mark.auth_common
# TODO: remove 'fails_on_rgw' and once we have learned how to pass both the 'Date' and 'X-Amz-Date' header during signing and not 'X-Amz-Date' before
@pytest.mark.fails_on_rgw
def test_object_create_amz_date_and_no_date():
    date = formatdate(usegmt=True)
    bucket_name, key_name = _add_header_create_object({'Date': '', 'X-Amz-Date': date})
    client = get_client()
    client.put_object(Bucket=bucket_name, Key=key_name, Body='bar')

# the teardown is really messed up here. check it out
@pytest.mark.auth_common
# TODO: remove 'fails_on_rgw' and once we have learned how to remove the authorization header
@pytest.mark.fails_on_rgw
def test_object_create_bad_authorization_none():
    e = _remove_header_create_bad_object('Authorization')
    status, error_code = _get_status_and_error_code(e.response)
    assert status == 403

@pytest.mark.auth_common
# TODO: remove 'fails_on_rgw' and once we have learned how to remove the content-length header
@pytest.mark.fails_on_rgw
def test_bucket_create_contentlength_none():
    remove = 'Content-Length'
    _remove_header_create_bucket(remove)

@pytest.mark.auth_common
# TODO: remove 'fails_on_rgw' and once we have learned how to remove the content-length header
@pytest.mark.fails_on_rgw
def test_object_acl_create_contentlength_none():
    bucket_name = get_new_bucket()
    client = get_client()
    client.put_object(Bucket=bucket_name, Key='foo', Body='bar')

    remove = 'Content-Length'
    def remove_header(**kwargs):
        if (remove in kwargs['params']['headers']):
            del kwargs['params']['headers'][remove]

    client.meta.events.register('before-call.s3.PutObjectAcl', remove_header)
    client.put_object_acl(Bucket=bucket_name, Key='foo', ACL='public-read')

@pytest.mark.auth_common
def test_bucket_put_bad_canned_acl():
    bucket_name = get_new_bucket()
    client = get_client()

    headers = {'x-amz-acl': 'public-ready'}
    add_headers = (lambda **kwargs: kwargs['params']['headers'].update(headers))
    client.meta.events.register('before-call.s3.PutBucketAcl', add_headers)

    e = assert_raises(ClientError, client.put_bucket_acl, Bucket=bucket_name, ACL='public-read')
    status = _get_status(e.response)
    assert status == 400

@pytest.mark.auth_common
def test_bucket_create_bad_expect_mismatch():
    bucket_name = get_new_bucket_name()
    client = get_client()

    headers = {'Expect': 200}
    add_headers = (lambda **kwargs: kwargs['params']['headers'].update(headers))
    client.meta.events.register('before-call.s3.CreateBucket', add_headers)
    _call_with_unknown_expectation(client.create_bucket, Bucket=bucket_name)

@pytest.mark.auth_common
def test_bucket_create_bad_expect_empty():
    headers = {'Expect': ''}
    _add_header_create_bucket(headers)

@pytest.mark.auth_common
# TODO: The request isn't even making it to the RGW past the frontend
# This test had 'fails_on_rgw' before the move to boto3
@pytest.mark.fails_on_rgw
def test_bucket_create_bad_contentlength_empty():
    headers = {'Content-Length': ''}
    e = _add_header_create_bad_bucket(headers)
    status, error_code = _get_status_and_error_code(e.response)
    assert status == 400

@pytest.mark.auth_common
@pytest.mark.fails_on_mod_proxy_fcgi
def test_bucket_create_bad_contentlength_negative():
    headers = {'Content-Length': '-1'}
    e = _add_header_create_bad_bucket(headers)
    status = _get_status(e.response)
    assert status == 400

@pytest.mark.auth_common
# TODO: remove 'fails_on_rgw' and once we have learned how to remove the content-length header
@pytest.mark.fails_on_rgw
def test_bucket_create_bad_contentlength_none():
    remove = 'Content-Length'
    _remove_header_create_bucket(remove)

@pytest.mark.auth_common
# TODO: remove 'fails_on_rgw' and once we have learned how to manipulate the authorization header
@pytest.mark.fails_on_rgw
def test_bucket_create_bad_authorization_empty():
    headers = {'Authorization': ''}
    e = _add_header_create_bad_bucket(headers)
    status, error_code = _get_status_and_error_code(e.response)
    assert status == 403
    assert error_code == 'AccessDenied'

@pytest.mark.auth_common
# TODO: remove 'fails_on_rgw' and once we have learned how to manipulate the authorization header
@pytest.mark.fails_on_rgw
def test_bucket_create_bad_authorization_none():
    e = _remove_header_create_bad_bucket('Authorization')
    status, error_code = _get_status_and_error_code(e.response)
    assert status == 403
    assert error_code == 'AccessDenied'

@pytest.mark.auth_aws2
def test_object_create_bad_md5_invalid_garbage_aws2():
    v2_client = get_v2_client()
    headers = {'Content-MD5': 'AWS HAHAHA'}
    e = _add_header_create_bad_object(headers, v2_client)
    status, error_code = _get_status_and_error_code(e.response)
    assert status == 400
    assert error_code == 'InvalidDigest'

@pytest.mark.auth_aws2
# TODO: remove 'fails_on_rgw' and once we have learned how to manipulate the Content-Length header
@pytest.mark.fails_on_rgw
def test_object_create_bad_contentlength_mismatch_below_aws2():
    v2_client = get_v2_client()
    content = 'bar'
    length = len(content) - 1
    headers = {'Content-Length': str(length)}
    e = _add_header_create_bad_object(headers, v2_client)
    status, error_code = _get_status_and_error_code(e.response)
    assert status == 400
    assert error_code == 'BadDigest'

@pytest.mark.auth_aws2
# TODO: remove 'fails_on_rgw' and once we have learned how to manipulate the authorization header
@pytest.mark.fails_on_rgw
def test_object_create_bad_authorization_incorrect_aws2():
    v2_client = get_v2_client()
    headers = {'Authorization': 'AWS AKIAIGR7ZNNBHC5BKSUB:FWeDfwojDSdS2Ztmpfeubhd9isU='}
    e = _add_header_create_bad_object(headers, v2_client)
    status, error_code = _get_status_and_error_code(e.response)
    assert status == 403
    assert error_code == 'InvalidDigest'

@pytest.mark.auth_aws2
# TODO: remove 'fails_on_rgw' and once we have learned how to manipulate the authorization header
@pytest.mark.fails_on_rgw
def test_object_create_bad_authorization_invalid_aws2():
    v2_client = get_v2_client()
    headers = {'Authorization': 'AWS HAHAHA'}
    e = _add_header_create_bad_object(headers, v2_client)
    status, error_code = _get_status_and_error_code(e.response)
    assert status == 400
    assert error_code == 'InvalidArgument'

@pytest.mark.auth_aws2
def test_object_create_bad_ua_empty_aws2():
    v2_client = get_v2_client()
    headers = {'User-Agent': ''}
    bucket_name, key_name = _add_header_create_object(headers, v2_client)
    v2_client.put_object(Bucket=bucket_name, Key=key_name, Body='bar')

@pytest.mark.auth_aws2
def test_object_create_bad_ua_none_aws2():
    v2_client = get_v2_client()
    remove = 'User-Agent'
    bucket_name, key_name = _remove_header_create_object(remove, v2_client)
    v2_client.put_object(Bucket=bucket_name, Key=key_name, Body='bar')

@pytest.mark.auth_aws2
def test_object_create_bad_date_invalid_aws2():
    v2_client = get_v2_client()
    headers = {'x-amz-date': 'Bad Date'}
    e = _add_header_create_bad_object(headers, v2_client)
    status, error_code = _get_status_and_error_code(e.response)
    assert status == 403
    assert error_code == 'AccessDenied'

@pytest.mark.auth_aws2
def test_object_create_bad_date_empty_aws2():
    v2_client = get_v2_client()
    headers = {'x-amz-date': ''}
    e = _add_header_create_bad_object(headers, v2_client)
    status, error_code = _get_status_and_error_code(e.response)
    assert status == 403
    assert error_code == 'AccessDenied'

@pytest.mark.auth_aws2
# TODO: remove 'fails_on_rgw' and once we have learned how to remove the date header
@pytest.mark.fails_on_rgw
def test_object_create_bad_date_none_aws2():
    v2_client = get_v2_client()
    remove = 'x-amz-date'
    e = _remove_header_create_bad_object(remove, v2_client)
    status, error_code = _get_status_and_error_code(e.response)
    assert status == 403
    assert error_code == 'AccessDenied'

@pytest.mark.auth_aws2
def test_object_create_bad_date_before_today_aws2():
    v2_client = get_v2_client()
    headers = {'x-amz-date': 'Tue, 07 Jul 2010 21:53:04 GMT'}
    e = _add_header_create_bad_object(headers, v2_client)
    status, error_code = _get_status_and_error_code(e.response)
    assert status == 403
    assert error_code == 'RequestTimeTooSkewed'

@pytest.mark.auth_aws2
def test_object_create_bad_date_before_epoch_aws2():
    v2_client = get_v2_client()
    headers = {'x-amz-date': 'Tue, 07 Jul 1950 21:53:04 GMT'}
    e = _add_header_create_bad_object(headers, v2_client)
    status, error_code = _get_status_and_error_code(e.response)
    assert status == 403
    assert error_code == 'AccessDenied'

@pytest.mark.auth_aws2
def test_object_create_bad_date_after_end_aws2():
    v2_client = get_v2_client()
    headers = {'x-amz-date': 'Tue, 07 Jul 9999 21:53:04 GMT'}
    e = _add_header_create_bad_object(headers, v2_client)
    status, error_code = _get_status_and_error_code(e.response)
    assert status == 403
    assert error_code == 'RequestTimeTooSkewed'

@pytest.mark.auth_aws2
# TODO: remove 'fails_on_rgw' and once we have learned how to remove the date header
@pytest.mark.fails_on_rgw
def test_bucket_create_bad_authorization_invalid_aws2():
    v2_client = get_v2_client()
    headers = {'Authorization': 'AWS HAHAHA'}
    e = _add_header_create_bad_bucket(headers, v2_client)
    status, error_code = _get_status_and_error_code(e.response)
    assert status == 400
    assert error_code == 'InvalidArgument'

@pytest.mark.auth_aws2
@pytest.mark.fails_on_rgw
def test_bucket_create_bad_ua_empty_aws2():
    v2_client = get_v2_client()
    headers = {'User-Agent': ''}
    _add_header_create_bucket(headers, v2_client)

@pytest.mark.auth_aws2
@pytest.mark.fails_on_rgw
def test_bucket_create_bad_ua_none_aws2():
    v2_client = get_v2_client()
    remove = 'User-Agent'
    _remove_header_create_bucket(remove, v2_client)

@pytest.mark.auth_aws2
def test_bucket_create_bad_date_invalid_aws2():
    v2_client = get_v2_client()
    headers = {'x-amz-date': 'Bad Date'}
    e = _add_header_create_bad_bucket(headers, v2_client)
    status, error_code = _get_status_and_error_code(e.response)
    assert status == 403
    assert error_code == 'AccessDenied'

@pytest.mark.auth_aws2
def test_bucket_create_bad_date_empty_aws2():
    v2_client = get_v2_client()
    headers = {'x-amz-date': ''}
    e = _add_header_create_bad_bucket(headers, v2_client)
    status, error_code = _get_status_and_error_code(e.response)
    assert status == 403
    assert error_code == 'AccessDenied'

@pytest.mark.auth_aws2
# TODO: remove 'fails_on_rgw' and once we have learned how to remove the date header
@pytest.mark.fails_on_rgw
def test_bucket_create_bad_date_none_aws2():
    v2_client = get_v2_client()
    remove = 'x-amz-date'
    e = _remove_header_create_bad_bucket(remove, v2_client)
    status, error_code = _get_status_and_error_code(e.response)
    assert status == 403
    assert error_code == 'AccessDenied'

@pytest.mark.auth_aws2
def test_bucket_create_bad_date_before_today_aws2():
    v2_client = get_v2_client()
    headers = {'x-amz-date': 'Tue, 07 Jul 2010 21:53:04 GMT'}
    e = _add_header_create_bad_bucket(headers, v2_client)
    status, error_code = _get_status_and_error_code(e.response)
    assert status == 403
    assert error_code == 'RequestTimeTooSkewed'

@pytest.mark.auth_aws2
def test_bucket_create_bad_date_after_today_aws2():
    v2_client = get_v2_client()
    headers = {'x-amz-date': 'Tue, 07 Jul 2030 21:53:04 GMT'}
    e = _add_header_create_bad_bucket(headers, v2_client)
    status, error_code = _get_status_and_error_code(e.response)
    assert status == 403
    assert error_code == 'RequestTimeTooSkewed'

@pytest.mark.auth_aws2
def test_bucket_create_bad_date_before_epoch_aws2():
    v2_client = get_v2_client()
    headers = {'x-amz-date': 'Tue, 07 Jul 1950 21:53:04 GMT'}
    e = _add_header_create_bad_bucket(headers, v2_client)
    status, error_code = _get_status_and_error_code(e.response)
    assert status == 403
    assert error_code == 'AccessDenied'

@pytest.mark.auth_aws4
def test_sigv4_host_good():
    signer = _get_s3sigv4_signer()
    req = AWSRequest(
        method="GET",
        url=get_config_endpoint() + "/",
    )
    signer.add_auth(req)
    assert req.url is not None
    resp = requests.get(req.url, headers=dict(req.headers), verify=get_config_ssl_verify())
    assert(resp.status_code == 200)

@pytest.mark.auth_aws4
def test_sigv4_host_bad():
    # This passes even without the check in `get_v4_canonical_headers`
    # since the signatures don't match.
    signer = _get_s3sigv4_signer()
    req = AWSRequest(
        method="GET",
        url=get_config_endpoint() + "/",
    )
    signer.add_auth(req)
    authorization = req.headers['Authorization']
    authorization = authorization.replace("SignedHeaders=host;", "SignedHeaders=")
    del req.headers['Authorization']
    req.headers['Authorization'] = authorization
    assert req.url is not None
    resp = requests.get(req.url, headers=dict(req.headers), verify=get_config_ssl_verify())
    assert(resp.status_code == 403)

@pytest.mark.auth_aws4
def test_sigv4_xamz_good():
    signer = _get_s3sigv4_signer()
    req = AWSRequest(
        method="GET",
        url=get_config_endpoint() + "/",
        headers={"x-amz-benevolent": "good-header"},
    )
    signer.add_auth(req)
    assert req.url is not None
    resp = requests.get(req.url, headers=dict(req.headers), verify=get_config_ssl_verify())
    assert(resp.status_code == 200)

@pytest.mark.auth_aws4
def test_sigv4_xamz_bad():
    signer = _get_s3sigv4_signer()
    req = AWSRequest(
        method="GET",
        url=get_config_endpoint() + "/",
        headers={"x-amz-benevolent": "good-header"},
    )
    signer.add_auth(req)
    req.headers['x-amz-malevolent'] = 'evil-header'
    assert req.url is not None
    resp = requests.get(req.url, headers=dict(req.headers), verify=get_config_ssl_verify())
    assert(resp.status_code == 403)

@pytest.mark.auth_aws4
def test_sigv4_contenttype_good():
    signer = _get_s3sigv4_signer()
    req = AWSRequest(
        method="GET",
        url=get_config_endpoint() + "/",
        headers={"content-type": "application/octet-stream"},
    )
    signer.add_auth(req)
    assert req.url is not None
    resp = requests.get(req.url, headers=dict(req.headers), verify=get_config_ssl_verify())
    assert(resp.status_code == 200)

@pytest.mark.auth_aws4
def test_sigv4_contenttype_unsigned():
    # An unsigned Content-Type must be ACCEPTED: AWS documents it as optional
    # in the signature, and real S3 accepts it. See the rationale in
    # get_v4_canonical_headers() (src/rgw/rgw_auth_s3.cc).
    # test_sigv4_xamz_bad still pins the CVE-2026-54330 behaviour.
    signer = _get_s3sigv4_signer()
    req = AWSRequest(
        method="GET",
        url=get_config_endpoint() + "/",
    )
    signer.add_auth(req)
    req.headers["content-type"] = "application/octet-stream"
    assert req.url is not None
    resp = requests.get(req.url, headers=dict(req.headers), verify=get_config_ssl_verify())
    assert(resp.status_code == 200)

@pytest.mark.auth_aws4
def test_sigv4_missing_header():
    # This passes even without the check in `get_v4_canonical_headers`
    # since the signatures don't match.
    signer = _get_s3sigv4_signer()
    req = AWSRequest(
        method="GET",
        url=get_config_endpoint() + "/",
        headers={"x-amz-problematic": "dubious-header"},
    )
    signer.add_auth(req)
    del req.headers['x-amz-problematic']
    assert req.url is not None
    resp = requests.get(req.url, headers=dict(req.headers), verify=get_config_ssl_verify())
    assert(resp.status_code == 403)

@pytest.mark.auth_aws4
def test_sigv4_with_signed_content_sha256():
    signer = _get_s3sigv4_signer()
    req = AWSRequest(method="GET", url=get_config_endpoint() + "/")
    signer.add_auth(req)
    assert req.url is not None
    assert 'x-amz-content-sha256' in req.headers
    resp = requests.get(req.url, headers=dict(req.headers), verify=get_config_ssl_verify())
    assert(resp.status_code == 200)

@pytest.mark.auth_aws4
def test_sigv4_without_signed_content_sha256():
    # custom signer that excludes x-amz-content-sha256 from signed-headers
    class CustomAuth(S3SigV4Auth):
        def headers_to_sign(self, request):
            saved = request.headers['x-amz-content-sha256']
            del request.headers['x-amz-content-sha256']
            result = super().headers_to_sign(request)
            request.headers['x-amz-content-sha256'] = saved
            return result

    creds = Credentials(access_key=get_main_aws_access_key(),
                        secret_key=get_main_aws_secret_key())
    signer = CustomAuth(credentials=creds, service_name="s3",
                        region_name=get_main_api_name())
    req = AWSRequest(method="GET", url=get_config_endpoint() + "/")
    signer.add_auth(req)
    assert req.url is not None
    assert 'x-amz-content-sha256' in req.headers
    resp = requests.get(req.url, headers=dict(req.headers), verify=get_config_ssl_verify())
    assert(resp.status_code == 200)

@pytest.mark.auth_aws4
def test_sigv4_xgoog_signed():
    signer = _get_s3sigv4_signer()
    req = AWSRequest(
        method="GET",
        url=get_config_endpoint() + "/",
        headers={"x-goog-benevolent": "good-header"},
    )
    signer.add_auth(req)
    assert req.url is not None
    resp = requests.get(req.url, headers=dict(req.headers), verify=get_config_ssl_verify())
    assert(resp.status_code == 200)

@pytest.mark.auth_aws4
def test_sigv4_presigned_xamz_bad():
    signer = _get_s3sigv4_query_signer()
    req = AWSRequest(method="GET", url=get_config_endpoint() + "/")
    signer.add_auth(req)
    resp = requests.get(req.url, headers={'x-amz-malevolent': 'evil-header'})
    assert(resp.status_code == 403)

@pytest.mark.auth_aws4
def test_sigv4_presigned_contenttype_unsigned():
    # A presigned URL only signs `host`, so any uploader that sends its own
    # content-type sends it unsigned. Of course every browser does this, so
    # thats the most common S3 upload shape in the wild and it has to work.
    signer = _get_s3sigv4_query_signer()
    req = AWSRequest(method="GET", url=get_config_endpoint() + "/")
    signer.add_auth(req)
    resp = requests.get(req.url, headers={'content-type': 'application/octet-stream'},
                        verify=get_config_ssl_verify())
    assert(resp.status_code == 200)

@pytest.mark.auth_aws4
def test_sigv4_presigned_contenttype_plus_xamz_bad():
    # ...but an unsigned x-amz- header sitting alongside an unsigned
    # content-type still has to be rejected. Thats the combination a careless
    # relaxation of the header checks would let slip through.
    signer = _get_s3sigv4_query_signer()
    req = AWSRequest(method="GET", url=get_config_endpoint() + "/")
    signer.add_auth(req)
    resp = requests.get(req.url, headers={'content-type': 'application/octet-stream',
                                          'x-amz-malevolent': 'evil-header'},
                        verify=get_config_ssl_verify())
    assert(resp.status_code == 403)

@pytest.mark.auth_aws4
def test_sigv4_presigned_good():
    signer = _get_s3sigv4_query_signer()
    req = AWSRequest(method="GET", url=get_config_endpoint() + "/")
    signer.add_auth(req)
    resp = requests.get(req.url)
    assert(resp.status_code == 200)

@pytest.mark.auth_aws4
def test_sigv4_presigned_put_xgoog_meta_unsigned():
    # RGW files an X-Goog- header under its x-amz- name, so an unsigned
    # X-Goog-Meta-Foo on a presigned PUT would store user metadata the URL's
    # signer never named. It has to be refused like an unsigned x-amz- header.
    bucket = get_new_bucket()
    key = 'foo'
    signer = _get_s3sigv4_query_signer()
    req = AWSRequest(method="PUT", url=get_config_endpoint() + "/" + bucket + "/" + key)
    signer.add_auth(req)
    resp = requests.put(req.url, data=b'bar', headers={'X-Goog-Meta-Foo': 'evil-header'},
                        verify=get_config_ssl_verify())
    assert(resp.status_code == 403)
    client = get_client()
    e = assert_raises(ClientError, client.head_object, Bucket=bucket, Key=key)
    assert(_get_status(e.response) == 404)

    # the same URL without the unsigned header is accepted
    resp = requests.put(req.url, data=b'bar', verify=get_config_ssl_verify())
    assert(resp.status_code == 200)
    assert(client.head_object(Bucket=bucket, Key=key)['Metadata'] == {})

@pytest.mark.auth_aws2
def test_sigv2_signed_copy_source_moved_to_xgoog():
    # The SigV2 string to sign names an X-Goog- header by its x-amz- name,
    # but RGW reads the copy source from X-Amz-Copy-Source alone. So a signed
    # X-Amz-Copy-Source resent as X-Goog-Copy-Source keeps its signature and
    # drops the copy, turning the CopyObject into a PutObject of the empty
    # body. It has to be refused.
    bucket = get_new_bucket()
    client = get_client()
    client.put_object(Bucket=bucket, Key='src', Body=b'source')
    creds = Credentials(access_key=get_main_aws_access_key(), secret_key=get_main_aws_secret_key())
    req = AWSRequest(method='PUT', url=get_config_endpoint() + '/' + bucket + '/dst',
                     headers={'X-Amz-Copy-Source': bucket + '/src'})
    HmacV1Auth(credentials=creds).add_auth(req)
    moved = dict(req.headers)
    moved['X-Goog-Copy-Source'] = moved.pop('X-Amz-Copy-Source')
    resp = requests.put(req.url, headers=moved, verify=get_config_ssl_verify())
    assert(resp.status_code == 403)
    e = assert_raises(ClientError, client.head_object, Bucket=bucket, Key='dst')
    assert(_get_status(e.response) == 404)

    # the same signature with the header as signed copies the source
    resp = requests.put(req.url, headers=dict(req.headers), verify=get_config_ssl_verify())
    assert(resp.status_code == 200)
    assert(client.get_object(Bucket=bucket, Key='dst')['Body'].read() == b'source')

@pytest.mark.auth_aws2
def test_sigv2_presigned_multipart_meta_moved_to_query():
    # The SigV2 string to sign of a presigned URL writes the query's
    # x-amz-meta-* lines straight after the headers', so one signature holds
    # with a signed X-Amz-Meta-Foo sent as a header or moved into the query,
    # where HmacV1QueryAuth puts it. Both forms must mean the same, but RGW's
    # CreateMultipartUpload reads its metadata from the headers alone.
    bucket = get_new_bucket()
    client = get_client()
    creds = Credentials(access_key=get_main_aws_access_key(), secret_key=get_main_aws_secret_key())
    for key, as_header in (('query', False), ('header', True)):
        req = AWSRequest(method='POST', url=get_config_endpoint() + '/' + bucket + '/' + key + '?uploads',
                         headers={'X-Amz-Meta-Foo': 'bar'})
        HmacV1QueryAuth(credentials=creds, expires=3600).add_auth(req)
        url = req.url
        headers = {}
        if as_header:
            parts = urlsplit(url)
            query = '&'.join(p for p in parts.query.split('&') if not p.startswith('x-amz-meta-foo='))
            url = parts._replace(query=query).geturl()
            headers = {'X-Amz-Meta-Foo': 'bar'}
        assert(('x-amz-meta-foo=bar' in url) != as_header)
        resp = requests.post(url, headers=headers, verify=get_config_ssl_verify())
        assert(resp.status_code == 200)
        upload_id = ET.fromstring(resp.content).find('{http://s3.amazonaws.com/doc/2006-03-01/}UploadId').text
        part = client.upload_part(Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=1, Body=b'data')
        client.complete_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id,
                                         MultipartUpload={'Parts': [{'ETag': part['ETag'], 'PartNumber': 1}]})
        assert(client.head_object(Bucket=bucket, Key=key)['Metadata'] == {'foo': 'bar'})

@pytest.mark.auth_aws2
def test_sigv2_presigned_copy_replace_meta_in_query():
    # A presigned URL carries the metadata it signs in its query, which the
    # SigV2 string to sign writes after the headers' x-amz-* lines. A
    # CopyObject that replaces its metadata must store metadata so signed as
    # it stores metadata signed as a header, but RGW's CopyObject reads its
    # metadata from the headers alone. The copy's own directive sorts after
    # x-amz-meta-foo, so here the two forms sign different strings.
    bucket = get_new_bucket()
    client = get_client()
    client.put_object(Bucket=bucket, Key='src', Body=b'source', Metadata={'old': 'x'})
    signer = HmacV1Auth(credentials=Credentials(access_key=get_main_aws_access_key(),
                                                secret_key=get_main_aws_secret_key()))
    expires = str(int(time.time()) + 3600)
    copy = {'X-Amz-Copy-Source': bucket + '/src', 'X-Amz-Metadata-Directive': 'REPLACE'}
    for key, amz, query in (
            ('query', 'x-amz-copy-source:{b}/src\nx-amz-metadata-directive:REPLACE\nx-amz-meta-foo:bar\n',
             {'x-amz-meta-foo': 'bar'}),
            ('header', 'x-amz-copy-source:{b}/src\nx-amz-meta-foo:bar\nx-amz-metadata-directive:REPLACE\n', {})):
        string_to_sign = 'PUT\n\n\n' + expires + '\n' + amz.format(b=bucket) + '/' + bucket + '/' + key
        query.update({'AWSAccessKeyId': get_main_aws_access_key(), 'Expires': expires,
                      'Signature': signer.sign_string(string_to_sign)})
        headers = dict(copy)
        if key == 'header':
            headers['X-Amz-Meta-Foo'] = 'bar'
        resp = requests.put(get_config_endpoint() + '/' + bucket + '/' + key + '?' + urlencode(query),
                            headers=headers, verify=get_config_ssl_verify())
        assert(resp.status_code == 200)
        assert(client.head_object(Bucket=bucket, Key=key)['Metadata'] == {'foo': 'bar'})

@pytest.mark.auth_aws2
def test_sigv2_presigned_meta_lines_packed_into_one_query_value():
    # The SigV2 string to sign writes each query x-amz-meta-* line as
    # name:value and a newline, unescaped, after url-decoding it, so one
    # parameter whose value holds %0A signs as the several lines it spells:
    # x-amz-meta-a=1%0Ax-amz-meta-b:2 signs as the two lines a presigned PUT
    # with both names signs, yet stores one attr. It has to be refused.
    bucket = get_new_bucket()
    client = get_client()
    creds = Credentials(access_key=get_main_aws_access_key(), secret_key=get_main_aws_secret_key())
    req = AWSRequest(method='PUT', url=get_config_endpoint() + '/' + bucket + '/key',
                     headers={'X-Amz-Meta-A': '1', 'X-Amz-Meta-B': '2'})
    HmacV1QueryAuth(credentials=creds, expires=3600).add_auth(req)
    parts = urlsplit(req.url)
    params = parts.query.split('&')
    assert('x-amz-meta-a=1' in params and 'x-amz-meta-b=2' in params)
    packed = ['x-amz-meta-a=1%0Ax-amz-meta-b%3A2' if p == 'x-amz-meta-a=1' else p
              for p in params if p != 'x-amz-meta-b=2']
    resp = requests.put(parts._replace(query='&'.join(packed)).geturl(), data=b'packed',
                        verify=get_config_ssl_verify())
    assert(resp.status_code == 403)
    e = assert_raises(ClientError, client.head_object, Bucket=bucket, Key='key')
    assert(_get_status(e.response) == 404)

    # the URL as signed stores both attrs
    resp = requests.put(req.url, data=b'signed', verify=get_config_ssl_verify())
    assert(resp.status_code == 200)
    assert(client.head_object(Bucket=bucket, Key='key')['Metadata'] == {'a': '1', 'b': '2'})

@pytest.mark.auth_aws2
def test_sigv2_presigned_meta_name_with_colon():
    # A query x-amz-meta-* line is name:value, so a colon in the name moves
    # the boundary: the name x-amz-meta-a:x with the value y signs as
    # x-amz-meta-a with the value x:y, yet names another attr. No header name
    # holds a colon. It has to be refused.
    bucket = get_new_bucket()
    client = get_client()
    creds = Credentials(access_key=get_main_aws_access_key(), secret_key=get_main_aws_secret_key())
    req = AWSRequest(method='PUT', url=get_config_endpoint() + '/' + bucket + '/key',
                     headers={'X-Amz-Meta-A': 'x:y'})
    HmacV1QueryAuth(credentials=creds, expires=3600).add_auth(req)
    parts = urlsplit(req.url)
    params = parts.query.split('&')
    assert('x-amz-meta-a=x%3Ay' in params)
    moved = ['x-amz-meta-a%3Ax=y' if p == 'x-amz-meta-a=x%3Ay' else p for p in params]
    resp = requests.put(parts._replace(query='&'.join(moved)).geturl(), data=b'moved',
                        verify=get_config_ssl_verify())
    assert(resp.status_code == 403)
    e = assert_raises(ClientError, client.head_object, Bucket=bucket, Key='key')
    assert(_get_status(e.response) == 404)

    # the URL as signed stores the value with its colon
    resp = requests.put(req.url, data=b'signed', verify=get_config_ssl_verify())
    assert(resp.status_code == 200)
    assert(client.head_object(Bucket=bucket, Key='key')['Metadata'] == {'a': 'x:y'})

@pytest.mark.auth_aws2
def test_sigv2_presigned_copy_source_moved_to_expires():
    # A presigned URL's Expires is the SigV2 date line, written as sent, and
    # its expiry is read with atoll, which stops at the first non-digit. So a
    # signed X-Amz-Copy-Source line resent inside Expires, after %0A, keeps
    # the signature and drops the copy, turning the CopyObject into a
    # PutObject of the request's body. It has to be refused.
    bucket = get_new_bucket()
    client = get_client()
    client.put_object(Bucket=bucket, Key='src', Body=b'source')
    signer = HmacV1Auth(credentials=Credentials(access_key=get_main_aws_access_key(),
                                                secret_key=get_main_aws_secret_key()))
    expires = str(int(time.time()) + 3600)
    signature = signer.sign_string('PUT\n\n\n' + expires + '\nx-amz-copy-source:' + bucket + '/src\n/' + bucket + '/dst')
    url = get_config_endpoint() + '/' + bucket + '/dst?AWSAccessKeyId=' + get_main_aws_access_key()
    sig = '&' + urlencode({'Signature': signature})
    resp = requests.put(url + '&Expires=' + expires + '%0Ax-amz-copy-source%3A' + bucket + '%2Fsrc' + sig,
                        verify=get_config_ssl_verify())
    assert(resp.status_code == 403)
    e = assert_raises(ClientError, client.head_object, Bucket=bucket, Key='dst')
    assert(_get_status(e.response) == 404)

    # the same signature with the header as signed copies the source
    resp = requests.put(url + '&Expires=' + expires + sig, headers={'X-Amz-Copy-Source': bucket + '/src'},
                        verify=get_config_ssl_verify())
    assert(resp.status_code == 200)
    assert(client.get_object(Bucket=bucket, Key='dst')['Body'].read() == b'source')

@pytest.mark.auth_aws2
def test_sigv2_presigned_upload_part_with_upload_id_packed_into_part_number():
    # The SigV2 canonical resource joins the signed sub-resources with '&'
    # and writes each url-decoded value unescaped, so partNumber=1%26uploadId%3DU
    # signs as an UploadPart's partNumber=1&uploadId=U while it names no
    # upload. It must not be served as a PutObject of the part's body.
    bucket = get_new_bucket()
    client = get_client()
    upload_id = client.create_multipart_upload(Bucket=bucket, Key='key')['UploadId']
    creds = Credentials(access_key=get_main_aws_access_key(), secret_key=get_main_aws_secret_key())
    req = AWSRequest(method='PUT', url=get_config_endpoint() + '/' + bucket + '/key?' +
                     urlencode({'partNumber': '1', 'uploadId': upload_id}))
    HmacV1QueryAuth(credentials=creds, expires=3600).add_auth(req)
    parts = urlsplit(req.url)
    pair = urlencode({'partNumber': '1', 'uploadId': upload_id})
    assert(parts.query.startswith(pair + '&'))
    packed = urlencode({'partNumber': '1&uploadId=' + upload_id}) + parts.query[len(pair):]
    resp = requests.put(parts._replace(query=packed).geturl(), data=b'packed', verify=get_config_ssl_verify())
    assert(resp.status_code in (400, 403))
    e = assert_raises(ClientError, client.head_object, Bucket=bucket, Key='key')
    assert(_get_status(e.response) == 404)

    # the URL as signed uploads the part
    resp = requests.put(req.url, data=b'part', verify=get_config_ssl_verify())
    assert(resp.status_code == 200)
    client.complete_multipart_upload(Bucket=bucket, Key='key', UploadId=upload_id,
                                     MultipartUpload={'Parts': [{'ETag': resp.headers['ETag'], 'PartNumber': 1}]})
    assert(client.get_object(Bucket=bucket, Key='key')['Body'].read() == b'part')

@pytest.mark.auth_aws2
def test_sigv2_header_put_unsigned_meta_in_query():
    # A SigV2 request signed in its Authorization header signs no query
    # parameter but the sub-resources, yet RGW's PutObject merges the query's
    # x-amz-meta-* into the object's metadata on every route. So a signed
    # PutObject resent with ?x-amz-meta-x=1 keeps its signature and gains
    # metadata its signer never signed. It must not be stored.
    bucket = get_new_bucket()
    client = get_client()
    creds = Credentials(access_key=get_main_aws_access_key(), secret_key=get_main_aws_secret_key())
    req = AWSRequest(method='PUT', url=get_config_endpoint() + '/' + bucket + '/key',
                     headers={'X-Amz-Meta-Foo': 'bar'}, data=b'body')
    HmacV1Auth(credentials=creds).add_auth(req)
    resp = requests.put(req.url + '?x-amz-meta-x=1', headers=dict(req.headers), data=b'body',
                        verify=get_config_ssl_verify())
    assert(resp.status_code == 200)
    assert(client.head_object(Bucket=bucket, Key='key')['Metadata'] == {'foo': 'bar'})


# ---------------------------------------------------------------------------
# X38: a signed request moved into an absolute-form request target must not be
# served as a different operation than the one it was signed for.
#
# The operation, bucket and key are derived from the request target, and a
# signature covers the path and query the server splits from that target. If a
# server takes the path from an absolute-form target's *query* instead of its
# path, a request signed for GetObject on bucket/key can be served as
# ListBuckets / GetBucketPolicy / GetObjectAcl / GetObjectTagging / GetUsage --
# a signature minted for one op replayed as another.
#
# These tests send the target verbatim with http.client (requests rewrites an
# absolute-form target to origin-form) and assert the security PROPERTY, not a
# status code: the response is an error, or it is the signed object's own body;
# it is never a listing, ACL, tagging, policy, location or usage document.
# ---------------------------------------------------------------------------

_X38_CANARY = b'x38-canary-object-body'

# Root elements / markers of the "other op" documents a re-target could select.
_X38_OTHER_OP_MARKERS = [
    b'<ListAllMyBucketsResult',   # ListBuckets
    b'<ListBucketResult',         # ListObjects
    b'<AccessControlPolicy',      # Get{Object,Bucket}Acl
    b'<Tagging',                  # Get{Object,Bucket}Tagging
    b'<Usage',                    # GetUsage (admin)
    b'<LocationConstraint',       # GetBucketLocation
    b'"Statement"',               # GetBucketPolicy (JSON)
]


def _x38_host_port():
    parts = urlsplit(get_config_endpoint())
    return parts.scheme, parts.hostname, (parts.port or (443 if parts.scheme == 'https' else 80))


def _x38_make_object():
    """Create a bucket + object with a distinctive canary body. Returns (bucket, key)."""
    bucket = get_new_bucket()
    client = get_client()
    key = 'x38/target'
    client.put_object(Bucket=bucket, Key=key, Body=_X38_CANARY)
    return bucket, key


def _x38_sigv4_presigned(bucket, key):
    signer = _get_s3sigv4_query_signer()
    req = AWSRequest(method='GET', url=get_config_endpoint() + '/' + bucket + '/' + key)
    signer.add_auth(req)
    return urlsplit(req.url).query, {}


def _x38_sigv4_header(bucket, key):
    signer = _get_s3sigv4_signer()
    req = AWSRequest(method='GET', url=get_config_endpoint() + '/' + bucket + '/' + key)
    signer.add_auth(req)
    return '', dict(req.headers)


def _x38_sigv2_presigned(bucket, key):
    creds = Credentials(access_key=get_main_aws_access_key(), secret_key=get_main_aws_secret_key())
    signer = HmacV1QueryAuth(credentials=creds, expires=100000)
    req = AWSRequest(method='GET', url=get_config_endpoint() + '/' + bucket + '/' + key)
    signer.add_auth(req)
    return urlsplit(req.url).query, {}


def _x38_sigv2_header(bucket, key):
    creds = Credentials(access_key=get_main_aws_access_key(), secret_key=get_main_aws_secret_key())
    signer = HmacV1Auth(credentials=creds)
    req = AWSRequest(method='GET', url=get_config_endpoint() + '/' + bucket + '/' + key)
    signer.add_auth(req)
    return '', dict(req.headers)


_X38_FORMS = {
    'sigv4_presigned': _x38_sigv4_presigned,
    'sigv2_presigned': _x38_sigv2_presigned,
    'sigv4_header': _x38_sigv4_header,
    'sigv2_header': _x38_sigv2_header,
}


def _x38_send(target, headers):
    """Send GET <target> verbatim (absolute-form) and return (status, body)."""
    scheme, host, port = _x38_host_port()
    if scheme == 'https':
        import ssl
        ctx = None if get_config_ssl_verify() else ssl._create_unverified_context()
        conn = http.client.HTTPSConnection(host, port, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port)
    try:
        conn.putrequest('GET', target, skip_host=True, skip_accept_encoding=True)
        conn.putheader('Host', host)
        for k, v in headers.items():
            if k.lower() == 'host':
                continue
            conn.putheader(k, v)
        conn.endheaders()
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def _x38_assert_property(status, body):
    """Error, or the signed object's own body -- never another op's document."""
    if status >= 400:
        return
    for marker in _X38_OTHER_OP_MARKERS:
        assert marker not in body, \
            f'retarget served a different-op document (status {status}, marker {marker!r}): {body[:200]!r}'
    assert body == _X38_CANARY, \
        f'retarget served a non-error, non-object body (status {status}): {body[:200]!r}'


@pytest.mark.auth_common
@pytest.mark.parametrize('form', list(_X38_FORMS))
@pytest.mark.parametrize('lead', ['acl', 'policy', 'tagging', 'versioning', 'usage'])
def test_x38_retarget_path_in_query_after_subresource(form, lead):
    # The signed path /bucket/key is hidden in the query behind an unsigned
    # sub-resource that would otherwise select a different op.
    bucket, key = _x38_make_object()
    _, host, _ = _x38_host_port()
    query, headers = _X38_FORMS[form](bucket, key)
    sep = '?' if query else ''
    target = 'http://%s?%s&x/%s/%s%s%s' % (host, lead, bucket, key, sep, query)
    status, body = _x38_send(target, headers)
    _x38_assert_property(status, body)


@pytest.mark.auth_common
@pytest.mark.parametrize('form', list(_X38_FORMS))
def test_x38_retarget_path_in_query_bare(form):
    # Path in the query with no leading sub-resource; read as an empty path it
    # would select ListBuckets.
    bucket, key = _x38_make_object()
    _, host, _ = _x38_host_port()
    query, headers = _X38_FORMS[form](bucket, key)
    sep = '?' if query else ''
    target = 'http://%s?/%s/%s%s%s' % (host, bucket, key, sep, query)
    status, body = _x38_send(target, headers)
    _x38_assert_property(status, body)


@pytest.mark.auth_common
@pytest.mark.parametrize('form', list(_X38_FORMS))
def test_x38_retarget_bad_percent_escape_in_path(form):
    # A malformed percent-escape in the query-hidden path must not be
    # emptied/truncated into a different op.
    bucket, key = _x38_make_object()
    _, host, _ = _x38_host_port()
    query, headers = _X38_FORMS[form](bucket, key)
    sep = '?' if query else ''
    target = 'http://%s?x/%s/%s%%zz%s%s' % (host, bucket, key, sep, query)
    status, body = _x38_send(target, headers)
    _x38_assert_property(status, body)
