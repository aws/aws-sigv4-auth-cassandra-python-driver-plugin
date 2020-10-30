# AWS SigV4 Auth Cassandra Python Driver 4.x Plugin
# %%
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# %%
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import hashlib
import hmac
from datetime import datetime

import six

from six.moves.urllib.parse import quote_plus
from boto3 import Session
from cassandra.auth import AuthProvider, Authenticator


def _ensure_b(data):
    return six.ensure_binary(data, encoding="utf-8")


_SIGV4_INITIAL_RESPONSE = _ensure_b("SigV4\0\0")
_NONCE_KEY = _ensure_b("nonce=")
_NONCE_LENGTH = 32
_CANONICAL_SERVICE = "cassandra"
_SIGV4_DATESTAMP_FORMAT = "%Y%m%d"
_SIGV4_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S"
_AWS4_SIGNING_ALGORITHM = "AWS4-HMAC-SHA256"
_AMZ_ALGO_HEADER = "X-Amz-Algorithm=" + _AWS4_SIGNING_ALGORITHM
_AMZ_EXPIRES_HEADER = "X-Amz-Expires=900"


class SigV4AuthProvider(AuthProvider):

    def __init__(self, session=None, aws_access_key_id=None, aws_secret_access_key=None,
                 aws_session_token=None, region_name=None):
        if not session:
            self.session = Session(aws_access_key_id=aws_access_key_id,
                                   aws_secret_access_key=aws_secret_access_key,
                                   aws_session_token=aws_session_token, region_name=region_name)
        else:
            self.session = session

    def new_authenticator(self, host):
        return SigV4Authenticator(self.session)


class SigV4Authenticator(Authenticator):

    def __init__(self, session):
        self.session = session
        session.get_credentials()
        if not self.session.region_name:
            raise ValueError("Can't authenticate without a region name")

    def initial_response(self):
        return _SIGV4_INITIAL_RESPONSE

    def evaluate_challenge(self, challenge):
        challenge = _ensure_b(challenge)
        nonce = _extract_nonce(challenge)
        request_timestamp = datetime.utcnow()
        credentials = self.session.get_credentials()
        signature = _generate_signature(nonce, request_timestamp, credentials,
                                        self.session.region_name)
        response = "signature={0},access_key={1},amzdate={2}".format(signature,
                                                                     credentials.access_key,
                                                                     _format_timestamp(
                                                                         request_timestamp))

        if credentials.token:
            response += ",session_token={0}".format(credentials.token)
        return response


def _extract_nonce(challenge):
    try:
        nonce_start = challenge.index(_NONCE_KEY) + len(_NONCE_KEY)
        nonce_end = nonce_start + _NONCE_LENGTH
    except Exception as e:
        raise ValueError("Couldn't extract nonce from challenge, {0}".format(e))
    return challenge[nonce_start:nonce_end]


def _format_timestamp(date_time):
    return "{0}.{1:03d}Z".format(date_time.strftime(_SIGV4_TIMESTAMP_FORMAT),
                                 int(round(date_time.microsecond / 1000)))


def _format_datestamp(date_time):
    return date_time.strftime(_SIGV4_DATESTAMP_FORMAT)


def _generate_scope(credentials_scope_date, region):
    return "{0}/{1}/{2}/aws4_request".format(credentials_scope_date, region, _CANONICAL_SERVICE)


def _generate_signature(nonce, request_timestamp, credentials, region):
    credentials_scope_date = _format_datestamp(request_timestamp)
    signing_scope = _generate_scope(credentials_scope_date, region)
    canonical_request = _generate_canonical_request(credentials.access_key, signing_scope,
                                                    request_timestamp, nonce)

    string_to_sign = "{0}\n{1}\n{2}\n{3}".format(_AWS4_SIGNING_ALGORITHM,
                                                 _format_timestamp(request_timestamp),
                                                 signing_scope,
                                                 _sha_256_hash(canonical_request))

    signing_key = _generate_signing_key(credentials.secret_key, credentials_scope_date, region,
                                        _CANONICAL_SERVICE)

    return _sha_256_hmac(signing_key, string_to_sign, hex_result=True)


def _generate_signing_key(key, date_stamp, region, service):
    secret = six.ensure_str("AWS4" + key, encoding="utf-8")
    k_date = _sha_256_hmac(secret, date_stamp)
    k_region = _sha_256_hmac(k_date, region)
    k_service = _sha_256_hmac(k_region, service)
    k_signing = _sha_256_hmac(k_service, 'aws4_request')
    return k_signing


def _generate_canonical_request(access_key_id, signing_scope, request_timestamp, nonce):
    headers = [_AMZ_ALGO_HEADER, _create_credential_header(access_key_id, signing_scope),
               "X-Amz-Date={0}".format(quote_plus(_format_timestamp(request_timestamp))),
               _AMZ_EXPIRES_HEADER]
    headers.sort()
    query_string = "&".join(headers)
    return "PUT\n/authenticate\n{0}\nhost:{1}\n\nhost\n{2}".format(query_string, _CANONICAL_SERVICE,
                                                                   _sha_256_hash(nonce))


def _create_credential_header(access_key_id, signing_scope):
    return "X-Amz-Credential={0}%2F{1}".format(access_key_id, quote_plus(signing_scope))


def _sha_256_hash(data):
    try:
        hasher = hashlib.sha256()
        hasher.update(_ensure_b(data))
        return hasher.hexdigest()
    except Exception as e:
        raise RuntimeError("Couldn't generate sha256 hash, {}".format(e))


def _sha_256_hmac(key, msg, hex_result=False):
    if hex_result:
        sig = hmac.new(_ensure_b(key), _ensure_b(msg), hashlib.sha256).hexdigest()
    else:
        sig = hmac.new(_ensure_b(key), _ensure_b(msg), hashlib.sha256).digest()
    return sig
