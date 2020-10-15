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

import codecs
import unittest
import mock

import six

from datetime import datetime

from botocore.credentials import Credentials

from cassandra_sigv4.auth import _extract_nonce, _generate_signature, _generate_canonical_request, \
    _generate_signing_key, \
    _format_datestamp, _generate_scope, SigV4AuthProvider

_test_timestamp = datetime(year=2020, month=6, day=9, hour=22, minute=41, second=51)
_test_nonce = "91703fdc2ef562e19fbdab0f58e42fe5"
_test_credentials = Credentials(access_key="UserID-1", secret_key="UserSecretKey-1")
_test_region = "us-west-2"
_test_service = "cassandra"


class HelperMethodTests(unittest.TestCase):

    @mock.patch('cassandra_sigv4.auth.datetime')
    def test_full_authorization(self, mock_dt):
        mock_dt.utcnow.return_value = _test_timestamp
        expected_inital = six.ensure_binary("SigV4\0\0", encoding="utf-8")
        expected_signed = "signature=7f3691c18a81b8ce7457699effbfae5b09b4e0714ab38c1292dbdf082c9ddd87,access_key=UserID-1,amzdate=2020-06-09T22:41:51.000Z"

        provider = SigV4AuthProvider(aws_access_key_id=_test_credentials.access_key,
                                     aws_secret_access_key=_test_credentials.secret_key,
                                     region_name="us-west-2")

        authenticator = provider.new_authenticator(None)
        inital_response = authenticator.initial_response()
        signed_response = authenticator.evaluate_challenge(
            "garbage nonce={0} garbage".format(_test_nonce))

        self.assertEqual(expected_inital, inital_response)
        self.assertEqual(expected_signed, signed_response)

    def test_extract_nonce(self):
        test_nonce = "12345678901234567890123456789012"
        test_challange = six.ensure_binary("notpart_nonce={test_nonce}not_part".format(**locals()),
                                           'utf-8')
        test_nonce_binary = six.ensure_binary(test_nonce, 'utf-8')

        result = _extract_nonce(test_challange)

        self.assertEqual(test_nonce_binary, result)

    def test_generate_signature(self):
        expected = "7f3691c18a81b8ce7457699effbfae5b09b4e0714ab38c1292dbdf082c9ddd87"

        result = _generate_signature(_test_nonce, _test_timestamp, _test_credentials, _test_region)

        self.assertEqual(expected, result)

    def test_canonicalize_request(self):
        scope = "20200609/us-west-2/cassandra/aws4_request"
        expected = "PUT\n" \
                   "/authenticate\n" \
                   "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=UserID-1%2F20200609%2Fus-west-2%2Fcassandra%2Faws4_request&X-Amz-Date=2020-06-09T22%3A41%3A51.000Z&X-Amz-Expires=900\n" \
                   "host:cassandra\n\n" \
                   "host\n" \
                   "ddf250111597b3f35e51e649f59e3f8b30ff5b247166d709dc1b1e60bd927070"

        result = _generate_canonical_request(_test_credentials.access_key, scope, _test_timestamp,
                                             _test_nonce)

        self.assertEqual(expected, result)

    def test_generate_signing_key(self):
        expected = codecs.decode("7fb139473f153aec1b05747b0cd5cd77a1186d22ae895a3a0128e699d72e1aba",
                                 'hex_codec')
        date_stamp = _format_datestamp(_test_timestamp)

        result = _generate_signing_key(_test_credentials.secret_key, date_stamp, _test_region,
                                       _test_service)

        self.assertEqual(expected, result)

    def test_generate_scope(self):
        expected = "20200609/us-west-2/cassandra/aws4_request"
        date_stamp = _format_datestamp(_test_timestamp)

        result = _generate_scope(date_stamp, _test_region)

        self.assertEqual(expected, result)


if __name__ == '__main__':
    unittest.main()
