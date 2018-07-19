import unittest

from datetime import datetime, timedelta
from mock import Mock

from xero.auth import make_public_credentials, make_partner_credentials, PublicCredentials
from xero.exceptions import XeroException, XeroNotVerified, XeroUnauthorized
from asynctest import patch
from asyncio import get_event_loop


class PublicCredentialsTest(unittest.TestCase):
    def setUp(self):
        self.loop = get_event_loop()

    @patch('xero.auth.make_authed_request')
    def test_initial_constructor(self, make_authed_request):
        "Initial construction causes a requst to get a request token"
        make_authed_request.return_value = Mock(
            status_code=200,
            data='oauth_token=token&oauth_token_secret=token_secret'
        )

        credentials = self.loop.run_until_complete(
            make_public_credentials(
                consumer_key='key',
                consumer_secret='secret',
                scope='payroll.endpoint'
            )
        )

        # A HTTP request was made
        self.assertTrue(make_authed_request.called)

        state = credentials.state

        # Expiry times should be calculated
        self.assertIsNotNone(state.pop("oauth_authorization_expires_at"))
        self.assertIsNotNone(state.pop("oauth_expires_at"))

        self.assertEqual(state, {
            'consumer_key': 'key',
            'consumer_secret': 'secret',
            'oauth_token': 'token',
            'oauth_token_secret': 'token_secret',
            'verified': False,
            'scope': 'payroll.endpoint'
        })

    @patch('xero.auth.make_authed_request')
    def test_bad_credentials(self, make_authed_request):
        "Initial construction with bad credentials raises an exception"
        make_authed_request.return_value = Mock(
            status_code=401,
            data='oauth_problem=consumer_key_unknown&oauth_problem_advice=Consumer%20key%20was%20not%20recognised'
        )

        with self.assertRaises(XeroUnauthorized):
            self.loop.run_until_complete(
                make_public_credentials(
                    consumer_key='unknown',
                    consumer_secret='unknown'
                )
            )

    @patch('xero.auth.make_authed_request')
    def test_unvalidated_constructor(self, make_authed_request):
        "Credentials with an unverified request token can be constructed"
        credentials = self.loop.run_until_complete(
            make_public_credentials(
                consumer_key='key',
                consumer_secret='secret',
                oauth_token='token',
                oauth_token_secret='token_secret',
            )
        )

        self.assertEqual(credentials.state, {
            'consumer_key': 'key',
            'consumer_secret': 'secret',
            'oauth_token': 'token',
            'oauth_token_secret': 'token_secret',
            'verified': False
        })

        # No HTTP requests were made
        self.assertFalse(make_authed_request.called)

    @patch('xero.auth.make_authed_request')
    def test_validated_constructor(self, make_authed_request):
        "A validated set of credentials can be reconstructed"
        credentials = self.loop.run_until_complete(
            make_public_credentials(
                consumer_key='key',
                consumer_secret='secret',
                oauth_token='validated_token',
                oauth_token_secret='validated_token_secret',
                verified=True
            )
        )

        self.assertEqual(credentials.state, {
            'consumer_key': 'key',
            'consumer_secret': 'secret',
            'oauth_token': 'validated_token',
            'oauth_token_secret': 'validated_token_secret',
            'verified': True
        })

        try:
            credentials.oauth
        except XeroNotVerified:
            self.fail('Credentials should have been verified')

        # No HTTP requests were made
        self.assertFalse(make_authed_request.called)

    @patch('xero.auth.make_authed_request')
    def test_url(self, make_authed_request):
        "The request token URL can be obtained"
        make_authed_request.return_value = Mock(
            status_code=200,
            data='oauth_token=token&oauth_token_secret=token_secret'
        )

        credentials = self.loop.run_until_complete(
            make_public_credentials(
                consumer_key='key',
                consumer_secret='secret'
            )
        )

        self.assertEqual(credentials.url, 'https://api.xero.com/oauth/Authorize?oauth_token=token')

    @patch('xero.auth.make_authed_request')
    def test_url_with_scope(self, make_authed_request):
        "The request token URL includes the scope parameter"
        make_authed_request.return_value = Mock(
            status_code=200,
            data='oauth_token=token&oauth_token_secret=token_secret'
        )

        credentials = self.loop.run_until_complete(
            make_public_credentials(
                consumer_key='key',
                consumer_secret='secret',
                scope="payroll.endpoint"
            )
        )

        self.assertIn('scope=payroll.endpoint', credentials.url)

    @patch('xero.auth.make_authed_request')
    def test_verify(self, make_authed_request):
        "Unverfied credentials can be verified"
        make_authed_request.return_value = Mock(
            status_code=200,
            data='oauth_token=verified_token&oauth_token_secret=verified_token_secret'
        )

        credentials = self.loop.run_until_complete(
            make_public_credentials(
                consumer_key='key',
                consumer_secret='secret',
                oauth_token='token',
                oauth_token_secret='token_secret',
            )
        )

        self.loop.run_until_complete(
            credentials.verify('verifier')
        )

        # A HTTP request was made
        self.assertTrue(make_authed_request.called)

        state = credentials.state

        # Expiry times should be calculated
        self.assertIsNotNone(state.pop("oauth_authorization_expires_at"))
        self.assertIsNotNone(state.pop("oauth_expires_at"))

        self.assertEqual(state, {
            'consumer_key': 'key',
            'consumer_secret': 'secret',
            'oauth_token': 'verified_token',
            'oauth_token_secret': 'verified_token_secret',
            'verified': True
        })

        try:
            credentials.oauth
        except XeroNotVerified:
            self.fail('Credentials should have been verified')

    @patch('xero.auth.make_authed_request')
    def test_verify_failure(self, make_authed_request):
        "If verification credentials are bad, an error is raised"
        make_authed_request.return_value = Mock(
            status_code=401,
            data='oauth_problem=bad_verifier&oauth_problem_advice=The consumer was denied access to this resource.'
        )

        credentials = self.loop.run_until_complete(
            make_public_credentials(
                consumer_key='key',
                consumer_secret='secret',
                oauth_token='token',
                oauth_token_secret='token_secret',
            )
        )

        with self.assertRaises(XeroUnauthorized):
            self.loop.run_until_complete(
                credentials.verify('badverifier')
            )

        with self.assertRaises(XeroNotVerified):
            credentials.oauth

    def test_expired(self):
        "Expired credentials are correctly detected"
        now = datetime(2014, 1, 1, 12, 0, 0)
        soon = now + timedelta(minutes=30)

        credentials = PublicCredentials(
            consumer_key='key',
            consumer_secret='secret',
            oauth_token='token',
            oauth_token_secret='token_secret',
        )

        # At this point, oauth_expires_at isn't set
        with self.assertRaises(XeroException):
            credentials.expired(now)

        # Not yet expired
        credentials.oauth_expires_at = soon
        self.assertFalse(credentials.expired(now=now))

        # Expired
        self.assertTrue(credentials.expired(now=soon))


class PartnerCredentialsTest(unittest.TestCase):
    def setUp(self):
        self.loop = get_event_loop()

    @patch('xero.auth.make_authed_request')
    def test_initial_constructor(self, make_authed_request):
        "Initial construction causes a request to get a request token"
        make_authed_request.return_value = Mock(
            status_code=200,
            data='oauth_token=token&oauth_token_secret=token_secret'
        )

        credentials = self.loop.run_until_complete(
            make_partner_credentials(
                consumer_key='key',
                consumer_secret='secret',
                rsa_key='abc',
                scope='payroll.endpoint'
            )
        )

        # A HTTP request was made
        self.assertTrue(make_authed_request.called)

        state = credentials.state

        # Expiry times should be calculated
        self.assertIsNotNone(state.pop("oauth_authorization_expires_at"))
        self.assertIsNotNone(state.pop("oauth_expires_at"))

        self.assertEqual(state, {
            'consumer_key': 'key',
            'consumer_secret': 'secret',
            'oauth_token': 'token',
            'oauth_token_secret': 'token_secret',
            'verified': False,
            'scope': 'payroll.endpoint'
        })

    @patch('xero.auth.make_authed_request')
    def test_refresh(self, make_authed_request):
        "Refresh function gets a new token"
        make_authed_request.return_value = Mock(
            status_code=200,
            data='oauth_token=token2&oauth_token_secret=token_secret2&oauth_session_handle=session'
        )

        credentials = self.loop.run_until_complete(
            make_partner_credentials(
                consumer_key='key',
                consumer_secret='secret',
                rsa_key="key",
                oauth_token='token',
                oauth_token_secret='token_secret',
                verified=True
            )
        )

        self.loop.run_until_complete(
            credentials.refresh()
        )

        # Expiry times should be calculated
        state = credentials.state
        self.assertIsNotNone(state.pop("oauth_authorization_expires_at"))
        self.assertIsNotNone(state.pop("oauth_expires_at"))

        self.assertEqual(state, {
            'consumer_key': 'key',
            'consumer_secret': 'secret',
            'oauth_token': 'token2',
            'oauth_token_secret': 'token_secret2',
            'oauth_session_handle': 'session',
            'verified': True
        })
