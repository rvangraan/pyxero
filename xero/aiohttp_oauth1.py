import logging
from oauthlib.common import extract_params
from oauthlib.oauth1 import Client, SIGNATURE_HMAC, SIGNATURE_TYPE_AUTH_HEADER
from oauthlib.oauth1 import SIGNATURE_TYPE_BODY
from aiohttp import request
import yarl
from collections import namedtuple

response = namedtuple('response', ['data', 'status_code', 'headers', 'encoding'])


CONTENT_TYPE_FORM_URLENCODED = 'application/x-www-form-urlencoded'
CONTENT_TYPE_MULTI_PART = 'multipart/form-data'

log = logging.getLogger(__name__)


class OAuth1:
    """Signs the asyncio request using OAuth 1 (RFC5849)"""

    client_class = Client

    def __init__(
            self, client_key,
            client_secret=None,
            resource_owner_key=None,
            resource_owner_secret=None,
            callback_uri=None,
            signature_method=SIGNATURE_HMAC,
            signature_type=SIGNATURE_TYPE_AUTH_HEADER,
            rsa_key=None, verifier=None,
            decoding=None,
            client_class=None,
            force_include_body=False,
            **kwargs):

        try:
            signature_type = signature_type.upper()
        except AttributeError:
            pass

        client_class = client_class or self.client_class

        self.force_include_body = force_include_body

        self.client = client_class(client_key, client_secret, resource_owner_key,
            resource_owner_secret, callback_uri, signature_method,
            signature_type, rsa_key, verifier, decoding=decoding, **kwargs)

    def sign(self, url, method, body, headers):
        """Returns the url, headers and body inc. the oauth1 stuff

        Parameters may be included from the body if the content-type is
        urlencoded, if no content type is set a guess is made.
        """
        content_type = headers.get('Content-Type', '')
        if (not content_type and extract_params(body)
                or self.client.signature_type == SIGNATURE_TYPE_BODY):
            content_type = CONTENT_TYPE_FORM_URLENCODED

        is_form_encoded = (CONTENT_TYPE_FORM_URLENCODED in content_type)

        log.debug('Including body in call to sign: %s',
                  is_form_encoded or self.force_include_body)

        if is_form_encoded:
            headers['Content-Type'] = CONTENT_TYPE_FORM_URLENCODED
            url, headers, body = self.client.sign(
                url, method, body or '', headers
            )
        elif self.force_include_body:
            # To allow custom clients to work on non form encoded bodies.
            url, headers, body = self.client.sign(
                url, method, body or '', headers
            )
        else:
            # Omit body data in the signing of non form-encoded requests
            url, headers, _ = self.client.sign(
                url, method, None, headers
            )

        return url, body, headers


async def make_authed_request(
        url, method, oauth_client, params=None, body=None, headers=None, **kwargs
):
    if params:
        url_for_signing = str(yarl.URL(url).with_query(sorted(params.items())))
    else:
        url_for_signing = url

    _, body, headers = oauth_client.sign(url_for_signing, method, body, headers)

    async with request(method, url, params=params, headers=headers, data=body, **kwargs) as res:
        if res.headers['content-type'].startswith('application/json') or \
           res.headers['content-type'].startswith('text/html'):
            data = await res.text()
        elif res.status == 200:
            data = await res.read()
        else:
            data = await res.text()

        return response(
            data=data,
            status_code=res.status,
            headers=res.headers,
            encoding=res.charset,
        )
