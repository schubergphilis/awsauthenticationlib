#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: awsauthenticationlib.py
#
# Copyright 2020 Costas Tyfoxylos
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to
#  deal in the Software without restriction, including without limitation the
#  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
#  sell copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
#  all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
#  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
#  DEALINGS IN THE SOFTWARE.
#

"""
Main code for awsauthenticationlib.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

import json
import logging
import urllib

from dataclasses import dataclass

import botocore
import boto3
import requests

from bs4 import BeautifulSoup as Bfs

from .awsauthenticationlibexceptions import NoSigninTokenReceived, InvalidCredentials, ExpiredCredentials

__author__ = '''Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''11-03-2020'''
__copyright__ = '''Copyright 2020, Costas Tyfoxylos'''
__credits__ = ["Costas Tyfoxylos"]
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

# This is the main prefix used for logging
LOGGER_BASENAME = '''awsauthenticationlib'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())


SESSION_DURATION = 3600


@dataclass
class CookieFilter:
    """Object modeling a cookie for litering."""

    name: str
    domain: str = None
    exact_match: bool = False


@dataclass
class Domains:
    """Dataclass holding the domains required for authenticating."""

    region: str
    root: str = 'aws.amazon.com'
    sign_in: str = f'signin.{root}'
    console: str = f'console.{root}'

    @property
    def regional_console(self):
        """The domain of the regional console.

        Returns:
            regional_console (str): The regional console domain.

        """
        return f'{self.region}.console.{self.root}'


@dataclass
class Urls:
    """Dataclass holding the urls required for authenticating."""

    region: str
    scheme: str = 'https://'
    root_domain: str = 'aws.amazon.com'
    root: str = f'{scheme}{root_domain}'
    sign_in: str = f'{scheme}signin.{root_domain}'
    console: str = f'{scheme}console.{root_domain}'
    federation: str = f'{sign_in}/federation'

    @property
    def regional_console(self):
        """The url of the regional console.

        Returns:
            regional_console (str): The regional console url.

        """
        return f'{self.scheme}{self.region}.console.{self.root_domain}'

    @property
    def regional_single_sign_on(self):
        """The url of the regional single sign on.

        Returns:
            regional_single_sign_on (str): The regional single sign on url.

        """
        return f'{self.scheme}{self.region}.console.{self.root_domain}/singlesignon'

    @property
    def regional_relay_state(self):
        """The regional relay state url.

        Returns:
            relay_state (str): The regional relay state url.

        """
        return f'{self.regional_console}home?region={self.region}#'


class LoggerMixin:  # pylint: disable=too-few-public-methods
    """Logger."""

    @property
    def logger(self):
        """Exposes the logger to be used by objects using the Mixin.

        Returns:
            logger (logger): The properly named logger.

        """
        return logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')


class AwsAuthenticator(LoggerMixin):   # pylint: disable=too-many-instance-attributes
    """Interfaces with aws authentication mechanisms, providing pre signed urls, or authenticated sessions."""

    def __init__(self, arn, session_duration=None):
        self.arn = arn
        self.session_duration = session_duration if session_duration else SESSION_DURATION
        self._session = requests.Session()
        self._sts_connection = boto3.client('sts')
        self.region = self._sts_connection._client_config.region_name
        self._assumed_role = self._get_assumed_role(arn)
        self.urls = Urls(self.region)
        self.domains = Domains(self.region)

    def _get_assumed_role(self, arn):
        self.logger.debug('Trying to assume role "%s".', arn)
        try:
            return self._sts_connection.assume_role(RoleArn=arn,
                                                    RoleSessionName="AssumeRoleSession",
                                                    DurationSeconds=self.session_duration)
        except botocore.exceptions.ParamValidationError as error:
            raise ValueError('The arn you provided is incorrect: {}'.format(error)) from None
        except (botocore.exceptions.NoCredentialsError, botocore.exceptions.ClientError) as error:
            raise InvalidCredentials(error) from None

    @property
    def session_credentials(self):
        """Valid credentials for a session.

        Returns:
            credentials (dict): A properly structured dictionary of session credentials.

        """
        payload = {'sessionId': 'AccessKeyId',
                   'sessionKey': 'SecretAccessKey',
                   'sessionToken': 'SessionToken'}
        return self._get_credentials(payload)

    @property
    def assumed_role_credentials(self):
        """Valid credentials for an assumed session.

        Returns:
            credentials (dict): A properly structured dictionary of an assumed session credentials.

        """
        payload = {'aws_access_key_id': 'AccessKeyId',
                   'aws_secret_access_key': 'SecretAccessKey',
                   'aws_session_token': 'SessionToken'}
        return self._get_credentials(payload)

    def _get_credentials(self, payload):
        self.logger.debug('Getting credentials from assumed role object.')
        credentials = self._assumed_role.get('Credentials')
        self.logger.debug('Building payload.')
        payload_ = {key: credentials.get(value)
                    for key, value in payload.items()}
        return payload_

    def _get_signin_token(self):
        self.logger.debug('Trying to get signin token.')
        params = {'Action': 'getSigninToken',
                  # 'SessionDuration': str(duration),
                  'Session': json.dumps(self.session_credentials)}
        response = requests.get(self.urls.federation, params=params)
        if all([response.status_code == 401, response.text == 'Token Expired']):
            try:
                self._assumed_role = self._get_assumed_role(self.arn)
                return self._get_signin_token()
            except InvalidCredentials:
                self.logger.error('The credentials on the environment do not provide access for session refresh.')
                raise
        if response.ok:
            return response.json().get('SigninToken')
        raise NoSigninTokenReceived(response.status_code, response.text)

    def get_signed_url(self, domain='Example.com'):
        """Returns a pre signed url that is authenticated.

        Args:
            domain (str): The domain to request the session as.

        Returns:
            url (str): An authenticated pre signed url.

        """
        params = {'Action': 'login',
                  'Issuer': domain,
                  'Destination': self.urls.console,
                  'SigninToken': self._get_signin_token()}
        return f'{self.urls.federation}?{urllib.parse.urlencode(params)}'

    @staticmethod
    def _filter_cookies(cookies, filters=None):
        filters = [CookieFilter(*filter_) for filter_ in filters]
        result_cookies = []
        for filter_ in filters:
            for cookie in cookies:
                conditions = [cookie.name == filter_.name]
                if filter_.exact_match:
                    conditions.extend([filter_.domain == f'{cookie.domain}{cookie.path}'])
                elif filter_.domain:
                    conditions.extend([filter_.domain in f'{cookie.domain}{cookie.path}'])
                if all(conditions):
                    result_cookies.append(cookie)
        return result_cookies

    @staticmethod
    def _cookies_to_dict(cookies):
        return {cookie.name: cookie.value for cookie in cookies}

    @staticmethod
    def _header_cookie_from_cookies(cookies):
        return '; '.join([f'{key}={value}'
                          for key, value in AwsAuthenticator._cookies_to_dict(cookies).items()])

    @property
    def _default_headers(self):
        return {'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Encoding': 'gzip, deflate, br',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:73.0) '
                              'Gecko/20100101 Firefox/73.0'}

    @property
    def _standard_cookies(self):
        return [('aws-account-data',),
                ('aws-ubid-main',),
                ('aws-userInfo',),
                ('awsc-actm',),
                ('awsm-vid',)]

    def _get_response(self, url, extra_cookies=None, params=None):
        extra_cookies = extra_cookies or []
        cookies_to_filter = self._standard_cookies + extra_cookies
        headers = self._default_headers
        cookies = self._filter_cookies(self._session.cookies, cookies_to_filter)
        headers['Cookie'] = self._header_cookie_from_cookies(cookies)
        arguments = {'url': url,
                     'headers': headers,
                     'cookies': self._cookies_to_dict(cookies),
                     'allow_redirects': False}
        if params:
            arguments.update({'params': params})
        self.logger.debug('Getting url :%s', url)
        response = requests.get(**arguments)
        if not response.ok:
            try:
                error_response = Bfs(response.text, features='html.parser')
                error_title = error_response.title.string.strip()
                err_msg = error_response.find('div', {'id': 'content'}).find('p').string
            except AttributeError:
                raise ValueError('Response received: %s' % response.text)
            if all([response.status_code == 400, error_title == 'Credentials expired']):
                raise ExpiredCredentials(response.status_code, err_msg)
            else:
                raise ValueError('Response received: %s' % response.text)
        self._session.cookies.update(response.cookies)
        return response

    def _authenticate(self, url, domain=None):
        host = urllib.parse.urlparse(url)[1]
        filter_host = host if not domain else f'/{domain}'
        self._get_response(url, extra_cookies=[('JSESSIONID', filter_host), ('seance', filter_host)])
        hash_args = self._get_response(url,
                                       extra_cookies=[('JSESSIONID', filter_host), ('seance', filter_host)],
                                       params={'state': 'hashArgs'})
        url = hash_args.headers.get('Location')
        oauth = self._get_response(url, extra_cookies=[('aws-creds', self.domains.sign_in)])
        url = oauth.headers.get('Location')
        oauth_challenge = self._get_response(url, extra_cookies=[('JSESSIONID', host, True), ('seance', host, True)])
        url = oauth_challenge.headers.get('Location')
        response = self._get_response(url, extra_cookies=[('aws-creds', filter_host),
                                                          ('JSESSIONID', host),
                                                          ('seance', host)])
        return response

    def get_sso_authenticated_session(self):
        """Authenticates to Single Sign On and returns an authenticated session.

        Returns:
            session (requests.Session): An authenticated session with headers and cookies set.

        """
        service = 'singlesignon'
        url = f'{self.urls.regional_console}/{service}/home?region={self.region}#/dashboard'
        return self._get_authenticated_session(service, url)

    def _get_authenticated_session(self, service, url):
        """Authenticates to an AWS service and returns an authenticated session.

        Returns:
            session (requests.Session): An authenticated session with headers and cookies set.

        """
        self._get_response(self.get_signed_url(self.arn))
        dashboard = self._authenticate(url, domain=service)
        soup = Bfs(dashboard.text, features='html.parser')
        try:
            csrf_token = soup.find('meta', {'name': 'awsc-csrf-token'}).attrs.get('content')
        except AttributeError:
            raise ValueError('Response received: %s' % dashboard.text)
        session = requests.Session()
        cookies_to_filter = self._standard_cookies + [('JSESSIONID', self.domains.regional_console),
                                                      ('aws-creds', f'{self.domains.regional_console}/{service}'),
                                                      ('seance', self.domains.regional_console)]
        headers = self._default_headers
        cookies = self._filter_cookies(self._session.cookies, cookies_to_filter)
        headers['Cookie'] = self._header_cookie_from_cookies(cookies)
        headers['X-CSRF-TOKEN'] = csrf_token
        session.headers.update(headers)
        for cookie in cookies:
            session.cookies.set_cookie(cookie)
        return session
