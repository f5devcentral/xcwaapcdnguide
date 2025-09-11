# -*- coding: utf-8 -*-
#
# Copyright (c) 2020 F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import os
import time
import sys
import logging
import warnings
from functools import wraps
from ..module_utils.constants import BASE_HEADERS, RETRY_CODES, MAX_RETRIES, BACKOFF_FACTOR
from ..module_utils.exceptions import XcApiError, XcAuthError, XcTimeoutError, XcValidationError

from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible.module_utils.urls import Request

try:
    from ansible.utils.display import Display
    display = Display()
except ImportError:
    display = None

try:
    import json as _json
except ImportError:
    import simplejson as _json


def _debug_log(message):
    """Helper function to log debug messages that will be visible in Ansible output."""
    if os.environ.get('XC_DEBUG', '').lower() in ['true', '1', 'yes']:
        # Store debug messages in a global list for later retrieval
        if not hasattr(_debug_log, 'messages'):
            _debug_log.messages = []
        _debug_log.messages.append(f"[XC_DEBUG] {message}")
        
        # Use stderr directly to support proper newlines
        debug_msg = f"XC_DEBUG: {message}"
        sys.stderr.write(f"{debug_msg}\n")
        sys.stderr.flush()


def get_debug_messages():
    """Get all collected debug messages"""
    if hasattr(_debug_log, 'messages'):
        return _debug_log.messages.copy()
    return []


def clear_debug_messages():
    """Clear all collected debug messages"""
    if hasattr(_debug_log, 'messages'):
        _debug_log.messages.clear()


def retry_on_exception(max_retries=MAX_RETRIES, backoff_factor=BACKOFF_FACTOR):
    """Decorator for retrying failed requests with exponential backoff."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except HTTPError as e:
                    if e.code in RETRY_CODES and attempt < max_retries - 1:
                        wait_time = backoff_factor ** attempt
                        logging.warning(f"Request failed with {e.code}, retrying in {wait_time}s (attempt {attempt + 1}/{max_retries})")
                        time.sleep(wait_time)
                        continue
                    raise XcApiError(f"API request failed: {e.reason}", status_code=e.code, response=e)
                except Exception as e:
                    if attempt < max_retries - 1:
                        wait_time = backoff_factor ** attempt
                        logging.warning(f"Request failed with {str(e)}, retrying in {wait_time}s (attempt {attempt + 1}/{max_retries})")
                        time.sleep(wait_time)
                        continue
                    raise
            return func(*args, **kwargs)
        return wrapper
    return decorator


class XcRestClient(object):
    def __init__(self, *args, **kwargs):
        self.params = kwargs
        self.module = kwargs.get('module', None)
        self.provider = self.params.get('provider', None)
        self.api_token = self.merge_provider_api_token_param(self.provider)
        self.tenant = self.merge_provider_tenant_param(self.provider)
        
        # Debug logging
        _debug_log(f"Initializing F5 XC client for tenant: {self.tenant}")
        _debug_log(f"API token configured: {'Yes' if self.api_token else 'No'}")
        
        # Validate required parameters
        if not self.api_token:
            raise XcValidationError("API token is required. Set via provider or XC_API_TOKEN environment variable")
        if not self.tenant:
            raise XcValidationError("Tenant is required. Set via provider or XC_TENANT environment variable")

    @staticmethod
    def validate_params(key, store):
        if store and key in store and store[key] is not None:
            return True
        else:
            return False

    def merge_provider_api_token_param(self, provider):
        result = None
        if self.validate_params('api_token', provider):
            result = provider['api_token']
        elif self.validate_params('XC_API_TOKEN', os.environ):
            result = os.environ.get('XC_API_TOKEN')
        return result

    def merge_provider_tenant_param(self, provider):
        result = None
        if self.validate_params('tenant', provider):
            result = provider['tenant']
        elif self.validate_params('XC_TENANT', os.environ):
            result = os.environ.get('XC_TENANT')
        return result

    @property
    def api(self):
        return RestApi(
            headers={"Authorization": "APIToken {0}".format(self.api_token)},
            host=self.tenant
        )


class RestApi(object):
    def __init__(self, headers=None, use_proxy=True, force=False, timeout=120,
                 validate_certs=True, url_username=None, url_password=None,
                 http_agent=None, force_basic_auth=False, follow_redirects='urllib2',
                 client_cert=None, client_key=None, cookies=None, host=None):
        self.request = Request(
            headers=headers,
            use_proxy=use_proxy,
            force=force,
            timeout=timeout,
            validate_certs=validate_certs,
            url_username=url_username,
            url_password=url_password,
            http_agent=http_agent,
            force_basic_auth=force_basic_auth,
            follow_redirects=follow_redirects,
            client_cert=client_cert,
            client_key=client_key,
            cookies=cookies
        )
        self.last_url = None
        self.host = host

    def get_headers(self, result):
        try:
            return dict(result.getheaders())
        except AttributeError:
            return result.headers

    def update_response(self, response, result):
        response.headers = self.get_headers(result)
        response._content = result.read()
        response.status = result.getcode()
        response.url = result.geturl()
        response.msg = "OK (%s bytes)" % response.headers.get('Content-Length', 'unknown')

    def send(self, method, url, **kwargs):
        response = Response()

        self.last_url = url

        body = None
        data = kwargs.pop('data', None)
        json = kwargs.pop('json', None)

        if not data and json is not None:
            self.request.headers.update(BASE_HEADERS)
            body = _json.dumps(json)
            if not isinstance(body, bytes):
                body = body.encode('utf-8')
        if data:
            body = data
        if body:
            kwargs['data'] = body

        # Debug logging
        _debug_log(f"Making API call: {method} {url}")
        if json:
            formatted_json = _json.dumps(json, indent=2)
            _debug_log(f"Request body:\n{formatted_json}")
        elif body:
            _debug_log(f"Request data: {body}")

        try:
            result = self.request.open(method, url, **kwargs)
        except HTTPError as e:
            _debug_log(f"HTTP Error {e.code}: {e.reason}")
            # Enhanced error handling with proper exceptions
            if e.code == 401:
                raise XcAuthError(f"Authentication failed: {e.reason}", status_code=e.code)
            elif e.code == 403:
                raise XcAuthError(f"Access forbidden: {e.reason}", status_code=e.code)
            elif e.code >= 500:
                # Read the response body for server errors
                error_body = e.read().decode('utf-8') if hasattr(e, 'read') else 'No response body'
                raise XcApiError(f"Server error {e.code}: {e.reason}. Response: {error_body}", status_code=e.code)
            else:
                # For other errors, update response and return
                self.update_response(response, e)
                _debug_log(f"Response status: {response.status}")
                try:
                    error_json = response.json()
                    if error_json is None:
                        _debug_log(f"Error response: null")
                    else:
                        formatted_error = _json.dumps(error_json, indent=2)
                        _debug_log(f"Error response:\n{formatted_error}")
                except (ValueError, TypeError):
                    _debug_log(f"Error response content: {response.content}")
                return response

        self.update_response(response, result)
        
        _debug_log(f"Response status: {response.status}")
        try:
            response_json = response.json()
            if response_json is None:
                _debug_log(f"Response data: null")
            else:
                formatted_response = _json.dumps(response_json, indent=2)
                _debug_log(f"Response data:\n{formatted_response}")
        except (ValueError, TypeError) as e:
            _debug_log(f"Response content: {response.content}")
            _debug_log(f"JSON parse error: {e}")
        
        return response

    @retry_on_exception()
    def delete(self, url, **kwargs):
        return self.send('DELETE', f"https://{self.host}{url}", **kwargs)

    @retry_on_exception()
    def get(self, url, **kwargs):
        return self.send('GET', f"https://{self.host}{url}", **kwargs)

    @retry_on_exception()
    def patch(self, url, data=None, **kwargs):
        return self.send('PATCH', f"https://{self.host}{url}", data=data, **kwargs)

    @retry_on_exception()
    def post(self, url, data=None, **kwargs):
        return self.send('POST', f"https://{self.host}{url}", data=data, **kwargs)

    @retry_on_exception()
    def put(self, url, data=None, **kwargs):
        return self.send('PUT', f"https://{self.host}{url}", data=data, **kwargs)


class Response(object):
    def __init__(self):
        self._content = None
        self.status = None
        self.headers = dict()
        self.url = None
        self.reason = None
        self.request = None
        self.msg = None

    @property
    def content(self):
        return self._content

    @property
    def raw_content(self):
        return self._content

    def json(self):
        return _json.loads(self._content or 'null')

    @property
    def ok(self):
        if self.status is not None and int(self.status) > 400:
            return False
        try:
            response = self.json()
            if response and 'code' in response and response['code'] > 400:
                return False
        except (ValueError, TypeError):
            pass
        return True

    # Provide compatibility with code expecting 'status_code'
    @property
    def status_code(self):
        return self.status

    @status_code.setter
    def status_code(self, value):
        self.status = value
