# -*- coding: utf-8 -*-
#
# Copyright (c) 2020 F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
F5 Distributed Cloud Ansible Module Utilities

This package provides common utilities for F5 XC Ansible modules.
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

# Core client and base classes
from .client import XcRestClient, RestApi, Response
from .common import AnsibleF5Parameters, F5ModuleError, f5_argument_spec, f5_provider_spec
from .common import validate_domain, validate_namespace, sanitize_name

# Exception classes
from .exceptions import (
    XcApiError, XcAuthError, XcConfigError, 
    XcTimeoutError, XcValidationError
)

# Utility functions
from .utils import (
    wait_for_state, poll_for_completion, format_api_url,
    safe_get, deep_merge, normalize_response
)

# Constants
from .constants import (
    BASE_HEADERS, MAX_RETRIES, BACKOFF_FACTOR, RETRY_CODES,
    DEFAULT_TIMEOUT, LONG_OPERATION_TIMEOUT,
    DOMAIN_REGEX, NAMESPACE_REGEX
)

__all__ = [
    # Core classes
    'XcRestClient', 'RestApi', 'Response', 'AnsibleF5Parameters',
    
    # Exceptions
    'F5ModuleError', 'XcApiError', 'XcAuthError', 'XcConfigError',
    'XcTimeoutError', 'XcValidationError',
    
    # Utility functions
    'validate_domain', 'validate_namespace', 'sanitize_name',
    'wait_for_state', 'poll_for_completion', 'format_api_url',
    'safe_get', 'deep_merge', 'normalize_response',
    
    # Configuration
    'f5_argument_spec', 'f5_provider_spec',
    
    # Constants
    'BASE_HEADERS', 'MAX_RETRIES', 'BACKOFF_FACTOR', 'RETRY_CODES',
    'DEFAULT_TIMEOUT', 'LONG_OPERATION_TIMEOUT',
    'DOMAIN_REGEX', 'NAMESPACE_REGEX'
]