# -*- coding: utf-8 -*-
#
# Copyright (c) 2020 F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


class F5ModuleError(Exception):
    """Base exception for F5 XC module errors."""
    pass


class XcApiError(F5ModuleError):
    """Exception for F5 XC API-related errors."""
    def __init__(self, message, status_code=None, response=None):
        super(XcApiError, self).__init__(message)
        self.status_code = status_code
        self.response = response


class XcAuthError(XcApiError):
    """Exception for authentication/authorization errors."""
    pass


class XcConfigError(F5ModuleError):
    """Exception for configuration validation errors."""
    pass


class XcTimeoutError(F5ModuleError):
    """Exception for timeout-related errors."""
    pass


class XcValidationError(F5ModuleError):
    """Exception for input validation errors."""
    pass
