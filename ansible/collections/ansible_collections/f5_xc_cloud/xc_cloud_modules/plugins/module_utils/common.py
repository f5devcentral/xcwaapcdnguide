# -*- coding: utf-8 -*-
#
# Copyright (c) 2017 F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import re
from ansible.module_utils.basic import env_fallback
from ansible.module_utils.six import iteritems
from collections import defaultdict
 # Namespace regex removed; server-side validation will be used
from .exceptions import F5ModuleError, XcValidationError


class AnsibleF5Parameters(object):
    def __init__(self, *args, **kwargs):
        self._values = defaultdict(lambda: None)
        self._values['__warnings'] = []
        self.client = kwargs.pop('client', None)
        self._module = kwargs.pop('module', None)
        self._params = {}

        params = kwargs.pop('params', None)
        if params:
            self.update(params=params)
            self._params.update(params)

    def update(self, params=None):
        if params:
            self._params.update(params)
            for k, v in iteritems(params):
                # Adding this here because ``username`` is a connection parameter
                # and in cases where it is also an API parameter, we run the risk
                # of overriding the specified parameter with the connection parameter.
                #
                # Since this is a problem, and since "username" is never a valid
                # parameter outside its usage in connection params (where we do not
                # use the ApiParameter or ModuleParameters classes) it is safe to
                # skip over it if it is provided.
                if k == 'password':
                    continue
                if k == 'api_token':
                    continue
                if self.api_map is not None and k in self.api_map:
                    map_key = self.api_map[k]
                else:
                    map_key = k

                # Handle weird API parameters like `dns.proxy.__iter__` by
                # using a map provided by the module developer
                class_attr = getattr(type(self), map_key, None)
                if isinstance(class_attr, property):
                    # There is a mapped value for the api_map key
                    if class_attr.fset is None:
                        # If the mapped value does not have
                        # an associated setter
                        self._values[map_key] = v
                    else:
                        # The mapped value has a setter
                        setattr(self, map_key, v)
                else:
                    # If the mapped value is not a @property
                    self._values[map_key] = v

    def api_params(self):
        result = {}
        for api_attribute in self.api_attributes:
            if self.api_map is not None and api_attribute in self.api_map:
                result[api_attribute] = getattr(self, self.api_map[api_attribute])
            else:
                result[api_attribute] = getattr(self, api_attribute)
        result = self._filter_params(result)
        return result

    def __getattr__(self, item):
        # Ensures that properties that weren't defined, and therefore stashed
        # in the `_values` dict, will be retrievable.
        return self._values[item]

    def _filter_params(self, params):
        return dict((k, v) for k, v in iteritems(params) if v is not None)


def validate_domain(domain):
    """Domain validation disabled; defer to server-side checks."""
    if not domain:
        raise XcValidationError("Domain cannot be empty")
    return True


def validate_namespace(namespace):
    """Namespace validation simplified; only ensure non-empty."""
    if not namespace:
        raise XcValidationError("Namespace cannot be empty")
    return True


def sanitize_name(name):
    """Sanitize resource names for F5 XC."""
    if not name:
        return name
    # Remove invalid characters and convert to lowercase
    sanitized = re.sub(r'[^a-z0-9-]', '-', name.lower())
    # Remove leading/trailing hyphens and collapse multiple hyphens
    sanitized = re.sub(r'^-+|-+$', '', sanitized)
    sanitized = re.sub(r'-+', '-', sanitized)
    return sanitized


class F5ModuleError(Exception):
    pass


f5_provider_spec = {
    'tenant': dict(
        default='console.ves.volterra.io',
        fallback=(env_fallback, ['XC_TENANT'])
    ),
    'api_token': dict(
        required=True,
        no_log=True,  # Prevent token from being logged
        fallback=(env_fallback, ['XC_API_TOKEN'])
    ),
    'validate_certs': dict(
        type='bool',
        default=True,  # Changed to True for better security
        fallback=(env_fallback, ['VALIDATE_CERTS'])
    ),
    'timeout': dict(
        type='int',
        default=120,
        fallback=(env_fallback, ['XC_TIMEOUT'])
    ),
}

f5_argument_spec = {
    'provider': dict(type='dict', options=f5_provider_spec),
}
