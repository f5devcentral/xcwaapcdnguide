#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: origin_pool_info
short_description: Gather information about F5 Distributed Cloud Origin Pools
description:
    - Retrieve information about F5 Distributed Cloud Origin Pools
    - This is a read-only module that does not modify any resources
    - Supports querying single origin pools or listing all in a namespace
    - Returns detailed configuration and status information
version_added: "0.1.0"
options:
    name:
        description:
            - Name of a specific Origin Pool to retrieve
            - If not specified, all origin pools in the namespace will be returned
            - Mutually exclusive with C(filters)
        type: str
    namespace:
        description:
            - Namespace to query for Origin Pools
            - If not specified, uses the default namespace from API credentials
        type: str
        required: true
    filters:
        description:
            - Optional filters to apply when querying multiple origin pools
            - Mutually exclusive with C(name)
        type: dict
        suboptions:
            labels:
                description:
                    - Filter by label selectors
                    - Key-value pairs that must match origin pool labels
                type: dict
            state:
                description:
                    - Filter by origin pool state
                type: str
                choices: ['ACTIVE', 'PENDING', 'ERROR', 'DELETING']
    exact:
        description:
            - When C(true), only return exact matches for filters
            - When C(false), allow partial matches where supported
        type: bool
        default: false
    include_status:
        description:
            - Include detailed status information in the response
            - May increase response time for large queries
        type: bool
        default: true
    include_spec:
        description:
            - Include full specification details in the response
            - When C(false), only metadata is returned
        type: bool
        default: true
notes:
    - This module is read-only and will never modify resources
    - Always returns C(changed: false)
    - Supports check mode without any side effects
author:
    - Alex Shemyakin (@yoctoalex)
requirements:
    - F5 Distributed Cloud Console access
    - Valid API token with read permissions
    - Access to the specified namespace
'''

EXAMPLES = r'''
---
# Get information about a specific origin pool
- name: Get specific origin pool info
  origin_pool_info:
    name: "my-origin-pool"
    namespace: "production"
  register: pool_info

- name: Display origin pool servers
  debug:
    msg: "Pool serves: {{ pool_info.resources[0].spec.origin_servers }}"

# Get all origin pools in a namespace
- name: Get all origin pools in namespace
  origin_pool_info:
    namespace: "production"
  register: all_pools

- name: Show count of origin pools
  debug:
    msg: "Found {{ all_pools.resources | length }} origin pools"

# Filter origin pools by labels
- name: Get origin pools with specific labels
  origin_pool_info:
    namespace: "production"
    filters:
      labels:
        environment: "prod"
        team: "platform"
  register: filtered_pools

# Get minimal information (metadata only)
- name: Get origin pool metadata only
  origin_pool_info:
    name: "my-origin-pool"
    namespace: "production"
    include_spec: false
    include_status: false
  register: pool_metadata

# Filter by state
- name: Get only active origin pools
  origin_pool_info:
    namespace: "production"
    filters:
      state: "ACTIVE"
  register: active_pools

# Use in a loop to check multiple namespaces
- name: Get origin pools from multiple namespaces
  origin_pool_info:
    namespace: "{{ item }}"
  loop:
    - "production"
    - "staging"
    - "development"
  register: multi_namespace_pools

# Check if an origin pool exists
- name: Check if origin pool exists
  origin_pool_info:
    name: "my-origin-pool"
    namespace: "production"
  register: pool_check
  failed_when: false

- name: Fail if origin pool doesn't exist
  fail:
    msg: "Origin pool 'my-origin-pool' not found"
  when: pool_check.resources | length == 0
'''

RETURN = r'''
---
changed:
    description: Always false for info modules
    type: bool
    returned: always
    sample: false
resources:
    description: List of Origin Pool resources
    type: list
    returned: always
    elements: dict
    contains:
        metadata:
            description: Origin pool metadata
            type: dict
            contains:
                name:
                    description: Origin pool name
                    type: str
                    sample: "my-origin-pool"
                namespace:
                    description: Origin pool namespace
                    type: str
                    sample: "production"
                labels:
                    description: Origin pool labels
                    type: dict
                    sample: {"app": "web", "env": "prod"}
                annotations:
                    description: Origin pool annotations
                    type: dict
                description:
                    description: Origin pool description
                    type: str
                    sample: "Production web origin pool"
                disable:
                    description: Whether origin pool is disabled
                    type: bool
                    sample: false
        spec:
            description: Origin pool specification (when include_spec=true)
            type: dict
            contains:
                origin_servers:
                    description: List of origin servers
                    type: list
                port:
                    description: Port number
                    type: int
                    sample: 80
                loadbalancer_algorithm:
                    description: Load balancing algorithm
                    type: str
                    sample: "ROUND_ROBIN"
                endpoint_selection:
                    description: Endpoint selection strategy
                    type: str
                    sample: "DISTRIBUTED"
        status:
            description: Origin pool status (when include_status=true)
            type: dict
            contains:
                state:
                    description: Current state of the origin pool
                    type: str
                    sample: "ACTIVE"
                conditions:
                    description: Status conditions
                    type: list
warnings:
    description: List of warnings encountered during execution
    type: list
    elements: str
    returned: always
    sample: []
'''

from ansible.module_utils.basic import AnsibleModule
from copy import deepcopy

from ..module_utils.client import XcRestClient
from ..module_utils.common import (
    AnsibleF5Parameters, f5_argument_spec
)
from ..module_utils.exceptions import F5ModuleError, XcApiError, XcValidationError
from ..module_utils.utils import safe_get, normalize_response


class InfoParameters(AnsibleF5Parameters):
    returnables = ['resources', 'warnings']

    def to_return(self):
        result = {}
        for returnable in self.returnables:
            value = getattr(self, returnable)
            if value is not None:
                result[returnable] = value
        result = self._filter_params(result)
        return result

    @property
    def name(self):
        return self._values.get('name')
    
    @property
    def namespace(self):
        return self._values.get('namespace')
    
    @property
    def filters(self):
        return self._values.get('filters', {})
    
    @property
    def exact(self):
        return self._values.get('exact', False)
    
    @property
    def include_status(self):
        return self._values.get('include_status', True)
    
    @property
    def include_spec(self):
        return self._values.get('include_spec', True)

    def validate_params(self):
        """Validate module parameters."""
        if not self.namespace:
            raise XcValidationError("namespace is required")
        
        # Namespace format validation intentionally skipped; server authoritative
        
        # Validate mutually exclusive parameters
        if self.name and self.filters:
            raise XcValidationError("'name' and 'filters' are mutually exclusive")
        
        # Validate filter parameters
        if self.filters:
            self._validate_filters()
        
        return True

    def _validate_filters(self):
        """Validate filter parameters."""
        filters = self.filters
        
        if 'state' in filters:
            valid_states = ['ACTIVE', 'PENDING', 'ERROR', 'DELETING']
            if filters['state'] not in valid_states:
                raise XcValidationError(f"Invalid state filter. Must be one of: {valid_states}")
        
        if 'labels' in filters:
            if not isinstance(filters['labels'], dict):
                raise XcValidationError("labels filter must be a dictionary")


class InfoManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.client = XcRestClient(**self.module.params)
        
        self.want = InfoParameters(params=self.module.params)
        self.resources = []
        self.warnings = []
        
        # Validate parameters early
        try:
            self.want.validate_params()
        except XcValidationError as e:
            self.module.fail_json(msg=f"Parameter validation failed: {str(e)}")

    @staticmethod
    def _prune_none(obj):
        """Recursively remove keys with None values and empty containers.

        Mirrors pruning strategy in main module for consistent idempotent output.
        """
        if isinstance(obj, dict):
            new_obj = {}
            for k, v in obj.items():
                if v is None:
                    continue
                pruned = InfoManager._prune_none(v)
                # Skip empty dict/list after pruning
                if pruned in (None, {}, []):
                    continue
                new_obj[k] = pruned
            return new_obj
        if isinstance(obj, list):
            new_list = [InfoManager._prune_none(v) for v in obj]
            new_list = [v for v in new_list if v not in (None, {}, [])]
            return new_list
        return obj

    def _build_uri(self, name=None):
        """Build API URI for different operations."""
        namespace = self.want.namespace
        # Use non-versioned endpoint for parity with origin_pool
        base_uri = f'/api/config/namespaces/{namespace}/origin_pools'
        
        if name:
            return f"{base_uri}/{name}"
        return base_uri

    def _handle_response(self, response, operation=''):
        """Handle API response with proper error handling."""
        if not response.ok:
            if response.status_code == 404:
                # For info modules, 404 is not necessarily an error
                return None
            
            error_msg = f"API {operation} failed"
            try:
                error_data = response.json()
                if 'error' in error_data:
                    error_msg = f"{error_msg}: {error_data['error']}"
                elif 'message' in error_data:
                    error_msg = f"{error_msg}: {error_data['message']}"
            except (ValueError, KeyError):
                error_msg = f"{error_msg}: HTTP {response.status_code}"
            
            raise XcApiError(error_msg, status_code=response.status_code, response=response)
        
        return normalize_response(response)

    def _filter_resource(self, resource):
        """Apply filters to a single resource."""
        if not self.want.filters:
            return True
        
        filters = self.want.filters
        
        # Filter by state
        if 'state' in filters:
            resource_state = safe_get(resource, 'status', 'state')
            if resource_state != filters['state']:
                return False
        
        # Filter by labels
        if 'labels' in filters:
            resource_labels = safe_get(resource, 'metadata', 'labels', default={})
            for key, value in filters['labels'].items():
                if self.want.exact:
                    if resource_labels.get(key) != value:
                        return False
                else:
                    if key not in resource_labels or value not in str(resource_labels[key]):
                        return False
        
        return True

    def _process_resource(self, resource):
        """Process a single resource according to module options."""
        if not resource:
            return None
        
        # Deep copy to avoid mutating original and enable safe pruning
        processed = deepcopy(resource)

        # Remove or prune spec
        if not self.want.include_spec and 'spec' in processed:
            del processed['spec']
        elif 'spec' in processed:
            processed['spec'] = self._prune_none(processed['spec'])
            if processed['spec'] in ({}, []):
                processed.pop('spec', None)

        # Prune metadata None values for consistency with main module
        if 'metadata' in processed:
            processed['metadata'] = self._prune_none(processed['metadata'])
            if processed['metadata'] in ({}, []):
                processed.pop('metadata', None)

        # Remove status if not requested. Some resources may not include status; that's OK.
        if not self.want.include_status and 'status' in processed:
            del processed['status']

        # Note: Some origin pools may not expose a status block; absence is not an error.

        return processed

    def exec_module(self):
        """Main execution method."""
        try:
            if self.want.name:
                self.get_single_resource()
            else:
                self.get_multiple_resources()
            
            # Process resources according to options
            self.resources = [
                self._process_resource(resource) 
                for resource in self.resources 
                if resource and self._filter_resource(resource)
            ]
            
            result = {
                'changed': False,
                'resources': self.resources,
                'warnings': self.warnings
            }
            
            return result
            
        except XcApiError as e:
            self.module.fail_json(msg=f"API Error: {str(e)}")
        except XcValidationError as e:
            self.module.fail_json(msg=f"Validation Error: {str(e)}")
        except Exception as e:
            self.module.fail_json(msg=f"Unexpected error: {str(e)}")

    def get_single_resource(self):
        """Get information about a single origin pool."""
        try:
            uri = self._build_uri(self.want.name)
            response = self.client.api.get(url=uri)
            
            response_data = self._handle_response(response, 'GET')
            
            if response_data and response_data.get('metadata'):
                self.resources = [response_data]
            else:
                self.resources = []
                self.warnings.append(f"Origin pool '{self.want.name}' not found in namespace '{self.want.namespace}'")
                
        except XcApiError as e:
            if e.status_code == 404:
                self.resources = []
                self.warnings.append(f"Origin pool '{self.want.name}' not found in namespace '{self.want.namespace}'")
            else:
                raise

    def get_multiple_resources(self):
        """Get information about multiple origin pools."""
        try:
            uri = self._build_uri()
            response = self.client.api.get(url=uri)
            
            response_data = self._handle_response(response, 'LIST')
            
            if response_data and 'items' in response_data:
                self.resources = response_data['items']
            else:
                self.resources = []
                self.warnings.append(f"No origin pools found in namespace '{self.want.namespace}'")
                
        except XcApiError as e:
            if e.status_code == 404:
                self.resources = []
                self.warnings.append(f"Namespace '{self.want.namespace}' not found or no origin pools exist")
            else:
                raise


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True

        argument_spec = dict(
            name=dict(
                type='str'
            ),
            namespace=dict(
                type='str',
                required=True
            ),
            filters=dict(
                type='dict',
                options=dict(
                    labels=dict(
                        type='dict'
                    ),
                    state=dict(
                        type='str',
                        choices=['ACTIVE', 'PENDING', 'ERROR', 'DELETING']
                    )
                )
            ),
            exact=dict(
                type='bool',
                default=False
            ),
            include_status=dict(
                type='bool',
                default=True
            ),
            include_spec=dict(
                type='bool',
                default=True
            )
        )
        
        self.argument_spec = {}
        self.argument_spec.update(f5_argument_spec)
        self.argument_spec.update(argument_spec)
        
        # Add mutual exclusions
        self.mutually_exclusive = [
            ['name', 'filters']
        ]


def main():
    """Main entry point for the module."""
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
        mutually_exclusive=getattr(spec, 'mutually_exclusive', [])
    )
    
    try:
        # Initialize info manager and execute
        im = InfoManager(module=module)
        results = im.exec_module()
        module.exit_json(**results)
        
    except F5ModuleError as ex:
        module.fail_json(msg=f"Module execution failed: {str(ex)}")
    except XcApiError as ex:
        module.fail_json(msg=f"API error: {str(ex)}")
    except XcValidationError as ex:
        module.fail_json(msg=f"Validation error: {str(ex)}")
    except Exception as ex:
        module.fail_json(msg=f"Unexpected error: {str(ex)}")


if __name__ == '__main__':
    main()
