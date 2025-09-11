#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: namespaces_info
short_description: Gather comprehensive information about F5 Distributed Cloud Namespaces
description:
    - Retrieve detailed information about F5 Distributed Cloud namespaces
    - Read-only module that never changes resources (always returns changed: false)
    - List all namespaces with optional filtering capabilities
    - Filter by name, labels, or annotations to find specific namespaces
    - Access comprehensive configuration including metadata and system information
    - Supports both basic metadata retrieval and full configuration details
version_added: "0.1.0"
options:
    name:
        description:
            - Filter by namespace name (exact match)
            - If specified, only namespaces with this exact name will be returned
            - Case-sensitive string matching
        type: str
    labels:
        description:
            - Filter by metadata labels using key-value pairs
            - All specified labels must match (AND logic)
            - Supports exact string matching for both keys and values
        type: dict
    annotations:
        description:
            - Filter by metadata annotations using key-value pairs  
            - All specified annotations must match (AND logic)
            - Supports exact string matching for both keys and values
        type: dict
    include_system_namespaces:
        description:
            - Include system namespaces in the results
            - System namespaces are typically managed by the platform
            - When false (default), filters out system-managed namespaces
        type: bool
        default: false
    full_details:
        description:
            - Fetch complete configuration details for each namespace
            - When false (default), returns only basic metadata (name, labels, annotations)
            - When true, retrieves comprehensive configuration including all system metadata
            - "Full details include:"
            - "  • System Metadata: Creation/modification timestamps, UIDs, tenant information"
            - "  • Complete Specifications: Full namespace configuration and status"
            - "  • Administrative Information: Disable flags, initialization status"
        type: bool
        default: false

extends_documentation_fragment:
  - f5_xc_cloud.xc_cloud_modules.f5
  - f5_xc_cloud.xc_cloud_modules.common

notes:
    - Always returns changed: false (read-only operation)
    - Supports check mode for validation
    - Returns empty list if no namespaces match the filter criteria
    - All filtering is performed client-side after retrieving namespace list
    - System namespaces (like 'system', 'shared', 'ves-system') are filtered out by default

author:
    - Alex Shemyakin (@yoctoalex)
'''

EXAMPLES = r'''
- name: Get all namespaces (excluding system namespaces)
  f5_xc_cloud.xc_cloud_modules.namespaces_info:
  register: all_namespaces

- name: Get all namespaces including system namespaces
  f5_xc_cloud.xc_cloud_modules.namespaces_info:
    include_system_namespaces: true
  register: all_namespaces_with_system

- name: Get specific namespace by name
  f5_xc_cloud.xc_cloud_modules.namespaces_info:
    name: "production"
  register: production_namespace

- name: Get namespaces with specific labels
  f5_xc_cloud.xc_cloud_modules.namespaces_info:
    labels:
      environment: "production"
      team: "platform"
  register: filtered_namespaces

- name: Get namespaces with full details
  f5_xc_cloud.xc_cloud_modules.namespaces_info:
    full_details: true
  register: detailed_namespaces

- name: Display namespace names
  debug:
    msg: "Found namespaces: {{ all_namespaces.resources | map(attribute='metadata.name') | list }}"

- name: Check if production namespace exists
  debug:
    msg: "Production namespace exists"
  when: production_namespace.resources | length > 0
'''

RETURN = r'''
changed:
    description: Always false for info modules
    type: bool
    returned: always
    sample: false
resources:
    description: List of namespace resources
    type: list
    returned: always
    elements: dict
    contains:
        metadata:
            description: Namespace metadata
            type: dict
            contains:
                name:
                    description: Name of the namespace
                    type: str
                    sample: "production-namespace"
                namespace:
                    description: Parent namespace (usually "system")
                    type: str
                    sample: "system"
                labels:
                    description: User-defined labels
                    type: dict
                    sample: {"environment": "production", "team": "platform"}
                annotations:
                    description: User-defined annotations
                    type: dict
                    sample: {"created-by": "ansible"}
                description:
                    description: Human readable description
                    type: str
                    sample: "Production environment namespace"
                disable:
                    description: Administrative disable flag
                    type: bool
                    sample: false
                creation_timestamp:
                    description: When the namespace was created
                    type: str
                    sample: "2023-01-01T00:00:00.000Z"
                modification_timestamp:
                    description: When the namespace was last modified
                    type: str
                    sample: "2023-01-15T10:30:00.000Z"
        spec:
            description: Namespace specification
            type: dict
            sample: {}
        system_metadata:
            description: System-managed metadata (when full_details=true)
            type: dict
            contains:
                uid:
                    description: Unique identifier
                    type: str
                    sample: "12345678-1234-1234-1234-123456789abc"
                tenant:
                    description: Tenant name
                    type: str
                    sample: "example-tenant"
                creator_id:
                    description: Creator identifier
                    type: str
                    sample: "admin@example.com"
                initializers:
                    description: Initialization status
                    type: dict
                    contains:
                        pending:
                            description: List of pending initializers
                            type: list
                            sample: []
                finalizers:
                    description: Cleanup handlers
                    type: list
                    sample: []
'''

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.module_info_list_base import BaseInfoListManager, BaseParameters
from ..module_utils.exceptions import F5ModuleError
from ..module_utils.common import f5_argument_spec
from ..module_utils.constants import NAMESPACES_WEB_ENDPOINT


def build_endpoint():
    """Build namespace list endpoint URL."""
    return NAMESPACES_WEB_ENDPOINT


class NamespacesInfoParameters(BaseParameters):
    """Parameters class for namespaces info operations."""
    returnables = ["resources"]


class NamespacesInfoManager(BaseInfoListManager):
    """Manager class for namespaces info operations."""
    
    resource_singular = "namespaces_info"
    
    def _build_endpoint(self, name=None):
        """Build namespace list endpoint URL."""
        return build_endpoint()
    
    def _create_parameters_instance(self, data):
        """Create namespaces-specific parameters instance."""
        return NamespacesInfoParameters(data)
    
    def _filter_resource(self, resource):
        """Filter individual namespace resource based on module parameters."""
        # Filter by name if specified
        if self.params.get('name'):
            resource_name = resource.get('metadata', {}).get('name', '')
            if resource_name != self.params.get('name'):
                return False
        
        # Filter by labels if specified
        if self.params.get('labels'):
            resource_labels = resource.get('metadata', {}).get('labels', {})
            for key, value in self.params.get('labels').items():
                if resource_labels.get(key) != value:
                    return False
        
        # Filter by annotations if specified
        if self.params.get('annotations'):
            resource_annotations = resource.get('metadata', {}).get('annotations', {})
            for key, value in self.params.get('annotations').items():
                if resource_annotations.get(key) != value:
                    return False
        
        # Filter out system namespaces if not requested
        if not self.params.get('include_system_namespaces', False):
            resource_name = resource.get('metadata', {}).get('name', '')
            system_namespaces = ['system', 'shared', 'ves-system']
            if resource_name in system_namespaces or resource_name.startswith('system'):
                return False
        
        return True
    
    def _process_resource(self, resource):
        """Process individual namespace resource."""
        # If not full_details, remove system_metadata
        if not self.params.get('full_details', False):
            processed = {
                'metadata': resource.get('metadata', {}),
                'spec': resource.get('spec', {})
            }
            return processed
        
        return resource
    api_map = {}

    api_attributes = []

    returnables = [
        'metadata',
        'spec',
        'system_metadata'
    ]

    @property
    def name(self):
        return self._values.get('name')

    @property
    def include_system_namespaces(self):
        return self._values.get('include_system_namespaces', False)

    @property
    def labels(self):
        return self._values.get('labels')

    @property
    def show_details(self):
        return self._values.get('show_details', True)

    @staticmethod
    def _prune_none(data):
        """
        Recursively remove None values from nested dictionaries and lists.
        
        Args:
            data: The data structure to prune
            
        Returns:
            The pruned data structure
        """
        if isinstance(data, dict):
            return {k: InfoParameters._prune_none(v) for k, v in data.items() if v is not None}
        elif isinstance(data, list):
            return [InfoParameters._prune_none(item) for item in data if item is not None]
        else:
            return data

    def to_return(self):
        result = {}
        try:
            for returnable in self.returnables:
                value = getattr(self, returnable, None)
                if value is not None:
                    result[returnable] = value
            result = self._filter_params(result)
            result = self._prune_none(result)
        except Exception:
            raise
        return result


class InfoManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.client = XcRestClient(**self.module.params)
        self.want = InfoParameters(params=self.module.params)

    def exec_module(self):
        result = dict()
        
        if self.want.name:
            # Get specific namespace
            namespace_info = self.read_namespace_from_device(self.want.name)
            if namespace_info:
                params = InfoParameters(params=namespace_info)
                result.update(namespace=params.to_return())
            else:
                result.update(namespace={})
        else:
            # Get all namespaces
            namespaces_info = self.read_all_namespaces_from_device()
            filtered_namespaces = self._filter_namespaces(namespaces_info)
            
            processed_namespaces = []
            for ns_info in filtered_namespaces:
                params = InfoParameters(params=ns_info)
                processed_namespaces.append(params.to_return())
                
            result.update(namespaces=processed_namespaces)
            
        return result

    def read_namespace_from_device(self, name):
        """Read specific namespace from device."""
        uri = f"{NAMESPACES_WEB_ENDPOINT}/{name}"
        
        try:
            response = self.client.api.get(url=uri)
            
            if response.status == 404:
                return None
                
            if response.status not in [200, 201, 202]:
                raise F5ModuleError(f"Failed to retrieve namespace '{name}': {response.content}")
                
            return response.json()
            
        except Exception as ex:
            raise F5ModuleError(f"Error reading namespace '{name}': {str(ex)}")

    def read_all_namespaces_from_device(self):
        """Read all namespaces from device."""
        uri = NAMESPACES_WEB_ENDPOINT
        
        try:
            response = self.client.api.get(url=uri)
            
            if response.status not in [200, 201, 202]:
                raise F5ModuleError(f"Failed to retrieve namespaces: {response.content}")
                
            result = response.json()
            return result.get('items', [])
            
        except Exception as ex:
            raise F5ModuleError(f"Error reading namespaces: {str(ex)}")

    def _filter_namespaces(self, namespaces):
        """Filter namespaces based on module parameters."""
        filtered = []
        
        for namespace in namespaces:
            # Filter out system namespaces if not requested
            if not self.want.include_system_namespaces:
                ns_name = namespace.get('metadata', {}).get('name', '')
                if ns_name.startswith('system') or ns_name in ['ves-system', 'shared']:
                    continue
            
            # Filter by labels if specified
            if self.want.labels:
                ns_labels = namespace.get('metadata', {}).get('labels', {})
                if not all(ns_labels.get(k) == v for k, v in self.want.labels.items()):
                    continue
            
            # Include minimal details if requested
            if not self.want.show_details:
                namespace = self._minimize_namespace_details(namespace)
                
            filtered.append(namespace)
            
        return filtered

    def _minimize_namespace_details(self, namespace):
        """Remove detailed system information for minimal output."""
        minimal = {
            'metadata': {
                'name': namespace.get('metadata', {}).get('name'),
                'labels': namespace.get('metadata', {}).get('labels'),
                'description': namespace.get('metadata', {}).get('description'),
                'creation_timestamp': namespace.get('metadata', {}).get('creation_timestamp')
            },
            'spec': namespace.get('spec', {})
        }
        return minimal


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True

        argument_spec = dict(
            name=dict(
                type='str'
            ),
            labels=dict(
                type='dict'
            ),
            annotations=dict(
                type='dict'
            ),
            include_system_namespaces=dict(
                type='bool',
                default=False
            ),
            full_details=dict(
                type='bool',
                default=False
            )
        )
        self.argument_spec = {}
        self.argument_spec.update(f5_argument_spec)
        self.argument_spec.update(argument_spec)


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode
    )
    try:
        mm = NamespacesInfoManager(module=module)
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
