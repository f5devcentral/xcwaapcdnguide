#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: namespace
short_description: Manage F5 Distributed Cloud Namespaces
description:
    - Create, update, and delete F5 Distributed Cloud namespaces using the BaseManager architecture
    - Namespaces create logical independent workspaces within a tenant for organizing resources
    - Within a namespace, contained objects must have unique names
    - Supports idempotent operations with intelligent change detection
    - Provides configurable output fields through returnables parameter
    - Includes cascade delete functionality for safe namespace removal
    - Built on the generic BaseManager framework for consistent module behavior
version_added: "0.1.0"
options:
    state:
        description:
            - Desired state of the namespace
            - C(present) ensures the namespace is created or updated
            - C(absent) ensures the namespace is removed
        type: str
        choices: [present, absent]
        default: present
    metadata:
        description:
            - Metadata for the namespace resource
        type: dict
        required: true
        suboptions:
            name:
                description:
                    - Name of the namespace. Must be unique within the tenant
                    - Must follow DNS-1035 format
                    - Cannot be changed after creation
                type: str
                required: true
            namespace:
                description:
                    - Parent namespace for the new namespace
                    - This field is automatically set to empty string for namespace resources
                    - Any value provided will be ignored as per F5 XC API requirements
                type: str
                default: system
            labels:
                description:
                    - Map of string keys and values for organizing and categorizing objects
                    - Used by selector expressions
                type: dict
                default: {}
            annotations:
                description:
                    - Unstructured key-value map for storing arbitrary metadata
                    - Not queryable and preserved when modifying objects
                type: dict
                default: {}
            description:
                description:
                    - Human readable description for the namespace
                    - Used for documentation and identification purposes
                type: str
            disable:
                description:
                    - Administratively disable the namespace
                    - When set to true, the namespace becomes non-functional
                    - Resources within disabled namespaces may not be accessible
                type: bool
                default: false
    spec:
        description:
            - Specification for the namespace configuration
            - Currently empty for namespace resources but maintained for API consistency
            - Future namespace-specific configuration options will be added here
        type: dict
        default: {}
    returnables:
        description:
            - List of fields to include in the resource output
            - Controls which fields from the API response are returned
            - Available fields: metadata, spec
            - Defaults to all available fields if not specified
        type: list
        elements: str
        choices: ['metadata', 'spec']
        default: ['metadata', 'spec']
author:
  - Alex Shemyakin (@yoctoalex)
requirements:
  - F5 XC API access with valid credentials
  - F5 XC tenant with appropriate permissions for namespace management
notes:
  - This module uses the generic BaseManager architecture for consistent behavior
  - Namespace operations use cascade delete for safe resource removal
  - The module.namespace field is automatically set to empty string for namespace resources
  - Idempotent operations are supported through intelligent change detection
  - Check mode is fully supported for testing configuration changes
  - Use returnables parameter to control which fields are included in output
seealso:
  - module: f5_xc_cloud.xc_cloud_modules.http_loadbalancer
  - module: f5_xc_cloud.xc_cloud_modules.origin_pool
  - module: f5_xc_cloud.xc_cloud_modules.application_firewall
'''

EXAMPLES = r'''
---
# Create a basic namespace with minimal configuration
- name: Create development namespace
  f5_xc_cloud.xc_cloud_modules.namespace:
    state: present
    metadata:
      name: "dev-namespace"
      description: "Development environment namespace"

# Create namespace with comprehensive metadata and labels
- name: Create production namespace with labels
  f5_xc_cloud.xc_cloud_modules.namespace:
    state: present
    metadata:
      name: "production-namespace"
      description: "Production environment for critical workloads"
      labels:
        environment: "production"
        team: "platform"
        cost-center: "engineering"
        criticality: "high"

# Create namespace with annotations for additional metadata
- name: Create namespace with detailed annotations
  f5_xc_cloud.xc_cloud_modules.namespace:
    state: present
    metadata:
      name: "staging-namespace"
      description: "Staging environment for testing"
      annotations:
        created-by: "ansible-automation"
        purpose: "pre-production-testing"
        contact: "devops-team@example.com"
        maintenance-window: "sunday-02:00-04:00"
      labels:
        environment: "staging"
        version: "v2.1"

# Create disabled namespace for future use
- name: Create disabled namespace
  f5_xc_cloud.xc_cloud_modules.namespace:
    state: present
    metadata:
      name: "future-namespace"
      description: "Reserved namespace for future projects"
      disable: true
      labels:
        status: "reserved"

# Update existing namespace labels and description
- name: Update namespace metadata
  f5_xc_cloud.xc_cloud_modules.namespace:
    state: present
    metadata:
      name: "existing-namespace"
      description: "Updated description for existing namespace"
      labels:
        environment: "production"
        updated: "{{ ansible_date_time.epoch }}"

# Remove a namespace using cascade delete
- name: Remove namespace and all its resources
  f5_xc_cloud.xc_cloud_modules.namespace:
    state: absent
    metadata:
      name: "old-namespace"

# Check mode - verify what changes would be made
- name: Check what changes would be made to namespace
  f5_xc_cloud.xc_cloud_modules.namespace:
    state: present
    metadata:
      name: "test-namespace"
      description: "Testing namespace changes"
      labels:
        environment: "test"
  check_mode: yes

# Configure specific return fields in output
- name: Create namespace with limited output fields
  f5_xc_cloud.xc_cloud_modules.namespace:
    state: present
    metadata:
      name: "minimal-output-namespace"
      description: "Namespace with minimal output"
    returnables: ["metadata"]
  register: result

# Create multiple namespaces with loop
- name: Create multiple environment namespaces
  f5_xc_cloud.xc_cloud_modules.namespace:
    state: present
    metadata:
      name: "{{ item.name }}-namespace"
      description: "{{ item.description }}"
      labels: "{{ item.labels }}"
  loop:
    - name: "dev"
      description: "Development environment"
      labels:
        environment: "development"
        team: "frontend"
    - name: "test"
      description: "Testing environment"
      labels:
        environment: "testing"
        team: "qa"
    - name: "prod"
      description: "Production environment"
      labels:
        environment: "production"
        team: "operations"
'''

RETURN = r'''
changed:
    description: 
        - Indicates whether the namespace was modified during execution
        - True when namespace was created, updated, or deleted
        - False when no changes were needed (idempotent operation)
    returned: always
    type: bool
    sample: true
resource:
    description: 
        - Complete namespace resource data from F5 XC API
        - Contains fields specified in the returnables configuration
        - Only returned when state=present and operation succeeds
        - Fields are filtered based on returnables parameter settings
    returned: when state=present
    type: dict
    sample: {
        "metadata": {
            "name": "production-namespace",
            "namespace": "",
            "labels": {
                "environment": "production",
                "team": "platform",
                "cost-center": "engineering"
            },
            "annotations": {
                "created-by": "ansible-automation",
                "contact": "devops@example.com"
            },
            "description": "Production environment namespace",
            "disable": false,
            "uid": "ves-io-99999999-8888-7777-6666-555555555555",
            "creation_timestamp": "2023-01-01T00:00:00.000000Z",
            "modification_timestamp": "2023-01-15T10:30:00.000000Z"
        },
        "spec": {},
        "system_metadata": {
            "uid": "ves-io-99999999-8888-7777-6666-555555555555",
            "creation_timestamp": "2023-01-01T00:00:00.000000Z",
            "modification_timestamp": "2023-01-15T10:30:00.000000Z"
        }
    }
msg:
    description:
        - Human-readable message describing the operation result
        - Provides context about what action was taken
        - Helpful for debugging and logging purposes
    returned: when changed=true or when errors occur
    type: str
    sample: "Namespace 'production-namespace' was created successfully"
api_response:
    description:
        - Raw response data from the F5 XC API
        - Contains complete server response for debugging
        - Only included when module debugging is enabled
    returned: when ansible verbosity >= 3
    type: dict
'''

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.module_base import BaseManager, BaseParameters
from ..module_utils.exceptions import F5ModuleError
from ..module_utils.common import f5_argument_spec
from ..module_utils.constants import (
    NAMESPACES_WEB_ENDPOINT, NAMESPACE_CASCADE_DELETE_ENDPOINT
)

def namespace_endpoint(ns=None, name=None):
    """Build namespace endpoint URL.
    
    For namespace resources, we don't use the parent namespace in the URL
    since namespaces are top-level resources.
    """
    base = NAMESPACES_WEB_ENDPOINT
    return base if name is None else f"{base}/{name}"


class NamespaceParameters(BaseParameters):
    """Parameters class for namespace-specific processing."""
    returnables = ["metadata", "spec", "system_metadata"]
    updatables = ["metadata", "spec"]

    @property
    def metadata(self):
        """Construct metadata according to API specification."""
        metadata = self._values.get('metadata', {})
        if not metadata:
            return metadata
            
        # For namespace resources, the metadata.namespace field should be empty
        # This is different from other resources that live within a namespace
        metadata = metadata.copy()
        metadata['namespace'] = ''
        
        # Ensure required fields have defaults
        if 'labels' not in metadata:
            metadata['labels'] = {}
        if 'annotations' not in metadata:
            metadata['annotations'] = {}
        if 'disable' not in metadata:
            metadata['disable'] = False
            
        # Remove None values that might cause comparison issues
        metadata = {k: v for k, v in metadata.items() if v is not None}
            
        return metadata

    @property
    def spec(self):
        return self._values.get('spec', {})

    @property
    def system_metadata(self):
        return self._values.get('system_metadata')


class NamespaceManager(BaseManager):
    """Manager for namespace resources using BaseManager."""
    
    resource_singular = "namespace"

    def __init__(self, module, api=None):
        super(NamespaceManager, self).__init__(module, api)
        # Override the want parameter to use namespace-specific processing
        self.want = NamespaceParameters(self.params)
        self.have = NamespaceParameters({})

    # -------- Required abstract method implementations --------
    def _get_resource_name(self):
        """Extract namespace name from params."""
        return self.params.get('metadata', {}).get('name')

    def _build_endpoint(self, name=None):
        """Build namespace endpoint URL."""
        return namespace_endpoint(name=name)

    def _desired_body(self):
        """Build request body for namespace operations."""
        body = {}
        meta = self.params.get('metadata')
        spec = self.params.get('spec')
        
        if meta:
            # Process metadata with namespace-specific logic
            processed_meta = meta.copy()
            # Ensure namespace field is empty for namespace resources
            processed_meta['namespace'] = ''
            body['metadata'] = processed_meta
            
        if spec is not None:
            body['spec'] = spec
            
        return body

    # -------- Optional method overrides --------
    def _normalize_existing(self, data):
        """Override to handle namespace-specific response normalization."""
        # Call parent normalization first
        normalized = super(NamespaceManager, self)._normalize_existing(data)
        
        # Ensure namespace field is consistently empty for namespace resources
        if isinstance(normalized, dict) and 'metadata' in normalized:
            if isinstance(normalized['metadata'], dict):
                normalized['metadata']['namespace'] = ''
        
        return normalized

    def _create_parameters_instance(self, data):
        """Create namespace-specific parameters instance."""
        return NamespaceParameters(data)

    def _delete(self):
        """Override delete to use cascade delete for namespaces."""
        name = self._get_resource_name()
        if not name:
            self.module.fail_json(msg="Name is required for namespace deletion")
            
        # Use cascade delete endpoint for namespaces
        uri = NAMESPACE_CASCADE_DELETE_ENDPOINT.format(name=name)
        resp = self.api.post(uri)
        
        if resp.status == 404:
            return False
        if resp.status not in (200, 201, 202):
            self.module.fail_json(msg=resp.content)
        
        # Clear have after successful deletion
        self.have = NamespaceParameters({})
        return True


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True

        argument_spec = dict(
            state=dict(default='present', choices=['present', 'absent']),
            metadata=dict(
                type='dict',
                required=True,
                options=dict(
                    name=dict(type='str', required=True),
                    namespace=dict(type='str', default='system'),
                    labels=dict(type='dict', default={}),
                    annotations=dict(type='dict', default={}),
                    description=dict(type='str'),
                    disable=dict(type='bool', default=False)
                )
            ),
            spec=dict(type='dict', default={}),
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
        mm = NamespaceManager(module=module)
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
