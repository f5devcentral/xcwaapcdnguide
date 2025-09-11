#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: health_check
short_description: Manage F5 Distributed Cloud Health Checks
description:
    - Create, update, and delete F5 Distributed Cloud Health Check configurations using BaseManager architecture
    - Health checks monitor the availability and responsiveness of origin servers in origin pools
    - Supports HTTP and TCP health checking mechanisms with customizable parameters
    - Built on the generic BaseManager framework for consistent module behavior with intelligent change detection
    - Provides configurable output fields and full check mode support
    - Integrates with F5 XC load balancing ecosystem for comprehensive service monitoring
version_added: "0.1.0"
options:
    state:
        description:
            - Desired state of the health check
            - C(present) ensures the health check is created or updated
            - C(absent) ensures the health check is removed
        type: str
        choices: [present, absent]
        default: present
    metadata:
        description:
            - Metadata for the health check resource
        type: dict
        required: true
        suboptions:
            name:
                description:
                    - Name of the health check. Must be unique within the namespace
                    - Must follow DNS-1035 format
                    - Cannot be changed after creation
                type: str
                required: true
            namespace:
                description:
                    - Namespace where the health check will be created
                    - Must be a valid F5 XC namespace
                type: str
                required: true
            labels:
                description:
                    - Map of string keys and values for organizing and categorizing objects
                    - Used by selector expressions for grouping resources
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
                    - Human readable description for the health check
                    - Used for documentation and identification purposes
                type: str
            disable:
                description:
                    - Administratively disable the health check
                    - When set to true, the health check becomes non-functional
                type: bool
                default: false
    spec:
        description:
            - Specification for the health check configuration
            - Contains all health check-specific settings and parameters
        type: dict
        default: {}
        suboptions:
            healthy_threshold:
                description:
                    - Number of consecutive successful health checks required
                    - Origin server becomes healthy after this many successes
                type: int
                default: 2
            unhealthy_threshold:
                description:
                    - Number of consecutive failed health checks required
                    - Origin server becomes unhealthy after this many failures
                type: int
                default: 3
            interval:
                description:
                    - Interval between health checks in seconds
                    - Determines how frequently health checks are performed
                type: int
                default: 30
            timeout:
                description:
                    - Timeout for each health check attempt in seconds
                    - Health check fails if no response within this time
                type: int
                default: 10
            jitter_percent:
                description:
                    - Percentage of random jitter added to check intervals
                    - Helps distribute health check load across time
                type: int
                default: 0
            http_health_check:
                description:
                    - HTTP-specific health check configuration
                    - Used for checking HTTP/HTTPS endpoints
                type: dict
                suboptions:
                    path:
                        description:
                            - HTTP path for the health check request
                            - Default is "/" if not specified
                        type: str
                        default: "/"
                    host_header:
                        description:
                            - Host header value for HTTP health check requests
                            - Uses origin server hostname if not specified
                        type: str
                    expected_status_codes:
                        description:
                            - List of HTTP status codes considered healthy
                            - Health check passes if response matches any code
                        type: list
                        elements: str
                        default: ["200"]
                    headers:
                        description:
                            - Additional HTTP headers to include in health check requests
                            - Key-value pairs of header names and values
                        type: dict
                        default: {}
                    request_headers_to_remove:
                        description:
                            - List of header names to remove from health check requests
                            - Useful for excluding sensitive or unnecessary headers
                        type: list
                        elements: str
                        default: []
                    use_http2:
                        description:
                            - Enable HTTP/2 for health check requests
                            - Uses HTTP/1.1 if disabled
                        type: bool
                        default: false
                    use_origin_server_name:
                        description:
                            - Use origin server name for SNI and Host header
                            - Enables proper TLS negotiation for HTTPS health checks
                        type: dict
            tcp_health_check:
                description:
                    - TCP-specific health check configuration
                    - Used for checking TCP service availability
                type: dict
                suboptions:
                    send_payload:
                        description:
                            - Data payload to send during TCP health check
                            - Can be used for application-specific health checks
                        type: str
                    expected_response:
                        description:
                            - Expected response data from TCP health check
                            - Health check passes if response matches this value
                        type: str
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
  - F5 XC tenant with appropriate permissions for health check management
notes:
  - This module uses the generic BaseManager architecture for consistent behavior
  - Health checks are essential for ensuring origin server availability in load balancing
  - Both HTTP and TCP health check types are supported with extensive configuration options
  - Idempotent operations are supported through intelligent change detection
  - Check mode is fully supported for testing configuration changes
  - Use returnables parameter to control which fields are included in output
seealso:
  - module: f5_xc_cloud.xc_cloud_modules.origin_pool
  - module: f5_xc_cloud.xc_cloud_modules.http_loadbalancer
  - module: f5_xc_cloud.xc_cloud_modules.namespace
'''

EXAMPLES = r'''
---
# Create a basic HTTP health check
- name: Create basic HTTP health check
  f5_xc_cloud.xc_cloud_modules.health_check:
    state: present
    metadata:
      name: "basic-http-health"
      namespace: "production"
      description: "Basic HTTP health check"
    spec:
      interval: 30
      timeout: 10
      healthy_threshold: 2
      unhealthy_threshold: 3
      http_health_check:
        path: "/health"
        expected_status_codes: ["200"]

# Create comprehensive HTTP health check with custom headers
- name: Create comprehensive HTTP health check
  f5_xc_cloud.xc_cloud_modules.health_check:
    state: present
    metadata:
      name: "comprehensive-http-health"
      namespace: "production"
      description: "Comprehensive HTTP health check with custom configuration"
      labels:
        environment: "production"
        service: "web-app"
    spec:
      interval: 15
      timeout: 5
      healthy_threshold: 3
      unhealthy_threshold: 2
      jitter_percent: 10
      http_health_check:
        path: "/api/health"
        host_header: "api.example.com"
        expected_status_codes: ["200", "204"]
        headers:
          User-Agent: "F5-XC-HealthCheck/1.0"
          X-Health-Check: "true"
        use_http2: true
        use_origin_server_name: {}

# Create TCP health check for database
- name: Create TCP health check for database
  f5_xc_cloud.xc_cloud_modules.health_check:
    state: present
    metadata:
      name: "database-tcp-health"
      namespace: "production"
      description: "TCP health check for database service"
      labels:
        environment: "production"
        service: "database"
        protocol: "tcp"
    spec:
      interval: 20
      timeout: 5
      healthy_threshold: 2
      unhealthy_threshold: 3
      tcp_health_check:
        send_payload: "PING"
        expected_response: "PONG"

# Remove a health check
- name: Remove health check
  f5_xc_cloud.xc_cloud_modules.health_check:
    state: absent
    metadata:
      name: "old-health-check"
      namespace: "staging"
'''

RETURN = r'''
changed:
    description: 
        - Indicates whether the health check was modified during execution
        - True when health check was created, updated, or deleted
        - False when no changes were needed (idempotent operation)
    returned: always
    type: bool
    sample: true
resource:
    description: 
        - Complete health check resource data from F5 XC API
        - Contains fields specified in the returnables configuration
        - Only returned when state=present and operation succeeds
        - Fields are filtered based on returnables parameter settings
    returned: when state=present
    type: dict
    sample: {
        "metadata": {
            "name": "production-health-check",
            "namespace": "production",
            "labels": {
                "environment": "production",
                "service": "web-app",
                "protocol": "http"
            },
            "annotations": {
                "managed-by": "ansible",
                "contact": "infrastructure-team@example.com"
            },
            "description": "Production HTTP health check for web application",
            "disable": false
        },
        "spec": {
            "healthy_threshold": 3,
            "unhealthy_threshold": 2,
            "interval": 15,
            "timeout": 5,
            "jitter_percent": 10,
            "http_health_check": {
                "path": "/api/health",
                "host_header": "api.example.com",
                "expected_status_codes": ["200", "204"],
                "headers": {
                    "User-Agent": "F5-XC-HealthCheck/1.0",
                    "X-Health-Check": "true"
                },
                "request_headers_to_remove": [],
                "use_http2": true,
                "use_origin_server_name": {}
            }
        }
    }
msg:
    description:
        - Human-readable message describing the operation result
        - Provides context about what action was taken
    returned: when changed=true or when errors occur
    type: str
    sample: "Health check 'production-health-check' was created successfully"
api_response:
    description:
        - Raw response data from the F5 XC API
        - Contains complete server response
    returned: when ansible verbosity >= 3
    type: dict
'''

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.module_base import BaseManager, BaseParameters
from ..module_utils.exceptions import F5ModuleError
from ..module_utils.common import f5_argument_spec
from ..module_utils.constants import HEALTHCHECKS_ENDPOINT_NONVERSIONED

def build_endpoint(namespace, name=None):
    """Build health check endpoint URL."""
    base = HEALTHCHECKS_ENDPOINT_NONVERSIONED.format(namespace=namespace)
    return base if name is None else f"{base}/{name}"


class HealthCheckParameters(BaseParameters):
    """Parameters class for health check-specific processing."""
    returnables = ["metadata", "spec", "system_metadata"]
    updatables = ["metadata", "spec"]

    @property
    def metadata(self):
        """Construct metadata according to API specification."""
        metadata = self._values.get('metadata', {})
        if not metadata:
            return metadata
            
        # Process metadata normally for health check resources
        metadata = metadata.copy()
        
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


class HealthCheckManager(BaseManager):
    """Manager for health check resources using BaseManager."""
    
    resource_singular = "health_check"
    ignore_change_paths = [
        # Add any paths that should be ignored during change detection
    ]

    def __init__(self, module, api=None):
        super(HealthCheckManager, self).__init__(module, api)
        # Override the want parameter to use health check-specific processing
        self.want = HealthCheckParameters(self.params)
        self.have = HealthCheckParameters({})

    # -------- Required abstract method implementations --------
    def _get_resource_name(self):
        """Extract health check name from params."""
        return self.params.get('metadata', {}).get('name')

    def _build_endpoint(self, name=None):
        """Build health check endpoint URL."""
        namespace = self.params.get('metadata', {}).get('namespace')
        if not namespace:
            self.module.fail_json(msg="Namespace is required for health check operations")
        return build_endpoint(namespace, name)

    def _desired_body(self):
        """Build request body for health check operations."""
        body = {}
        meta = self.params.get('metadata')
        spec = self.params.get('spec')
        
        if meta:
            body['metadata'] = meta
            
        if spec is not None:
            body['spec'] = spec
            
        return body

    # -------- Optional method overrides --------
    def _create_parameters_instance(self, data):
        """Create health check-specific parameters instance."""
        return HealthCheckParameters(data)


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
                    namespace=dict(type='str', required=True),
                    labels=dict(type='dict', default={}),
                    annotations=dict(type='dict', default={}),
                    description=dict(type='str', default=''),
                    disable=dict(type='bool', default=False)
                )
            ),
            spec=dict(
                type='dict',
                default={},
                options=dict(
                    healthy_threshold=dict(type='int', default=2),
                    unhealthy_threshold=dict(type='int', default=3),
                    interval=dict(type='int', default=30),
                    timeout=dict(type='int', default=10),
                    jitter_percent=dict(type='int', default=0),
                    http_health_check=dict(
                        type='dict',
                        options=dict(
                            path=dict(type='str', default='/'),
                            host_header=dict(type='str'),
                            expected_status_codes=dict(
                                type='list', 
                                elements='str', 
                                default=['200']
                            ),
                            headers=dict(type='dict', default={}),
                            request_headers_to_remove=dict(
                                type='list', 
                                elements='str', 
                                default=[]
                            ),
                            use_http2=dict(type='bool', default=False),
                            use_origin_server_name=dict(type='dict')
                        )
                    ),
                    tcp_health_check=dict(
                        type='dict',
                        options=dict(
                            send_payload=dict(type='str'),
                            expected_response=dict(type='str')
                        )
                    )
                )
            ),
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
        mm = HealthCheckManager(module=module)
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()