#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: origin_pool
short_description: Manage Origin pool
description:
    - Origin pool is a view to create cluster and endpoint that can be used in HTTP loadbalancer or TCP loadbalancer
version_added: "0.1.0"
options:
    metadata:
        annotations:
            description:
                - Annotations is an unstructured key value map stored with a resource
                  that may be set by external tools to store and retrieve arbitrary metadata.
                  They are not queryable and should be preserved when modifying objects.
            type: object
        description:
            description:
                - Human readable description for the object
            type: str
        disable:
            description:
                - A value of true will administratively disable the object
            type: bool
        labels:
            description:
                - Map of string keys and values that can be used to organize and categorize (scope and select)
                  objects as chosen by the user. Values specified here will be used by selector expression
            type: object
        name:
            type: str
            required: True
            description:
                - This is the name of configuration object. It has to be unique within the namespace.
                  It can only be specified during create API and cannot be changed during replace API.
                  The value of name has to follow DNS-1035 format.
        namespace:
            description:
                - This defines the workspace within which each the configuration object is to be created.
                  Must be a DNS_LABEL format
            type: str
    state:
        description:
            - When C(state) is C(present), ensures the object is created or modified.
            - When C(state) is C(absent), ensures the object is removed.
        type: str
        choices:
          - present
          - absent
        default: present
    spec:
        type: dict
        description:
            - Origin Pool specification defining the pool configuration
        suboptions:
            advanced_options:
                description:
                    - Advanced configuration options for the origin pool
                type: dict
                suboptions:
                    auto_http_config:
                        description: Enable automatic HTTP configuration
                        type: dict
                    circuit_breaker:
                        description: Circuit breaker configuration
                        type: dict
                        suboptions:
                            connection_limit:
                                description: Maximum number of connections
                                type: int
                            max_requests:
                                description: Maximum number of requests
                                type: int
                            pending_requests:
                                description: Maximum number of pending requests
                                type: int
                            priority:
                                description: Circuit breaker priority
                                type: str
                                choices: ['DEFAULT']
                            retries:
                                description: Number of retries
                                type: int
                    default_circuit_breaker:
                        description: Use default circuit breaker settings
                        type: dict
                    disable_circuit_breaker:
                        description: Disable circuit breaker
                        type: dict
                    connection_timeout:
                        description: Connection timeout in milliseconds
                        type: int
                    http_idle_timeout:
                        description: HTTP idle timeout in milliseconds
                        type: int
                    outlier_detection:
                        description: Outlier detection configuration
                        type: dict
                    disable_outlier_detection:
                        description: Disable outlier detection
                        type: dict
                    proxy_protocol_v1:
                        description: Enable proxy protocol v1
                        type: dict
                    proxy_protocol_v2:
                        description: Enable proxy protocol v2
                        type: dict
                    disable_proxy_protocol:
                        description: Disable proxy protocol
                        type: dict
            endpoint_selection:
                description:
                    - Endpoint selection method for load balancing
                type: str
                choices: ['DISTRIBUTED', 'LOCAL_ONLY', 'LOCAL_PREFERRED']
                default: 'DISTRIBUTED'
            health_check_port:
                description:
                    - Port number for health checks
                type: int
            healthcheck:
                description:
                    - Health check configuration reference
                type: list
                elements: dict
                suboptions:
                    name:
                        description: Health check name
                        type: str
                        required: true
                    namespace:
                        description: Health check namespace
                        type: str
                        required: true
                    tenant:
                        description: Health check tenant
                        type: str
            loadbalancer_algorithm:
                description:
                    - Load balancing algorithm for distributing requests
                type: str
                choices: ['ROUND_ROBIN', 'LEAST_REQUEST', 'RING_HASH', 'RANDOM', 'LB_OVERRIDE']
                default: 'ROUND_ROBIN'
            origin_servers:
                description:
                    - List of origin servers in the pool
                type: list
                elements: dict
                suboptions:
                    k8s_service:
                        description: Kubernetes service definition
                        type: dict
                        suboptions:
                            service_name:
                                description: Name of the Kubernetes service
                                type: str
                                required: true
                            protocol:
                                description: Protocol for the service
                                type: str
                                choices: ['PROTOCOL_TCP', 'PROTOCOL_UDP']
                                default: 'PROTOCOL_TCP'
                            site_locator:
                                description: Site location for the service
                                type: dict
                                suboptions:
                                    site:
                                        description: Specific site reference
                                        type: dict
                                        suboptions:
                                            name:
                                                description: Site name
                                                type: str
                                                required: true
                                            namespace:
                                                description: Site namespace
                                                type: str
                                                required: true
                                            tenant:
                                                description: Site tenant
                                                type: str
                                    virtual_site:
                                        description: Virtual site reference
                                        type: dict
                                        suboptions:
                                            name:
                                                description: Virtual site name
                                                type: str
                                                required: true
                                            namespace:
                                                description: Virtual site namespace
                                                type: str
                                                required: true
                                            tenant:
                                                description: Virtual site tenant
                                                type: str
                            inside_network:
                                description: Use inside network
                                type: dict
                            outside_network:
                                description: Use outside network
                                type: dict
                            vk8s_networks:
                                description: Use virtual Kubernetes networks
                                type: dict
                    public_ip:
                        description: Public IP address configuration
                        type: dict
                        suboptions:
                            ip:
                                description: IP address
                                type: str
                                required: true
                    public_name:
                        description: Public DNS name configuration
                        type: dict
                        suboptions:
                            dns_name:
                                description: DNS name
                                type: str
                                required: true
                            refresh_interval:
                                description: DNS refresh interval in seconds
                                type: int
                    private_ip:
                        description: Private IP address configuration
                        type: dict
                        suboptions:
                            ip:
                                description: Private IP address
                                type: str
                                required: true
                            site_locator:
                                description: Site location for private IP
                                type: dict
                            inside_network:
                                description: Use inside network
                                type: dict
                            outside_network:
                                description: Use outside network
                                type: dict
                    private_name:
                        description: Private DNS name configuration
                        type: dict
                        suboptions:
                            dns_name:
                                description: Private DNS name
                                type: str
                                required: true
                            refresh_interval:
                                description: DNS refresh interval in seconds
                                type: int
            port:
                description:
                    - Port number for the origin servers
                type: int
            automatic_port:
                description:
                    - Use automatic port selection
                type: dict
            lb_port:
                description:
                    - Use load balancer port
                type: dict
            same_as_endpoint_port:
                description:
                    - Use the same port as the endpoint
                type: dict
            no_tls:
                description:
                    - Disable TLS for connections to origin servers
                type: dict
            use_tls:
                description:
                    - TLS configuration for connections to origin servers
                type: dict
                suboptions:
                    no_mtls:
                        description: Disable mutual TLS
                        type: dict
                    use_mtls:
                        description: Enable mutual TLS with certificates
                        type: dict
                    skip_server_verification:
                        description: Skip server certificate verification
                        type: dict
                    use_server_verification:
                        description: Enable server certificate verification
                        type: dict
                    sni:
                        description: Server Name Indication value
                        type: str
                    disable_sni:
                        description: Disable SNI
                        type: dict
                    use_host_header_as_sni:
                        description: Use Host header as SNI
                        type: dict
                    tls_config:
                        description: TLS security configuration
                        type: dict
                        suboptions:
                            default_security:
                                description: Use default TLS security
                                type: dict
                            low_security:
                                description: Use low TLS security
                                type: dict
                            medium_security:
                                description: Use medium TLS security
                                type: dict
                            custom_security:
                                description: Custom TLS security settings
                                type: dict
'''

EXAMPLES = r'''
---
- name: Configure Origin pool
  hosts: webservers
  collections:
    - yoctoalex.xc_cloud_modules
  connection: local

  environment:
    XC_API_TOKEN: "your_api_token"
    XC_TENANT: "console.ves.volterra.io"

  tasks:
    - name: create origin pool
      origin_pool:
        state: present
        metadata:
          namespace: "default"
          name: "demo-pool"
        spec:
          origin_servers:
            - k8s_service:
                service_name: "demo-app.default"
                site_locator:
                  virtual_site:
                    tenant: "ves-io"
                    namespace: "shared"
                    name: "ves-io-all-res"
                vk8s_networks:
          port: 8080
          loadbalancer_algorithm: "LB_OVERRIDE"
          endpoint_selection: "LOCAL_PREFERRED"
'''

RETURN = r'''
changed:
    description: 
        - Indicates whether the origin pool was modified during execution
        - True when pool was created, updated, or deleted
        - False when no changes were needed (idempotent operation)
    returned: always
    type: bool
    sample: true
resource:
    description: 
        - Complete origin pool resource data from F5 XC API
        - Contains fields specified in the returnables configuration
        - Only returned when state=present and operation succeeds
        - Fields are filtered based on returnables parameter settings
    returned: when state=present
    type: dict
    sample: {
        "metadata": {
            "annotations": {},
            "description": "Production origin pool for web services",
            "disable": false,
            "labels": {
                "environment": "production",
                "team": "infrastructure"
            },
            "name": "production-pool",
            "namespace": "production"
        },
        "spec": {
            "advanced_options": {
                "auto_http_config": {},
                "circuit_breaker": {
                    "connection_limit": 1000,
                    "max_requests": 100,
                    "pending_requests": 50,
                    "priority": "DEFAULT",
                    "retries": 3
                },
                "connection_timeout": 30000,
                "default_circuit_breaker": {},
                "disable_circuit_breaker": {},
                "disable_lb_source_ip_persistance": {},
                "disable_outlier_detection": {},
                "disable_proxy_protocol": {},
                "disable_subsets": {},
                "enable_lb_source_ip_persistance": {},
                "enable_subsets": {
                    "any_endpoint": {},
                    "default_subset": {
                        "default_subset": {}
                    },
                    "endpoint_subsets": [
                        {
                            "keys": [
                                "version"
                            ]
                        }
                    ],
                    "fail_request": {}
                },
                "http1_config": {
                    "header_transformation": {
                        "default_header_transformation": {},
                        "legacy_header_transformation": {},
                        "preserve_case_header_transformation": {},
                        "proper_case_header_transformation": {}
                    }
                },
                "http2_options": {
                    "enabled": true
                },
                "http_idle_timeout": 60000,
                "no_panic_threshold": {},
                "outlier_detection": {
                    "base_ejection_time": 30000,
                    "consecutive_5xx": 5,
                    "consecutive_gateway_failure": 5,
                    "interval": 30000,
                    "max_ejection_percent": 50
                },
                "panic_threshold": 50,
                "proxy_protocol_v1": {},
                "proxy_protocol_v2": {}
            },
            "automatic_port": {},
            "endpoint_selection": "DISTRIBUTED",
            "health_check_port": 8080,
            "healthcheck": [
                {
                    "name": "web-health-check",
                    "namespace": "production",
                    "tenant": "ves-io"
                }
            ],
            "lb_port": {},
            "loadbalancer_algorithm": "ROUND_ROBIN",
            "no_tls": {},
            "origin_servers": [
                {
                    "k8s_service": {
                        "inside_network": {},
                        "outside_network": {},
                        "protocol": "PROTOCOL_TCP",
                        "service_name": "web-service.production",
                        "site_locator": {
                            "virtual_site": {
                                "name": "ves-io-all-res",
                                "namespace": "shared",
                                "tenant": "ves-io"
                            }
                        },
                        "snat_pool": {
                            "no_snat_pool": {}
                        },
                        "vk8s_networks": {}
                    }
                },
                {
                    "public_ip": {
                        "ip": "203.0.113.10"
                    }
                },
                {
                    "private_ip": {
                        "inside_network": {},
                        "ip": "10.0.1.100",
                        "outside_network": {},
                        "site_locator": {
                            "site": {
                                "name": "dc-site-1",
                                "namespace": "system",
                                "tenant": "ves-io"
                            }
                        },
                        "snat_pool": {
                            "no_snat_pool": {}
                        }
                    }
                }
            ],
            "port": 8080,
            "same_as_endpoint_port": {},
            "upstream_conn_pool_reuse_type": {
                "enable_conn_pool_reuse": {}
            },
            "use_tls": {
                "default_session_key_caching": {},
                "disable_session_key_caching": {},
                "disable_sni": {},
                "max_session_keys": 100,
                "no_mtls": {},
                "skip_server_verification": {},
                "sni": "api.example.com",
                "tls_config": {
                    "default_security": {}
                },
                "use_host_header_as_sni": {},
                "use_server_verification": {
                    "trusted_ca": {
                        "name": "system-ca",
                        "namespace": "shared",
                        "tenant": "ves-io"
                    }
                },
                "volterra_trusted_ca": {}
            }
        },
        "system_metadata": {
            "creation_timestamp": "2023-01-01T00:00:00.000000Z",
            "creator_class": "user",
            "creator_id": "admin@example.com",
            "deletion_timestamp": null,
            "finalizers": [],
            "labels": {},
            "modification_timestamp": "2023-01-15T10:30:00.000000Z",
            "object_index": 12345,
            "owner_view": {
                "kind": "origin_pool",
                "name": "production-pool",
                "namespace": "production",
                "uid": "ves-io-99999999-8888-7777-6666-555555555555"
            },
            "tenant": "ves-io",
            "uid": "ves-io-99999999-8888-7777-6666-555555555555"
        }
    }
msg:
    description:
        - Human-readable message describing the operation result
        - Provides context about what action was taken
    returned: when changed=true or when errors occur
    type: str
    sample: "Origin pool 'production-pool' was created successfully"
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
from ..module_utils.constants import ORIGIN_POOLS_ENDPOINT_NONVERSIONED

def build_endpoint(namespace, name=None):
    """Build origin pool endpoint URL."""
    base = ORIGIN_POOLS_ENDPOINT_NONVERSIONED.format(namespace=namespace)
    return base if name is None else f"{base}/{name}"


class OriginPoolParameters(BaseParameters):
    """Parameters class for origin pool-specific processing."""
    returnables = ["metadata", "spec", "system_metadata"]
    updatables = ["metadata", "spec"]

    @property
    def metadata(self):
        """Construct metadata according to API specification."""
        metadata = self._values.get('metadata', {})
        if not metadata:
            return metadata
            
        # Process metadata normally for origin pool resources
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


class OriginPoolManager(BaseManager):
    """Manager for origin pool resources using BaseManager."""
    
    resource_singular = "origin_pool"
    ignore_change_paths = [
        # Add any paths that should be ignored during change detection
    ]

    def __init__(self, module, api=None):
        super(OriginPoolManager, self).__init__(module, api)
        # Override the want parameter to use origin pool-specific processing
        self.want = OriginPoolParameters(self.params)
        self.have = OriginPoolParameters({})

    # -------- Required abstract method implementations --------
    def _get_resource_name(self):
        """Extract origin pool name from params."""
        return self.params.get('metadata', {}).get('name')

    def _build_endpoint(self, name=None):
        """Build origin pool endpoint URL."""
        namespace = self.params.get('metadata', {}).get('namespace')
        if not namespace:
            self.module.fail_json(msg="Namespace is required for origin pool operations")
        return build_endpoint(namespace, name)

    def _desired_body(self):
        """Build request body for origin pool operations."""
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
        """Create origin pool-specific parameters instance."""
        return OriginPoolParameters(data)


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
                    advanced_options=dict(
                        type='dict',
                        options=dict(
                            auto_http_config=dict(type='dict'),
                            circuit_breaker=dict(
                                type='dict',
                                options=dict(
                                    connection_limit=dict(type='int'),
                                    max_requests=dict(type='int'),
                                    pending_requests=dict(type='int'),
                                    priority=dict(type='str', choices=['DEFAULT']),
                                    retries=dict(type='int')
                                )
                            ),
                            default_circuit_breaker=dict(type='dict'),
                            disable_circuit_breaker=dict(type='dict'),
                            connection_timeout=dict(type='int'),
                            http_idle_timeout=dict(type='int'),
                            outlier_detection=dict(type='dict'),
                            disable_outlier_detection=dict(type='dict'),
                            proxy_protocol_v1=dict(type='dict'),
                            proxy_protocol_v2=dict(type='dict'),
                            disable_proxy_protocol=dict(type='dict'),
                            enable_lb_source_ip_persistance=dict(type='dict'),
                            disable_lb_source_ip_persistance=dict(type='dict'),
                            enable_subsets=dict(type='dict'),
                            disable_subsets=dict(type='dict'),
                            http1_config=dict(type='dict'),
                            http2_options=dict(type='dict'),
                            no_panic_threshold=dict(type='dict'),
                            panic_threshold=dict(type='int')
                        )
                    ),
                    automatic_port=dict(type='dict'),
                    endpoint_selection=dict(
                        type='str',
                        default="DISTRIBUTED",
                        choices=['DISTRIBUTED', 'LOCAL_ONLY', 'LOCAL_PREFERRED']
                    ),
                    health_check_port=dict(type='int'),
                    healthcheck=dict(
                        type='list', 
                        elements='dict',
                        options=dict(
                            name=dict(type='str', required=True),
                            namespace=dict(type='str', required=True),
                            tenant=dict(type='str')
                        )
                    ),
                    lb_port=dict(type='dict'),
                    loadbalancer_algorithm=dict(
                        type='str',
                        default="ROUND_ROBIN",
                        choices=['ROUND_ROBIN', 'LEAST_REQUEST', 'RING_HASH', 'RANDOM', 'LB_OVERRIDE']
                    ),
                    no_tls=dict(type='dict'),
                    origin_servers=dict(
                        type='list', 
                        elements='dict',
                        options=dict(
                            k8s_service=dict(
                                type='dict',
                                options=dict(
                                    service_name=dict(type='str', required=True),
                                    protocol=dict(
                                        type='str',
                                        choices=['PROTOCOL_TCP', 'PROTOCOL_UDP'],
                                        default='PROTOCOL_TCP'
                                    ),
                                    site_locator=dict(
                                        type='dict',
                                        options=dict(
                                            site=dict(
                                                type='dict',
                                                options=dict(
                                                    name=dict(type='str', required=True),
                                                    namespace=dict(type='str', required=True),
                                                    tenant=dict(type='str')
                                                )
                                            ),
                                            virtual_site=dict(
                                                type='dict',
                                                options=dict(
                                                    name=dict(type='str', required=True),
                                                    namespace=dict(type='str', required=True),
                                                    tenant=dict(type='str')
                                                )
                                            )
                                        )
                                    ),
                                    inside_network=dict(type='dict'),
                                    outside_network=dict(type='dict'),
                                    vk8s_networks=dict(type='dict'),
                                    snat_pool=dict(type='dict')
                                )
                            ),
                            public_ip=dict(
                                type='dict',
                                options=dict(
                                    ip=dict(type='str', required=True)
                                )
                            ),
                            public_name=dict(
                                type='dict',
                                options=dict(
                                    dns_name=dict(type='str', required=True),
                                    refresh_interval=dict(type='int')
                                )
                            ),
                            private_ip=dict(
                                type='dict',
                                options=dict(
                                    ip=dict(type='str', required=True),
                                    site_locator=dict(type='dict'),
                                    inside_network=dict(type='dict'),
                                    outside_network=dict(type='dict'),
                                    segment=dict(type='dict'),
                                    snat_pool=dict(type='dict')
                                )
                            ),
                            private_name=dict(
                                type='dict',
                                options=dict(
                                    dns_name=dict(type='str', required=True),
                                    refresh_interval=dict(type='int'),
                                    site_locator=dict(type='dict'),
                                    inside_network=dict(type='dict'),
                                    outside_network=dict(type='dict'),
                                    segment=dict(type='dict'),
                                    snat_pool=dict(type='dict')
                                )
                            ),
                            vn_private_ip=dict(
                                type='dict',
                                options=dict(
                                    ip=dict(type='str', required=True),
                                    virtual_network=dict(type='dict')
                                )
                            ),
                            vn_private_name=dict(
                                type='dict',
                                options=dict(
                                    dns_name=dict(type='str', required=True),
                                    private_network=dict(type='dict')
                                )
                            ),
                            cbip_service=dict(type='dict'),
                            consul_service=dict(type='dict'),
                            custom_endpoint_object=dict(type='dict'),
                            labels=dict(type='dict', default={})
                        )
                    ),
                    port=dict(type='int'),
                    same_as_endpoint_port=dict(type='dict'),
                    upstream_conn_pool_reuse_type=dict(
                        type='dict',
                        options=dict(
                            disable_conn_pool_reuse=dict(type='dict'),
                            enable_conn_pool_reuse=dict(type='dict')
                        )
                    ),
                    use_tls=dict(
                        type='dict',
                        options=dict(
                            no_mtls=dict(type='dict'),
                            use_mtls=dict(type='dict'),
                            use_mtls_obj=dict(type='dict'),
                            skip_server_verification=dict(type='dict'),
                            use_server_verification=dict(type='dict'),
                            sni=dict(type='str'),
                            disable_sni=dict(type='dict'),
                            use_host_header_as_sni=dict(type='dict'),
                            default_session_key_caching=dict(type='dict'),
                            disable_session_key_caching=dict(type='dict'),
                            max_session_keys=dict(type='int'),
                            tls_config=dict(
                                type='dict',
                                options=dict(
                                    default_security=dict(type='dict'),
                                    low_security=dict(type='dict'),
                                    medium_security=dict(type='dict'),
                                    custom_security=dict(type='dict')
                                )
                            ),
                            volterra_trusted_ca=dict(type='dict')
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
        mm = OriginPoolManager(module=module)
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
