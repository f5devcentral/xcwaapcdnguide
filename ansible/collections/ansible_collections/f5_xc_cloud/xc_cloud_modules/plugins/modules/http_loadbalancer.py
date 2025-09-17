#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: http_loadbalancer
short_description: Manage F5 Distributed Cloud HTTP Load Balancer
description:
    - Create, update, delete, or fetch F5 Distributed Cloud HTTP Load Balancers
    - Supports both HTTP and HTTPS configurations with automatic certificate management
    - Provides comprehensive load balancing, security, and traffic management features
    - Includes advanced security features like WAF, bot protection, DDoS mitigation, and API protection
    - Supports complex routing, rate limiting, and client management capabilities
    - Built on the generic BaseManager framework for consistent module behavior with intelligent change detection
    - Provides configurable output fields and full check mode support
    - This module manages the lifecycle of load balancers (create, update, delete)
version_added: "0.1.0"
options:
    state:
        description:
            - Desired state of the HTTP Load Balancer
            - C(present) ensures the load balancer is created or updated
            - C(absent) ensures the load balancer is removed
        type: str
        choices: [present, absent]
        default: present
    metadata:
        description:
            - Metadata for the HTTP Load Balancer resource
        type: dict
        required: true
        suboptions:
            name:
                description:
                    - Name of the HTTP Load Balancer (DNS-1035 format)
                    - Must be unique within the namespace
                type: str
                required: true
            namespace:
                description:
                    - Namespace where the load balancer will be created
                    - Must be a valid DNS label format
                type: str
                required: true
            labels:
                description:
                    - Key-value pairs for organizing and selecting objects
                type: dict
            annotations:
                description:
                    - Unstructured key-value metadata
                type: dict
            description:
                description:
                    - Human readable description
                type: str
            disable:
                description:
                    - Administratively disable the load balancer
                type: bool
    spec:
        description:
            - HTTP Load Balancer specification
            - Comprehensive configuration including security, routing, and advanced features
            - See F5 Distributed Cloud API documentation for detailed options
        type: dict
        suboptions:
            domains:
                description:
                    - List of domains that this load balancer will serve
                    - Must be valid FQDN format
                type: list
                elements: str
                required: true
            http:
                description:
                    - HTTP configuration (port 80)
                    - Mutually exclusive with https and https_auto_cert
                type: dict
                suboptions:
                    port:
                        description: HTTP port number
                        type: int
                        default: 80
                    dns_volterra_managed:
                        description: Use F5 XC managed DNS
                        type: bool
            https:
                description:
                    - HTTPS configuration with custom certificates
                    - Mutually exclusive with http and https_auto_cert
                type: dict
            https_auto_cert:
                description:
                    - HTTPS configuration with automatic certificate management
                    - Mutually exclusive with http and https
                type: dict
            default_route_pools:
                description:
                    - Default routing pools for load balancing
                    - List of origin pools with priority and weight
                type: list
                elements: dict
            app_firewall:
                description:
                    - Application firewall (WAF) configuration
                    - Reference to an existing application firewall policy
                type: dict
                suboptions:
                    name:
                        description: Name of the application firewall
                        type: str
                        required: true
                    namespace:
                        description: Namespace of the application firewall
                        type: str
                    tenant:
                        description: Tenant of the application firewall
                        type: str
            bot_defense:
                description:
                    - Bot protection configuration
                    - Provides advanced bot detection and mitigation capabilities
                type: dict
            rate_limit:
                description:
                    - Rate limiting configuration
                    - Controls request rates per client/endpoint
                type: dict
            blocked_clients:
                description:
                    - List of blocked client configurations
                    - IP addresses, ASNs, or other client identifiers to block
                type: list
            trusted_clients:
                description:
                    - List of trusted client configurations
                    - Clients that bypass certain security checks
                type: list
            routes:
                description:
                    - Custom routing rules
                    - Advanced routing based on path, headers, etc.
                type: list
                default: []

extends_documentation_fragment:
  - f5_xc_cloud.xc_cloud_modules.f5
  - f5_xc_cloud.xc_cloud_modules.common

notes:
  - Supports check mode for validation without making changes
  - Uses intelligent change detection to minimize unnecessary updates
  - Provides detailed diff output when run with --diff flag
  - Use returnables parameter to control which fields are included in output

seealso:
  - module: f5_xc_cloud.xc_cloud_modules.namespace
  - module: f5_xc_cloud.xc_cloud_modules.origin_pool
  - module: f5_xc_cloud.xc_cloud_modules.application_firewall
'''

EXAMPLES = r'''
---
# Create a basic HTTP Load Balancer
- name: Create basic HTTP Load Balancer
  f5_xc_cloud.xc_cloud_modules.http_loadbalancer:
    state: present
    metadata:
      name: "basic-http-lb"
      namespace: "production"
      description: "Basic HTTP Load Balancer"
    spec:
      domains:
        - "app.example.com"
      http:
        port: 80
        dns_volterra_managed: false
      default_route_pools:
        - pool:
            tenant: "system"
            namespace: "production"
            name: "backend-pool"
          weight: 1
          priority: 1

# Create HTTPS Load Balancer with WAF
- name: Create HTTPS Load Balancer with WAF
  f5_xc_cloud.xc_cloud_modules.http_loadbalancer:
    state: present
    metadata:
      name: "secure-https-lb"
      namespace: "production"
      description: "HTTPS Load Balancer with WAF protection"
    spec:
      domains:
        - "secure.example.com"
      https_auto_cert:
        port: 443
        dns_volterra_managed: true
      default_route_pools:
        - pool:
            tenant: "system"
            namespace: "production"
            name: "backend-pool"
          weight: 1
          priority: 1
      app_firewall:
        tenant: "system"
        namespace: "production"
        name: "security-policy"

# Create Load Balancer with Bot Protection and Rate Limiting
- name: Create protected Load Balancer
  f5_xc_cloud.xc_cloud_modules.http_loadbalancer:
    state: present
    metadata:
      name: "protected-lb"
      namespace: "production"
    spec:
      domains:
        - "api.example.com"
      https_auto_cert:
        port: 443
        dns_volterra_managed: true
      default_route_pools:
        - pool:
            tenant: "system"
            namespace: "production"
            name: "api-backend"
          weight: 1
          priority: 1
      bot_defense:
        regional_endpoint: "US"
      rate_limit:
        no_policies: {}

# Delete Load Balancer
- name: Delete HTTP Load Balancer
  f5_xc_cloud.xc_cloud_modules.http_loadbalancer:
    state: absent
    metadata:
      name: "old-lb"
      namespace: "production"
'''

RETURN = r'''
changed:
    description: Whether the resource was changed
    type: bool
    returned: always
resource:
    description:
        - HTTP Load Balancer resource data
        - Only returned when state=present and operation succeeds
    returned: when state=present
    type: dict
    sample:
        metadata:
            name: "example-lb"
            namespace: "production"
            description: "Example Load Balancer"
        spec:
            domains:
                - "app.example.com"
            http:
                port: 80
                dns_volterra_managed: false
        system_metadata:
            creation_timestamp: "2023-01-01T00:00:00Z"
            modification_timestamp: "2023-01-01T00:00:00Z"
            creator_id: "user@example.com"
diff:
    description:
        - Detailed diff of changes made
        - Shows before/after states and field-level changes
        - Only included when --diff flag is used
        - before: state before changes
        - after: state after changes  
        - changes: dictionary of changed fields with before/after values
    type: dict
    sample:
        before:
            spec:
                domains: ["old.example.com"]
        after:
            spec:
                domains: ["new.example.com"]
        changes:
            spec.domains:
                before: ["old.example.com"]
                after: ["new.example.com"]
    returned: when changed=true or when errors occur
message:
    description: Additional information about the operation
    type: str
    returned: when ansible verbosity >= 3
'''

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.module_base import BaseManager, BaseParameters
from ..module_utils.exceptions import F5ModuleError
from ..module_utils.common import f5_argument_spec
from ..module_utils.constants import HTTP_LOADBALANCERS_ENDPOINT_NONVERSIONED


def build_endpoint(namespace, name=None):
    """Build HTTP Load Balancer endpoint URL."""
    base = HTTP_LOADBALANCERS_ENDPOINT_NONVERSIONED.format(namespace=namespace)
    return base if name is None else f"{base}/{name}"


class HttpLoadbalancerParameters(BaseParameters):
    """Parameters class for HTTP Load Balancer-specific processing."""
    returnables = ["metadata", "spec", "system_metadata"]
    updatables = ["metadata", "spec"]

    @property
    def metadata(self):
        """Construct metadata according to API specification."""
        metadata = self._values.get('metadata', {})
        if not metadata:
            return metadata
            
        # Process metadata normally for HTTP Load Balancer resources
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


class HttpLoadbalancerManager(BaseManager):
    """Manager class for HTTP Load Balancer operations using BaseManager architecture."""
    
    resource_singular = "http_loadbalancer"

    def __init__(self, module, api=None):
        super(HttpLoadbalancerManager, self).__init__(module, api)
        # Override the want parameter to use HTTP Load Balancer-specific processing
        self.want = HttpLoadbalancerParameters(self.params)
        self.have = HttpLoadbalancerParameters({})    # -------- Required abstract method implementations --------
    def _get_resource_name(self):
        """Extract HTTP Load Balancer name from params."""
        return self.params.get('metadata', {}).get('name')
    
    def _build_endpoint(self, name=None):
        """Build HTTP Load Balancer endpoint URL."""
        namespace = self.params.get('metadata', {}).get('namespace')
        if not namespace:
            self.module.fail_json(msg="Namespace is required for HTTP Load Balancer operations")
        return build_endpoint(namespace, name)
    
    def _desired_body(self):
        """Build request body for HTTP Load Balancer operations."""
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
        """Create HTTP Load Balancer-specific parameters instance."""
        return HttpLoadbalancerParameters(data)


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True

        argument_spec = dict(
            state=dict(
                default='present',
                choices=['present', 'absent'],
                type='str'
            ),
            metadata=dict(
                type='dict',
                required=True,
                options=dict(
                    name=dict(
                        type='str',
                        required=True
                    ),
                    namespace=dict(
                        type='str',
                        required=True
                    ),
                    labels=dict(
                        type='dict',
                        default={}
                    ),
                    annotations=dict(
                        type='dict',
                        default={}
                    ),
                    description=dict(
                        type='str',
                        default=""
                    ),
                    disable=dict(
                        type='bool',
                        default=False
                    )
                )
            ),
            spec=dict(
                type='dict',
                options=dict(
                    # Core Configuration
                    domains=dict(
                        type='list',
                        elements='str'
                    ),
                    
                    # Advertising Configuration
                    add_location=dict(type='bool', default=False),
                    advertise_custom=dict(type='dict'),
                    advertise_on_public=dict(type='dict'),
                    advertise_on_public_default_vip=dict(type='dict'),
                    do_not_advertise=dict(type='dict'),
                    
                    # HTTP/HTTPS Configuration
                    http=dict(
                        type='dict',
                        options=dict(
                            dns_volterra_managed=dict(type='bool'),
                            port=dict(type='int', default=80),
                            port_ranges=dict(type='str')
                        )
                    ),
                    https=dict(
                        type='dict',
                        options=dict(
                            add_hsts=dict(type='bool'),
                            append_server_name=dict(type='str'),
                            coalescing_options=dict(type='dict'),
                            connection_idle_timeout=dict(type='int'),
                            default_header=dict(type='dict'),
                            default_loadbalancer=dict(type='dict'),
                            disable_path_normalize=dict(type='dict'),
                            enable_path_normalize=dict(type='dict'),
                            http_protocol_options=dict(type='dict'),
                            http_redirect=dict(type='bool'),
                            non_default_loadbalancer=dict(type='dict'),
                            pass_through=dict(type='dict'),
                            port=dict(type='int', default=443),
                            port_ranges=dict(type='str'),
                            server_name=dict(type='str'),
                            tls_cert_params=dict(type='dict'),
                            tls_parameters=dict(type='dict')
                        )
                    ),
                    https_auto_cert=dict(
                        type='dict',
                        options=dict(
                            add_hsts=dict(type='bool'),
                            append_server_name=dict(type='str'),
                            coalescing_options=dict(type='dict'),
                            connection_idle_timeout=dict(type='int'),
                            default_header=dict(type='dict'),
                            default_loadbalancer=dict(type='dict'),
                            disable_path_normalize=dict(type='dict'),
                            enable_path_normalize=dict(type='dict'),
                            http_protocol_options=dict(type='dict'),
                            http_redirect=dict(type='bool'),
                            no_mtls=dict(type='dict'),
                            non_default_loadbalancer=dict(type='dict'),
                            pass_through=dict(type='dict'),
                            port=dict(type='int', default=443),
                            port_ranges=dict(type='str'),
                            server_name=dict(type='str'),
                            tls_config=dict(type='dict'),
                            use_mtls=dict(type='dict')
                        )
                    ),
                    
                    # Pool Configuration
                    default_pool=dict(
                        type='dict',
                        options=dict(
                            advanced_options=dict(type='dict'),
                            automatic_port=dict(type='dict'),
                            endpoint_selection=dict(
                                type='str',
                                choices=['DISTRIBUTED', 'LOCAL_PREFERRED', 'ROUND_ROBIN']
                            ),
                            health_check_port=dict(type='int'),
                            healthcheck=dict(type='list'),
                            lb_port=dict(type='dict'),
                            loadbalancer_algorithm=dict(
                                type='str',
                                choices=['ROUND_ROBIN', 'LEAST_REQUEST', 'RING_HASH', 'RANDOM', 'MAGLEV']
                            ),
                            no_tls=dict(type='dict'),
                            origin_servers=dict(type='list'),
                            port=dict(type='int'),
                            same_as_endpoint_port=dict(type='dict'),
                            upstream_conn_pool_reuse_type=dict(type='dict'),
                            use_tls=dict(type='dict'),
                            view_internal=dict(type='dict')
                        )
                    ),
                    default_pool_list=dict(
                        type='dict',
                        options=dict(
                            pools=dict(type='list')
                        )
                    ),
                    default_route_pools=dict(type='list'),
                    routes=dict(type='list', default=[]),
                    
                    # Load Balancing Algorithms
                    least_active=dict(type='dict'),
                    random=dict(type='dict'),
                    ring_hash=dict(
                        type='dict',
                        options=dict(
                            hash_policy=dict(type='list')
                        )
                    ),
                    round_robin=dict(type='dict'),
                    
                    # Stickiness
                    cookie_stickiness=dict(
                        type='dict',
                        options=dict(
                            add_httponly=dict(type='dict'),
                            add_secure=dict(type='dict'),
                            ignore_httponly=dict(type='dict'),
                            ignore_samesite=dict(type='dict'),
                            ignore_secure=dict(type='dict'),
                            name=dict(type='str'),
                            path=dict(type='str'),
                            samesite_lax=dict(type='dict'),
                            samesite_none=dict(type='dict'),
                            samesite_strict=dict(type='dict'),
                            ttl=dict(type='int')
                        )
                    ),
                    source_ip_stickiness=dict(type='dict'),
                    
                    # Security Features - WAF
                    app_firewall=dict(
                        type='dict',
                        options=dict(
                            name=dict(type='str'),
                            namespace=dict(type='str'),
                            tenant=dict(type='str')
                        )
                    ),
                    disable_waf=dict(type='dict'),
                    
                    # Bot Protection & Challenges
                    bot_defense=dict(
                        type='dict',
                        options=dict(
                            disable_cors_support=dict(type='dict'),
                            enable_cors_support=dict(type='dict'),
                            policy=dict(type='dict'),
                            regional_endpoint=dict(
                                type='str',
                                choices=['AUTO', 'US', 'EU', 'ASIA']
                            ),
                            timeout=dict(type='int')
                        )
                    ),
                    disable_bot_defense=dict(type='dict'),
                    bot_defense_advanced=dict(type='dict'),
                    
                    captcha_challenge=dict(
                        type='dict',
                        options=dict(
                            cookie_expiry=dict(type='int'),
                            custom_page=dict(type='str')
                        )
                    ),
                    js_challenge=dict(
                        type='dict',
                        options=dict(
                            cookie_expiry=dict(type='int'),
                            custom_page=dict(type='str'),
                            js_script_delay=dict(type='int')
                        )
                    ),
                    no_challenge=dict(type='dict'),
                    enable_challenge=dict(type='dict'),
                    policy_based_challenge=dict(type='dict'),
                    
                    # Client Side Defense
                    client_side_defense=dict(type='dict'),
                    disable_client_side_defense=dict(type='dict'),
                    
                    # Rate Limiting
                    rate_limit=dict(
                        type='dict',
                        options=dict(
                            custom_ip_allowed_list=dict(type='dict'),
                            ip_allowed_list=dict(type='dict'),
                            no_ip_allowed_list=dict(type='dict'),
                            no_policies=dict(type='dict'),
                            policies=dict(type='dict'),
                            rate_limiter=dict(type='dict')
                        )
                    ),
                    disable_rate_limit=dict(type='dict'),
                    
                    # API Protection and Rate Limiting
                    api_protection_rules=dict(type='dict'),
                    api_rate_limit=dict(type='dict'),
                    api_specification=dict(type='dict'),
                    api_testing=dict(type='dict'),
                    
                    # Service Policies
                    active_service_policies=dict(type='dict'),
                    no_service_policies=dict(type='dict'),
                    service_policies_from_namespace=dict(type='dict'),
                    
                    # API Discovery and Definition
                    enable_api_discovery=dict(type='dict'),
                    disable_api_discovery=dict(type='dict'),
                    disable_api_definition=dict(type='dict'),
                    disable_api_testing=dict(type='dict'),
                    
                    # JWT Validation
                    jwt_validation=dict(type='dict'),
                    
                    # IP Reputation and Threat Detection
                    enable_ip_reputation=dict(type='dict'),
                    disable_ip_reputation=dict(type='dict'),
                    enable_malicious_user_detection=dict(type='dict'),
                    disable_malicious_user_detection=dict(type='dict'),
                    enable_threat_mesh=dict(type='dict'),
                    disable_threat_mesh=dict(type='dict'),
                    
                    # Trust Client IP Headers
                    enable_trust_client_ip_headers=dict(type='dict'),
                    disable_trust_client_ip_headers=dict(type='dict'),
                    
                    # Malware Protection
                    malware_protection_settings=dict(type='dict'),
                    disable_malware_protection=dict(type='dict'),
                    
                    # CORS and CSRF Policies
                    cors_policy=dict(type='dict'),
                    csrf_policy=dict(type='dict'),
                    
                    # GraphQL Rules
                    graphql_rules=dict(
                        type='list',
                        elements='dict',
                        default=[]
                    ),
                    
                    # Data Protection
                    data_guard_rules=dict(
                        type='list',
                        elements='dict',
                        default=[]
                    ),
                    sensitive_data_policy=dict(type='dict'),
                    default_sensitive_data_policy=dict(type='dict'),
                    sensitive_data_disclosure_rules=dict(type='dict'),
                    protected_cookies=dict(
                        type='list',
                        elements='dict',
                        default=[]
                    ),
                    
                    # DDoS Protection
                    ddos_mitigation_rules=dict(
                        type='list',
                        elements='dict',
                        default=[]
                    ),
                    l7_ddos_action_block=dict(type='dict'),
                    l7_ddos_action_default=dict(type='dict'),
                    l7_ddos_action_js_challenge=dict(type='dict'),
                    l7_ddos_protection=dict(type='dict'),
                    slow_ddos_mitigation=dict(type='dict'),
                    
                    # Caching Configuration
                    caching_policy=dict(type='dict'),
                    disable_caching=dict(type='dict'),
                    
                    # User Identification
                    user_identification=dict(type='dict'),
                    user_id_client_ip=dict(type='dict'),
                    
                    # Origin Server Subset Rules
                    origin_server_subset_rule_list=dict(type='dict'),
                    
                    # More Options and Advanced Settings
                    more_option=dict(type='dict'),
                    system_default_timeouts=dict(type='dict'),
                    
                    # Application Types
                    multi_lb_app=dict(type='dict'),
                    single_lb_app=dict(type='dict'),
                    
                    # Client Management
                    blocked_clients=dict(
                        type='list',
                        elements='dict',
                        default=[]
                    ),
                    trusted_clients=dict(
                        type='list',
                        elements='dict',
                        default=[]
                    )
                )
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
        mm = HttpLoadbalancerManager(module=module)
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()