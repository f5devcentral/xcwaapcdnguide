#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: cdn_loadbalancer
short_description: Manage F5 Distributed Cloud CDN Load Balancers
description:
    - Create, update, and delete F5 Distributed Cloud CDN Load Balancer configurations using BaseManager architecture
    - CDN Load Balancers provide content delivery network capabilities with origin pool management, caching, and security features
    - Supports HTTP/HTTPS protocols, SSL/TLS termination, and comprehensive security policies including WAF integration
    - Built on the generic BaseManager framework for consistent module behavior with intelligent change detection
    - Provides configurable output fields and full check mode support
    - Integrates with F5 XC ecosystem for comprehensive content delivery and application protection
version_added: "0.1.0"
options:
    state:
        description:
            - Desired state of the application firewall
            - C(present) ensures the firewall is created or updated
            - C(absent) ensures the firewall is removed
        type: str
        choices: [present, absent]
        default: present
    metadata:
        description:
            - Metadata for the CDN Load Balancer resource
        type: dict
        required: true
        suboptions:
            name:
                description:
                    - Name of the CDN Load Balancer. Must be unique within the namespace
                    - Must follow DNS-1035 format
                    - Cannot be changed after creation
                type: str
                required: true
            namespace:
                description:
                    - Namespace where the CDN Load Balancer will be created
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
                    - Human readable description for the CDN Load Balancer
                    - Used for documentation and identification purposes
                type: str
            disable:
                description:
                    - Administratively disable the CDN Load Balancer
                    - When set to true, the load balancer becomes non-functional
                type: bool
                default: false
    spec:
        description:
            - Specification for the CDN Load Balancer configuration
            - Contains all CDN-specific settings including domains, origin pools, and security policies
        type: dict
        default: {}
        suboptions:
            domains:
                description:
                    - List of domains for the CDN Load Balancer
                    - These are the domains that will be served by the CDN
                type: list
                elements: str
                required: true
            origin_pool:
                description:
                    - Configuration for the origin pool
                    - Defines where content is sourced from
                type: dict
                suboptions:
                    public_name:
                        description:
                            - DNS name for the origin server
                        type: dict
                    origin_servers:
                        description:
                            - List of origin servers
                        type: list
                        elements: dict
                    no_tls:
                        description:
                            - Disable TLS for origin connections
                        type: dict
                    use_tls:
                        description:
                            - Enable and configure TLS for origin connections
                        type: dict
                    follow_origin_redirect:
                        description:
                            - Follow redirects from origin servers
                        type: bool
            http:
                description:
                    - HTTP configuration for the CDN Load Balancer
                type: dict
                suboptions:
                    dns_volterra_managed:
                        description:
                            - Use Volterra-managed DNS
                        type: bool
            https:
                description:
                    - HTTPS configuration for the CDN Load Balancer
                type: dict
            https_auto_cert:
                description:
                    - Automatic certificate management for HTTPS
                type: dict
            app_firewall:
                description:
                    - Application firewall configuration
                type: dict
            bot_defense:
                description:
                    - Bot defense configuration
                type: dict
            client_side_defense:
                description:
                    - Client-side defense configuration
                type: dict
            captcha_challenge:
                description:
                    - CAPTCHA challenge configuration
                type: dict
            js_challenge:
                description:
                    - JavaScript challenge configuration
                type: dict
            enable_challenge:
                description:
                    - Enable challenge mechanisms
                type: dict
            no_challenge:
                description:
                    - Disable challenge mechanisms
                type: dict
            policy_based_challenge:
                description:
                    - Policy-based challenge configuration
                type: dict
            api_rate_limit:
                description:
                    - API rate limiting configuration
                type: dict
            rate_limit:
                description:
                    - General rate limiting configuration
                type: dict
            disable_rate_limit:
                description:
                    - Disable rate limiting
                type: dict
            disable_waf:
                description:
                    - Disable Web Application Firewall
                type: dict
            enable_ip_reputation:
                description:
                    - Enable IP reputation checking
                type: dict
            disable_ip_reputation:
                description:
                    - Disable IP reputation checking
                type: dict
            enable_malicious_user_detection:
                description:
                    - Enable malicious user detection
                type: dict
            disable_malicious_user_detection:
                description:
                    - Disable malicious user detection
                type: dict
            enable_threat_mesh:
                description:
                    - Enable threat mesh protection
                type: dict
            disable_threat_mesh:
                description:
                    - Disable threat mesh protection
                type: dict
            api_specification:
                description:
                    - API specification configuration
                type: dict
            disable_api_definition:
                description:
                    - Disable API definition
                type: dict
            enable_api_discovery:
                description:
                    - Enable API discovery
                type: dict
            disable_api_discovery:
                description:
                    - Disable API discovery
                type: dict
            jwt_validation:
                description:
                    - JWT validation configuration
                type: dict
            cors_policy:
                description:
                    - CORS policy configuration
                type: dict
            csrf_policy:
                description:
                    - CSRF policy configuration
                type: dict
            graphql_rules:
                description:
                    - GraphQL rules configuration
                type: list
                elements: dict
            data_guard_rules:
                description:
                    - Data guard rules configuration
                type: list
                elements: dict
            ddos_mitigation_rules:
                description:
                    - DDoS mitigation rules
                type: list
                elements: dict
            blocked_clients:
                description:
                    - List of blocked clients
                type: list
                elements: dict
            trusted_clients:
                description:
                    - List of trusted clients
                type: list
                elements: dict
            custom_cache_rule:
                description:
                    - Custom cache rule configuration
                type: dict
            default_cache_action:
                description:
                    - Default cache action configuration
                type: dict
            active_service_policies:
                description:
                    - Active service policies configuration
                type: dict
            no_service_policies:
                description:
                    - Disable service policies
                type: dict
            service_policies_from_namespace:
                description:
                    - Use service policies from namespace
                type: dict
            l7_ddos_action_block:
                description:
                    - Layer 7 DDoS action block configuration
                type: dict
            l7_ddos_action_default:
                description:
                    - Layer 7 DDoS default action configuration
                type: dict
            l7_ddos_action_js_challenge:
                description:
                    - Layer 7 DDoS JavaScript challenge action
                type: dict
            slow_ddos_mitigation:
                description:
                    - Slow DDoS mitigation configuration
                type: dict
            user_identification:
                description:
                    - User identification configuration
                type: dict
            user_id_client_ip:
                description:
                    - User ID client IP configuration
                type: dict
            sensitive_data_policy:
                description:
                    - Sensitive data policy configuration
                type: dict
            default_sensitive_data_policy:
                description:
                    - Default sensitive data policy configuration
                type: dict
            protected_cookies:
                description:
                    - Protected cookies configuration
                type: list
                elements: dict
            other_settings:
                description:
                    - Other miscellaneous settings
                type: dict
            system_default_timeouts:
                description:
                    - System default timeout configuration
                type: dict
            disable_client_side_defense:
                description:
                    - Disable client-side defense
                type: dict
            add_location:
                description:
                    - Add location information
                type: bool
                description:
                    - Custom blocking response page configuration
                    - Allows customization of user-facing block pages
                type: dict
            bot_protection_setting:
                description:
                    - Bot protection configuration settings
                    - Controls detection and handling of automated traffic
                type: dict
            custom_anonymization:
                description:
                    - Custom anonymization settings for logs and reports
                    - Specifies which data elements to anonymize
                type: dict
            default_anonymization:
                description:
                    - Use default anonymization settings
                    - Applies standard anonymization rules
                type: dict
            default_bot_setting:
                description:
                    - Use default bot protection settings
                    - Applies standard bot detection and mitigation
                type: dict
            default_detection_settings:
                description:
                    - Use default threat detection settings
                    - Applies standard security signatures and rules
                type: dict
            detection_settings:
                description:
                    - Custom threat detection configuration
                    - Allows fine-tuning of security signatures and rules
                type: dict
            disable_anonymization:
                description:
                    - Disable anonymization for logs and reports
                    - Use when full data visibility is required
                type: dict
            monitoring:
                description:
                    - Enable monitoring mode without blocking
                    - Threats are detected and logged but not blocked
                type: dict
            use_default_blocking_page:
                description:
                    - Use the default system blocking page
                    - Standard block page for detected threats
                type: dict
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
  - F5 XC tenant with appropriate permissions for application firewall management
notes:
  - This module uses the generic BaseManager architecture for consistent behavior
  - Application firewall policies protect web applications from various attack vectors
  - The module supports both monitoring and blocking modes for flexible deployment
  - Idempotent operations are supported through intelligent change detection
  - Check mode is fully supported for testing configuration changes
  - Use returnables parameter to control which fields are included in output
seealso:
  - module: f5_xc_cloud.xc_cloud_modules.namespace
  - module: f5_xc_cloud.xc_cloud_modules.http_loadbalancer
  - module: f5_xc_cloud.xc_cloud_modules.origin_pool
'''

EXAMPLES = r'''
---
# Create a basic CDN Load Balancer
- name: Create basic CDN Load Balancer
  f5_xc_cloud.xc_cloud_modules.cdn_loadbalancer:
    state: present
    metadata:
      name: "basic-cdn-lb"
      namespace: "production"
      description: "Basic CDN Load Balancer"
    spec:
      domains:
        - "cdn.example.com"
      origin_pool:
        public_name:
          dns_name: "origin.example.com"
        no_tls: {}
      http:
        dns_volterra_managed: false

# Create CDN Load Balancer with HTTPS and WAF protection
- name: Create secure CDN Load Balancer
  f5_xc_cloud.xc_cloud_modules.cdn_loadbalancer:
    state: present
    metadata:
      name: "secure-cdn-lb"
      namespace: "production"
      description: "Secure CDN with HTTPS and WAF"
      labels:
        environment: "production"
        security-level: "high"
    spec:
      domains:
        - "secure-cdn.example.com"
      origin_pool:
        public_name:
          dns_name: "secure-origin.example.com"
        use_tls: {}
        follow_origin_redirect: true
      https_auto_cert: {}
      app_firewall:
        ref:
          name: "production-waf"
          namespace: "shared"

# Create comprehensive CDN Load Balancer with multiple security features
- name: Create comprehensive CDN Load Balancer
  f5_xc_cloud.xc_cloud_modules.cdn_loadbalancer:
    state: present
    metadata:
      name: "comprehensive-cdn-lb"
      namespace: "production"
      description: "Full-featured CDN with security"
      labels:
        environment: "production"
        team: "platform"
        criticality: "high"
      annotations:
        managed-by: "ansible"
        contact: "platform-team@example.com"
    spec:
      domains:
        - "api.example.com"
        - "app.example.com"
      origin_pool:
        origin_servers:
          - public_name:
              dns_name: "api-server1.example.com"
          - public_name:
              dns_name: "api-server2.example.com"
        use_tls:
          tls_config:
            default_security: true
        follow_origin_redirect: false
      https_auto_cert: {}
      app_firewall:
        ref:
          name: "api-protection-waf"
          namespace: "security"
      bot_defense: {}
      enable_malicious_user_detection: {}
      api_rate_limit:
        api_endpoint_rules:
          - metadata:
              name: "login-limit"
            api_endpoint:
              path: "/api/login"
              methods: ["POST"]
            rate_limit:
              rate_limit_type: "PER_IP"
              requests_per_period: 5
              period: 60
      cors_policy:
        allow_origin:
          - "https://trusted-app.example.com"
        allow_methods:
          - "GET"
          - "POST"
          - "PUT"
        allow_headers:
          - "Content-Type"
          - "Authorization"

# Remove CDN Load Balancer
- name: Remove CDN Load Balancer
  f5_xc_cloud.xc_cloud_modules.cdn_loadbalancer:
    state: absent
    metadata:
      name: "old-cdn-lb"
      namespace: "production"
      ai_risk_based_blocking:
        high_risk_action: "AI_BLOCK"
        medium_risk_action: "AI_BLOCK"
        low_risk_action: "AI_BLOCK"
      blocking: {}
      detection_settings:
        signature_selection_setting:
          attack_type_settings:
            disabled_attack_types:
              - "ATTACK_TYPE_COMMAND_EXECUTION"
          high_medium_low_accuracy_signatures: {}
        enable_suppression: {}
        enable_threat_campaigns: {}
        violation_settings:
          disabled_violation_types:
            - "VIOL_HTTP_PROTOCOL_BAD_HTTP_VERSION"
      bot_protection_setting:
        malicious_bot_action: "BLOCK"
        suspicious_bot_action: "REPORT"
        good_bot_action: "REPORT"
      allow_all_response_codes: {}
      default_anonymization: {}

# Create WAF with custom blocking page
- name: Create WAF with custom blocking page
  f5_xc_cloud.xc_cloud_modules.application_firewall:
    state: present
    metadata:
      name: "custom-block-waf"
      namespace: "production"
      description: "WAF with custom blocking page"
    spec:
      blocking: {}
      blocking_page:
        response_code: "Forbidden"
        blocking_page: "string:///customized_blocking_page_content"
      detection_settings:
        signature_selection_setting:
          high_medium_low_accuracy_signatures: {}
        enable_suppression: {}
        enable_threat_campaigns: {}

# Create WAF in monitoring mode (non-blocking)
- name: Create monitoring-only WAF
  f5_xc_cloud.xc_cloud_modules.application_firewall:
    state: present
    metadata:
      name: "monitoring-waf"
      namespace: "staging"
      description: "WAF in monitoring mode for testing"
      labels:
        environment: "staging"
        mode: "monitoring"
    spec:
      monitoring: {}
      default_detection_settings: {}
      default_bot_setting: {}
      allow_all_response_codes: {}
      default_anonymization: {}

# Update existing WAF to add bot protection
- name: Update WAF with bot protection
  f5_xc_cloud.xc_cloud_modules.application_firewall:
    state: present
    metadata:
      name: "existing-waf"
      namespace: "production"
      description: "Updated WAF with enhanced bot protection"
    spec:
      blocking: {}
      bot_protection_setting:
        malicious_bot_action: "BLOCK"
        suspicious_bot_action: "CHALLENGE"
        good_bot_action: "ALLOW"
      default_detection_settings: {}

# Remove an application firewall
- name: Remove application firewall
  f5_xc_cloud.xc_cloud_modules.application_firewall:
    state: absent
    metadata:
      name: "old-waf"
      namespace: "production"

# Check mode - verify what changes would be made
- name: Check WAF configuration changes
  f5_xc_cloud.xc_cloud_modules.application_firewall:
    state: present
    metadata:
      name: "test-waf"
      namespace: "staging"
      description: "Testing WAF configuration"
      labels:
        environment: "test"
    spec:
      monitoring: {}
      default_detection_settings: {}
  check_mode: yes

# Configure specific return fields in output
- name: Create WAF with limited output
  f5_xc_cloud.xc_cloud_modules.application_firewall:
    state: present
    metadata:
      name: "minimal-output-waf"
      namespace: "production"
      description: "WAF with minimal output"
    spec:
      blocking: {}
      default_detection_settings: {}
    returnables: ["metadata"]
  register: result

# Create multiple WAFs for different environments
- name: Create environment-specific WAFs
  f5_xc_cloud.xc_cloud_modules.application_firewall:
    state: present
    metadata:
      name: "{{ item.name }}-waf"
      namespace: "{{ item.namespace }}"
      description: "{{ item.description }}"
      labels: "{{ item.labels }}"
    spec: "{{ item.spec }}"
  loop:
    - name: "dev"
      namespace: "development"
      description: "Development environment WAF"
      labels:
        environment: "development"
        protection-level: "low"
      spec:
        monitoring: {}
        default_detection_settings: {}
    - name: "prod"
      namespace: "production"
      description: "Production environment WAF"
      labels:
        environment: "production"
        protection-level: "high"
      spec:
        blocking: {}
        ai_risk_based_blocking:
          high_risk_action: "AI_BLOCK"
          medium_risk_action: "AI_BLOCK"
          low_risk_action: "AI_REPORT"
'''

RETURN = r'''
changed:
    description: 
        - Indicates whether the CDN Load Balancer was modified during execution
        - True when load balancer was created, updated, or deleted
        - False when no changes were needed (idempotent operation)
    returned: always
    type: bool
    sample: true
resource:
    description: 
        - Complete CDN Load Balancer resource data from F5 XC API
        - Contains fields specified in the returnables configuration
        - Only returned when state=present and operation succeeds
        - Fields are filtered based on returnables parameter settings
    returned: when state=present
    type: dict
    sample: {
        "metadata": {
            "name": "production-cdn-lb",
            "namespace": "production",
            "labels": {
                "environment": "production",
                "team": "platform",
                "service": "content-delivery"
            },
            "annotations": {
                "managed-by": "ansible",
                "contact": "platform-team@example.com"
            },
            "description": "Production CDN Load Balancer",
            "disable": false,
            "uid": "ves-io-99999999-8888-7777-6666-555555555555",
            "creation_timestamp": "2023-01-01T00:00:00.000000Z",
            "modification_timestamp": "2023-01-15T10:30:00.000000Z"
        },
        "spec": {
            "domains": [
                "cdn.example.com",
                "api.example.com"
            ],
            "origin_pool": {
                "public_name": {
                    "dns_name": "origin.example.com"
                },
                "use_tls": {
                    "tls_config": {
                        "default_security": true
                    }
                },
                "follow_origin_redirect": false
            },
            "https_auto_cert": {},
            "app_firewall": {
                "ref": {
                    "name": "production-waf",
                    "namespace": "security"
                }
            },
            "bot_defense": {},
            "enable_malicious_user_detection": {},
            "api_rate_limit": {
                "api_endpoint_rules": [
                    {
                        "metadata": {
                            "name": "login-limit"
                        },
                        "api_endpoint": {
                            "path": "/api/login",
                            "methods": ["POST"]
                        },
                        "rate_limit": {
                            "rate_limit_type": "PER_IP",
                            "requests_per_period": 5,
                            "period": 60
                        }
                    }
                ]
            }
        },
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
    returned: when changed=true or when errors occur
    type: str
    sample: "Application firewall 'production-waf' was created successfully"
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
from ..module_utils.constants import (
    CDN_LOADBALANCERS_ENDPOINT_NONVERSIONED
)

def build_endpoint(namespace, name=None):
    """Build CDN Load Balancer endpoint URL."""
    base = CDN_LOADBALANCERS_ENDPOINT_NONVERSIONED.format(namespace=namespace)
    return base if name is None else f"{base}/{name}"


class CdnLoadbalancerParameters(BaseParameters):
    """Parameters class for CDN Load Balancer-specific processing."""
    returnables = ["metadata", "spec", "system_metadata"]
    updatables = ["metadata", "spec"]

    @property
    def metadata(self):
        """Construct metadata according to API specification."""
        metadata = self._values.get('metadata', {})
        if not metadata:
            return metadata
            
        # Process metadata normally for CDN Load Balancer resources
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


class CdnLoadbalancerManager(BaseManager):
    """Manager for CDN Load Balancer resources using BaseManager."""
    
    resource_singular = "cdn_loadbalancer"

    def __init__(self, module, api=None):
        super(CdnLoadbalancerManager, self).__init__(module, api)
        # Override the want parameter to use CDN Load Balancer-specific processing
        self.want = CdnLoadbalancerParameters(self.params)
        self.have = CdnLoadbalancerParameters({})

    # -------- Required abstract method implementations --------
    def _get_resource_name(self):
        """Extract CDN Load Balancer name from params."""
        return self.params.get('metadata', {}).get('name')

    def _build_endpoint(self, name=None):
        """Build CDN Load Balancer endpoint URL."""
        namespace = self.params.get('metadata', {}).get('namespace')
        if not namespace:
            self.module.fail_json(msg="Namespace is required for CDN Load Balancer operations")
        return build_endpoint(namespace, name)

    def _desired_body(self):
        """Build request body for CDN Load Balancer operations."""
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
        """Create CDN Load Balancer-specific parameters instance."""
        return CdnLoadbalancerParameters(data)


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
                    # Core CDN LB configuration
                    domains=dict(type='list', elements='str'),
                    origin_pool=dict(type='dict'),
                    
                    # Protocol configurations
                    http=dict(type='dict'),
                    https=dict(type='dict'),
                    https_auto_cert=dict(type='dict'),
                    
                    # Security and protection features
                    app_firewall=dict(type='dict'),
                    bot_defense=dict(type='dict'),
                    client_side_defense=dict(type='dict'),
                    captcha_challenge=dict(type='dict'),
                    js_challenge=dict(type='dict'),
                    enable_challenge=dict(type='dict'),
                    no_challenge=dict(type='dict'),
                    policy_based_challenge=dict(type='dict'),
                    
                    # Rate limiting and traffic management
                    api_rate_limit=dict(type='dict'),
                    rate_limit=dict(type='dict'),
                    disable_rate_limit=dict(type='dict'),
                    
                    # WAF and security policies
                    disable_waf=dict(type='dict'),
                    enable_ip_reputation=dict(type='dict'),
                    disable_ip_reputation=dict(type='dict'),
                    enable_malicious_user_detection=dict(type='dict'),
                    disable_malicious_user_detection=dict(type='dict'),
                    enable_threat_mesh=dict(type='dict'),
                    disable_threat_mesh=dict(type='dict'),
                    
                    # API features
                    api_specification=dict(type='dict'),
                    disable_api_definition=dict(type='dict'),
                    enable_api_discovery=dict(type='dict'),
                    disable_api_discovery=dict(type='dict'),
                    jwt_validation=dict(type='dict'),
                    
                    # Security policies and rules
                    cors_policy=dict(type='dict'),
                    csrf_policy=dict(type='dict'),
                    graphql_rules=dict(type='list', elements='dict', default=[]),
                    data_guard_rules=dict(type='list', elements='dict', default=[]),
                    ddos_mitigation_rules=dict(type='list', elements='dict', default=[]),

                    # Client management
                    blocked_clients=dict(type='list', elements='dict', default=[]),
                    trusted_clients=dict(type='list', elements='dict', default=[]),
                    
                    # Cache configuration
                    custom_cache_rule=dict(type='dict'),
                    default_cache_action=dict(type='dict'),
                    
                    # Service policies
                    active_service_policies=dict(type='dict'),
                    no_service_policies=dict(type='dict'),
                    service_policies_from_namespace=dict(type='dict'),
                    
                    # DDoS protection
                    l7_ddos_action_block=dict(type='dict'),
                    l7_ddos_action_default=dict(type='dict'),
                    l7_ddos_action_js_challenge=dict(type='dict'),
                    slow_ddos_mitigation=dict(type='dict'),
                    
                    # User identification
                    user_identification=dict(type='dict'),
                    user_id_client_ip=dict(type='dict'),
                    
                    # Data protection
                    sensitive_data_policy=dict(type='dict'),
                    default_sensitive_data_policy=dict(type='dict'),
                    protected_cookies=dict(type='list', elements='dict', default=[]),
                    
                    # Additional settings
                    other_settings=dict(type='dict'),
                    system_default_timeouts=dict(type='dict'),
                    disable_client_side_defense=dict(type='dict')
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
        mm = CdnLoadbalancerManager(module=module)
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
