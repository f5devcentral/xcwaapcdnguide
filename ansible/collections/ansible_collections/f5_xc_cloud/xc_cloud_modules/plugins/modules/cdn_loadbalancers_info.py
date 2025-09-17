#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: cdn_loadbalancer_info
short_description: Gather comprehensive information about F5 Distributed Cloud CDN Load Balancers
description:
    - Retrieve detailed information about F5 Distributed Cloud CDN (Content Delivery Network) Load Balancers
    - Read-only module that never changes resources (always returns changed: false)
    - List all CDN load balancers in a namespace with optional filtering capabilities
    - Filter by name, labels, or annotations to find specific load balancers
    - Access comprehensive configuration including security policies, caching rules, API protection, and advanced features
    - Supports both basic metadata retrieval and full configuration details
version_added: "0.1.0"
options:
    namespace:
        description:
            - Namespace to query for CDN Load Balancers
            - Required parameter that defines the scope of the search
        type: str
        required: true
    name:
        description:
            - Filter by CDN Load Balancer name (exact match)
            - If specified, only load balancers with this exact name will be returned
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
    full_details:
        description:
            - Fetch complete configuration details for each CDN Load Balancer
            - When false (default), returns only basic metadata (name, namespace, labels, annotations)
            - When true, retrieves comprehensive configuration including all security and performance settings
            - "Full details include:"
            - "  • Security: Web Application Firewall, Bot Defense, DDoS Protection, API Protection"
            - "  • Performance: Caching rules, Origin Pool configuration, Load Balancing settings"
            - "  • Access Control: CORS/CSRF policies, Rate Limiting, IP Reputation, Client Authentication"
            - "  • Monitoring: Service Policies, Data Guard, Malicious User Detection, Threat Intelligence"
            - "  • Advanced Features: GraphQL protection, JWT validation, Certificate management"
            - May take longer as it requires individual API calls per CDN Load Balancer
        type: bool
        default: false

extends_documentation_fragment:
  - f5_xc_cloud.xc_cloud_modules.f5
  - f5_xc_cloud.xc_cloud_modules.common

notes:
    - Always returns changed: false (read-only operation)
    - Supports check mode for validation
    - Returns empty list if no CDN Load Balancers match the filter criteria
    - All filtering is performed client-side after retrieving load balancer list
    - Full details mode provides access to comprehensive F5 XC security and performance features
    - "Comprehensive configuration coverage includes:"
    - "  • API Rate Limiting with endpoint-specific rules and bypass configurations"
    - "  • API Specification validation with OpenAPI enforcement and custom validation rules"
    - "  • Web Application Firewall integration with custom security policies"
    - "  • Advanced Bot Defense with JavaScript challenges and mobile SDK support"
    - "  • Client-Side Defense against malicious scripts and code injection"
    - "  • CORS/CSRF protection with customizable domain and method policies"
    - "  • Custom Cache Rules for content delivery optimization"
    - "  • Data Guard for sensitive information protection and compliance"
    - "  • DDoS Mitigation with L7 protection and traffic analysis"
    - "  • GraphQL security with query depth and complexity controls"
    - "  • JWT Validation for API authentication and authorization"
    - "  • Sensitive Data Policy enforcement for data loss prevention"
    - "  • Service Policy integration for advanced traffic management"
    - "  • Certificate management including auto-renewal and custom TLS configurations"

author:
    - Alex Shemyakin (@yoctoalex)
'''

EXAMPLES = r'''
- name: Get all CDN Load Balancers in namespace
  f5_xc_cloud.xc_cloud_modules.cdn_loadbalancer_info:
    namespace: "production"
  register: all_cdns

- name: Get specific CDN Load Balancer by name
  f5_xc_cloud.xc_cloud_modules.cdn_loadbalancer_info:
    namespace: "production"
    name: "my-cdn-lb"
  register: specific_cdn

- name: Filter CDN Load Balancers by labels
  f5_xc_cloud.xc_cloud_modules.cdn_loadbalancer_info:
    namespace: "production"
    labels:
      environment: "prod"
      team: "frontend"
  register: labeled_cdns

- name: Filter CDN Load Balancers by annotations
  f5_xc_cloud.xc_cloud_modules.cdn_loadbalancer_info:
    namespace: "production"
    annotations:
      "example.com/owner": "team-a"
      "example.com/purpose": "static-content"
  register: annotated_cdns

- name: Combined filtering
  f5_xc_cloud.xc_cloud_modules.cdn_loadbalancer_info:
    namespace: "production"
    name: "cdn-lb-1"
    labels:
      environment: "prod"
    annotations:
      "example.com/tier": "frontend"
  register: filtered_cdns

- name: Display found CDN Load Balancers
  debug:
    msg: "Found {{ cdn_results.resources | length }} CDN Load Balancers"
  vars:
    cdn_results: "{{ all_cdns }}"

- name: Get CDN Load Balancers with full configuration details
  f5_xc_cloud.xc_cloud_modules.cdn_loadbalancer_info:
    namespace: "production"
    full_details: true
  register: detailed_cdns

- name: Get full details for a specific CDN Load Balancer
  f5_xc_cloud.xc_cloud_modules.cdn_loadbalancer_info:
    namespace: "production"
    name: "my-cdn-lb"
    full_details: true
  register: detailed_specific_cdn
'''

RETURN = r'''
changed:
    description: Always false for info modules
    type: bool
    returned: always
    sample: false
resources:
    description: 
        - List of CDN Load Balancer resources that match the filter criteria
        - Contains comprehensive configuration data when full_details=true
        - Basic metadata only when full_details=false (default)
    type: list
    elements: dict
    returned: always
    sample:
        # Basic metadata (full_details=false)
        - metadata:
            name: "my-cdn-lb"
            namespace: "production"
            labels:
              environment: "prod"
              team: "frontend"
            annotations:
              "example.com/owner": "team-a"
          system_metadata:
            creation_timestamp: "2023-01-01T00:00:00Z"
            uid: "12345678-1234-1234-1234-123456789abc"
        
        # Full configuration details (full_details=true)
        - metadata:
            name: "comprehensive-cdn-lb"
            namespace: "production"
            labels:
              environment: "prod"
              security: "enhanced"
            annotations:
              "example.com/tier": "enterprise"
          get_spec:
            # Core Configuration
            domains: ["cdn.example.com", "api.example.com"]
            origin_pool:
              origin_servers:
                - public_name:
                    dns_name: "backend.example.com"
                  port: 443
              use_tls:
                default_security: {}
                use_server_verification:
                  volterra_trusted_ca: {}
            
            # Security Features
            app_firewall:
              name: "enterprise-waf"
              namespace: "security"
            
            bot_defense:
              policy:
                protected_app_endpoints:
                  - any_domain: {}
                    path:
                      prefix: "/api"
                    mitigation:
                      block: {}
                    flow_label:
                      authentication: {}
            
            # API Protection
            api_rate_limit:
              api_endpoint_rules:
                - any_domain: {}
                  api_endpoint_path: "/api/v1/users"
                  api_endpoint_method:
                    methods: ["GET", "POST"]
                  inline_rate_limiter:
                    threshold: 100
                    unit: "SECOND"
            
            api_specification:
              api_definition:
                name: "user-api-spec"
                namespace: "apis"
              validation_all_spec_endpoints:
                validation_mode:
                  validation_mode_active:
                    enforcement_block: {}
            
            # Performance & Caching
            default_cache_action:
              cache_ttl_default: "3600s"
            
            custom_cache_rule:
              cdn_cache_rules:
                - name: "static-content-cache"
                  namespace: "performance"
            
            # Access Control
            cors_policy:
              allow_origin: ["https://app.example.com"]
              allow_methods: "GET,POST,PUT,DELETE"
              allow_headers: "Content-Type,Authorization"
              allow_credentials: true
              maximum_age: 86400
            
            csrf_policy:
              custom_domain_list:
                domains: ["app.example.com"]
            
            # Advanced Security
            jwt_validation:
              action:
                block: {}
              jwks_config:
                cleartext: "https://auth.example.com/.well-known/jwks.json"
              target:
                api_groups:
                  api_groups: ["protected-apis"]
            
            data_guard_rules:
              - any_domain: {}
                path:
                  prefix: "/api/users"
                apply_data_guard: {}
                metadata:
                  name: "user-data-protection"
            
            # Rate Limiting
            rate_limit:
              rate_limiter:
                total_number: 1000
                unit: "SECOND"
                action_block:
                  minutes:
                    duration: 15
            
            # DDoS Protection  
            ddos_mitigation_rules:
              - metadata:
                  name: "suspicious-traffic-block"
                ddos_client_source:
                  country_list: ["COUNTRY_MALICIOUS"]
                block: {}
            
            # Certificate & TLS
            https_auto_cert:
              add_hsts: true
              http_redirect: true
              tls_config:
                tls_12_plus: {}
            
            # Monitoring & Policies
            service_policies_from_namespace: {}
            
            sensitive_data_policy:
              sensitive_data_policy_ref:
                name: "pci-compliance"
                namespace: "security"
          
          # Status Information
          status_set:
            - cdn_status:
                deployment_status: "CDN_LB_STATUS_ACTIVE"
                cfg_version: 123
              virtual_host_status:
                state: "VIRTUAL_HOST_READY"
          
          system_metadata:
            creation_timestamp: "2023-01-01T00:00:00Z"
            modification_timestamp: "2023-01-15T10:30:00Z"
            uid: "87654321-4321-4321-4321-cba987654321"
            tenant: "enterprise-tenant"
'''

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.module_info_list_base import BaseInfoListManager, BaseParameters
from ..module_utils.exceptions import F5ModuleError
from ..module_utils.common import f5_argument_spec
from ..module_utils.constants import CDN_LOADBALANCERS_ENDPOINT_NONVERSIONED


def build_endpoint(namespace):
    """Build CDN Load Balancer list endpoint URL."""
    return CDN_LOADBALANCERS_ENDPOINT_NONVERSIONED.format(namespace=namespace)


class CdnLoadbalancerInfoParameters(BaseParameters):
    """Parameters class for CDN Load Balancer info operations."""
    returnables = ["resources"]


class CdnLoadbalancerInfoManager(BaseInfoListManager):
    """Manager class for CDN Load Balancer info operations."""
    
    resource_singular = "cdn_loadbalancer_info"
    
    def _build_endpoint(self, name=None):
        """Build CDN Load Balancer list endpoint URL."""
        namespace = self.params.get('namespace')
        if not namespace:
            self.module.fail_json(msg="Namespace is required for CDN Load Balancer operations")
        return build_endpoint(namespace)
    
    def _create_parameters_instance(self, data):
        """Create CDN Load Balancer-specific parameters instance."""
        return CdnLoadbalancerInfoParameters(data)


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True

        argument_spec = dict(
            namespace=dict(
                type='str',
                required=True
            ),
            name=dict(
                type='str'
            ),
            labels=dict(
                type='dict'
            ),
            annotations=dict(
                type='dict'
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
        mm = CdnLoadbalancerInfoManager(module=module)
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
