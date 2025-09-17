#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: http_loadbalancers_info
short_description: Gather comprehensive information about F5 Distributed Cloud HTTP Load Balancers
description:
    - Retrieve detailed information about F5 Distributed Cloud HTTP Load Balancers
    - Read-only module that never changes resources (always returns changed: false)
    - List all HTTP load balancers in a namespace with optional filtering capabilities
    - Filter by name, labels, or annotations to find specific load balancers
    - Access comprehensive configuration including security policies, routing rules, API protection, and advanced features
    - Supports both basic metadata retrieval and full configuration details
version_added: "0.1.0"
options:
    namespace:
        description:
            - Namespace to query for HTTP Load Balancers
            - Required parameter that defines the scope of the search
        type: str
        required: true
    name:
        description:
            - Filter by HTTP Load Balancer name (exact match)
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
            - Fetch complete configuration details for each HTTP Load Balancer
            - When false (default), returns only basic metadata (name, namespace, labels, annotations)
            - When true, retrieves comprehensive configuration including all security and performance settings
            - "Full details include comprehensive F5 XC HTTP Load Balancer features:"
            - "  • Service Policies: Active service policies for advanced traffic management and security"
            - "  • Advertisement Options: Custom advertising, public IP configuration, virtual networks"
            - "  • API Protection: Endpoint and group-based protection rules with client matching"
            - "  • API Rate Limiting: Endpoint-specific rate limits, bypass rules, IP allow lists"
            - "  • API Specification: OpenAPI validation, custom validation rules, enforcement modes"
            - "  • API Testing: Automated API testing with authentication and scheduling"
            - "  • Application Firewall: Web Application Firewall integration and custom policies"
            - "  • Bot Defense: JavaScript challenges, mobile SDK, protected app endpoints, flow labeling"
            - "  • Advanced Bot Defense: Separate web and mobile bot defense configurations"
            - "  • Caching Policy: Custom cache rules, TTL settings, cache control"
            - "  • Challenge Systems: CAPTCHA and JavaScript challenge configurations"
            - "  • Client-Side Defense: JavaScript insertion policies and domain-based rules"
            - "  • Cookie Management: Session stickiness, protected cookies, security attributes"
            - "  • CORS Policy: Cross-origin resource sharing configuration and domain rules"
            - "  • CSRF Policy: Cross-site request forgery protection and domain validation"
            - "  • Data Guard: Sensitive data protection rules and domain-specific policies"
            - "  • DDoS Mitigation: Layer 7 DDoS protection rules and client source blocking"
            - "  • Origin Pools: Backend server configuration, health checks, load balancing algorithms"
            - "  • HTTP/HTTPS Configuration: Protocol settings, TLS termination, certificate management"
            - "  • Auto-Certificate: Automated certificate management and DNS validation"
            - "  • GraphQL Protection: Query validation, depth limits, introspection controls"
            - "  • JWT Validation: Token validation, claims verification, endpoint targeting"
            - "  • IP Reputation: Threat intelligence integration and category-based blocking"
            - "  • Malware Protection: File scanning, domain-specific rules, action policies"
            - "  • Advanced Options: Compression, buffering, timeouts, header manipulation"
            - "  • Route Configuration: Path-based routing, redirect rules, origin pool selection"
            - "  • Sensitive Data Policies: Data disclosure rules and field-level protection"
            - "  • Client Lists: Trusted and blocked client configurations with expiration"
            - "  • Load Balancing: Round robin, least active, ring hash algorithms with policies"
            - "  • DNS Information: Managed DNS records and IP address assignments"
            - "  • Certificate State: TLS certificate status and auto-renewal information"
            - "  • Status Information: Deployment status, health conditions, and error details"
            - May take longer as it requires individual API calls per HTTP Load Balancer
        type: bool
        default: false

extends_documentation_fragment:
  - f5_xc_cloud.xc_cloud_modules.f5
  - f5_xc_cloud.xc_cloud_modules.common

notes:
    - Always returns changed: false (read-only operation)
    - Supports check mode for validation
    - Returns empty list if no HTTP Load Balancers match the filter criteria
    - All filtering is performed client-side after retrieving load balancer list
    - Full details mode provides access to comprehensive F5 XC security and performance features
    - "Advanced Security Features (when full_details=true):"
    - "  • API Protection Rules: Endpoint and group-based access control with client matchers"
    - "  • API Rate Limiting: Granular rate limiting with endpoint rules, bypass configurations, and IP allow lists"
    - "  • API Specification Validation: OpenAPI schema enforcement with custom validation rules and settings"
    - "  • Web Application Firewall: Custom firewall policies with rule exclusions and inheritance"
    - "  • Bot Defense: Multi-layered bot protection with JavaScript challenges, mobile SDK, and flow labeling"
    - "  • Client-Side Defense: Protection against malicious scripts with JavaScript insertion policies"
    - "  • DDoS Protection: Layer 7 DDoS mitigation with custom policies and client source analysis"
    - "  • Data Guard: Sensitive data protection with domain-specific rules and field-level controls"
    - "  • IP Reputation: Threat intelligence integration with category-based IP blocking"
    - "  • Malware Protection: File scanning and malware detection with configurable action policies"
    - "  • JWT Validation: Token-based authentication with claims verification and endpoint targeting"
    - "  • GraphQL Security: Query validation, depth limits, batching controls, and introspection management"
    - "Advanced Routing and Load Balancing Features:"
    - "  • Origin Pool Configuration: Backend server management with health checks and load balancing algorithms"
    - "  • Route-based Policies: Path-based routing, redirect rules, and advanced traffic steering"
    - "  • Session Management: Cookie stickiness, source IP persistence, and ring hash algorithms"
    - "  • Protocol Support: HTTP/HTTPS configuration with TLS termination and certificate management"
    - "  • Auto-Certificate: Automated certificate provisioning, renewal, and DNS validation"
    - "Access Control and Policy Management:"
    - "  • CORS/CSRF Protection: Cross-origin and cross-site request forgery protection"
    - "  • Service Policies: Centralized policy management and inheritance"
    - "  • Client Lists: Trusted and blocked client configurations with time-based expiration"
    - "  • Challenge Systems: CAPTCHA and JavaScript challenge configurations for threat mitigation"
    - "  • Policy-based Challenges: Rule-based challenge deployment with custom conditions"
    - "Performance and Optimization Features:"
    - "  • Caching Policies: Custom cache rules, TTL settings, and cache control headers"
    - "  • Compression: Content compression with configurable settings and content type filtering"
    - "  • Buffer Policies: Request buffering and size limits for optimal performance"
    - "  • Timeout Management: Configurable timeouts for various connection and processing stages"
    - "  • Header Manipulation: Request and response header modification for traffic optimization"
    - "Monitoring and Compliance Features:"
    - "  • Sensitive Data Disclosure Rules: Field-level data protection and compliance monitoring"
    - "  • API Testing: Automated API testing with authentication and scheduling capabilities"
    - "  • Status Monitoring: Deployment status, health conditions, and comprehensive error reporting"
    - "  • DNS Management: Automated DNS record management and IP address assignment"

author:
    - Alex Shemyakin (@yoctoalex)
'''

EXAMPLES = r'''
- name: Get all HTTP Load Balancers in namespace
  f5_xc_cloud.xc_cloud_modules.http_loadbalancers_info:
    namespace: "production"
  register: all_http_lbs

- name: Get specific HTTP Load Balancer by name
  f5_xc_cloud.xc_cloud_modules.http_loadbalancers_info:
    namespace: "production"
    name: "my-http-lb"
  register: specific_http_lb

- name: Filter HTTP Load Balancers by labels
  f5_xc_cloud.xc_cloud_modules.http_loadbalancers_info:
    namespace: "production"
    labels:
      environment: "prod"
      team: "backend"
  register: labeled_http_lbs

- name: Filter HTTP Load Balancers by annotations
  f5_xc_cloud.xc_cloud_modules.http_loadbalancers_info:
    namespace: "production"
    annotations:
      "example.com/owner": "team-b"
      "example.com/purpose": "api-gateway"
  register: annotated_http_lbs

- name: Combined filtering with advanced features
  f5_xc_cloud.xc_cloud_modules.http_loadbalancers_info:
    namespace: "production"
    labels:
      environment: "prod"
    full_details: true
  register: detailed_http_lbs

- name: Get HTTP Load Balancers with comprehensive security configuration
  f5_xc_cloud.xc_cloud_modules.http_loadbalancers_info:
    namespace: "security"
    full_details: true
  register: security_http_lbs

- name: Display API protection and bot defense details
  debug:
    msg: |
      HTTP LB: {{ item.metadata.name }}
      API Protection: {{ item.get_spec.api_protection_rules | default('Not configured') }}
      Bot Defense: {{ item.get_spec.bot_defense | default('Not configured') }}
      WAF Policy: {{ item.get_spec.app_firewall | default('Not configured') }}
      Rate Limiting: {{ item.get_spec.rate_limit | default('Not configured') }}
      DDoS Protection: {{ item.get_spec.l7_ddos_protection | default('Not configured') }}
  loop: "{{ security_http_lbs.resources }}"
  when: security_http_lbs.resources is defined

- name: Check origin pool and routing configuration
  debug:
    msg: |
      HTTP LB: {{ item.metadata.name }}
      Default Pool: {{ item.get_spec.default_pool | default('Not configured') }}
      Routes: {{ item.get_spec.routes | length | default(0) }} configured
      Domains: {{ item.get_spec.domains | default([]) }}
      Load Balancing: {{ item.get_spec.round_robin | default(item.get_spec.least_active | default(item.get_spec.ring_hash | default('Not specified'))) }}
  loop: "{{ detailed_http_lbs.resources }}"
  when: detailed_http_lbs.resources is defined

- name: Analyze certificate and TLS configuration
  debug:
    msg: |
      HTTP LB: {{ item.metadata.name }}
      HTTPS Config: {{ item.get_spec.https | default('Not configured') }}
      Auto Cert: {{ item.get_spec.https_auto_cert | default('Not configured') }}
      Cert State: {{ item.get_spec.cert_state | default('Unknown') }}
      Auto Cert Info: {{ item.get_spec.auto_cert_info | default('Not available') }}
  loop: "{{ detailed_http_lbs.resources }}"
  when: detailed_http_lbs.resources is defined

- name: Review compliance and data protection settings
  debug:
    msg: |
      HTTP LB: {{ item.metadata.name }}
      Data Guard: {{ item.get_spec.data_guard_rules | default('Not configured') }}
      Sensitive Data Policy: {{ item.get_spec.sensitive_data_policy | default('Not configured') }}
      CORS Policy: {{ item.get_spec.cors_policy | default('Not configured') }}
      CSRF Policy: {{ item.get_spec.csrf_policy | default('Not configured') }}
      JWT Validation: {{ item.get_spec.jwt_validation | default('Not configured') }}
  loop: "{{ security_http_lbs.resources }}"
  when: security_http_lbs.resources is defined
    name: "api-gateway"
    labels:
      environment: "prod"
      tier: "api"
    annotations:
      "example.com/security": "enhanced"
  register: filtered_http_lbs

- name: Get HTTP Load Balancers with full configuration details
  f5_xc_cloud.xc_cloud_modules.http_loadbalancers_info:
    namespace: "production"
    full_details: true
  register: detailed_http_lbs

- name: Get full details for API gateway load balancer
  f5_xc_cloud.xc_cloud_modules.http_loadbalancers_info:
    namespace: "production"
    name: "api-gateway-lb"
    full_details: true
  register: detailed_api_gateway

- name: Display found HTTP Load Balancers count
  debug:
    msg: "Found {{ http_results.resources | length }} HTTP Load Balancers"
  vars:
    http_results: "{{ all_http_lbs }}"

- name: Show HTTP Load Balancers with WAF enabled
  f5_xc_cloud.xc_cloud_modules.http_loadbalancers_info:
    namespace: "production"
    labels:
      security: "waf-enabled"
    full_details: true
  register: waf_enabled_lbs

- name: List HTTP Load Balancers for API endpoints
  f5_xc_cloud.xc_cloud_modules.http_loadbalancers_info:
    namespace: "apis"
    annotations:
      "api.example.com/type": "rest-api"
    full_details: true
  register: api_load_balancers
'''

RETURN = r'''
changed:
    description: Always false for info modules
    type: bool
    returned: always
    sample: false
resources:
    description: 
        - List of HTTP Load Balancer resources that match the filter criteria
        - Contains comprehensive configuration data when full_details=true
        - Basic metadata only when full_details=false (default)
    type: list
    elements: dict
    returned: always
    sample:
        # Basic metadata (full_details=false)
        - metadata:
            name: "my-http-lb"
            namespace: "production"
            labels:
              environment: "prod"
              team: "backend"
            annotations:
              "example.com/owner": "team-b"
          system_metadata:
            creation_timestamp: "2023-01-01T00:00:00Z"
            uid: "12345678-1234-1234-1234-123456789abc"
        
        # Full configuration details (full_details=true)
        - metadata:
            name: "comprehensive-api-gateway"
            namespace: "production"
            labels:
              environment: "prod"
              security: "enhanced"
              tier: "api"
            annotations:
              "api.example.com/type": "rest-api"
              "example.com/tier": "enterprise"
          get_spec:
            # Core Configuration
            domains: ["api.example.com", "gateway.example.com"]
            https_auto_cert:
              add_hsts: true
              http_redirect: true
              tls_config:
                tls_12_plus: {}
            
            # Origin Pool Configuration
            origin_pools:
              - pool:
                  name: "backend-api-pool"
                  namespace: "production"
                weight: 1
                priority: 1
            
            # Routing Rules
            routes:
              - simple_route:
                  http_method: "ANY"
                  path:
                    prefix: "/api/v1"
                  origin_pools:
                    - pool:
                        name: "v1-api-pool"
                        namespace: "production"
                      weight: 1
            
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
            
            # API Protection and Security
            api_protection_rules:
              api_endpoint_rules:
                - any_domain: {}
                  api_endpoint_path: "/api/admin"
                  action:
                    deny: {}
                  client_matcher:
                    ip_prefix_list:
                      invert_match: true
                      ip_prefixes: ["10.0.0.0/8", "192.168.0.0/16"]
            
            api_rate_limit:
              api_endpoint_rules:
                - any_domain: {}
                  api_endpoint_path: "/api/v1/users"
                  api_endpoint_method:
                    methods: ["GET", "POST"]
                  inline_rate_limiter:
                    threshold: 100
                    unit: "SECOND"
              ip_allowed_list:
                prefixes: ["203.0.113.0/24"]
            
            api_specification:
              api_definition:
                name: "user-api-spec"
                namespace: "apis"
              validation_all_spec_endpoints:
                validation_mode:
                  validation_mode_active:
                    enforcement_block: {}
                    request_validation_properties: ["PROPERTY_QUERY_PARAMETERS"]
                settings:
                  property_validation_settings_default: {}
            
            # Advanced Security Features
            jwt_validation:
              action:
                block: {}
              jwks_config:
                cleartext: "https://auth.example.com/.well-known/jwks.json"
              target:
                base_paths:
                  base_paths: ["/api/secure"]
              token_location:
                bearer_token: {}
            
            # Bot Defense and Challenges
            bot_defense:
              policy:
                protected_app_endpoints:
                  - any_domain: {}
                    path:
                      prefix: "/api"
                    mitigation:
                      block: {}
                    flow_label:
                      authentication:
                        login: {}
                js_insert_all_pages:
                  javascript_location: "AFTER_HEAD"
              regional_endpoint: "AUTO"
              timeout: 30
            
            policy_based_challenge:
              rule_list:
                rules:
                  - metadata:
                      name: "suspicious-traffic-challenge"
                    spec:
                      path:
                        prefix_values: ["/admin"]
                      enable_javascript_challenge: {}
              js_challenge_parameters:
                cookie_expiry: 3600
                js_script_delay: 5
            
            # Data Protection and Compliance
            data_guard_rules:
              - any_domain: {}
                path:
                  prefix: "/api/users"
                apply_data_guard: {}
                metadata:
                  name: "protect-user-data"
            
            sensitive_data_disclosure_rules:
              sensitive_data_types_in_response:
                - api_endpoint:
                    methods: ["GET"]
                    path: "/api/users"
                  body:
                    fields: ["ssn", "credit_card"]
                  mask: {}
            
            # Performance and Optimization
            caching_policy:
              default_cache_action:
                cache_ttl_override: "300s"
              custom_cache_rule:
                cdn_cache_rules:
                  - name: "api-cache-rule"
                    namespace: "caching"
            
            compression_params:
              content_type: ["application/json", "text/html"]
              content_length: 1024
              remove_accept_encoding_header: false
            
            # CORS and Cross-Site Protection
            cors_policy:
              allow_origin: ["https://app.example.com"]
              allow_methods: "GET,POST,PUT,DELETE"
              allow_headers: "Authorization,Content-Type"
              allow_credentials: true
              maximum_age: 86400
            
            csrf_policy:
              custom_domain_list:
                domains: ["app.example.com", "admin.example.com"]
            
            # Malware and Threat Protection
            malware_protection_settings:
              malware_protection_rules:
                - domain:
                    any_domain: {}
                  path:
                    prefix: "/uploads"
                  action:
                    block: {}
                  http_methods: ["POST", "PUT"]
            
            enable_ip_reputation:
              ip_threat_categories: ["SPAM_SOURCES", "MALWARE_SOURCES"]
            
            # GraphQL Protection
            graphql_rules:
              - any_domain: {}
                exact_path: "/graphql"
                graphql_settings:
                  max_depth: 10
                  max_batched_queries: 5
                  disable_introspection: {}
                method_post: {}
            
            # Certificate and TLS Configuration
            https_auto_cert:
              add_hsts: true
              http_redirect: true
              tls_config:
                default_security: {}
              use_mtls:
                trusted_ca:
                  name: "enterprise-ca"
                  namespace: "certificates"
                client_certificate_optional: false
            
            # Status and Monitoring Information
            auto_cert_info:
              auto_cert_state: "AutoCertEnabled"
              auto_cert_expiry: "2024-12-31T23:59:59Z"
              auto_cert_issuer: "Let's Encrypt"
            
            dns_info:
              - ip_address: "203.0.113.100"
            
            cert_state: "AutoCertEnabled"
            
            # Load Balancing Configuration
            round_robin: {}
            
            # Client Management
            trusted_clients:
              - ip_prefix: "10.0.0.0/8"
                actions: ["SKIP_PROCESSING_WAF"]
                metadata:
                  name: "internal-network"
            
            blocked_clients:
              - ip_prefix: "192.0.2.0/24"
                expiration_timestamp: "2024-06-01T00:00:00Z"
                metadata:
                  name: "temporary-block"
          
          # System and Status Information
          system_metadata:
            creation_timestamp: "2023-01-01T00:00:00Z"
            modification_timestamp: "2023-06-01T12:00:00Z"
            uid: "12345678-1234-1234-1234-123456789abc"
            tenant: "acme-corp"
          
          status:
            - virtual_host_status:
                state: "VIRTUAL_HOST_READY"
                existing_certificate_state: "Valid"
              conditions:
                - type: "Ready"
                  status: "True"
                  last_update_time: "2023-06-01T12:00:00Z"
                  validation_mode_active:
                    enforcement_block: {}
            
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
            
            # Load Balancer Specific Features
            hash_policy_choice:
              source_ip: {}
            
            origin_server_subset_rule_choice:
              default_subset: {}
            
            # Monitoring & Policies
            service_policies_from_namespace: {}
            
            sensitive_data_policy:
              sensitive_data_policy_ref:
                name: "api-compliance"
                namespace: "security"
          
          # Status Information
          status_set:
            - http_loadbalancer_status:
                deployment_status: "HTTP_LB_STATUS_ACTIVE"
                cfg_version: 456
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
from ..module_utils.constants import HTTP_LOADBALANCERS_ENDPOINT_NONVERSIONED


def build_endpoint(namespace):
    """Build HTTP Load Balancer list endpoint URL."""
    return HTTP_LOADBALANCERS_ENDPOINT_NONVERSIONED.format(namespace=namespace)


class HttpLoadbalancerInfoParameters(BaseParameters):
    """Parameters class for HTTP Load Balancer info operations."""
    returnables = ["resources"]


class HttpLoadbalancerInfoManager(BaseInfoListManager):
    """Manager class for HTTP Load Balancer info operations."""
    
    resource_singular = "http_loadbalancer_info"
    
    def _build_endpoint(self, name=None):
        """Build HTTP Load Balancer list endpoint URL."""
        namespace = self.params.get('namespace')
        if not namespace:
            self.module.fail_json(msg="Namespace is required for HTTP Load Balancer operations")
        return build_endpoint(namespace)
    
    def _create_parameters_instance(self, data):
        """Create HTTP Load Balancer-specific parameters instance."""
        return HttpLoadbalancerInfoParameters(data)


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
        mm = HttpLoadbalancerInfoManager(module=module)
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
