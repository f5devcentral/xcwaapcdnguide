#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: application_firewall
short_description: Manage F5 Distributed Cloud Application Firewalls (WAF)
description:
    - Create, update, and delete F5 Distributed Cloud Application Firewall configurations using BaseManager architecture
    - Application Firewalls provide comprehensive web application protection including bot protection, threat detection, and customizable security policies
    - Supports advanced features like AI-based risk blocking, signature-based detection, and custom blocking pages
    - Built on the generic BaseManager framework for consistent module behavior with intelligent change detection
    - Provides configurable output fields and full check mode support
    - Integrates with F5 XC security ecosystem for comprehensive application protection
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
            - Metadata for the application firewall resource
        type: dict
        required: true
        suboptions:
            name:
                description:
                    - Name of the application firewall. Must be unique within the namespace
                    - Must follow DNS-1035 format
                    - Cannot be changed after creation
                type: str
                required: true
            namespace:
                description:
                    - Namespace where the application firewall will be created
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
                    - Human readable description for the application firewall
                    - Used for documentation and identification purposes
                type: str
            disable:
                description:
                    - Administratively disable the application firewall
                    - When set to true, the firewall becomes non-functional
                type: bool
                default: false
    spec:
        description:
            - Specification for the application firewall configuration
            - Contains all WAF-specific settings and security policies
        type: dict
        default: {}
        suboptions:
            ai_risk_based_blocking:
                description:
                    - Configuration for AI-powered risk-based blocking
                    - Provides intelligent threat detection and response
                type: dict
            allow_all_response_codes:
                description:
                    - Allow all HTTP response codes without filtering
                    - Use when response code filtering is not required
                type: dict
            allowed_response_codes:
                description:
                    - Specific list of allowed HTTP response status codes
                    - Blocks responses with codes not in this list
                type: dict
            blocking:
                description:
                    - Enable blocking mode for detected threats
                    - When configured, threats are actively blocked
                type: dict
            blocking_page:
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
# Create a basic application firewall with default settings
- name: Create basic application firewall
  f5_xc_cloud.xc_cloud_modules.application_firewall:
    state: present
    metadata:
      name: "basic-waf"
      namespace: "production"
      description: "Basic web application firewall"

# Create application firewall with AI risk-based blocking
- name: Create WAF with AI protection
  f5_xc_cloud.xc_cloud_modules.application_firewall:
    state: present
    metadata:
      name: "ai-protected-waf"
      namespace: "production"
      description: "WAF with AI-powered threat detection"
      labels:
        environment: "production"
        protection-level: "high"
    spec:
      ai_risk_based_blocking:
        high_risk_action: "AI_BLOCK"
        medium_risk_action: "AI_BLOCK"
        low_risk_action: "AI_REPORT"
      blocking: {}
      allow_all_response_codes: {}

# Create comprehensive WAF with bot protection and custom detection
- name: Create comprehensive application firewall
  f5_xc_cloud.xc_cloud_modules.application_firewall:
    state: present
    metadata:
      name: "comprehensive-waf"
      namespace: "production"
      description: "Full-featured WAF with bot protection"
      labels:
        environment: "production"
        team: "security"
        criticality: "high"
      annotations:
        managed-by: "ansible"
        contact: "security-team@example.com"
    spec:
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
        - Indicates whether the application firewall was modified during execution
        - True when firewall was created, updated, or deleted
        - False when no changes were needed (idempotent operation)
    returned: always
    type: bool
    sample: true
resource:
    description: 
        - Complete application firewall resource data from F5 XC API
        - Contains fields specified in the returnables configuration
        - Only returned when state=present and operation succeeds
        - Fields are filtered based on returnables parameter settings
    returned: when state=present
    type: dict
    sample: {
        "metadata": {
            "name": "production-waf",
            "namespace": "production",
            "labels": {
                "environment": "production",
                "team": "security",
                "protection-level": "high"
            },
            "annotations": {
                "managed-by": "ansible",
                "contact": "security-team@example.com"
            },
            "description": "Production application firewall",
            "disable": false,
            "uid": "ves-io-99999999-8888-7777-6666-555555555555",
            "creation_timestamp": "2023-01-01T00:00:00.000000Z",
            "modification_timestamp": "2023-01-15T10:30:00.000000Z"
        },
        "spec": {
            "ai_risk_based_blocking": {
                "high_risk_action": "AI_BLOCK",
                "medium_risk_action": "AI_BLOCK",
                "low_risk_action": "AI_REPORT"
            },
            "blocking": {},
            "bot_protection_setting": {
                "malicious_bot_action": "BLOCK",
                "suspicious_bot_action": "REPORT",
                "good_bot_action": "ALLOW"
            },
            "detection_settings": {
                "signature_selection_setting": {
                    "high_medium_low_accuracy_signatures": {}
                },
                "enable_suppression": {},
                "enable_threat_campaigns": {}
            },
            "allow_all_response_codes": {},
            "default_anonymization": {}
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
    APP_FIREWALLS_ENDPOINT_NONVERSIONED
)

def build_endpoint(namespace, name=None):
    """Build application firewall endpoint URL."""
    base = APP_FIREWALLS_ENDPOINT_NONVERSIONED.format(namespace=namespace)
    return base if name is None else f"{base}/{name}"


class ApplicationFirewallParameters(BaseParameters):
    """Parameters class for application firewall-specific processing."""
    returnables = ["metadata", "spec", "system_metadata"]
    updatables = ["metadata", "spec"]

    @property
    def metadata(self):
        """Construct metadata according to API specification."""
        metadata = self._values.get('metadata', {})
        if not metadata:
            return metadata
            
        # Process metadata normally for application firewall resources
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


class ApplicationFirewallManager(BaseManager):
    """Manager for application firewall resources using BaseManager."""
    
    resource_singular = "application_firewall"
    ignore_change_paths = [
        "spec.bot_protection_setting"
    ]

    def __init__(self, module, api=None):
        super(ApplicationFirewallManager, self).__init__(module, api)
        # Override the want parameter to use application firewall-specific processing
        self.want = ApplicationFirewallParameters(self.params)
        self.have = ApplicationFirewallParameters({})

    # -------- Required abstract method implementations --------
    def _get_resource_name(self):
        """Extract application firewall name from params."""
        return self.params.get('metadata', {}).get('name')

    def _build_endpoint(self, name=None):
        """Build application firewall endpoint URL."""
        namespace = self.params.get('metadata', {}).get('namespace')
        if not namespace:
            self.module.fail_json(msg="Namespace is required for application firewall operations")
        return build_endpoint(namespace, name)

    def _desired_body(self):
        """Build request body for application firewall operations."""
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
        """Create application firewall-specific parameters instance."""
        return ApplicationFirewallParameters(data)


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
                    ai_risk_based_blocking=dict(type='dict'),
                    allow_all_response_codes=dict(type='dict'),
                    allowed_response_codes=dict(type='dict'),
                    blocking=dict(type='dict'),
                    blocking_page=dict(type='dict'),
                    bot_protection_setting=dict(type='dict'),
                    custom_anonymization=dict(type='dict'),
                    default_anonymization=dict(type='dict'),
                    default_bot_setting=dict(type='dict'),
                    default_detection_settings=dict(type='dict'),
                    detection_settings=dict(type='dict'),
                    disable_anonymization=dict(type='dict'),
                    monitoring=dict(type='dict'),
                    use_default_blocking_page=dict(type='dict'),
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
        mm = ApplicationFirewallManager(module=module)
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
