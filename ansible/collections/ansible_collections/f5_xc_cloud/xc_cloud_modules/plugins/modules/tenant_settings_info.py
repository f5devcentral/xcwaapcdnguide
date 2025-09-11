#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: tenant_settings_info
short_description: Retrieve information about F5 Distributed Cloud Tenant Settings
description:
    - This module retrieves comprehensive information about F5 Distributed Cloud Tenant Settings
    - Read-only module that never changes resources (always returns changed: false)
    - Retrieves tenant configuration including security settings, credentials expiry, and administrative configuration
    - Provides access to tenant-level settings such as OTP configuration, SSO settings, SCIM integration, and API access controls
version_added: "0.1.0"

extends_documentation_fragment:
  - f5_xc_cloud.xc_cloud_modules.f5
  - f5_xc_cloud.xc_cloud_modules.common

notes:
    - Always returns changed: false (read-only operation)
    - Supports check mode for validation
    - This is a tenant-level resource - no namespace required
    - Returns comprehensive tenant configuration including security and administrative settings

author:
    - Alex Shemyakin (@yoctoalex)
'''

EXAMPLES = r'''
- name: Get tenant settings information
  f5_xc_cloud.xc_cloud_modules.tenant_settings_info:
  register: tenant_info

- name: Display tenant basic information
  debug:
    msg: |
      Tenant Name: {{ tenant_info.resource.name }}
      Company: {{ tenant_info.resource.company_name }}
      Domain: {{ tenant_info.resource.domain }}
      State: {{ tenant_info.resource.state }}

- name: Display security settings
  debug:
    msg: |
      SSO Enabled: {{ tenant_info.resource.sso_enabled }}
      OTP Enabled: {{ tenant_info.resource.otp_enabled }}
      OTP Status: {{ tenant_info.resource.otp_status }}
      SCIM Enabled: {{ tenant_info.resource.scim_enabled }}

- name: Display credential expiry limits
  debug:
    msg: |
      Max API Token Expiry: {{ tenant_info.resource.max_credentials_expiry.max_api_token_expiry_days }} days
      Max API Certificate Expiry: {{ tenant_info.resource.max_credentials_expiry.max_api_certificate_expiry_days }} days
      Max Kube Config Expiry: {{ tenant_info.resource.max_credentials_expiry.max_kube_config_expiry_days }} days
  when: tenant_info.resource.max_credentials_expiry is defined

- name: Check if tenant is in active state
  debug:
    msg: "Tenant is active"
  when: tenant_info.resource.state == "ACTIVE"
'''

RETURN = r'''
changed:
    description: Always false for info modules
    type: bool
    returned: always
    sample: false
resource:
    description: Tenant settings information
    type: dict
    returned: when tenant settings exist
    contains:
        active_plan_transition_id:
            description: Active plan transition identifier
            type: str
            returned: when available
            sample: "plan-transition-123"
        company_name:
            description: Company name associated with the tenant
            type: str
            returned: when available
            sample: "ACME Corporation"
        domain:
            description: Tenant domain
            type: str
            returned: when available
            sample: "acme-corp.ves.volterra.io"
        max_credentials_expiry:
            description: Maximum credential expiry settings
            type: dict
            returned: when available
            sample:
                max_api_certificate_expiry_days: 365
                max_api_token_expiry_days: 90
                max_kube_config_expiry_days: 30
        name:
            description: Tenant name
            type: str
            returned: when available
            sample: "acme-corp-tenant"
        original_tenant:
            description: Original tenant identifier
            type: str
            returned: when available
            sample: "original-tenant-id"
        otp_enabled:
            description: Whether OTP (One-Time Password) is enabled
            type: bool
            returned: when available
            sample: true
        otp_status:
            description: Current OTP status
            type: str
            returned: when available
            sample: "OTP_ENABLED"
        scim_enabled:
            description: Whether SCIM (System for Cross-domain Identity Management) is enabled
            type: bool
            returned: when available
            sample: true
        sso_enabled:
            description: Whether SSO (Single Sign-On) is enabled
            type: bool
            returned: when available
            sample: true
        state:
            description: Current tenant state
            type: str
            returned: when available
            sample: "ACTIVE"
'''

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.module_info_base import BaseInfoManager, BaseParameters
from ..module_utils.exceptions import F5ModuleError
from ..module_utils.common import f5_argument_spec


class TenantSettingsInfoParameters(BaseParameters):
    """Parameters class for tenant settings info operations."""
    returnables = [
        "active_plan_transition_id",
        "company_name", 
        "domain",
        "max_credentials_expiry",
        "name",
        "original_tenant",
        "otp_enabled",
        "otp_status", 
        "scim_enabled",
        "sso_enabled",
        "state"
    ]


class TenantSettingsInfoManager(BaseInfoManager):
    """Manager class for tenant settings info operations."""
    
    resource_singular = "tenant_settings_info"

    def _get_resource_name(self):
        """
        Get the resource name for tenant settings.
        For tenant settings, this is typically empty since it's a singleton resource.
        
        Returns:
            str: Empty string for tenant settings endpoint
        """
        return ""

    def _build_endpoint(self, name=None):
        """
        Build the API endpoint for tenant settings.
        
        Returns:
            str: The complete API endpoint for tenant settings
        """
        return "/api/web/namespaces/system/tenant/settings"
    
    def _create_parameters_instance(self, data):
        """Create tenant settings-specific parameters instance."""
        return TenantSettingsInfoParameters(data)


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        self.argument_spec = {}
        self.argument_spec.update(f5_argument_spec)


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode
    )
    
    try:
        mm = TenantSettingsInfoManager(module=module)
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
