#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: api_credentials
short_description: Tenant Settings
description:
    - Receive current tenant settings.
version_added: "0.0.1"
options:
    state:
        description:
            - When C(state) is C(present), ensures the object is created or modified.
            - When C(state) is C(absent), ensures the object is removed.
            - When C(state) is C(fetch), returns the object.
        type: str
        choices:
          - present
          - absent
          - fetch
        default: present
    expiration_days:
        type: int
        description:
            - Qty of days of service credential expiration.
    name:
        type: str
        description:
            - Name of API credential record. It will be saved in metadata.
    namespace:
        type: str
        required: True
        description:
            - Value of namespace is always "system".
    spec:
        password:
        api_type:
            description:
                - Types of API credential given when requesting credentials from volterra
            type: str
            choices:
              - API_CERTIFICATE
              - KUBE_CONFIG
              - API_TOKEN
              - SERVICE_API_TOKEN
              - SERVICE_API_CERTIFICATE
              - SERVICE_KUBE_CONFIG
              - SITE_GLOBAL_KUBE_CONFIG
              - SCIM_API_TOKEN
              - SERVICE_SITE_GLOBAL_KUBE_CONFIG
            default: API_CERTIFICATE
        virtual_k8s_name:
            description:
                - Name of virtual K8s cluster. Applicable for KUBE_CONFIG.
            type: str
        virtual_k8s_namespace:
            description:
                - Namespace of virtual K8s cluster. Applicable for KUBE_CONFIG.
            type: str
'''

EXAMPLES = r'''
---
- name: Manage API Credentials
  hosts: webservers
  collections:
    - yoctoalex.xc_cloud_modules
  connection: local

  environment:
    XC_API_TOKEN: "your_api_token"
    XC_TENANT: "console.ves.volterra.io"

  tasks:
    - name: create vk8s credentials
      api_credentials:
        state: present
        expiration_days: 5
        name: "demo-credentials"
        spec:
          api_type: "KUBE_CONFIG"
          virtual_k8s_name: "vk8s"
          virtual_k8s_namespace: "default"
      register: credentials
'''

RETURN = r'''
---
data:
    description:
        - data is the response format based on the API credential type.
        - In case of API_CERTIFICATES, the response is the base64 encoded value of certificate in PKCS12 format.
        - In case of KUBE_CONFIG, the response is the base64 encoded value of the K8s kubeconfig file
        - with contents as requested - cluster,namespace and base64 encoded certificate, key and CA.
    type: str
name:
    description:
        - Name of API credential record. It will be saved in metadata.
    type: str
'''

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.client import XcRestClient
from ..module_utils.common import (
    AnsibleF5Parameters, f5_argument_spec
)
from ..module_utils.exceptions import F5ModuleError


class Parameters(AnsibleF5Parameters):
    updatables = ['expiration_days', 'name', 'namespace', 'spec']

    returnables = ['data', 'name']

    def to_return(self):
        result = {}
        for returnable in self.returnables:
            result[returnable] = getattr(self, returnable)
        result = self._filter_params(result)
        return result

    def to_update(self):
        result = {}
        for updatebale in self.updatables:
            result[updatebale] = getattr(self, updatebale)
        result = self._filter_params(result)
        return result


class ModuleParameters(Parameters):
    @property
    def expiration_days(self):
        return self._values['expiration_days']

    @property
    def name(self):
        return self._values['name']

    @property
    def namespace(self):
        return self._values['namespace']

    @property
    def spec(self):
        return {
            'password': self._values['spec'].get('password', None),
            'type': self._values['spec'].get('api_type', None),
            'virtual_k8s_name': self._values['spec'].get('virtual_k8s_name', None),
            'virtual_k8s_namespace': self._values['spec'].get('virtual_k8s_namespace', None),
        }


class ApiParameters(Parameters):
    @property
    def data(self):
        return self._values['data']

    @property
    def name(self):
        return self._values['name']


class Changes(Parameters):
    def to_return(self):
        result = {}
        try:
            for returnable in self.returnables:
                result[returnable] = getattr(self, returnable)
            result = self._filter_params(result)
        except Exception:
            raise
        return result

    def to_update(self):
        result = {}
        try:
            for updatebale in self.updatables:
                result[updatebale] = getattr(self, updatebale)
            result = self._filter_params(result)
        except Exception:
            raise
        return result


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.client = XcRestClient(**self.module.params)

        self.want = ModuleParameters(params=self.module.params)
        self.have = ApiParameters()

    def exec_module(self):
        changed = False
        result = dict()
        state = self.want.state

        if state == 'present':
            changed = self.present()
        elif state == 'absent':
            changed = self.absent()
        elif state == 'fetch':
            self.exists()

        changes = self.have.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        return result

    def present(self):
        if self.exists():
            return False
        else:
            return self.create()

    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def remove(self):
        uri = f"/api/web/namespaces/{self.want.namespace}/revoke/api_credentials"
        response = self.client.api.post(url=uri, json=self.want.to_update())
        if response.status == 404:
            return False
        if response.status not in [200, 201, 202]:
            raise F5ModuleError(response.content)
        return True

    def exists(self):
        uri = f"/api/web/namespaces/{self.want.namespace}/api_credentials/{self.want.name}"
        response = self.client.api.get(url=uri)
        # TODO: server returns 500 error code instead of 404
        if response.status in [404, 500]:
            return False
        if response.status not in [200, 201, 202]:
            raise F5ModuleError(response.content)
        if response.json().get('object', None):
            return True
        return False

    def create(self):
        uri = f"/api/web/namespaces/{self.want.namespace}/api_credentials"
        response = self.client.api.post(url=uri, json=self.want.to_update())
        if response.status not in [200, 201, 202]:
            raise F5ModuleError(response.content)
        self.have = ApiParameters(params=response.json())
        return True


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = False

        argument_spec = dict(
            state=dict(
                default='present',
                choices=['present', 'absent', 'fetch']
            ),
            expiration_days=dict(type='int'),
            name=dict(type='str'),
            namespace=dict(type='str', default='system'),
            spec=dict(
                type=dict,
                password=dict(type=dict),
                api_type=dict(
                    type='str',
                    default='API_CERTIFICATE',
                    choices=[
                        'API_CERTIFICATE',
                        'KUBE_CONFIG',
                        'API_TOKEN',
                        'SERVICE_API_TOKEN',
                        'SERVICE_API_CERTIFICATE',
                        'SERVICE_KUBE_CONFIG',
                        'SITE_GLOBAL_KUBE_CONFIG',
                        'SCIM_API_TOKEN',
                        'SERVICE_SITE_GLOBAL_KUBE_CONFIG'
                    ]
                ),
                virtual_k8s_name=dict(type='str'),
                virtual_k8s_namespace=dict(type='str'),
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
        mm = ModuleManager(module=module)
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
