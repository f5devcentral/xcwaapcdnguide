#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: virtual_kubernetes
short_description: Manage Virtual Kubernetes
description:
    - Virtual K8s object exposes a Kubernetes API endpoint in the namespace that operates on all
      the physical Kubernetes clusters in each of the sites that are selected
      by the virtual-site referred to in the object.
version_added: "0.0.1"
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
            - When C(state) is C(fetch), returns the object.
        type: str
        choices:
          - present
          - absent
          - fetch
        default: present
    spec:
        description:
            - Create virtual_k8s will create the object in the storage backend for namespace metadata.namespace
              https://docs.cloud.f5.com/docs/api/virtual-k8s
        type: object (Virtual K8s)
    wait:
        description:
            - Wait until the object will be created on cloud.
        type: bool
        default: False
'''

EXAMPLES = r'''
---
- name: Configure Virtual Kubernetes
  hosts: webservers
  collections:
    - yoctoalex.xc_cloud_modules
  connection: local

  environment:
    XC_API_TOKEN: "your_api_token"
    XC_TENANT: "console.ves.volterra.io"

  tasks:
    - name: create vk8s
      virtual_kubernetes:
        state: present
        wait: True
        metadata:
          namespace: "default"
          name: "demo-vk8s"
        spec:
          vsite_refs:
            - kind: "virtual_site"
              tenant: "ves-io"
              namespace: "shared"
              name: "ves-io-all-res"
'''

RETURN = r'''
---
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
        - When C(state) is C(fetch), returns the object.
    type: str
    choices:
      - present
      - absent
      - fetch
    default: present
spec:
    description:
        - Create virtual_k8s will create the object in the storage backend for namespace metadata.namespace
          https://docs.cloud.f5.com/docs/api/virtual-k8s
    type: object (Virtual K8s)
'''

import time

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.client import XcRestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, f5_argument_spec
)


class Parameters(AnsibleF5Parameters):
    updatables = ['metadata', 'spec']

    returnables = ['metadata', 'spec']

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
    def metadata(self):
        return self._values['metadata']

    @property
    def spec(self):
        return self._values['spec']


class ApiParameters(Parameters):
    @property
    def metadata(self):
        return self._values['metadata']

    @property
    def spec(self):
        return self._values['spec']


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
        uri = f"/api/config/namespaces/{self.want.metadata['namespace']}/virtual_k8ss/{self.want.metadata['name']}"
        response = self.client.api.delete(url=uri)
        if response.status == 404:
            return False
        if response.status not in [200, 201, 202]:
            raise F5ModuleError(response.content)

    def exists(self):
        uri = f"/api/config/namespaces/{self.want.metadata['namespace']}/virtual_k8ss/{self.want.metadata['name']}"
        response = self.client.api.get(url=uri)
        if response.status == 404:
            return False
        if response.status not in [200, 201, 202]:
            raise F5ModuleError(response.content)
        if response.json().get('metadata', None):
            self.have = ApiParameters(params=response.json())
            return True
        return False

    def create(self):
        uri = f"/api/config/namespaces/{self.want.metadata['namespace']}/virtual_k8ss"
        response = self.client.api.post(url=uri, json=self.want.to_update())
        if response.status not in [200, 201, 202]:
            raise F5ModuleError(response.content)

        result = response.json()

        if self.want.wait:
            for retry in range(0, 100):
                uri = f"/api/config/namespaces/{self.want.metadata['namespace']}/virtual_k8ss/{self.want.metadata['name']}"
                response = self.client.api.get(url=uri, json=self.want.to_update())
                if response.status not in [200, 201, 202]:
                    raise F5ModuleError(response.content)
                result = response.json()
                if result['system_metadata']['initializers'] and \
                        len(result['system_metadata']['initializers']['pending']) == 0:
                    break
                time.sleep(15)

        self.have = ApiParameters(params=result)
        return True


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = False

        argument_spec = dict(
            state=dict(
                default='present',
                choices=['present', 'absent', 'fetch']
            ),
            wait=dict(type='bool', default=False),
            metadata=dict(
                type='dict',
                name=dict(required=True),
                labels=dict(type=dict),
                annotations=dict(type=dict),
                description=dict(type="str"),
                disable=dict(type='bool')
            ),
            spec=dict(
                type=dict,
                default_flavor_ref=dict(type=dict),
                disabled=dict(type=dict),
                isolated=dict(type=dict),
                vsite_refs=dict(type=dict),
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
