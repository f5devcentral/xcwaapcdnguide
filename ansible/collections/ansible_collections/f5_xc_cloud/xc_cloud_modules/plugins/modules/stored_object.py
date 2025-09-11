#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: stored_object
short_description: Manage Service Policies
description:
    - A service_policy object consists of an unordered list of predicates and a list of service policy rules.
version_added: "0.0.1"
options:
    state:
        description:
            - When C(state) is C(present), ensures the object is created or modified.
            - When C(state) is C(absent), ensures the object is removed.
        type: str
        choices:
          - present
          - absent
          - fetch
        default: present

    bytes_value:
        description:
            - Exclusive with [string_value] Binary object contents. Should be encoded in base64 scheme.
        type: str
    content_format:
        description:
            - The optional content format associated with object
        type: str
    description:
        description:
            - The optional description associated with object
        type: str
    mobile_sdk:
        description:
            - Describes attributes specific to object type - mobile-sdk
        type: object
    name:
        description:
            - Name of the stored_object.
        type: str
        required: True
    namespace:
        description:
            - Namespace in which object is to be created
        type: str
        required: True
    no_attributes:
        description:
            - This can be used for messages where no values are needed
        type: object
    object_type:
        description:
            - Type of the stored_object
        type: str
        required: True
    string_value:
        description:
            - Exclusive with [bytes_value] String formatted contents
        type: str
'''

EXAMPLES = r'''
---
- name: Configure Service Policy
  hosts: webservers
  collections:
    - yoctoalex.xc_cloud_modules
  connection: local

  environment:
    XC_API_TOKEN: "your_api_token"
    XC_TENANT: "console.ves.volterra.io"

  tasks:
    - name: upload swagger file
      stored_object:
        state: present
        string_value: "{{ lookup('file', '../swagger.json') | string }}"
        content_format: "json"
        name: "demo-swagger"
        object_type: "swagger"
        namespace: "default"
'''

RETURN = r'''
---
metadata:

    creation_timestamp:
        description:
            - Creation date & time for the object
        type: str
        required: True
    description:
        description:
            - The optional description associated with object
        type: str
    mobile_sdk:
        description:
            - Describes attributes specific to object type - mobile-sdk
        type: object
    name:
        description:
            - Name of the stored_object.
        type: str
        required: True
    namespace:
        description:
            - Namespace in which object is to be created
        type: str
        required: True
    no_attributes:
        description:
            - This can be used for messages where no values are needed
        type: object
    url:
        description:
            - Url of the stored object
        type: str
        required: True
    version:
        description:
            - Version of the stored object
        type: str
        required: True
status:
    type: str
    choices:
        - STORED_OBJECT_STATUS_NONE
        - STORED_OBJECT_STATUS_CREATED
        - STORED_OBJECT_STATUS_UPDATED
        - STORED_OBJECT_STATUS_ALREADY_EXISTS
    description:
        - The stored object status represents status of create object response
          if object got created, updated or already exists.
'''

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.client import XcRestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, f5_argument_spec
)


class Parameters(AnsibleF5Parameters):
    updatables = ['bytes_value', 'content_format', 'description', 'name', 'namespace', 'object_type', 'string_value']

    returnables = ['metadata', 'status']

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
    def bytes_value(self):
        return self._values['bytes_value']

    @property
    def content_format(self):
        return self._values['content_format']

    @property
    def description(self):
        return self._values['description']

    @property
    def name(self):
        return self._values['name']

    @property
    def namespace(self):
        return self._values['namespace']

    @property
    def object_type(self):
        return self._values['object_type']

    @property
    def string_value(self):
        return self._values['string_value']


class ApiParameters(Parameters):
    @property
    def metadata(self):
        return self._values['metadata']

    @property
    def status(self):
        return self._values['status']

    @property
    def string_value(self):
        return self._values['string_value']

    @property
    def content_format(self):
        return self._values['content_format']


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

        changes = self.have.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        return result

    def present(self):
        return self.create()

    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def remove(self):
        uri = f"/api/object_store/namespaces/{self.want.namespace}/stored_objects/{self.want.object_type}/{self.want.name}"
        response = self.client.api.delete(url=uri)
        if response.status == 404:
            return False
        if response.status not in [200, 201, 202]:
            raise F5ModuleError(response.content)

    def create(self):
        uri = f"/api/object_store/namespaces/{self.want.namespace}/stored_objects/{self.want.object_type}/{self.want.name}"
        response = self.client.api.put(url=uri, json=self.want.to_update())
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
                choices=['present', 'absent']
            ),
            bytes_value=dict(type=dict),
            content_format=dict(type='str'),
            description=dict(type='str'),
            name=dict(required=True, type='str'),
            namespace=dict(required=True, type='str'),
            object_type=dict(required=True, type='str'),
            string_value=dict(type='str'),
            version=dict(type='str'),

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
