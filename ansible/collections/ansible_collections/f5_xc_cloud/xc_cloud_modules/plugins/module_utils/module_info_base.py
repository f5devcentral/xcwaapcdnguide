# -*- coding: utf-8 -*-
"""
Simple readonly base class for Ansible modules that only need to retrieve resources.

This module provides a minimal foundation for building read-only Ansible modules
that fetch resources via REST APIs without any state management or change tracking.

Example usage:

    class MyResourceParameters(BaseParameters):
        returnables = ["config", "status"]
        
        @property
        def config(self):
            return self._values.get('config', {})

    class MyResourceManager(BaseInfoManager):
        resource_singular = "my_resource"
        
        def _get_resource_name(self):
            return self.params.get('name')
        
        def _build_endpoint(self, name=None):
            base = "/api/my_resources"
            return base if name is None else f"{base}/{name}"
        
        def _create_parameters_instance(self, data):
            return MyResourceParameters(data)

    # In main():
    manager = MyResourceManager(module)
    result = manager.exec_module()
    module.exit_json(**result)
"""
from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible.module_utils.basic import AnsibleModule
from .resource_api import ResourceAPI


class BaseParameters(object):
    """Simple param helpers for readonly operations."""
    returnables = []

    def __init__(self, params=None):
        self._values = params or {}

    def _filter_params(self, data):
        return {k: v for k, v in data.items() if v is not None}

    def to_return(self):
        result = {}
        for key in self.returnables:
            result[key] = getattr(self, key, self._values.get(key))
        return self._filter_params(result)


class BaseInfoManager(object):
    """Simple read-only resource manager without state management or change tracking."""

    # --- Must be overridden in concrete module ---
    resource_singular = "resource"        # e.g. "application_firewall" (optional, for logging)
    
    def __init__(self, module, api=None):
        self.module = module
        self.params = module.params
        self.api = api or ResourceAPI(module)

    # -------- Core execution --------
    def exec_module(self):
        """Execute the module - simply fetch the resource."""
        resource_data = self._get_resource()
        
        result = {"changed": False}
        
        # Return resource data based on returnables configuration
        if resource_data:
            if hasattr(resource_data, 'returnables') and resource_data.returnables:
                # Only include fields specified in returnables
                filtered_data = {}
                for field in resource_data.returnables:
                    if field in resource_data._values:
                        filtered_data[field] = resource_data._values[field]
                if filtered_data:
                    result['resource'] = filtered_data
            elif hasattr(resource_data, '_values') and resource_data._values:
                # Return complete resource data
                result['resource'] = resource_data._values
            else:
                # Resource data is a dict
                result['resource'] = resource_data

        return result

    # -------- Abstract methods that MUST be implemented by subclasses --------
    def _get_resource_name(self):
        """Extract resource name from params. Must be implemented by subclass."""
        raise NotImplementedError("_get_resource_name must be implemented by subclass")
    
    def _build_endpoint(self, name=None):
        """Build endpoint URL for API calls. Must be implemented by subclass."""
        raise NotImplementedError("_build_endpoint must be implemented by subclass")

    # -------- Methods that CAN be overridden by subclasses --------
    def _normalize_existing(self, data):
        """Normalize API response data. Override for resource-specific cleanup."""
        if data is None:
            return {}
        
        def walk(d):
            if isinstance(d, dict):
                return {k: walk(v) for k, v in d.items() if v is not None}
            if isinstance(d, list):
                return [walk(x) for x in d]
            return d
        return walk(data)

    def _create_parameters_instance(self, data):
        """Create parameters instance. Override to use custom parameter classes."""
        return BaseParameters(data)

    # -------- Core get operation --------
    def _get_resource(self):
        """Get resource from API."""
        name = self._get_resource_name()
        resp = self.api.get(self._build_endpoint(name))
        
        if resp is None:
            self.module.fail_json(msg="Failed to get response from API. Check your credentials and network connectivity.")
        
        if resp.status == 404:
            # Resource doesn't exist
            return None
            
        if resp.status not in (200, 201, 202):
            self.module.fail_json(msg=resp.content)
        
        normalized = self._normalize_existing(resp.json())
        return self._create_parameters_instance(normalized)