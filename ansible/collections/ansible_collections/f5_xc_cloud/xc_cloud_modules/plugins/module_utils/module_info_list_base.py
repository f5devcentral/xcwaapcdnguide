# -*- coding: utf-8 -*-
"""
Base class for Ansible info modules that list and filter resources.

This module provides a foundation for building read-only Ansible modules
that list multiple resources with filtering capabilities.

Example usage:

    class MyResourceInfoParameters(BaseParameters):
        returnables = ["resources"]

    class MyResourceInfoManager(BaseInfoListManager):
        resource_singular = "my_resource_info"
        
        def _build_endpoint(self, name=None):
            namespace = self.params.get('namespace')
            base = f"/api/namespaces/{namespace}/my_resources"
            return base if name is None else f"{base}/{name}"
        
        def _create_parameters_instance(self, data):
            return MyResourceInfoParameters(data)

        # Optional: Override if you need custom logic
        # def _get_all_resources(self):
        #     # Custom implementation for listing resources
        #     return super()._get_all_resources()

    # In main():
    manager = MyResourceInfoManager(module)
    result = manager.exec_module()
    module.exit_json(**result)
"""
from __future__ import absolute_import, division, print_function
__metaclass__ = type

from .module_base import BaseParameters
from .resource_api import ResourceAPI


class BaseInfoListManager(object):
    """Independent base class for info modules that list and filter multiple resources."""
    
    # --- Can be overridden in concrete module ---
    resource_singular = "resource_info"  # e.g. "cdn_loadbalancer_info" (optional, for logging)
    
    def __init__(self, module, api=None):
        self.module = module
        self.params = module.params
        self.api = api or ResourceAPI(module)

    def exec_module(self):
        """Execute the module - fetch, filter, and optionally get detailed info."""
        resources = self._get_all_resources()
        filtered_resources = self.apply_filters(resources)
        
        # If full_details is requested, fetch detailed info for each filtered resource
        if self.params.get('full_details', False):
            detailed_resources = []
            for resource in filtered_resources:
                resource_name = resource.get('name')
                if resource_name:
                    detailed_data = self._get_full_details(resource_name)
                    if detailed_data:
                        detailed_resources.append(detailed_data)
                    else:
                        # If detailed fetch fails, keep the basic info
                        detailed_resources.append(resource)
                else:
                    detailed_resources.append(resource)
            filtered_resources = detailed_resources
        
        result = {"changed": False, "resources": filtered_resources}
        return result

    # -------- Generic methods that CAN be overridden by subclasses --------
    def _get_resource_name(self):
        """Get resource name for individual resource operations."""
        return self.params.get('name')
    
    def _build_endpoint(self, name=None):
        """Build API endpoint URL. Must be implemented by subclass."""
        raise NotImplementedError("_build_endpoint must be implemented by subclass")
    
    def _get_all_resources(self):
        """Get all resources from the API. Generic implementation using _build_endpoint."""
        resp = self.api.get(self._build_endpoint())
        
        if resp is None:
            self.module.fail_json(msg="Failed to get response from API. Check your credentials and network connectivity.")
        
        if resp.status == 404:
            # Namespace doesn't exist or no resources
            return []
            
        if resp.status not in (200, 201, 202):
            self.module.fail_json(msg=resp.content)
        
        data = resp.json()
        return self._extract_items_from_response(data)

    def _get_full_details(self, resource_name):
        """Get full details for a specific resource. Generic implementation."""
        # Build endpoint for individual resource
        endpoint = f"{self._build_endpoint()}/{resource_name}"
        
        resp = self.api.get(endpoint)
        
        if resp is None:
            return None
            
        if resp.status == 404:
            return None
            
        if resp.status not in (200, 201, 202):
            return None
        
        data = resp.json()
        if not data:
            return None
            
        return data

    # -------- Abstract methods that MUST be implemented by subclasses --------
    def _create_parameters_instance(self, data):
        """Create parameters instance. Must be implemented by subclass."""
        raise NotImplementedError("_create_parameters_instance must be implemented by subclass")

    # -------- Helper methods for common patterns --------
    def _extract_items_from_response(self, data):
        """Extract items array from API response. Common pattern for list APIs."""
        if not data:
            return []
        
        # Handle API response format - could be list or dict with items
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = data.get('items', [])
        else:
            items = []
        
        # Return valid dictionary items
        return [item for item in items if isinstance(item, dict)]

    # -------- Generic filtering methods --------
    def apply_filters(self, resources):
        """Apply client-side filtering based on module parameters."""
        if not resources:
            return []
        
        filtered = resources
        
        # Filter by name (exact match)
        name_filter = self.params.get('name')
        if name_filter:
            filtered = [r for r in filtered 
                       if r.get('name') == name_filter]
        
        # Filter by labels (all specified labels must match)
        labels_filter = self.params.get('labels')
        if labels_filter:
            filtered = [r for r in filtered if self._labels_match(r, labels_filter)]
        
        # Filter by annotations (all specified annotations must match)
        annotations_filter = self.params.get('annotations')
        if annotations_filter:
            filtered = [r for r in filtered if self._annotations_match(r, annotations_filter)]
        
        return filtered

    def _labels_match(self, resource, labels_filter):
        """Check if resource labels match the filter criteria."""
        resource_labels = resource.get('labels', {})
        for key, value in labels_filter.items():
            if resource_labels.get(key) != value:
                return False
        return True

    def _annotations_match(self, resource, annotations_filter):
        """Check if resource annotations match the filter criteria."""
        resource_annotations = resource.get('annotations', {})
        for key, value in annotations_filter.items():
            if resource_annotations.get(key) != value:
                return False
        return True