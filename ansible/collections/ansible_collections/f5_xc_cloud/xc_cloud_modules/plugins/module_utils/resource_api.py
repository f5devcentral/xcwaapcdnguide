# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function
__metaclass__ = type

from .client import XcRestClient


class ResourceAPI(object):
    """Resource API wrapper that provides a unified interface for HTTP operations.
    
    This wraps the XcRestClient to provide a consistent API for the BaseManager.
    """
    
    def __init__(self, module):
        self.module = module
        self.client = XcRestClient(**module.params)
    
    def get(self, url, **kwargs):
        """Send GET request"""
        return self.client.api.get(url=url, **kwargs)
    
    def post(self, url, **kwargs):
        """Send POST request"""
        return self.client.api.post(url=url, **kwargs)
    
    def put(self, url, **kwargs):
        """Send PUT request"""
        return self.client.api.put(url=url, **kwargs)
    
    def patch(self, url, **kwargs):
        """Send PATCH request"""
        return self.client.api.patch(url=url, **kwargs)
    
    def delete(self, url, **kwargs):
        """Send DELETE request"""
        return self.client.api.delete(url=url, **kwargs)


def build_endpoint(base_endpoint, namespace, resource_name=None):
    """Build F5 XC API endpoint URL.
    
    Args:
        base_endpoint: Base endpoint template with {namespace} placeholder
        namespace: Namespace name to substitute
        resource_name: Optional resource name to append to endpoint
        
    Returns:
        Complete endpoint URL
    """
    endpoint = base_endpoint.format(namespace=namespace)
    if resource_name:
        endpoint = f"{endpoint}/{resource_name}"
    return endpoint