# -*- coding: utf-8 -*-
"""
Generic base classes for Ansible modules.

This module provides a completely generic foundation for building Ansible modules
that manage resources via REST APIs. It makes no assumptions about resource structure,
field names, or API patterns.

Example usage:

    class MyResourceParameters(BaseParameters):
        returnables = ["config", "status"]
        updatables = ["config"]
        
        @property
        def config(self):
            # Custom logic for processing config field
            return self._values.get('config', {})

    class MyResourceManager(BaseManager):
        resource_singular = "my_resource"
        
        def _get_resource_name(self):
            return self.params.get('name')
        
        def _build_endpoint(self, name=None):
            base = "/api/my_resources"
            return base if name is None else f"{base}/{name}"
        
        def _desired_body(self):
            return {
                'name': self.params.get('name'),
                'config': self.params.get('config', {})
            }
        
        def _create_parameters_instance(self, data):
            return MyResourceParameters(data)

    # In main():
    manager = MyResourceManager(module)
    result = manager.exec_module()
    module.exit_json(**result)
"""
from __future__ import absolute_import, division, print_function
__metaclass__ = type

from copy import deepcopy
from ansible.module_utils.basic import AnsibleModule

# NOTE: API calls must be routed through ResourceAPI (see resource_api.py)
from .resource_api import ResourceAPI
from .diff import focused_user_diff


class BaseParameters(object):
    """Common param helpers.
    Subclasses can override properties to normalize/validate fields.
    """
    returnables = []
    updatables = []

    def __init__(self, params=None):
        self._values = params or {}

    def _filter_params(self, data):
        return {k: v for k, v in data.items() if v is not None}

    def to_return(self):
        result = {}
        for key in self.returnables:
            result[key] = getattr(self, key, self._values.get(key))
        return self._filter_params(result)

    def to_update(self):
        result = {}
        for key in self.updatables:
            result[key] = getattr(self, key, self._values.get(key))
        return self._filter_params(result)


class BaseManager(object):
    """Reusable CRUD flow with idempotency, diff, and check-mode support.

    This is a completely generic base class that makes no assumptions about
    the resource structure, field names, or API patterns. All resource-specific
    logic must be implemented in subclasses.
    """

    # --- Must be overridden in concrete module ---
    resource_singular = "resource"        # e.g. "application_firewall" (optional, for logging)
    
    def __init__(self, module, api=None):
        self.module = module
        self.params = module.params
        self.api = api or ResourceAPI(module)
        self.want = BaseParameters(self.params)
        self.have = BaseParameters({})
        self.changed = False
        self._changed_fields = {}
        self._resource_exists = False  # Track if resource actually exists
        self._before_delete = None  # Track state before deletion for diff
        self.update_method = self.params.get('update_method', 'put')  # 'put' or 'patch'
        # dot-paths to ignore from existing state (e.g. ["metadata.uid", "spec.hash"])
        self.ignore_paths = set(self.params.get('ignore_paths') or [])

    # -------- Core execution --------
    def exec_module(self):
        state = self.params.get('state', 'present')
        if state == 'present':
            self.changed = self.present()
        elif state == 'absent':
            self.changed = self.absent()
        else:
            self.module.fail_json(msg="Unsupported state: %s" % state)

        result = {"changed": self.changed}

        # Return resource data for present state based on returnables configuration
        if state == 'present':
            # Only include filtered resource data based on returnables
            if hasattr(self.have, 'returnables') and self.have.returnables:
                # Only include fields specified in returnables
                resource_data = {}
                for field in self.have.returnables:
                    if field in self.have._values:
                        resource_data[field] = self.have._values[field]
                if resource_data:  # Only add resource if there's data to return
                    result['resource'] = resource_data
            elif self.have._values:
                # If no returnables specified, return complete resource data
                result['resource'] = self.have._values

        # Return diff if asked (module._diff)
        if getattr(self.module, '_diff', False):
            diff = self._make_ansible_diff()
            if diff:
                result['diff'] = diff

        return result

    # -------- Abstract methods that MUST be implemented by subclasses --------
    def _get_resource_name(self):
        """Extract resource name from params. Must be implemented by subclass."""
        raise NotImplementedError("_get_resource_name must be implemented by subclass")
    
    def _build_endpoint(self, name=None):
        """Build endpoint URL for API calls. Must be implemented by subclass."""
        raise NotImplementedError("_build_endpoint must be implemented by subclass")
    
    def _desired_body(self):
        """Build request body from params. Must be implemented by subclass."""
        raise NotImplementedError("_desired_body must be implemented by subclass")

    def _get_api_body(self):
        """Get request body with None values pruned for API calls."""
        return _prune_none(self._desired_body())

    # -------- Methods that CAN be overridden by subclasses --------
    def _normalize_existing(self, data):
        """Normalize API response data. Override for resource-specific cleanup."""
        # Default implementation does minimal cleanup
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

    # -------- Core CRUD logic --------
    def _exists(self):
        """Check if resource exists and load current state."""
        name = self._get_resource_name()
        resp = self.api.get(self._build_endpoint(name))
        if resp is None:
            self.module.fail_json(msg="Failed to get response from API. Check your credentials and network connectivity.")
        if resp.status == 404:
            # Resource doesn't exist, reset have state to empty
            self.have = self._create_parameters_instance({})
            self._resource_exists = False
            return False
        if resp.status not in (200, 201, 202):
            self.module.fail_json(msg=resp.content)
        
        normalized = self._normalize_existing(resp.json())
        normalized = _remove_paths(normalized, self.ignore_paths)
        self.have = self._create_parameters_instance(normalized)
        self._resource_exists = True
        return True

    # -------- State handlers --------
    def present(self):
        exists = self._exists()
        desired_body = self._desired_body()

        if exists:
            before_full = deepcopy(self.have.to_update())  # filtered current state
            # Compute focused diff only for user-specified fields
            diff_needed, changed_fields = focused_user_diff(desired_body, before_full)
            
            # Filter out ignored change paths
            changed_fields = self._filter_ignored_changes(changed_fields)
            diff_needed = len(changed_fields) > 0
            
            self._changed_fields = changed_fields

            if not diff_needed:
                return False

            if self.module.check_mode:
                return True

            return self._update(self._get_api_body())
        else:
            if self.module.check_mode:
                return True
            return self._create(self._get_api_body())

    def absent(self):
        exists = self._exists()
        if not exists:
            return False
        
        # Capture actual existing state before deletion for diff
        # (self.have now contains the real resource state from _exists())
        self._before_delete = deepcopy(self.have.to_update())
        
        if self.module.check_mode:
            return True
        return self._delete()

    # -------- CRUD operations --------
    def _create(self, body):
        """Create a new resource."""
        resp = self.api.post(self._build_endpoint(None), json=body)
        if resp is None:
            self.module.fail_json(msg="Failed to get response from API during create operation. Check your credentials and network connectivity.")
        if resp.status not in (200, 201, 202):
            self.module.fail_json(msg=resp.content)
        # For return, prefer server echo; fallback to sent body
        data = self._normalize_existing(resp.json() or body)
        data = _remove_paths(data, self.ignore_paths)
        self.have = self._create_parameters_instance(data)
        return True

    def _update(self, body):
        """Update an existing resource."""
        name = self._get_resource_name()
        if self.update_method == 'patch':
            resp = self.api.patch(self._build_endpoint(name), json=body)
        else:
            resp = self.api.put(self._build_endpoint(name), json=body)
        if resp is None:
            self.module.fail_json(msg="Failed to get response from API during update operation. Check your credentials and network connectivity.")
        if resp.status not in (200, 201, 202):
            self.module.fail_json(msg=resp.content)
        data = self._normalize_existing(resp.json() or body)
        data = _remove_paths(data, self.ignore_paths)
        self.have = self._create_parameters_instance(data)
        return True

    def _delete(self):
        """Delete an existing resource."""
        name = self._get_resource_name()
        resp = self.api.delete(self._build_endpoint(name))
        if resp is None:
            self.module.fail_json(msg="Failed to get response from API during delete operation. Check your credentials and network connectivity.")
        if resp.status in (404,):
            return False
        if resp.status not in (200, 201, 202):
            self.module.fail_json(msg=resp.content)
        # Clear have after successful deletion
        self.have = self._create_parameters_instance({})
        return True

    # -------- Helpers --------
    def _filter_ignored_changes(self, changes):
        """Filter out changes for paths specified in ignore_change_paths."""
        if not hasattr(self, 'ignore_change_paths') or not self.ignore_change_paths:
            return changes
        
        filtered_changes = {}
        for path, change in changes.items():
            if path not in self.ignore_change_paths:
                filtered_changes[path] = change
        
        return filtered_changes

    def _make_ansible_diff(self):
        """Generate Ansible diff output."""
        state = self.params.get('state', 'present')
        
        # For absent operations with no changes, return empty diff
        if state == 'absent' and not self.changed:
            return {
                "before": {},
                "after": {},
                "changes": {}
            }
        
        # Check if this is a delete operation
        if self._before_delete is not None:
            # For delete operations: before = existing state, after = empty
            before_full = self._before_delete
            after_full = {}
            # Compute changes from existing state to empty
            _, changes = focused_user_diff(after_full, before_full)
        else:
            # For present operations
            # Only include "before" state if resource actually exists
            if self._resource_exists:
                before_full = self.have.to_update()
            else:
                before_full = {}
                
            desired_body = self._desired_body()
            
            # Prune None values from desired_body for consistent diff display
            desired_body_clean = _prune_none(desired_body)
            
            if self.update_method == 'patch':
                after_full = _deep_merge(deepcopy(before_full), deepcopy(desired_body_clean))
            else:  # put
                after_full = deepcopy(desired_body_clean)

            changed, changes = self._changed_fields != {}, self._changed_fields
            if not changed:
                # recompute if needed (e.g., when called after create)
                _, changes = focused_user_diff(desired_body_clean, before_full)

        # Filter out ignored change paths
        changes = self._filter_ignored_changes(changes)

        return {
            "before": before_full,
            "after": after_full,
            "changes": changes  # path-> {before, after}
        }


def _prune_none(obj):
    if isinstance(obj, dict):
        return {k: _prune_none(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [_prune_none(x) for x in obj]
    return obj


def _remove_paths(obj, dot_paths):
    """Remove keys from obj matching a set of dot paths (e.g., {"metadata.uid", "spec.hash"})."""
    if not dot_paths:
        return obj
    root = deepcopy(obj)
    for p in dot_paths:
        parts = [x for x in p.split('.') if x]
        _rm_path(root, parts)
    return root


def _rm_path(node, parts):
    if not parts or node is None:
        return
    key = parts[0]
    if isinstance(node, dict):
        if len(parts) == 1:
            node.pop(key, None)
        else:
            _rm_path(node.get(key), parts[1:])
            # cleanup empty dicts
            if isinstance(node.get(key), dict) and not node.get(key):
                node.pop(key, None)
    elif isinstance(node, list):
        # We ignore numeric indices for simplicity; apply to each element
        for item in node:
            _rm_path(item, parts)


def _deep_merge(base, over):
    if isinstance(base, dict) and isinstance(over, dict):
        out = dict(base)
        for k, v in over.items():
            out[k] = _deep_merge(base.get(k), v)
        return out
    if isinstance(base, list) and isinstance(over, list):
        # naive replace list
        return list(over)
    return deepcopy(over)