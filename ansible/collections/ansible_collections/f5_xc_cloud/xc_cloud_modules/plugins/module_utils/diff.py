# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function
__metaclass__ = type


def focused_user_diff(desired, existing):
    """
    Compare desired state (user input) with existing state to detect changes.
    
    This function performs an "overlap-only" comparison, meaning it only compares
    fields that are present in the desired state. This avoids false positives
    from server-side fields that the user didn't specify.
    
    Args:
        desired: Dictionary representing the desired state (user input)
        existing: Dictionary representing the current state from API
        
    Returns:
        tuple: (bool: changes_needed, dict: changed_fields)
               changed_fields format: {"path.to.field": {"before": old_val, "after": new_val}}
    """
    changed_fields = {}
    
    def _compare_recursive(desired_obj, existing_obj, path=""):
        """Recursively compare objects and track changes"""
        if desired_obj is None and existing_obj is None:
            return
        
        if desired_obj is None or existing_obj is None:
            if desired_obj != existing_obj:
                changed_fields[path] = {"before": existing_obj, "after": desired_obj}
            return
        
        if type(desired_obj) != type(existing_obj):
            changed_fields[path] = {"before": existing_obj, "after": desired_obj}
            return
        
        if isinstance(desired_obj, dict):
            # Only compare keys that exist in desired (overlap-only)
            for key in desired_obj.keys():
                key_path = f"{path}.{key}" if path else key
                existing_val = existing_obj.get(key)
                desired_val = desired_obj[key]
                _compare_recursive(desired_val, existing_val, key_path)
        
        elif isinstance(desired_obj, list):
            if len(desired_obj) != len(existing_obj):
                changed_fields[path] = {"before": existing_obj, "after": desired_obj}
                return
            
            for i, (desired_item, existing_item) in enumerate(zip(desired_obj, existing_obj)):
                item_path = f"{path}[{i}]"
                _compare_recursive(desired_item, existing_item, item_path)
        
        else:
            # Primitive types (string, int, bool, etc.)
            if desired_obj != existing_obj:
                changed_fields[path] = {"before": existing_obj, "after": desired_obj}
    
    _compare_recursive(desired, existing)
    
    changes_needed = len(changed_fields) > 0
    return changes_needed, changed_fields