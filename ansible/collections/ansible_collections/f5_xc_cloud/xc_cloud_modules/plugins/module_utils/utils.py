# -*- coding: utf-8 -*-
#
# Copyright (c) 2020 F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import time
from .exceptions import XcTimeoutError


def wait_for_state(check_func, expected_state, timeout=300, interval=10, log_func=None, *args, **kwargs):
    """
    Wait for a resource to reach the expected state.
    
    Args:
        check_func: Function to check current state
        expected_state: Expected state value
        timeout: Maximum time to wait (seconds)
        interval: Check interval (seconds)
        *args, **kwargs: Arguments to pass to check_func
    
    Returns:
        Current state when expected state is reached
        
    Raises:
        XcTimeoutError: If timeout is reached before expected state
    """
    start_time = time.time()
    
    attempt = 0
    while time.time() - start_time < timeout:
        attempt += 1
        current_state = check_func(*args, **kwargs)
        if log_func:
            try:
                log_func(f"state poll attempt={attempt} current_state={current_state} expected={expected_state}")
            except Exception:
                pass
        if current_state == expected_state:
            return current_state
        time.sleep(interval)
    
    raise XcTimeoutError(f"Timeout waiting for state '{expected_state}' after {timeout} seconds")


def poll_for_completion(status_func, completed_states, timeout=300, interval=10, *args, **kwargs):
    """
    Poll for operation completion.
    
    Args:
        status_func: Function to check operation status
        completed_states: List of states that indicate completion
        timeout: Maximum time to wait (seconds)
        interval: Check interval (seconds)
        *args, **kwargs: Arguments to pass to status_func
    
    Returns:
        Final status when operation completes
        
    Raises:
        XcTimeoutError: If timeout is reached before completion
    """
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        status = status_func(*args, **kwargs)
        if status in completed_states:
            return status
        time.sleep(interval)
    
    raise XcTimeoutError(f"Timeout waiting for completion after {timeout} seconds")


def format_api_url(endpoint, **params):
    """
    Format API endpoint URL with parameters.
    
    Args:
        endpoint: URL template with placeholders
        **params: Parameters to substitute in template
    
    Returns:
        Formatted URL
    """
    return endpoint.format(**params)


def safe_get(data, *keys, default=None):
    """
    Safely get nested dictionary values.
    
    Args:
        data: Dictionary to traverse
        *keys: Sequence of keys to traverse
        default: Default value if key path doesn't exist
    
    Returns:
        Value at key path or default
    """
    for key in keys:
        if isinstance(data, dict) and key in data:
            data = data[key]
        else:
            return default
    return data


def deep_merge(dict1, dict2):
    """
    Deep merge two dictionaries.
    
    Args:
        dict1: Base dictionary
        dict2: Dictionary to merge into dict1
    
    Returns:
        Merged dictionary
    """
    result = dict1.copy()
    
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    
    return result


def normalize_response(response):
    """
    Normalize API response format.
    
    Args:
        response: Raw API response
    
    Returns:
        Normalized response dictionary
    """
    if hasattr(response, 'json'):
        try:
            return response.json()
        except ValueError:
            return {'raw_content': response.content}
    elif isinstance(response, dict):
        return response
    else:
        return {'raw_content': str(response)}