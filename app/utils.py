"""
Utility Functions
"""
import os
import requests
from functools import wraps
from flask import request, session, redirect, url_for, render_template


def add_security_headers(response):
    """Add security headers to all responses"""
    from app import CONFIG

    # HSTS if SSL enabled
    if CONFIG['ssl']['enabled'] and CONFIG['security']['hsts_enabled']:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

    # Content Security Policy
    if CONFIG['security']['csp_enabled']:
        response.headers['Content-Security-Policy'] = CONFIG['security']['csp_policy']

    # Other security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'

    return response


def require_permission(permission):
    """Decorator to check user permissions"""
    from app import CONFIG

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not CONFIG['rbac']['enabled']:
                return f(*args, **kwargs)

            username = session.get('username')
            if not username:
                return redirect(url_for('routes.login'))

            # Get user role
            role = CONFIG['rbac']['users'].get(username, 'viewer')

            # Check permissions
            permissions = CONFIG['rbac']['roles'].get(role, [])
            if '*' not in permissions and permission not in permissions:
                log_audit_event(username, 'access_denied', f"Tried to access {request.path}")
                return render_template('error.html',
                                       error_code=403,
                                       error_message="You don't have permission to access this resource"), 403
            return f(*args, **kwargs)

        return decorated_function

    return decorator


def log_audit_event(username, action, details):
    """Log security-sensitive events"""
    from app import CONFIG, request
    from datetime import datetime
    import json

    if not CONFIG['audit_log']['enabled']:
        return

    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'username': username,
        'action': action,
        'details': details,
        'ip': request.remote_addr
    }

    try:
        audit_log_path = os.path.join('logs', CONFIG['audit_log']['file'])
        with open(audit_log_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(log_entry) + '\n')
    except Exception:
        pass


def fetch_single_endpoint(api_name, endpoint_name, endpoint_path):
    from app import CONFIG, state

    try:
        api_config = CONFIG['api_endpoints'][api_name]
        base_url = api_config['base_url'].rstrip('/')
        endpoint = endpoint_path.split('?')[0]
        params = {}

        # Parse query parameters
        if '?' in endpoint_path:
            query = endpoint_path.split('?')[1]
            params = dict(p.split('=') for p in query.split('&'))

        full_url = f"{base_url}/{endpoint}"

        # Check rate limits
        if state.api_tokens[api_name] <= 0:
            return None

        headers = {'Authorization': f"Bearer {api_config.get('api_key', '')}"}
        response = requests.get(full_url, params=params, timeout=3, headers=headers)
        response.raise_for_status()

        state.api_tokens[api_name] -= 1
        state.stats["api_calls"] += 1
        return endpoint_name, response.json()
    except Exception:
        return endpoint_name, None


def process_api_requests():
    from app import state
    from queue import Empty

    while state.running:
        try:
            task = state.request_queue.get(timeout=1)
            api_name, callback = task

            state.stats['active_threads'] += 1
            state.stats['request_queue'] = state.request_queue.qsize()

            # For APIs with multiple endpoints
            if 'endpoints' in state.config['api_endpoints'][api_name]:
                endpoints = state.config['api_endpoints'][api_name]['endpoints']
                results = {}

                futures = []
                for endpoint_name, endpoint_path in endpoints.items():
                    future = state.thread_pool.submit(
                        fetch_single_endpoint,
                        api_name,
                        endpoint_name,
                        endpoint_path
                    )
                    futures.append(future)

                for future in concurrent.futures.as_completed(futures):
                    endpoint_name, data = future.result()
                    if data:
                        results[endpoint_name] = data

                if results:
                    callback(api_name, results)
            else:
                # For single endpoint APIs
                data = fetch_single_endpoint(api_name, 'data', '')
                if data:
                    callback(api_name, {'data': data[1]})

            state.stats['active_threads'] -= 1
            state.request_queue.task_done()
        except Empty:
            continue
        except Exception:
            state.stats['active_threads'] -= 1


def get_log_lines(num_lines=100):
    from app import CONFIG
    log_file = os.path.join('logs', CONFIG['logging']['file'])

    try:
        with open(log_file, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f.readlines()[-num_lines:]]
    except Exception:
        return ["Log file not available"]