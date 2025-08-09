import os
import json
import requests
import jwt
import concurrent.futures
from functools import wraps
from flask import current_app, request, session, redirect, url_for, render_template
from datetime import datetime
from queue import Empty


def add_security_headers(response):
    """Add security headers to all responses"""
    config = current_app.config

    # HSTS if SSL enabled
    if config.get('ssl', {}).get('enabled', False) and config.get('security', {}).get('hsts_enabled', False):
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

    # Content Security Policy
    if config.get('security', {}).get('csp_enabled', False):
        response.headers['Content-Security-Policy'] = config['security']['csp_policy']

    # Other security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'

    return response


def require_permission(permission):
    """Decorator to check user permissions"""

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            config = current_app.config

            # If RBAC is disabled, allow access
            if not config.get('rbac', {}).get('enabled', False):
                return f(*args, **kwargs)

            username = session.get('username')
            if not username:
                return redirect(url_for('routes.login'))

            # Get user role and permissions
            role = config['rbac']['users'].get(username, 'viewer')
            permissions = config['rbac']['roles'].get(role, [])

            # Check permissions
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
    config = current_app.config
    if not config.get('audit_log', {}).get('enabled', False):
        return

    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'username': username,
        'action': action,
        'details': details,
        'ip': request.remote_addr
    }

    try:
        audit_log_path = os.path.join('logs', config['audit_log']['file'])
        with open(audit_log_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(log_entry) + '\n')
    except Exception as e:
        current_app.logger.error(f"Audit log write failed: {str(e)}")


def fetch_single_endpoint(api_name, endpoint_name, endpoint_path):
    """Fetch data from a single API endpoint"""
    config = current_app.config
    state = current_app.state

    try:
        api_config = config['api_endpoints'][api_name]
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
            current_app.logger.warning(f"Rate limited: {api_name}")
            return None

        headers = {'Authorization': f"Bearer {api_config.get('api_key', '')}"}
        response = requests.get(full_url, params=params, timeout=3, headers=headers)
        response.raise_for_status()

        state.api_tokens[api_name] -= 1
        state.stats["api_calls"] += 1
        return endpoint_name, response.json()
    except Exception as e:
        current_app.logger.error(f"API Error ({api_name}/{endpoint_name}): {str(e)}")
        return endpoint_name, None


def process_api_requests(app):
    """Process API requests from the queue"""
    while app.state.running:
        try:
            task = app.state.request_queue.get(timeout=1)
            api_name, callback = task

            app.state.stats['active_threads'] += 1
            app.state.stats['request_queue'] = app.state.request_queue.qsize()

            # For APIs with multiple endpoints
            if 'endpoints' in app.config['api_endpoints'][api_name]:
                endpoints = app.config['api_endpoints'][api_name]['endpoints']
                results = {}

                futures = []
                for endpoint_name, endpoint_path in endpoints.items():
                    future = app.state.thread_pool.submit(
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
                    callback(results)
            else:
                # For single endpoint APIs
                data = fetch_single_endpoint(api_name, 'data', '')
                if data:
                    callback({'data': data[1]})

            app.state.stats['active_threads'] -= 1
            app.state.request_queue.task_done()
        except Empty:
            continue
        except Exception as e:
            app.logger.error(f"Request processing error: {str(e)}")
            app.state.stats['active_threads'] -= 1


def get_log_lines(num_lines=100):
    """Get the most recent log lines"""
    config = current_app.config
    log_file = os.path.join('logs', config['logging']['file'])

    try:
        with open(log_file, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f.readlines()[-num_lines:]]
    except Exception:
        return ["Log file not available"]