"""
Configuration Handler
"""
import os
from os import system

import yaml
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime


def load_or_create_config():
    config_path = os.path.expanduser('~/.webdashrc.yml')
    defaults = {
        'server': {'host': '0.0.0.0', 'port': 5000, 'public_url': None},
        'auth': {'jwt_secret': 'super-secret-key-' + os.urandom(16).hex(), 'token_expiration': 3600},
        'poll_intervals': {'weather': 300, 'stocks': 60, 'news': 120},
        'api_endpoints': {
            'weather': {
                'base_url': "https://api.weather.com/v3/",
                'endpoints': {'current': 'current?location=London', 'forecast': 'forecast?days=3'},
                'api_key': 'YOUR_WEATHER_API_KEY'
            }
        },
        'rate_limits': {'weather': {'max': 10, 'replenish': 3}},
        'request_threading': {
            'max_workers': 10,
            'min_workers': 2,
            'cpu_threshold': 70,
            'mem_threshold': 80,
            'queue_size': 100,
            'backoff_factor': 1.5
        },
        'webui': {
            'log_lines': 100,
            'refresh_interval': 5,
            'auth': {'enabled': True, 'username': 'admin', 'password': 'securepassword'}
        },
        'logging': {
            'file': 'dashboard_manager.log',
            'max_bytes': 10 * 1024 * 1024,
            'backup_count': 5,
            'level': 'INFO'
        },
        'ssl': {'enabled': False, 'cert': 'cert.pem', 'key': 'key.pem'},
        'performance_monitoring': True,
        'redis': {'enabled': False, 'host': 'localhost', 'port': 6379, 'channel': 'dashboard_updates'},
        'auto_config': {'created': datetime.now().isoformat()},
        'security': {
            'cors_origins': ['*'],
            'hsts_enabled': True,
            'csp_enabled': True,
            'csp_policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.socket.io https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data:;"
        },
        'alerting': {
            'enabled': True,
            'webhook_url': '',
            'thresholds': {'cpu': 90, 'memory': 90, 'queue': 80}
        },
        'rbac': {
            'enabled': True,
            'roles': {
                'admin': ['*'],
                'operator': ['view_dashboard', 'view_config', 'control_services'],
                'viewer': ['view_dashboard']
            },
            'users': {
                'admin': 'admin',
                'operator1': 'operator',
                'viewer1': 'viewer'
            }
        },
        'audit_log': {'enabled': True, 'file': 'audit.log'}
    }

    if not os.path.exists(config_path):
        print(f"Creating new config file at {config_path}")
        try:
            with open(config_path, 'w') as f:
                yaml.dump(defaults, f)
            print("Configuration file created with default values.")
            print("Please edit it before restarting the application.")
            system().exit(0)
        except Exception as e:
            print(f"Error creating config: {e}")
            return defaults

    try:
        with open(config_path, 'r') as f:
            user_config = yaml.safe_load(f) or {}
            for key, value in defaults.items():
                if key not in user_config:
                    user_config[key] = value
            return user_config
    except Exception as e:
        print(f"Error loading config: {e}. Using defaults")
        return defaults


CONFIG = load_or_create_config()


def configure_logging(config):
    log_level = getattr(logging, config['logging']['level'].upper(), logging.INFO)
    logger = logging.getLogger('DashboardManager')
    logger.setLevel(log_level)

    os.makedirs('logs', exist_ok=True)
    log_file = os.path.join('logs', config['logging']['file'])

    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=config['logging']['max_bytes'],
        backupCount=config['logging']['backup_count'],
        encoding='utf-8'
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))
    logger.addHandler(console_handler)

    return logger