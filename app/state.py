"""
Application State Management
"""
import socket
import jwt
import psutil
import concurrent.futures
from datetime import datetime, timedelta
from queue import Queue

class DashboardState:
    def __init__(self, config):
        self.config = config
        self.latest_data = {api: {} for api in config['poll_intervals']}
        self.primary_clients = {}
        self.backup_clients = {}
        self.webui_clients = set()
        self.api_tokens = {
            api: limit["max"]
            for api, limit in config['rate_limits'].items()
        }
        self.running = True
        self.stats = {
            "messages_sent": 0,
            "api_calls": 0,
            "clients_served": 0,
            "failovers": 0,
            "webui_views": 0,
            "start_time": datetime.now().isoformat(),
            "request_queue": 0,
            "active_threads": 0,
            "thread_pool_size": config['request_threading']['max_workers'],
            "scheduler_running": False,
            "uptime": "00:00:00"  # Initialize uptime to prevent KeyError
        }
        self.performance = {
            "cpu": 0,
            "memory": 0,
            "bytes_sent": 0,
            "bytes_recv": 0,
            "bytes_sent_rate": 0,
            "bytes_recv_rate": 0,
            "prev_net_io": None
        }
        self.hostname = socket.gethostname()
        self.ip_address = self.get_ip_address()
        self.request_queue = Queue(maxsize=config['request_threading']['queue_size'])
        self.thread_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=config['request_threading']['max_workers']
        )
        self.auth_tokens = {}
        self.jobs = {}
        self.alerts_sent = set()

        # Initialize uptime
        self.update_uptime()

    def update_uptime(self):
        """Update uptime in stats"""
        delta = datetime.now() - datetime.fromisoformat(self.stats["start_time"])
        hours, remainder = divmod(delta.total_seconds(), 3600)
        minutes, seconds = divmod(remainder, 60)
        self.stats["uptime"] = f"{int(hours):02}:{int(minutes):02}:{int(seconds):02}"

    def get_ip_address(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def adjust_thread_pool(self):
        if not self.config['performance_monitoring']:
            return

        cpu = self.performance['cpu']
        mem = self.performance['memory']
        max_workers = self.config['request_threading']['max_workers']
        min_workers = self.config['request_threading']['min_workers']

        if cpu > self.config['request_threading']['cpu_threshold']:
            reduction = min(0.5, (cpu - self.config['request_threading']['cpu_threshold']) / 100)
            new_size = max(min_workers, int(max_workers * (1 - reduction)))
        elif mem > self.config['request_threading']['mem_threshold']:
            reduction = min(0.5, (mem - self.config['request_threading']['mem_threshold']) / 100)
            new_size = max(min_workers, int(max_workers * (1 - reduction)))
        else:
            new_size = max_workers

        if new_size != self.stats['thread_pool_size']:
            self.stats['thread_pool_size'] = new_size
            self.thread_pool._max_workers = new_size
            self.thread_pool._adjust_thread_count()

    def generate_auth_token(self, client_id):
        """Generate JWT token for client authentication"""
        payload = {
            'client_id': client_id,
            'exp': datetime.utcnow() + timedelta(seconds=self.config['auth']['token_expiration'])
        }
        return jwt.encode(payload, self.config['auth']['jwt_secret'], algorithm='HS256')

    def validate_auth_token(self, token):
        """Validate JWT token"""
        try:
            payload = jwt.decode(token, self.config['auth']['jwt_secret'], algorithms=['HS256'])
            return payload['client_id']
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    def check_thresholds(self):
        """Check if system thresholds are exceeded and send alerts"""
        if not self.config['alerting']['enabled']:
            return

        alerts = []
        alert_key = ""

        # CPU threshold
        cpu_threshold = self.config['alerting']['thresholds']['cpu']
        if self.performance['cpu'] > cpu_threshold:
            alert_key = f"cpu_{int(self.performance['cpu'])}"
            if alert_key not in self.alerts_sent:
                alerts.append(f"High CPU usage: {self.performance['cpu']}% (threshold: {cpu_threshold}%)")
                self.alerts_sent.add(alert_key)

        # Memory threshold
        mem_threshold = self.config['alerting']['thresholds']['memory']
        if self.performance['memory'] > mem_threshold:
            alert_key = f"mem_{int(self.performance['memory'])}"
            if alert_key not in self.alerts_sent:
                alerts.append(f"High Memory usage: {self.performance['memory']}% (threshold: {mem_threshold}%)")
                self.alerts_sent.add(alert_key)

        # Queue threshold
        queue_threshold = self.config['alerting']['thresholds']['queue']
        if self.stats['request_queue'] > queue_threshold:
            alert_key = f"queue_{self.stats['request_queue']}"
            if alert_key not in self.alerts_sent:
                max_queue = self.config['request_threading']['queue_size']
                alerts.append(
                    f"Request queue full: {self.stats['request_queue']}/{max_queue} (threshold: {queue_threshold})")
                self.alerts_sent.add(alert_key)

        if alerts:
            self.send_alerts(alerts)

    def send_alerts(self, alerts):
        """Send alerts through configured channels"""
        message = "🚨 Dashboard Manager Alert:\n" + "\n".join(alerts)

        # Webhook alerting
        if self.config['alerting']['webhook_url']:
            try:
                requests.post(
                    self.config['alerting']['webhook_url'],
                    json={'text': message}
                )
            except Exception:
                pass

        # Send to WebUI clients
        if self.webui_clients:
            from app.socketio import socketio
            socketio.emit('alert', {
                'message': message,
                'level': 'danger',
                'timestamp': datetime.now().isoformat()
            }, namespace='/webui')