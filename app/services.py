import signal
import threading
import time
import json
import requests
import psutil
from apscheduler.schedulers.background import BackgroundScheduler
from flask import current_app


class DashboardManager:
    def __init__(self, app):
        self.app = app
        self.scheduler = BackgroundScheduler()
        self.request_processor = None

        signal.signal(signal.SIGINT, self.graceful_shutdown)
        signal.signal(signal.SIGTERM, self.graceful_shutdown)

    def start_services(self):
        """Start all background services and scheduled jobs"""
        from .utils import process_api_requests

        self.request_processor = threading.Thread(
            target=process_api_requests,
            daemon=True,
            kwargs={'app': self.app}
        )
        self.request_processor.start()

        self.scheduler.start()
        self.app.state.stats['scheduler_running'] = True

        # Add polling jobs for each API service
        for api in self.app.config['poll_intervals']:
            self.scheduler.add_job(
                self.update_service,
                'interval',
                seconds=self.app.config['poll_intervals'][api],
                args=[api],
                id=f'poll_{api}'
            )
            self.app.state.jobs[f'poll_{api}'] = True

        # Add maintenance jobs
        self.scheduler.add_job(
            self.token_replenisher,
            'interval',
            minutes=5,
            id='token_replenisher'
        )
        self.scheduler.add_job(
            self.update_performance_stats,
            'interval',
            seconds=5,
            id='performance_stats'
        )
        self.scheduler.add_job(
            self.emit_log_update,
            'interval',
            seconds=self.app.config['webui']['refresh_interval'],
            id='log_update'
        )
        self.scheduler.add_job(
            self.log_stats,
            'interval',
            minutes=1,
            id='log_stats'
        )

    def token_replenisher(self):
        """Replenish API rate limit tokens"""
        if not self.app.state.running:
            return

        for api, limits in self.app.config['rate_limits'].items():
            self.app.state.api_tokens[api] = min(
                self.app.state.api_tokens[api] + limits["replenish"],
                limits["max"]
            )

    def update_performance_stats(self):
        """Update system performance metrics"""
        if not self.app.config['performance_monitoring']:
            return

        self.app.state.performance['cpu'] = psutil.cpu_percent()
        self.app.state.performance['memory'] = psutil.virtual_memory().percent

        # Network monitoring
        net_io = psutil.net_io_counters()
        prev_net_io = self.app.state.performance.get('prev_net_io', None)

        self.app.state.performance['bytes_sent'] = net_io.bytes_sent
        self.app.state.performance['bytes_recv'] = net_io.bytes_recv

        if prev_net_io:
            time_elapsed = 5  # seconds between runs
            self.app.state.performance['bytes_sent_rate'] = (net_io.bytes_sent - prev_net_io.bytes_sent) / time_elapsed
            self.app.state.performance['bytes_recv_rate'] = (net_io.bytes_recv - prev_net_io.bytes_recv) / time_elapsed

        self.app.state.performance['prev_net_io'] = net_io
        self.app.state.adjust_thread_pool()
        self.app.state.check_thresholds()

    def emit_log_update(self):
        """Trigger log update emission to web clients"""
        from .socket_handlers import emit_log_update
        emit_log_update(self.app)

    def log_stats(self):
        """Log system statistics"""
        stats = {
            "clients": len(self.app.state.primary_clients),
            "messages": self.app.state.stats["messages_sent"],
            "api_calls": self.app.state.stats["api_calls"]
        }
        self.app.logger.info(f"System stats: {json.dumps(stats)}")

    def update_service(self, api_name):
        """Update data for a specific service"""
        if not self.app.state.running:
            return

        def process_results(results):
            from .socket_handlers import socketio
            self.app.state.latest_data[api_name] = results

            # Broadcast to primary clients
            for sid in list(self.app.state.primary_clients.keys()):
                socketio.emit('data_update', {
                    'source': api_name,
                    'data': results
                }, room=sid, namespace='/primary')

            self.app.state.stats["messages_sent"] += len(self.app.state.primary_clients)

        try:
            self.app.state.request_queue.put((api_name, process_results), timeout=1)
            self.app.state.stats['request_queue'] = self.app.state.request_queue.qsize()
        except Exception as e:
            self.app.logger.warning(f"Request queue full for {api_name}, skipping update")
            time.sleep(self.app.config['request_threading']['backoff_factor'])

    def graceful_shutdown(self, signum, frame):
        """Handle graceful shutdown of services"""
        self.app.logger.warning(f"Shutting down... Signal: {signum}")
        self.app.state.running = False

        # Shutdown scheduler
        if self.scheduler.running:
            self.scheduler.shutdown()

        # Wait for request processor thread
        if self.request_processor and self.request_processor.is_alive():
            self.request_processor.join(timeout=5)

        self.app.logger.info("Shutdown complete")