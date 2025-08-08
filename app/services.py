"""
Background Services
"""
import os
import signal
import threading
import time
import requests
from apscheduler.schedulers.background import BackgroundScheduler
from . import CONFIG, state, utils, logger
from .socketio import emit_log_update


class DashboardManager:
    def __init__(self, app):
        self.app = app
        self.scheduler = BackgroundScheduler()
        self.request_processor = None
        self.thread_pool = None

        signal.signal(signal.SIGINT, self.graceful_shutdown)
        signal.signal(signal.SIGTERM, self.graceful_shutdown)

    def start_services(self):
        """Start all background services"""
        # Start request processor thread
        self.request_processor = threading.Thread(
            target=utils.process_api_requests,
            daemon=True
        )
        self.request_processor.start()

        # Start scheduler
        self.scheduler.start()
        state.stats['scheduler_running'] = True

        # Add polling jobs
        for api in CONFIG['poll_intervals']:
            job_id = f'poll_{api}'
            self.scheduler.add_job(
                self.update_service,
                'interval',
                seconds=CONFIG['poll_intervals'][api],
                args=[api],
                id=job_id
            )
            state.jobs[job_id] = True

        self.scheduler.add_job(self.token_replenisher, 'interval', minutes=5, id='token_replenisher')
        self.scheduler.add_job(self.update_performance_stats, 'interval', seconds=5, id='performance_stats')
        self.scheduler.add_job(self.emit_log_update_job, 'interval', seconds=CONFIG['webui']['refresh_interval'],
                               id='log_update')
        self.scheduler.add_job(self.log_stats, 'interval', minutes=1, id='log_stats')

    def token_replenisher(self):
        if not state.running:
            return

        for api, limits in CONFIG['rate_limits'].items():
            state.api_tokens[api] = min(
                state.api_tokens[api] + limits["replenish"],
                limits["max"]
            )

    def update_performance_stats(self):
        if not CONFIG['performance_monitoring']:
            return

        state.performance['cpu'] = psutil.cpu_percent()
        state.performance['memory'] = psutil.virtual_memory().percent

        # Network monitoring
        net_io = psutil.net_io_counters()
        prev_net_io = state.performance.get('prev_net_io', None)

        state.performance['bytes_sent'] = net_io.bytes_sent
        state.performance['bytes_recv'] = net_io.bytes_recv

        if prev_net_io:
            time_elapsed = 5  # seconds between runs
            state.performance['bytes_sent_rate'] = (net_io.bytes_sent - prev_net_io.bytes_sent) / time_elapsed
            state.performance['bytes_recv_rate'] = (net_io.bytes_recv - prev_net_io.bytes_recv) / time_elapsed

        state.performance['prev_net_io'] = net_io
        state.adjust_thread_pool()

        # Check for threshold alerts
        state.check_thresholds()

    def emit_log_update_job(self):
        emit_log_update()

    def log_stats(self):
        stats = {
            "clients": len(state.primary_clients),
            "messages": state.stats["messages_sent"],
            "api_calls": state.stats["api_calls"]
        }
        logger.info(f"System stats: {json.dumps(stats)}")

    def update_service(self, api_name):
        if not state.running:
            return

        def process_results(api_name, results):
            state.latest_data[api_name] = results

            # Broadcast to primary clients
            for sid in list(state.primary_clients.keys()):
                socketio.emit('data_update', {
                    'source': api_name,
                    'data': results
                }, room=sid, namespace='/primary')

            state.stats["messages_sent"] += len(state.primary_clients)

        try:
            state.request_queue.put((api_name, process_results), timeout=1)
            state.stats['request_queue'] = state.request_queue.qsize()
        except Full:
            time.sleep(CONFIG['request_threading']['backoff_factor'])

    def graceful_shutdown(self, signum, frame):
        logger.warning(f"Shutting down... Signal: {signum}")
        state.running = False

        # Shutdown components
        if self.scheduler.running:
            self.scheduler.shutdown()

        # Wait for threads
        if self.request_processor and self.request_processor.is_alive():
            self.request_processor.join(timeout=5)

        logger.info("Shutdown complete")
        sys.exit(0)

    def run(self):
        # Create HTML templates if missing
        os.makedirs('templates', exist_ok=True)

        # Create templates (implementation from original script)
        # ... (template creation code from original script) ...

        # Start background services
        self.start_services()

        # Display connection info
        public_url = CONFIG['server'].get('public_url', f"http://{state.ip_address}")
        if public_url == "0.0.0.0":
            public_url = f"http://{state.ip_address}"

        port = CONFIG['server']['port']
        print("\n" + "=" * 60)
        print(f" Dashboard Manager Running")
        print("=" * 60)
        print(f" Single Port Serving: {public_url}:{port}")
        print(f" Web UI:             {public_url}:{port}/")
        print(f" Login:              {public_url}:{port}/login")
        print(f" Configuration:      {public_url}:{port}/config")
        print(f" Health Checks:      {public_url}:{port}/health")
        print(f" Primary WebSocket:  {public_url}:{port}/primary")
        print(f" Backup WebSocket:   {public_url}:{port}/backup")
        print(f" Token Generation:   {public_url}:{port}/token?client_id=your_client")
        print(f" Sample Client:      {public_url}:{port}/sample_client")
        print("=" * 60 + "\n")