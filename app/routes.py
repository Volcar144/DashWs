"""
Application Routes
"""
import os
import yaml
from flask import Blueprint, request, render_template, jsonify, session, redirect, url_for, current_app
from datetime import datetime

from .globals import get_state, get_config
from .services import DashboardManager
from .utils import require_permission, log_audit_event

bp = Blueprint('routes', __name__)

@bp.route('/login', methods=['GET', 'POST'])
def login():
    config = current_app.config
    # If auth is disabled, redirect to dashboard
    if not config['webui']['auth']['enabled']:
        return redirect(url_for('.dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check credentials
        if (username == config['webui']['auth']['username'] and
                password == config['webui']['auth']['password']):

            # Determine role
            role = config['rbac']['users'].get(username, 'viewer')

            # Set session
            session['logged_in'] = True
            session['username'] = username
            session['role'] = role

            log_audit_event(username, 'login', "Successful login")
            return redirect(url_for('.dashboard'))
        else:
            log_audit_event(username, 'login_failed', "Invalid credentials")
            return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@bp.route('/logout')
def logout():
    username = session.get('username', 'unknown')
    log_audit_event(username, 'logout', "User logged out")
    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('.login'))

@bp.route('/health')
def health_check():
    current_app.state.update_uptime()
    return jsonify({
        'status': 'OK',
        'timestamp': datetime.now().isoformat(),
        'uptime': current_app.state.stats['uptime']
    })

@bp.route('/')
@require_permission('view_dashboard')
def dashboard():
    current_app.state.stats["webui_views"] += 1
    current_app.state.update_uptime()


    host = current_app.config['server']['host']
    public_url = current_app.config['server'].get('public_url', f"http://{current_app.state.ip_address}")
    if public_url == "0.0.0.0":
        public_url = f"http://{current_app.state.ip_address}"

    port = current_app.config['server']['port']
    primary_ws = f"{public_url}:{port}/primary"
    backup_ws = f"{public_url}:{port}/backup"

    # Get job statuses
    job_statuses = {}
    if hasattr(current_app, 'DashboardManager') and current_app.DashboardManager.scheduler.running:
        for api in current_app.config['poll_intervals']:
            job_id = f'poll_{api}'
            job = current_app.DashboardManager.scheduler.get_job(job_id)
            job_id = f'poll_{api}'
            job = current_app.DashboardManager.scheduler.get_job(job_id)
            if job:
                job_statuses[api] = {
                    'next_run': job.next_run_time.strftime('%Y-%m-%d %H:%M:%S') if job.next_run_time else 'N/A',
                    'enabled': not job.pending
                }

    return render_template('dashboard.html',
                       config=current_app.config,
                       state=current_app.state,
                       auth_enabled=current_app.config['webui']['auth']['enabled'],
                       primary_ws=primary_ws,
                       backup_ws=backup_ws,
                       logged_in=session.get('logged_in', False),
                       username=session.get('username', ''),
                       role=session.get('role', 'viewer'),
                       job_statuses=job_statuses,
                       scheduler_running=current_app.DashboardManager.scheduler.running if hasattr(current_app, 'DashboardManager') else False)

@bp.route('/health/detailed')
def detailed_health_check():
    state = get_state()
    services = {}
    for api in get_config()['poll_intervals']:
        job_id = f'poll_{api}'
        job = DashboardManager.scheduler.get_job(job_id)
        services[api] = {
            'status': 'active' if job and not job.pending else 'inactive',
            'last_run': job.previous_run_time.isoformat() if job and job.previous_run_time else 'never',
            'next_run': job.next_run_time.isoformat() if job and job.next_run_time else 'N/A'
        }

    return jsonify({
        'status': 'OK' if all(s['status'] == 'active' for s in services.values()) else 'WARNING',
        'services': services,
        'system': {
            'cpu': state.performance['cpu'],
            'memory': state.performance['memory'],
            'threads': state.stats['active_threads'],
            'queue': state.stats['request_queue']
        }
    })


@bp.route('/token', methods=['GET'])
@require_permission('generate_token')
def generate_token():
    state = get_state()
    client_id = request.args.get('client_id', 'sample_client')
    token = state.generate_auth_token(client_id)
    return jsonify({
        'status': 'success',
        'token': token,
        'client_id': client_id
    })

@bp.route('/config', methods=['GET', 'POST'])
@require_permission('view_config')
def config_editor():
    config_path = os.path.expanduser('~/.webdashrc.yml')
    message = None

    if request.method == 'POST' and session.get('role') == 'admin':
        try:
            new_config = request.form['config']
            parsed = yaml.safe_load(new_config)
            with open(config_path, 'w') as f:
                yaml.dump(parsed, f)
            message = {'type': 'success', 'text': 'Configuration saved! Restart server to apply changes.'}
            log_audit_event(session['username'], 'config_update', "Configuration modified")
        except Exception as e:
            message = {'type': 'error', 'text': f'Error saving config: {str(e)}'}
            log_audit_event(session['username'], 'config_update_failed', f"Error: {str(e)}")

    try:
        with open(config_path, 'r') as f:
            current_config = f.read()
    except Exception as e:
        current_config = f"# Error loading config: {str(e)}"

    return render_template('config_editor.html',
                           config=current_config,
                           message=message,
                           auth_enabled=get_config()['webui']['auth']['enabled'],
                           logged_in=session.get('logged_in', False),
                           username=session.get('username', ''),
                           role=session.get('role', 'viewer'),
                           can_edit=session.get('role') == 'admin')

@bp.route('/control/scheduler/start', methods=['POST'])
@require_permission('control_services')
def start_scheduler():
    state = get_state()
    if not DashboardManager.scheduler.running:
        DashboardManager.scheduler.start()
        state.stats['scheduler_running'] = True
        log_audit_event(session['username'], 'scheduler_start', "Scheduler started")
        return jsonify({'status': 'success', 'message': 'Scheduler started'})
    return jsonify({'status': 'info', 'message': 'Scheduler already running'})

@bp.route('/control/scheduler/stop', methods=['POST'])
@require_permission('control_services')
def stop_scheduler():
    state = get_state()
    if DashboardManager.scheduler.running:
        DashboardManager.scheduler.shutdown()
        state.stats['scheduler_running'] = False
        log_audit_event(session['username'], 'scheduler_stop', "Scheduler stopped")
        return jsonify({'status': 'success', 'message': 'Scheduler stopped'})
    return jsonify({'status': 'info', 'message': 'Scheduler already stopped'})

@bp.route('/control/job/<job_id>/enable', methods=['POST'])
@require_permission('control_services')
def enable_job(job_id):
    job = DashboardManager.scheduler.get_job(job_id)
    if job:
        job.resume()
        log_audit_event(session['username'], 'job_enable', f"Job {job_id} enabled")
        return jsonify({'status': 'success', 'message': f'Job {job_id} enabled'})
    return jsonify({'status': 'error', 'message': f'Job {job_id} not found'}), 404

@bp.route('/control/job/<job_id>/disable', methods=['POST'])
@require_permission('control_services')
def disable_job(job_id):
    job = DashboardManager.scheduler.get_job(job_id)
    if job:
        job.pause()
        log_audit_event(session['username'], 'job_disable', f"Job {job_id} disabled")
        return jsonify({'status': 'success', 'message': f'Job {job_id} disabled'})
    return jsonify({'status': 'error', 'message': f'Job {job_id} not found'}), 404

@bp.route('/control/job/<job_id>/trigger', methods=['POST'])
@require_permission('control_services')
def trigger_job(job_id):
    job = DashboardManager.scheduler.get_job(job_id)
    if job:
        job.modify(next_run_time=datetime.now())
        log_audit_event(session['username'], 'job_trigger', f"Job {job_id} triggered")
        return jsonify({'status': 'success', 'message': f'Job {job_id} triggered'})
    return jsonify({'status': 'error', 'message': f'Job {job_id} not found'}), 404

@bp.route('/control/service/<service_name>/trigger', methods=['POST'])
@require_permission('control_services')
def trigger_service(service_name):
    if service_name in get_config()['poll_intervals']:
        DashboardManager.update_service(service_name)
        log_audit_event(session['username'], 'service_trigger', f"Service {service_name} triggered")
        return jsonify({'status': 'success', 'message': f'Service {service_name} triggered'})
    return jsonify({'status': 'error', 'message': f'Service {service_name} not found'}), 404

@bp.route('/sample_client')
def serve_sample_client():
    return """
    <!DOCTYPE html>
<html>
<head>
    <title>Dashboard Client</title>
    <script src="https://cdn.socket.io/4.7.2/socket.io.min.js"></script>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Segoe UI', sans-serif; background: #1e1e2e; color: #cdd6f4; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { text-align: center; margin-bottom: 30px; }
        .panels { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 20px; }
        .panel { background: #313244; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .panel-header { background: #45475a; padding: 15px; font-weight: bold; }
        .panel-body { padding: 15px; }
        .data-item { margin-bottom: 15px; }
        .data-label { font-size: 14px; color: #a6adc8; margin-bottom: 5px; }
        .data-value { font-size: 24px; font-weight: bold; }
        .status-bar { height: 5px; background: #585b70; margin-top: 10px; }
        .status-fill { height: 100%; background: #a6e3a1; width: 0%; transition: width 0.5s; }
        .connection-status { position: fixed; top: 20px; right: 20px; padding: 10px 15px; border-radius: 20px; }
        .connected { background: #a6e3a1; color: #1e1e2e; }
        .disconnected { background: #f38ba8; color: #1e1e2e; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Dashboard Client</h1>
            <p>Real-time Data Monitoring</p>
        </div>

        <div class="connection-status disconnected" id="connStatus">
            DISCONNECTED
        </div>

        <div class="panels" id="dataPanels">
            <!-- Panels will be dynamically created here -->
        </div>
    </div>

    <script>
        // Configuration
        const config = {
            clientId: 'sample_client_' + Math.random().toString(36).substr(2, 5),
            services: ['weather', 'stocks', 'news']
        };

        // State management
        const state = {
            connected: false,
            data: {},
            token: null
        };

        // DOM elements
        const connStatus = document.getElementById('connStatus');
        const dataPanels = document.getElementById('dataPanels');

        // Initialize
        async function init() {
            await fetchToken();
            connectToServer();
            createPanels();
        }

        // Fetch JWT token
        async function fetchToken() {
            try {
                // Get the base URL from the current location
                const baseURL = window.location.origin;
                const response = await fetch(`${baseURL}/token?client_id=${config.clientId}`);
                const data = await response.json();
                state.token = data.token;
            } catch (error) {
                console.error('Token fetch failed:', error);
                setTimeout(fetchToken, 5000);
            }
        }

        // Connect to WebSocket server
        function connectToServer() {
            // Get the base URL from the current location
            const baseURL = window.location.origin;
            const socket = io(baseURL + '/primary', {
                query: { token: state.token },
                reconnection: true,
                reconnectionAttempts: Infinity,
                reconnectionDelay: 1000,
                reconnectionDelayMax: 5000,
                transports: ['websocket']  // Force WebSocket transport
            });

            socket.on('connect', () => {
                state.connected = true;
                updateConnectionStatus();
                console.log('Connected to server');
            });

            socket.on('disconnect', () => {
                state.connected = false;
                updateConnectionStatus();
                console.log('Disconnected from server');
            });

            socket.on('connect_error', (error) => {
                console.error('Connection error:', error);
                // Attempt to reconnect
                setTimeout(() => {
                    fetchToken().then(() => {
                        socket.io.opts.query.token = state.token;
                        socket.connect();
                    });
                }, 5000);
            });

            socket.on('initial_data', (data) => {
                state.data = data;
                updatePanels();
            });

            socket.on('data_update', (update) => {
                state.data[update.source] = update.data;
                updatePanels();
            });
        }

        // Create panels for each service
        function createPanels() {
            config.services.forEach(service => {
                const panel = document.createElement('div');
                panel.className = 'panel';
                panel.id = `panel-${service}`;
                panel.innerHTML = `
                    <div class="panel-header">${service.toUpperCase()}</div>
                    <div class="panel-body" id="content-${service}">
                        <div class="data-value">Loading...</div>
                        <div class="status-bar"><div class="status-fill" id="status-${service}"></div></div>
                    </div>
                `;
                dataPanels.appendChild(panel);
            });
        }

        // Update panels with data
        function updatePanels() {
            config.services.forEach(service => {
                const contentDiv = document.getElementById(`content-${service}`);
                if (state.data[service]) {
                    let content = '';
                    for (const [key, value] of Object.entries(state.data[service])) {
                        content += `<div class="data-item">
                            <div class="data-label">${key}</div>
                            <div class="data-value">${formatValue(value)}</div>
                        </div>`;
                    }
                    contentDiv.innerHTML = content + `<div class="status-bar"><div class="status-fill" id="status-${service}"></div></div>`;

                    // Animate status bar
                    setTimeout(() => {
                        const statusBar = document.getElementById(`status-${service}`);
                        if (statusBar) statusBar.style.width = '100%';
                    }, 100);
                }
            });
        }

        // Format values based on type
        function formatValue(value) {
            if (typeof value === 'number') {
                return value.toLocaleString();
            }
            if (typeof value === 'object') {
                return JSON.stringify(value, null, 2);
            }
            return value;
        }

        // Update connection status UI
        function updateConnectionStatus() {
            if (state.connected) {
                connStatus.textContent = 'CONNECTED';
                connStatus.className = 'connection-status connected';
            } else {
                connStatus.textContent = 'DISCONNECTED';
                connStatus.className = 'connection-status disconnected';
            }
        }

        // Initialize the client
        init();
    </script>
</body>
</html>

    """