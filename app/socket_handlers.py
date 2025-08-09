from flask_socketio import SocketIO, emit
from flask import request

socketio = SocketIO()

def init_socketio(app):
    """Initialize SocketIO with the Flask app"""
    socketio.init_app(
        app,
        cors_allowed_origins=app.config['security']['cors_origins'],
        async_mode='threading'
    )

    # Web UI Socket
    @socketio.on('connect', namespace='/webui')
    def handle_webui_connect():
        app.state.webui_clients.add(request.sid)
        emit_log_update(app)

    @socketio.on('disconnect', namespace='/webui')
    def handle_webui_disconnect():
        app.state.webui_clients.discard(request.sid)

    @socketio.on('manual_refresh', namespace='/webui')
    def handle_manual_refresh():
        for api in app.config['poll_intervals']:
            app.manager.update_service(api)
        emit_log_update(app)

    # Primary WebSocket
    @socketio.on('connect', namespace='/primary')
    def handle_primary_connect():
        token = request.args.get('token')
        if not token:
            return False

        client_id = app.state.validate_auth_token(token)
        if not client_id:
            return False

        app.state.primary_clients[request.sid] = client_id
        app.state.stats["clients_served"] += 1
        emit('initial_data', app.state.latest_data, room=request.sid, namespace='/primary')
        return True

    @socketio.on('disconnect', namespace='/primary')
    def handle_primary_disconnect():
        if request.sid in app.state.primary_clients:
            app.state.primary_clients.pop(request.sid)

    # Backup WebSocket
    @socketio.on('connect', namespace='/backup')
    def handle_backup_connect():
        token = request.args.get('token')
        if not token:
            return False

        client_id = app.state.validate_auth_token(token)
        if not client_id:
            return False

        app.state.backup_clients[request.sid] = client_id
        emit('status', {'message': 'BACKUP_ACTIVE'}, room=request.sid, namespace='/backup')
        return True

    @socketio.on('disconnect', namespace='/backup')
    def handle_backup_disconnect():
        if request.sid in app.state.backup_clients:
            app.state.backup_clients.pop(request.sid)

def emit_log_update(app):
    """Emit log updates to web UI clients"""
    if app.state.webui_clients:
        from .utils import get_log_lines
        app.state.update_uptime()
        logs = get_log_lines(app.config['webui']['log_lines'])
        emit('log_update', {
            'logs': logs,
            'stats': app.state.stats,
            'performance': app.state.performance,
            'clients': {
                'primary': len(app.state.primary_clients),
                'backup': len(app.state.backup_clients),
                'webui': len(app.state.webui_clients)
            }
        }, namespace='/webui')