"""
SocketIO Handlers
"""
from flask_socketio import SocketIO, emit, join_room, leave_room
from . import CONFIG, state, utils
from .routes import manager

socketio = SocketIO(cors_allowed_origins=CONFIG['security']['cors_origins'], async_mode='threading')

# Web UI Socket
@socketio.on('connect', namespace='/webui')
def handle_webui_connect():
    state.webui_clients.add(request.sid)
    emit_log_update()

@socketio.on('disconnect', namespace='/webui')
def handle_webui_disconnect():
    state.webui_clients.discard(request.sid)

@socketio.on('manual_refresh', namespace='/webui')
def handle_manual_refresh():
    # Trigger updates for all services
    for api in CONFIG['poll_intervals']:
        manager.update_service(api)
    emit_log_update()

# Primary WebSocket
@socketio.on('connect', namespace='/primary')
def handle_primary_connect():
    token = request.args.get('token')
    if not token:
        return False

    client_id = state.validate_auth_token(token)
    if not client_id:
        return False

    state.primary_clients[request.sid] = client_id
    state.stats["clients_served"] += 1
    emit('initial_data', state.latest_data, room=request.sid, namespace='/primary')
    return True

@socketio.on('disconnect', namespace='/primary')
def handle_primary_disconnect():
    if request.sid in state.primary_clients:
        client_id = state.primary_clients.pop(request.sid)

# Backup WebSocket
@socketio.on('connect', namespace='/backup')
def handle_backup_connect():
    token = request.args.get('token')
    if not token:
        return False

    client_id = state.validate_auth_token(token)
    if not client_id:
        return False

    state.backup_clients[request.sid] = client_id
    emit('status', {'message': 'BACKUP_ACTIVE'}, room=request.sid, namespace='/backup')
    return True

@socketio.on('disconnect', namespace='/backup')
def handle_backup_disconnect():
    if request.sid in state.backup_clients:
        client_id = state.backup_clients.pop(request.sid)

def emit_log_update():
    if state.webui_clients:
        state.update_uptime()
        logs = utils.get_log_lines(CONFIG['webui']['log_lines'])
        emit('log_update', {
            'logs': logs,
            'stats': state.stats,
            'performance': state.performance,
            'clients': {
                'primary': len(state.primary_clients),
                'backup': len(state.backup_clients),
                'webui': len(state.webui_clients)
            }
        }, namespace='/webui')