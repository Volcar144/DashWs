#!/usr/bin/env python3
import os
from app import create_app
from app.services import DashboardManager

if __name__ == '__main__':
    app = create_app()
    manager = DashboardManager(app)


    from app.socket_handlers import socketio

    socketio.run(
            app,
            host=app.config['HOST'],
            port=app.config['PORT'],
            debug=True,
            use_reloader=False,
            allow_unsafe_werkzeug=True
        )