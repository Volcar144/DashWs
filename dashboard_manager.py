#!/usr/bin/env python3
"""
Dashboard Manager - Main Entry Point
"""
import os
import sys
from app import create_app

if __name__ == '__main__':
    # Create application instance
    app = create_app()

        from app.socketio import socketio

        socketio.run(
            app,
            host=app.config['HOST'],
            port=app.config['PORT'],
            debug=True,
            use_reloader=False,
            allow_unsafe_werkzeug=True
        )