"""
Application Factory
"""
from flask import Flask
from .config import CONFIG, configure_logging
from .state import DashboardState
from . import routes, socketio, services


def create_app():
    """Create and configure the Flask application"""
    app = Flask(__name__)

    # Load configuration
    app.config.update(CONFIG)
    app.config['HOST'] = CONFIG['server']['host']
    app.config['PORT'] = CONFIG['server']['port']
    app.secret_key = CONFIG['auth']['jwt_secret']

    # Configure logging
    logger = configure_logging(CONFIG)
    app.logger = logger

    # Initialize application state
    app.state = DashboardState(CONFIG)

    # Register blueprints and routes
    app.register_blueprint(routes.bp)

    # Initialize SocketIO
    socketio.init_app(app)

    # Initialize services
    app.manager = services.DashboardManager(app)
    return app