from flask import Flask
from .config import CONFIG, configure_logging
from .services import DashboardManager
from .state import DashboardState

def create_app():
    app = Flask(__name__, template_folder='../templates')  # Add template_folder parameter
    app.config.update(CONFIG)
    app.config['HOST'] = CONFIG['server']['host']
    app.config['PORT'] = CONFIG['server']['port']
    app.secret_key = CONFIG['auth']['jwt_secret']

    # Configure logging
    logger = configure_logging(CONFIG)
    app.logger = logger

    # Initialize application state
    app.state = DashboardState(CONFIG)

    app.DashboardManager = DashboardManager(app)  # Add this line

    # Initialize routes
    from .routes import bp as routes_blueprint
    app.register_blueprint(routes_blueprint)

    # Initialize SocketIO
    from .socket_handlers import init_socketio
    init_socketio(app)

    return app