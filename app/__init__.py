from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from config import Config

db = SQLAlchemy()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)

    # Register Blueprints
    from app.routes.main_routes import main_bp
    from app.routes.scanner_routes import scanner_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(scanner_bp)

    with app.app_context():
        db.create_all()

    return app
