import os
from flask import Flask
from config import Config
from app.extensions import db, migrate
from app.logging_config import setup_logging

def create_app():
    """Application factory for SentinelSOC."""
    app = Flask(__name__)
    app.config.from_object(Config)

    # 1. Initialize Logging Configuration
    setup_logging(app)

    # 2. Initialize Extensions
    db.init_app(app)
    migrate.init_app(app, db)

    # Import models to ensure they are registered with SQLAlchemy
    from app import models

    # 3. Create required directories
    os.makedirs(app.config.get("UPLOAD_FOLDER", "uploads"), exist_ok=True)
    os.makedirs(app.config.get("LOG_FOLDER", "logs"), exist_ok=True)

    # 4. Register Blueprints
    from app.blueprints.api import api
    from app.blueprints.main import main
    
    app.register_blueprint(api)
    app.register_blueprint(main)

    app.logger.info("SentinelSOC App successfully initialized and routes registered")
    return app