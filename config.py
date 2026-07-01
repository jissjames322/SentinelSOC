import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "change_this_to_a_long_random_secret")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///sentinel.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    GEOIP_DB = os.getenv("GEOIP_DB", "database/GeoLite2-City.mmdb")
    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", "uploads")
    LOG_FOLDER = os.getenv("LOG_FOLDER", "logs")
    
    # Ingestion constraints
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB limit