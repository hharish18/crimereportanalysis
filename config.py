import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_DIR = os.path.join(BASE_DIR, "database")
os.makedirs(DB_DIR, exist_ok=True)


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    raw_db_url = os.environ.get("DATABASE_URL")
    if raw_db_url and raw_db_url.startswith("postgres://"):
        raw_db_url = raw_db_url.replace("postgres://", "postgresql://", 1)
        
    SQLALCHEMY_DATABASE_URI = raw_db_url or f"sqlite:///{os.path.join(DB_DIR, 'crime_report.db')}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 1800,
    }

    MAX_CONTENT_LENGTH = 8 * 1024 * 1024
    UPLOAD_FOLDER = os.path.join("static", "uploads")
    ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf", "doc", "docx"}

    MAIL_ENABLED = False
    MAIL_FROM = os.environ.get("MAIL_FROM", "noreply@crime.local")
