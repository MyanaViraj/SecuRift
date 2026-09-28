import os
import secrets

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    # Use environment variable or generate dynamic cryptographic key
    _env_secret = os.environ.get("SECURIFT_SECRET_KEY")
    if _env_secret:
        SECRET_KEY = _env_secret
    else:
        # Fallback: generate persistent or per-run secure random token (32 bytes)
        SECRET_KEY = secrets.token_hex(32)

    DEBUG = os.environ.get("SECURIFT_DEBUG", "false").lower() in ("true", "1")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'database.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # CSRF Protection
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600

    # Uploads and paths
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
    PCAP_FOLDER = os.path.join(UPLOAD_FOLDER, "pcaps")
    SNORT_LOG_FOLDER = os.path.join(UPLOAD_FOLDER, "snort_logs")
    REPORTS_FOLDER = os.path.join(BASE_DIR, "reports")
    RULES_FOLDER = os.path.join(BASE_DIR, "snort_rules")

    # Safety and upload limits (50 MB)
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024
    ALLOWED_PCAP_EXTENSIONS = {"pcap", "pcapng"}
    ALLOWED_LOG_EXTENSIONS = {"log", "txt", "alert", "fast"}

    # Detection tool binary paths (detected dynamically)
    SNORT_PATH = os.environ.get("SNORT_PATH", None)
    TSHARK_PATH = os.environ.get("TSHARK_PATH", None)

    @classmethod
    def ensure_directories(cls):
        """Create necessary project directories if they do not exist."""
        for path in [
            cls.UPLOAD_FOLDER,
            cls.PCAP_FOLDER,
            cls.SNORT_LOG_FOLDER,
            cls.REPORTS_FOLDER,
            cls.RULES_FOLDER,
        ]:
            os.makedirs(path, exist_ok=True)

class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False
    SECRET_KEY = "test-csrf-and-secret-key-32-chars-long"
