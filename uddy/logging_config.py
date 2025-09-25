import os
from pathlib import Path


USE_X_FORWARDED_HOST = True
USE_X_FORWARDED_PORT = True
# Decide log directory:
#   - Local: BASE_DIR/logs (auto-created if missing)
#   - Production: /tmp if LOG_TO_TMP is set (e.g. on Render)
BASE_DIR = Path(__file__).resolve().parent.parent
if os.getenv("LOG_TO_TMP"):
    LOG_FILE = "/tmp/django.log"
else:
    log_dir = BASE_DIR / "logs"
    log_dir.mkdir(exist_ok=True)
    LOG_FILE = log_dir / "django.log"

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "{levelname} {asctime} {module} {message}",
            "style": "{",
        },
    },
    "handlers": {
        "file": {
            "level": "INFO",
            "class": "logging.FileHandler",
            "filename": str(LOG_FILE),
            "formatter": "verbose",
        },
        "console": {
            "level": "INFO",
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
    },
    "loggers": {
        "django": {
            "handlers": ["file", "console"],
            "level": "INFO",
            "propagate": True,
        },
    },
}