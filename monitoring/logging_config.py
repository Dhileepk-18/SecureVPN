import logging
from logging.handlers import RotatingFileHandler
import os

# Add custom SECURITY log level (Level 35 - between WARNING and ERROR)
SECURITY_LEVEL_NUM = 35
logging.addLevelName(SECURITY_LEVEL_NUM, "SECURITY")

def security(self, message, *args, **kws):
    if self.isEnabledFor(SECURITY_LEVEL_NUM):
        self._log(SECURITY_LEVEL_NUM, message, args, **kws)

logging.Logger.security = security

def setup_logger(name: str = "SecureVPN", log_file: str = "securevpn.log", level=logging.INFO):
    """Configures structured console & rotating file logger."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    # Avoid duplicate handlers if already configured
    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # 1. Console Handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # 2. Bounded Rotating File Handler (5 MB max per file, 3 backups)
    file_handler = RotatingFileHandler(
        log_file, maxBytes=5 * 1024 * 1024, backupCount=3
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger
