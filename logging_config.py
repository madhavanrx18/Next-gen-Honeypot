import logging
import os
from datetime import datetime
from logging.handlers import RotatingFileHandler

# Create logs directory if it doesn't exist
if not os.path.exists('logs'):
    os.makedirs('logs')

# Configure logging format
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

def setup_logger(name, log_file, level=logging.INFO):
    """Set up a logger with file and console handlers"""
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Create formatters
    formatter = logging.Formatter(LOG_FORMAT, DATE_FORMAT)

    # Create file handler
    file_handler = RotatingFileHandler(
        f'logs/{log_file}',
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger

# Set up different loggers for different types of events
login_logger = setup_logger('login', 'login_attempts.log')
security_logger = setup_logger('security', 'security_events.log')
system_logger = setup_logger('system', 'system_events.log')
error_logger = setup_logger('error', 'error_events.log')

# Example usage:
# login_logger.info("Login attempt from IP: 192.168.1.1")
# security_logger.warning("Multiple failed login attempts detected")
# system_logger.info("System started")
# error_logger.error("Database connection failed") 