# utils/logger.py
import logging
import os

def setup_logger():
    """Configure and return a logger with standardized formatting."""
    
    logger = logging.getLogger('KMSAnalyzer')
    
    # Only add handlers if they haven't been added already
    if not logger.handlers:
        # Set logging level from environment variable or default to INFO
        log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
        logger.setLevel(getattr(logging, log_level))

        # Create console handler
        handler = logging.StreamHandler()
        
        # Create a standard format for all log messages
        formatter = logging.Formatter(
            fmt='[%(asctime)s:%(levelname)s:%(filename)s:%(lineno)s - %(funcName)s()] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        # Prevent logs from being propagated to the root logger
        logger.propagate = False

    return logger

# Create and configure logger
logger = setup_logger()

# Usage example:
if __name__ == '__main__':
    logger.debug('Debug message')
    logger.info('Info message')
    logger.warning('Warning message')
    logger.error('Error message')
    logger.critical('Critical message')
