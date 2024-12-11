import logging
from datetime import datetime

class LogManager:
    @staticmethod
    def setup_logger(log_file):
        logger = logging.getLogger(log_file)
        logger.setLevel(logging.INFO)
        handler = logging.FileHandler(log_file, mode='a')
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    @staticmethod
    def log_signature_operation(logger, operation, algorithm, key_length, username=None):
        message = (f"Digital Signature {operation}: Algorithm={algorithm}, "
                   f"Key Length={key_length}")
        if username:
            message += f", Username={username}"
        logger.info(message)

    @staticmethod
    def log_certificate_operation(logger, operation, algorithm, key_length, subject, issuer):
        logger.info(f"Certificate {operation}: Algorithm={algorithm}, "
                    f"Key Length={key_length}, "
                    f"Subject={subject}, "
                    f"Issuer={issuer}")