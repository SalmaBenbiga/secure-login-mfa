import logging
import os
from logging.handlers import RotatingFileHandler
from flask import request, has_request_context

security_logger = logging.getLogger('security')


def init_security_logging(app):
    # Évite d'ajouter deux fois le même handler (create_app peut être appelée plusieurs fois)
    if security_logger.handlers:
        return

    log_dir = os.path.join(os.path.dirname(app.root_path), 'logs')
    os.makedirs(log_dir, exist_ok=True)

    handler = RotatingFileHandler(
        os.path.join(log_dir, 'security.log'),
        maxBytes=1_000_000,
        backupCount=5,
        encoding='utf-8'
    )
    handler.setFormatter(logging.Formatter('%(asctime)s | %(levelname)s | %(message)s'))

    security_logger.addHandler(handler)
    security_logger.setLevel(logging.INFO)
    security_logger.propagate = False


def _clean(value, max_len=80):
    # Neutralise l'injection de logs : pas de retour à la ligne, longueur limitée
    if value is None:
        return '-'
    return str(value).replace('\r', ' ').replace('\n', ' ')[:max_len]


def log_security_event(event, level=logging.INFO, username=None, user_id=None):
    ip = request.remote_addr if has_request_context() else '-'
    path = request.path if has_request_context() else '-'

    message = (
        f"event={event} "
        f"ip={_clean(ip)} "
        f"user_id={_clean(user_id)} "
        f"username={_clean(username)} "
        f"path={_clean(path)}"
    )
    security_logger.log(level, message)