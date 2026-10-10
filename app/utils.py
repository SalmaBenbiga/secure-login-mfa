import logging
from functools import wraps
from flask import session, jsonify
from app.models.user import User
from app.security_logger import log_security_event


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user_id')
        if user_id is None:
            return jsonify({'error': 'Authentification requise'}), 401

        user = User.query.get(user_id)
        if user is None or session.get('session_version') != user.session_version:
            log_security_event('STALE_SESSION_REJECTED', level=logging.WARNING, user_id=user_id)
            session.clear()
            return jsonify({'error': 'Authentification requise'}), 401

        return f(*args, **kwargs)
    return decorated_function