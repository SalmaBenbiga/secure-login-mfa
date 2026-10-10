from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import os
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
import logging
from flask import Flask, jsonify
from flask_wtf.csrf import CSRFError
from app.security_logger import init_security_logging, log_security_event

load_dotenv()  # charge les variables du fichier .env

db = SQLAlchemy()
bcrypt = Bcrypt()
migrate = Migrate()
limiter = Limiter(key_func=get_remote_address)
csrf = CSRFProtect()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Configuration de sécurité des cookies de session
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_COOKIE_SECURE'] = False
    app.config['PERMANENT_SESSION_LIFETIME'] = 1800
    
    db.init_app(app)
    bcrypt.init_app(app)
    migrate.init_app(app, db)
    limiter.init_app(app)
    csrf.init_app(app)

    init_security_logging(app)

    @app.errorhandler(429)
    def ratelimit_handler(e):
        log_security_event('RATE_LIMIT_EXCEEDED', level=logging.WARNING)
        return jsonify({'error': 'Trop de tentatives, réessayez plus tard'}), 429

    @app.errorhandler(CSRFError)
    def csrf_error_handler(e):
        log_security_event('CSRF_VALIDATION_FAILED', level=logging.WARNING)
        return jsonify({'error': 'Requête invalide'}), 400

    @app.errorhandler(400)
    def bad_request_handler(e):
        log_security_event('BAD_REQUEST', level=logging.WARNING)
        return jsonify({'error': 'Requête invalide'}), 400

    @app.errorhandler(415)
    def unsupported_media_type_handler(e):
        return jsonify({'error': 'Content-Type doit être application/json'}), 415
    
    @app.errorhandler(404)
    def not_found_handler(e):
        return jsonify({'error': 'Ressource introuvable'}), 404

    @app.errorhandler(500)
    def internal_error_handler(e):
        log_security_event('INTERNAL_SERVER_ERROR', level=logging.WARNING)
        return jsonify({'error': 'Une erreur interne est survenue'}), 500

    
    from app.routes.auth import auth_bp
    app.register_blueprint(auth_bp, url_prefix='/api/auth')

    from app.routes.mfa import mfa_bp
    app.register_blueprint(mfa_bp, url_prefix='/api/auth')

    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response
    
    return app