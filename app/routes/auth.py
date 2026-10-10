from flask import Blueprint, request, jsonify, session
from app import db, bcrypt
from app.models.user import User
import re
from flask_bcrypt import check_password_hash
from app.utils import login_required
from app import limiter
from flask_wtf.csrf import generate_csrf
from app import csrf
import logging
from app.security_logger import log_security_event

auth_bp = Blueprint('auth', __name__)

def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def is_strong_password(password):
    # Au moins 8 caractères, une majuscule, une minuscule, un chiffre
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    return True

@auth_bp.route('/register', methods=['POST'])
@csrf.exempt
def register():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Corps de requête JSON invalide ou manquant'}), 400

    username = data.get('username', '')
    email = data.get('email', '')
    password = data.get('password', '')
    
    if not isinstance(username, str) or not isinstance(email, str) or not isinstance(password, str):
        return jsonify({'error': 'Tous les champs sont requis'}), 400
    
    username = username.strip()
    email = email.strip().lower()
    
    # Validation des inputs
    if not username or not email or not password:
        return jsonify({'error': 'Tous les champs sont requis'}), 400
    
    if not is_valid_email(email):
        return jsonify({'error': 'Format email invalide'}), 400
    
    if not is_strong_password(password):
        return jsonify({'error': 'Le mot de passe doit contenir au moins 8 caractères, une majuscule, une minuscule et un chiffre'}), 400
    
    # Vérifier si l'utilisateur existe déjà
    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({'error': 'Utilisateur déjà existant'}), 409
    
    # Hash du mot de passe
    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    new_user = User(username=username, email=email, password_hash=password_hash)
    db.session.add(new_user)
    db.session.commit()
    log_security_event('REGISTER_SUCCESS', user_id=new_user.id, username=username)
    
    return jsonify({'message': 'Compte créé avec succès'}), 201


@auth_bp.route('/login', methods=['POST'])
@csrf.exempt
@limiter.limit("5 per minute")
def login():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Corps de requête JSON invalide ou manquant'}), 400
    
    username = data.get('username', '')
    password = data.get('password', '')
    
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({'error': 'Identifiants invalides'}), 400
    
    username = username.strip()
    
    if not username or not password:
        return jsonify({'error': 'Identifiants invalides'}), 400
    
    user = User.query.filter_by(username=username).first()
    
    # ⚠️ Point de sécurité critique : message générique
    if not user or not bcrypt.check_password_hash(user.password_hash, password):
        log_security_event('LOGIN_FAILED', level=logging.WARNING, username=username)
        return jsonify({'error': 'Identifiants invalides'}), 401
    

    # Si l'utilisateur a activé le MFA, on ne connecte pas encore complètement
    if user.mfa_enabled:
        session.permanent = True
        session['mfa_pending_user_id'] = user.id
        log_security_event('LOGIN_PASSWORD_OK_MFA_PENDING', user_id=user.id, username=username)
        return jsonify({'mfa_required': True}), 200
    
    # Pas de MFA activé -> connexion complète directe
    session.permanent = True
    session['user_id'] = user.id
    session['session_version'] = user.session_version
    log_security_event('LOGIN_SUCCESS', user_id=user.id, username=username)
    
    return jsonify({'message': 'Connexion réussie'}), 200

@auth_bp.route('/logout', methods=['POST'])
def logout():
    user_id = session.get('user_id')
    log_security_event('LOGOUT', user_id=user_id)

    if user_id is not None:
        user = User.query.get(user_id)
        if user:
            user.session_version += 1
            db.session.commit()

    session.clear()
    return jsonify({'message': 'Déconnecté avec succès'}), 200

@auth_bp.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    return jsonify({'message': 'Bienvenue sur ton dashboard'}), 200

@auth_bp.route('/csrf-token', methods=['GET'])
def get_csrf_token():
    token = generate_csrf()
    return jsonify({'csrf_token': token}), 200