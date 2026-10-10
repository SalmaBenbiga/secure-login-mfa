from flask import Blueprint, request, jsonify, session
import pyotp
import qrcode
import io
import base64
import secrets
from app.models.user import User, BackupCode
from app import db, bcrypt
from app.models.user import User
from app.utils import login_required
from app import limiter
import logging
from app.security_logger import log_security_event
from app.crypto_utils import encrypt_secret, decrypt_secret

mfa_bp = Blueprint('mfa', __name__)

def generate_qr_code_base64(provisioning_url):
    # Créer l'objet QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(provisioning_url)
    qr.make(fit=True)
    
    # Générer l'image
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convertir l'image en Base64 pour l'envoyer en JSON
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')
    
    return img_base64

@mfa_bp.route('/mfa/setup', methods=['POST'])
@login_required
def setup_mfa():
    user = User.query.get(session['user_id'])
    
    secret = pyotp.random_base32()
    user.mfa_secret = encrypt_secret(secret)
    db.session.commit()
    
    totp = pyotp.TOTP(secret)
    provisioning_url = totp.provisioning_uri(
        name=user.email,
        issuer_name="MonProjetSecurite"
    )

    qr_code_base64 = generate_qr_code_base64(provisioning_url)

    log_security_event('MFA_SETUP_INITIATED', user_id=user.id)
    
    return jsonify({
        'qr_code': f'data:image/png;base64,{qr_code_base64}',
        'manual_entry_secret': secret
    }), 200


@mfa_bp.route('/mfa/confirm', methods=['POST'])
@login_required
def confirm_mfa():
    user = User.query.get(session['user_id'])
    
    if not user.mfa_secret:
        return jsonify({'error': 'Aucun secret MFA en attente de confirmation'}), 400
    
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Corps de requête JSON invalide ou manquant'}), 400
    
    code = data.get('code', '')
    if not isinstance(code, str):
        return jsonify({'error': 'Code requis'}), 400
    
    code = code.strip()
    if not code:
        return jsonify({'error': 'Code requis'}), 400

    if code == user.last_used_totp_code:
        return jsonify({'error': 'Ce code a déjà été utilisé'}), 401
    
    totp = pyotp.TOTP(decrypt_secret(user.mfa_secret))
    
    if not totp.verify(code):
        return jsonify({'error': 'Code invalide ou expiré'}), 401
    
    # Génération des backup codes (code inchangé)
    plain_backup_codes = []
    for _ in range(8):
        plain_code = secrets.token_hex(4)
        plain_backup_codes.append(plain_code)
        hashed = bcrypt.generate_password_hash(plain_code).decode('utf-8')
        db.session.add(BackupCode(user_id=user.id, code_hash=hashed))
    
    user.mfa_enabled = True
    user.last_used_totp_code = code
    db.session.commit()
    log_security_event('MFA_ENABLED', user_id=user.id)
    
    return jsonify({
        'message': 'MFA activé avec succès',
        'backup_codes': plain_backup_codes
    }), 200

@mfa_bp.route('/mfa/verify-login', methods=['POST'])
@limiter.limit("5 per 5 minutes")
def verify_login():
    if 'mfa_pending_user_id' not in session:
        return jsonify({'error': 'Aucune connexion en attente de vérification MFA'}), 400
    
    user = User.query.get(session['mfa_pending_user_id'])
    
    if not user:
        session.pop('mfa_pending_user_id', None)
        return jsonify({'error': 'Session invalide'}), 400
    
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Corps de requête JSON invalide ou manquant'}), 400
    
    code = data.get('code', '')
    if not isinstance(code, str):
        return jsonify({'error': 'Code requis'}), 400
    
    code = code.strip()
    if not code:
        return jsonify({'error': 'Code requis'}), 400
    
    # Protection anti-replay : refuser un code déjà utilisé pour cet utilisateur
    if code == user.last_used_totp_code:
        log_security_event('MFA_REPLAY_BLOCKED', level=logging.WARNING, user_id=user.id)
        return jsonify({'error': 'Ce code a déjà été utilisé'}), 401
    
    totp = pyotp.TOTP(decrypt_secret(user.mfa_secret))
    
    if not totp.verify(code):
        log_security_event('MFA_FAILED', level=logging.WARNING, user_id=user.id)
        return jsonify({'error': 'Code invalide ou expiré'}), 401
    
    # Mémoriser ce code comme étant le dernier utilisé avec succès
    user.last_used_totp_code = code
    db.session.commit()
    
    session.pop('mfa_pending_user_id', None)
    session.permanent = True
    session['user_id'] = user.id
    session['session_version'] = user.session_version
    log_security_event('MFA_SUCCESS', user_id=user.id)

    return jsonify({'message': 'Connexion complète réussie'}), 200

@mfa_bp.route('/mfa/verify-backup-code', methods=['POST'])
@limiter.limit("5 per minute")
def verify_backup_code():
    if 'mfa_pending_user_id' not in session:
        return jsonify({'error': 'Aucune connexion en attente de vérification MFA'}), 400
    
    user = User.query.get(session['mfa_pending_user_id'])
    
    if not user:
        session.pop('mfa_pending_user_id', None)
        return jsonify({'error': 'Session invalide'}), 400
    
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Corps de requête JSON invalide ou manquant'}), 400
    
    submitted_code = data.get('code', '')
    if not isinstance(submitted_code, str):
        return jsonify({'error': 'Code requis'}), 400
    
    submitted_code = submitted_code.strip()
    if not submitted_code:
        return jsonify({'error': 'Code requis'}), 400
    
    # On ne récupère que les codes NON utilisés de cet utilisateur
    unused_codes = BackupCode.query.filter_by(user_id=user.id, used=False).all()
    
    matched_code = None
    for backup_code in unused_codes:
        if bcrypt.check_password_hash(backup_code.code_hash, submitted_code):
            matched_code = backup_code
            break
    
    if matched_code is None:
        log_security_event('BACKUP_CODE_FAILED', level=logging.WARNING, user_id=user.id)
        return jsonify({'error': 'Code de récupération invalide'}), 401
    
    matched_code.used = True
    db.session.commit()
    log_security_event('BACKUP_CODE_USED', level=logging.WARNING, user_id=user.id)

    session.pop('mfa_pending_user_id', None)
    session.permanent = True
    session['user_id'] = user.id
    session['session_version'] = user.session_version
    
    remaining = BackupCode.query.filter_by(user_id=user.id, used=False).count()
    
    return jsonify({
        'message': 'Connexion réussie via code de récupération',
        'remaining_backup_codes': remaining
    }), 200