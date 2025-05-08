from flask import Blueprint, render_template, request, redirect, url_for, session
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User
import pyotp, qrcode
import io, base64

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        mfa_secret = pyotp.random_base32()
        hashed_password = generate_password_hash(password)

        user = User(username=username, password=hashed_password, mfa_secret=mfa_secret)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('auth.login'))
    return render_template('register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            session['preauth_user_id'] = user.id  # 暂存，等待 MFA 验证
            return redirect(url_for('auth.mfa'))
    return render_template('login.html')

@auth_bp.route('/mfa', methods=['GET', 'POST'])
def mfa():
    user_id = session.get('preauth_user_id')
    if not user_id:
        return redirect(url_for('auth.login'))

    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('auth.login'))

    totp = pyotp.TOTP(user.mfa_secret)
    qr_uri = totp.provisioning_uri(name=user.username, issuer_name="ZTA-Demo")
    qr_img = qrcode.make(qr_uri)
    buf = io.BytesIO()
    qr_img.save(buf, format='PNG')
    img_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')

    if request.method == 'POST':
        token = request.form['token']
        if totp.verify(token):
            login_user(user)
            session.pop('preauth_user_id', None)
            return redirect(url_for('auth.dashboard'))
        else:
            return render_template('mfa.html', qr_code=img_base64, error="Invalid code")

 
    return render_template('mfa.html', qr_code=img_base64)

@auth_bp.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username, role=current_user.role)
