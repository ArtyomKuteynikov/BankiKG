# auth.py

from flask import Blueprint, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
from app.models import User, Codes
from . import db
from iqsms_rest import Gate
import random
import time
from .config import *

auth = Blueprint('auth', __name__)


@auth.route('/login')
def login():
    return render_template('auth/login.html')


@auth.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False
    user = User.query.filter_by(email=email).first()
    print(user)
    if not user or not check_password_hash(user.password, password):
        flash('Неверный пароль')
        return redirect(url_for('auth.login'))
    if user.role not in [1, 2]:
        flash('Нет доступа')
        return redirect(url_for('auth.login'))
    login_user(user, remember=remember)
    return redirect(url_for('main.users'))


@auth.route('/restore-pass', methods=['GET'])
def restore_pass():
    return render_template('auth/restore_pass.html')


@auth.route('/restore-pass', methods=['POST'])
def restore_pass_post():
    phone = request.form.get('phone').replace('+', '').replace(' ', '').replace('-', '').replace('(', '').replace(')',
                                                                                                                  '')
    user = User.query.filter_by(phone=phone).first()
    if not user or user.status != 'admin':
        flash('Пользователь не найден или не имеет доступ к панели администратора')
        return redirect(url_for('auth.login'))
    code = random.randint(1001, 9999)
    new_code = Codes(code=code, phone=phone)
    db.session.add(new_code)
    db.session.commit()
    sender = Gate(SMS_LOGIN, SMS_PASSWORD)
    status = sender.send_message(phone, f'Ваш код сброса пароля\n{code}', 'SMS DUCKOHT')

    return render_template('auth/check_code.html', phone=phone)


@auth.route('/check-code', methods=['POST'])
def check_code():
    phone = request.args.get('phone')
    code = Codes.query.filter_by(phone=phone).all()[-1].code
    user_input = request.form.get('code')

    if code != user_input:
        flash('Неверный код')
        return render_template('auth/check_code.html', phone=phone)

    return render_template('auth/new_password.html', phone=phone)


@auth.route('/set-password', methods=['POST'])
def set_password():
    phone = request.args.get('phone')
    password = request.form.get('password')
    conf_password = request.form.get('conf_password')
    if password != conf_password:
        flash('Пароли не совпадают')
        return render_template('auth/new_password.html')
    _ = User.query.filter_by(phone=phone).update({'password': generate_password_hash(password, method='sha256')})
    db.session.commit()
    return redirect(url_for('auth.login'))


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/profile')
def profile():
    user = {
        'name': current_user.name,
        'email': current_user.email,
        'phone': current_user.phone,
        'phone_confirmed': current_user.confirmed,
        'status': 'Активный' if current_user.status == 'active' else 'Заблокирован',
    }
    return render_template('profile.html', user=user)


@auth.route('/edit_profile', methods=['POST'])
def edit_profile():
    name = request.args.get('name')
    email = request.args.get('email')
    phone = str(request.args.get('phone')).replace('(', '').replace(')', '').replace('-', '').replace('+', '').replace(
        ' ', '')
    _ = User.query.filter_by(id=current_user.id).update({'name': name, 'phone': phone, 'email': email})
    db.session.commit()
    return redirect(url_for('auth.profile'))


@auth.route('/webapi/edit_password', methods=['POST'])
def edit_password():
    old_password = request.form.get('old_password')
    new_password = request.form.get('new_password')
    conf_password = request.form.get('conf_password')
    print(old_password, new_password, conf_password)
    if not check_password_hash(current_user.password, old_password):
        return {'status': False, 'error': 'Неверный старый пароль'}
    if conf_password != new_password:
        return {'status': False, 'error': 'Пароли не совпадают'}
    _ = User.query.filter_by(id=current_user.id).update({'password':  generate_password_hash(new_password, method='sha256')})
    db.session.commit()
    return {'status': True}
