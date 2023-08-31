# #Ce2p@91dpyL
import json
from datetime import datetime, timedelta
from os import getcwd
from flask import Blueprint, render_template, request, send_from_directory, make_response, session, redirect, url_for, \
    current_app, flash
from flask_login import login_required, current_user, login_user, logout_user
import os
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from app.models import User, Codes
from functools import wraps
from flask import current_app, request, jsonify
from iqsms_rest import Gate
import random
import time
from .user import generate_password
from .config import *
from .helpers import send_email


def dir_last_updated(folder):
    return str(max(os.path.getmtime(os.path.join(root_path, f)) for root_path, dirs, files in os.walk(folder)
                   for f in files))


def login_required_api(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = request.args.get('token')
        user = User.verify_auth_token(token)
        if not user:
            return current_app.response_class(
                response=json.dumps(
                    {'error': 'USER DOES NOT EXIST'}
                ),
                status=403,
                mimetype='application/json'
            )
        if user.status == "blocked":
            return current_app.response_class(
                response=json.dumps(
                    {'error': 'USER BLOCKED'}
                ),
                status=403,
                mimetype='application/json'
            )
        if user.role not in [1, 2]:
            return current_app.response_class(
                response=json.dumps(
                    {'error': 'PERMISSION DENIED'}
                ),
                status=403,
                mimetype='application/json'
            )
        try:
            return func(*args, **kwargs)
        except Exception as e:
            print(e)
            return current_app.response_class(
                response=json.dumps(
                    {'error': f'ERROR: {e}!'}
                ),
                status=400,
                mimetype='application/json'
            )

    return wrapper


main = Blueprint('main', __name__)

CWD = '/root/MeashStore/'


@main.route('/api/auth-admin')
def auth_admin():
    '''
    ---
       get:
         summary: Вход админа
         parameters:
             - in: query
               name: email
               schema:
                 type: string
                 example: example2@gmail.com
               description: email
             - in: query
               name: password
               schema:
                 type: string
                 example: 123
               description: password
             - in: query
               name: remember
               schema:
                 type: boolean
                 example: true
               description: password
         responses:
           '200':
             description: Результат
             content:
               application/json:
                 schema:      # Request body contents
                   type: object
                   properties:
                       result:
                         type: boolean
                       token:
                         type: string
                       role:
                         type: integer
                       msg:
                         type: string
           '400':
             description: Не передан обязательный параметр
             content:
               application/json:
                 schema: ErrorSchema
           '401':
             description: Неверный пароль или пользователь не существует
             content:
               application/json:
                 schema: ErrorSchema
           '403':
             description: Пользователь заблокирован
             content:
               application/json:
                 schema: ErrorSchema
         tags:
           - admin
        '''
    try:
        email = request.args.get('email')
        password = request.args.get('password')
        remember = True if request.args.get('remember') else False
        user = User.query.filter_by(email=email).first()
        if user:
            msg = ''
            if user.confirmed == 0:
                msg = 'Номер телефона не подтверждкен'
            if user.role not in [1, 2]:
                return current_app.response_class(
                    response=json.dumps(
                        {
                            'error': "NOT ADMIN",
                            'role': '',
                            'token': ''
                        }
                    ),
                    status=400,
                    mimetype='application/json'
                )
            if user.status == 'blocked':
                return current_app.response_class(
                    response=json.dumps(
                        {
                            'error': "USER BLOCKED",
                            'role': '',
                            'token': ''
                        }
                    ),
                    status=400,
                    mimetype='application/json'
                )
            if check_password_hash(user.password, password):
                login_user(user, remember=remember)
                return current_app.response_class(
                    response=json.dumps(
                        {
                            'result': True,
                            'token': user.generate_auth_token(expiration=86400 if remember else 3600),
                            'role': user.role,
                            'network': {
                                'id': user.group,
                                'name': Groups.query.filter_by(id=user.group).first().name
                            } if user.role != 2 else {},
                            'msg': msg
                        }
                    ),
                    status=200,
                    mimetype='application/json'
                )
            else:
                return current_app.response_class(
                    response=json.dumps(
                        {
                            'result': 'INCORRECT PASSWORD',
                            'token': '',
                            'role': ''
                        }
                    ),
                    status=400,
                    mimetype='application/json'
                )
        else:
            return current_app.response_class(
                response=json.dumps(
                    {
                        'result': 'USER DOES NOT EXIST',
                        'token': '',
                        'role': ''
                    }
                ),
                status=400,
                mimetype='application/json'
            )
    except Exception as e:
        return current_app.response_class(
            response=json.dumps(
                {'error': f'ERROR: {e}!'}
            ),
            status=400,
            mimetype='application/json'
        )


@main.route('/', methods=['POST', 'GET'])
@main.route('/users', methods=['POST', 'GET'])
@login_required
def users():
    print(url_for('main.edit_user', id=1))
    users = []
    user = current_user
    search_query = request.args.get('search', '')  # Получаем значение параметра 'search' из URL
    if user.role == 2:
        query = User.query.filter(User.name.contains(search_query) |
                                  User.email.contains(search_query) |
                                  User.phone.contains(search_query))
        all_users = query.all()
    else:
        query = User.query.filter((User.name.contains(search_query) |
                                   User.email.contains(search_query) |
                                   User.phone.contains(search_query)) & (User.role != 2))
        all_users = query.all()
    for i in all_users:
        users.append({
            'id': i.id,
            'name': i.name,
            'email': i.email,
            'phone': i.phone,
            'phone_confirmed': i.confirmed,
            'status': 'Активный' if i.status == 'active' else 'Заблокирован',
            'role': 'Пользователь' if i.role == 0 else 'Админ сервиса',
        })
    return render_template('stats.html', users=users)


@main.route('/user/<id>', methods=['GET'])
@login_required
def edit_user(id):
    user = User.query.filter_by(id=id).first()
    return render_template('user.html', user=user)


@main.route('/edit-user/<id>', methods=['POST'])
@login_required
def edit_user_post(id):
    name = request.form['name']
    phone = request.form['phone']
    email = request.form['email']
    user = User.query.filter_by(id=id).first()
    if User.query.filter_by(email=email).first() and user.email != email:
        flash('Пользователь с таким Email адресом уже зарегистрирован')
        return redirect('main.edit_user')
    if User.query.filter_by(phone=phone).first() and user.phone != phone:
        flash('Пользователь с таким номером телефона уже зарегистрирован')
        return redirect('main.edit_user')
    if user.phone != phone:
        _ = User.query.filter_by(id=id).update(
            {'name': name, 'phone': phone, 'email': email, 'confirmed': 0})
    else:
        _ = User.query.filter_by(id=id).update({'name': name, 'email': email, })
    db.session.commit()
    return redirect(url_for('main.edit_user', id=id))


@main.route('/add-user', methods=['POST'])
@login_required
def add_user():
    name = request.form['name']
    email = request.form['email']
    phone = str(request.form['phone']).replace('(', '').replace(')', '').replace('-', '').replace('+', '').replace(
        ' ', '')
    role = request.form['role']
    if User.query.filter_by(email=email).first():
        flash('Пользователь с таким Email адресом уже зарегистрирован')
        return redirect(url_for('main.users'))
    if User.query.filter_by(phone=phone).first():
        flash('Пользователь с таким номером телефона уже зарегистрирован')
        return redirect(url_for('main.users'))
    token = generate_password_hash(str(phone), method='sha256').replace('sha256$', '')
    password = generate_password(length=8)
    try:
        send_email(email, 'Регистрация в приложении BankiRU',
                   f'Вы зарегистрированы в приложении BankiRU\nВаш логин: {email}\nПароль: {password}\nРекомендуем вам сменить пароль')
    except:
        pass
    new_user = User(email=email, phone=phone, name=name, role=role, confirmed=0,
                    password=generate_password_hash(str(password), method='sha256'),
                    status="active", registered=int(time.time()))
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('main.users'))



@main.route('/api/delete-user/<id>', methods=['GET'])
@login_required
def delete_user(id):
    _ = User.query.filter_by(id=id).delete()
    db.session.commit()
    return redirect(url_for('main.users'))


@main.route('/api/block-user/<id>', methods=['GET'])
@login_required
def block_user(id):
    _ = User.query.filter_by(id=id).update({'status': 'blocked'})
    db.session.commit()
    return redirect(url_for('main.users'))


@main.route('/api/unblock-user/<id>', methods=['GET'])
@login_required
def unblock_user(id):
    _ = User.query.filter_by(id=id).update({'status': 'active'})
    db.session.commit()
    return redirect(url_for('main.users'))
