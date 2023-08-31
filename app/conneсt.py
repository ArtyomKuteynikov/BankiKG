import json
from datetime import datetime, timedelta
from os import getcwd
from flask import Blueprint, render_template, request, send_from_directory, make_response, session, redirect, url_for, \
    current_app
from flask_login import login_required, current_user, login_user, logout_user
import os
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from app.models import User, Codes
from app.models import user_mapping
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


def oauth(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        key = request.headers.get('KEY')
        secret = request.headers.get('SECRET')
        if key != key or secret != secret:
            return current_app.response_class(
                response=json.dumps(
                    {'error': f'NOT FOUND'}
                ),
                status=404,
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


def db2dict(data):
    result = []
    for i in data:
        d = i.__dict__
        d.pop('_sa_instance_state')
        result.append(d)
    return result


connect = Blueprint('connect', __name__)

CWD = '/root/MeashStore/'


@connect.route('/connect/user/select', methods=['GET'])
@oauth
def user_select():
    '''
    ---
   get:
     summary: SELECT from USER
     parameters:
         - in: header
           name: KEY
           schema:
             type: string
             example: zFp*h*4Q*xLa&@hV8%%*zXCLN69AOYUv3FearK42$2aNzfiyzRtEz&1e7605&2i@BnhasrFwYVgZ%KIsXE3I87D8B4YtofjngDQ#hqd&LVV@%YTv&jR1ABM0vXSoLd*m
           required: true
         - in: header
           name: SECRET
           schema:
             type: string
             example: x759Q2SToJ@KW4&eqbndZz7dAAERZQesQ@JSJkTd$KbEvNO6QNB8zKBR2n%kj0S&QAdg0pvDypl3Dtt07sICA1WaToQ0Eamxoe3#s0XH*t4CFs9m4rcuvnHT&HK5I5uF
           required: true
         - in: query
           name: type
           schema:
             type: string
             enum: [ "ALL", "CONTAIN", "EQUAL"]
             example: ALL
           description: type
         - in: query
           name: arg
           schema:
             type: string
             enum: [ "", "id", "name", "email", "phone", "status", "role", "group"]
             example:
           description: arg
         - in: query
           name: value
           schema:
             type: string
             example:
           description: value
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   users:
                     type: array
                     items:
                       type: object
                       properties:
                           phone:
                             type: string
                           name:
                             type: string
                           email:
                             type: string
                           role:
                             type: integer
                           registered:
                             type: integer
                           confirmed:
                             type: integer
                           password:
                             type: string
                           id:
                             type: integer
                           status:
                             type: string
                           group:
                             type: integer
                   result:
                     type: boolean
                   len:
                     type: integer
       '400':
         description: Не передан обязательный параметр
         content:
           application/json:
             schema: ErrorSchema
       '401':
         description: Неверный токен
         content:
           application/json:
             schema: ErrorSchema
       '403':
         description: Пользователь заблокирован
         content:
           application/json:
             schema: ErrorSchema
     tags:
       - DB
    '''
    type_ = request.args.get('type')
    arg = request.args.get('arg')
    search = request.args.get('value')
    if type_ == 'ALL':
        data = User.query.filter_by().all()
    elif type_ == 'CONTAIN':
        if arg not in user_mapping:
            return current_app.response_class(
                response=json.dumps(
                    {'error': f'ERROR: {arg} is incorrect argument!'}
                ),
                status=400,
                mimetype='application/json'
            )
        data = User.query.filter(user_mapping[arg].contains(search)).all()
    elif type_ == 'EQUAL':
        if arg not in user_mapping:
            return current_app.response_class(
                response=json.dumps(
                    {
                        'result': False,
                        'error': f'ERROR: {arg} is incorrect argument!'
                    }
                ),
                status=400,
                mimetype='application/json'
            )
        data = User.query.filter(user_mapping[arg] == search).all()
    else:
        return current_app.response_class(
            response=json.dumps(
                {
                    'result': False,
                    'error': f'ERROR: {type_} is invalid request type!'
                }
            ),
            status=400,
            mimetype='application/json'
        )
    return current_app.response_class(
        response=json.dumps(
            {
                'users': db2dict(data),
                'result': True,
                'len': len(data)
            }
        ),
        status=200,
        mimetype='application/json'
    )


@connect.route('/connect/user/update', methods=['PUT'])
@oauth
def user_update():
    '''
    ---
   put:
     summary: UPDATE USER
     parameters:
         - in: header
           name: KEY
           schema:
             type: string
             example: zFp*h*4Q*xLa&@hV8%%*zXCLN69AOYUv3FearK42$2aNzfiyzRtEz&1e7605&2i@BnhasrFwYVgZ%KIsXE3I87D8B4YtofjngDQ#hqd&LVV@%YTv&jR1ABM0vXSoLd*m
           required: true
         - in: header
           name: SECRET
           schema:
             type: string
             example: x759Q2SToJ@KW4&eqbndZz7dAAERZQesQ@JSJkTd$KbEvNO6QNB8zKBR2n%kj0S&QAdg0pvDypl3Dtt07sICA1WaToQ0Eamxoe3#s0XH*t4CFs9m4rcuvnHT&HK5I5uF
           required: true
         - in: query
           name: arg
           schema:
             type: string
             example: id
           description: arg
         - in: query
           name: value
           schema:
             type: string
             example: 1
           description: value
     requestBody:
        content:
          application/json:
              schema:
                type: object
                properties:
                   phone:
                     type: string
                   name:
                     type: string
                   email:
                     type: string
                   role:
                     type: integer
                   status:
                     type: string
                   group:
                     type: integer
                example:   # Sample object
                  phone: 79151290131
                  name: Иван Иванов
                  email: example2@gmail.com
                  role: 2
                  status: active
                  group: 3
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
                   updated_user:
                     type: object
                     properties:
                           phone:
                             type: string
                             phone: 79151290131
                           name:
                             type: string
                             name: Иван Иванов
                           email:
                             type: string
                             email: example2@gmail.com
                           role:
                             type: integer
                             role: 2
                           registered:
                             type: integer
                             registered: 1677680912
                           confirmed:
                             type: integer
                             confirmed: 0
                           id:
                             type: integer
                             id: 1
                           password:
                             type: string
                             password: sha256$mMUHE0QTMc93HgMS$99df51fafa8d876ad183dae2d2a2f0fa604b7181828afcd2436abda6312eebee
                           status:
                             type: string
                             status: active
                           group:
                             type: integer
                             group: 3
       '400':
         description: Не передан обязательный параметр
         content:
           application/json:
             schema: ErrorSchema
       '401':
         description: Неверный токен
         content:
           application/json:
             schema: ErrorSchema
       '403':
         description: Пользователь заблокирован
         content:
           application/json:
             schema: ErrorSchema
     tags:
       - DB
    '''
    arg = request.args.get('arg')
    value = request.args.get('value')
    update = request.json
    if arg not in user_mapping:
        return current_app.response_class(
            response=json.dumps(
                {
                    'result': False,
                    'error': f'ERROR: {arg} is incorrect argument!'
                }
            ),
            status=400,
            mimetype='application/json'
        )
    if 'password' in update:
        update['password'] = generate_password_hash(str(update['password']))
    user = User.query.filter(user_mapping[arg] == value).update(update)
    db.session.commit()
    return current_app.response_class(
        response=json.dumps(
            {
                'result': True,
                'updated_user': db2dict([User.query.filter(User.id == user).first()])[0]
            }
        ),
        status=200,
        mimetype='application/json'
    )


@connect.route('/connect/user/add', methods=['POST'])
@oauth
def user_add():
    '''
    ---
   post:
     summary: INSERT INTO USER
     parameters:
         - in: header
           name: KEY
           schema:
             type: string
             example: zFp*h*4Q*xLa&@hV8%%*zXCLN69AOYUv3FearK42$2aNzfiyzRtEz&1e7605&2i@BnhasrFwYVgZ%KIsXE3I87D8B4YtofjngDQ#hqd&LVV@%YTv&jR1ABM0vXSoLd*m
           required: true
         - in: header
           name: SECRET
           schema:
             type: string
             example: x759Q2SToJ@KW4&eqbndZz7dAAERZQesQ@JSJkTd$KbEvNO6QNB8zKBR2n%kj0S&QAdg0pvDypl3Dtt07sICA1WaToQ0Eamxoe3#s0XH*t4CFs9m4rcuvnHT&HK5I5uF
           required: true
     requestBody:
        content:
          application/json:
              schema:
                type: object
                properties:
                   phone:
                     type: string
                   name:
                     type: string
                   email:
                     type: string
                   role:
                     type: integer
                   status:
                     type: string
                   group:
                     type: integer
                   password:
                     type: integer
                example:   # Sample object
                  phone: 79151290139
                  name: Леха Петров
                  email: example7@gmail.com
                  role: 2
                  status: active
                  group: 3
                  password: 1234
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
                   added_user:
                     type: object
                     properties:
                           phone:
                             type: string
                             phone: 79151290139
                           role:
                             type: integer
                             role: 2
                           confirmed:
                             type: integer
                             confirmed: 0
                           registered:
                             type: integer
                             registered: 1692271043
                           name:
                             type: string
                             name: Леха Петров
                           email:
                             type: string
                             email: example7@gmail.com
                           password:
                             type: string
                             password: pbkdf2:sha256:260000$ZJtZBsjYHnkmi5bW$666e6d1f6ce9c9f553f007150f79e8cb498f630b458d2be8e4e9c6af28a274c1
                           id:
                             type: integer
                             id: 15
                           status:
                             type: string
                             status: active
                           group:
                             type: integer
                             group: 3
       '400':
         description: Не передан обязательный параметр
         content:
           application/json:
             schema: ErrorSchema
       '401':
         description: Неверный токен
         content:
           application/json:
             schema: ErrorSchema
       '403':
         description: Пользователь заблокирован
         content:
           application/json:
             schema: ErrorSchema
     tags:
       - DB
    '''
    user = request.json
    if 'password' not in user or 'name' not in user or 'phone' not in user or 'email' not in user or 'role' not in user or 'group' not in user:
        return current_app.response_class(
            response=json.dumps(
                {
                    'result': False,
                    'error': f'ERROR: invalid user data!'
                }
            ),
            status=400,
            mimetype='application/json'
        )
    new_user = User(name=user['name'], phone=user['phone'], email=user['email'], role=user['role'], group=user['group'],
                    password=generate_password_hash(str(user['password'])), status='active', confirmed=0,
                    registered=int(time.time()))
    db.session.add(new_user)
    db.session.commit()
    return current_app.response_class(
        response=json.dumps(
            {
                'result': True,
                'added_user': db2dict([User.query.filter_by(id=new_user.id).first()])[0]
            }
        ),
        status=200,
        mimetype='application/json'
    )


@connect.route('/connect/user/delete', methods=['DELETE', 'POST', 'GET'])
@oauth
def user_delete():
    '''
    ---
   delete:
     summary: DELETE USER
     parameters:
         - in: header
           name: KEY
           schema:
             type: string
             example: zFp*h*4Q*xLa&@hV8%%*zXCLN69AOYUv3FearK42$2aNzfiyzRtEz&1e7605&2i@BnhasrFwYVgZ%KIsXE3I87D8B4YtofjngDQ#hqd&LVV@%YTv&jR1ABM0vXSoLd*m
           required: true
         - in: header
           name: SECRET
           schema:
             type: string
             example: x759Q2SToJ@KW4&eqbndZz7dAAERZQesQ@JSJkTd$KbEvNO6QNB8zKBR2n%kj0S&QAdg0pvDypl3Dtt07sICA1WaToQ0Eamxoe3#s0XH*t4CFs9m4rcuvnHT&HK5I5uF
           required: true
         - in: query
           name: arg
           schema:
             type: string
             example: id
           description: arg
         - in: query
           name: value
           schema:
             type: string
             example: 15
           description: value
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
                   deleted_user:
                     type: object
                     properties:
                           phone:
                             type: string

                           name:
                             type: string

                           email:
                             type: string

                           role:
                             type: integer

                           registered:
                             type: integer

                           confirmed:
                             type: integer

                           password:
                             type: string

                           id:
                             type: integer

                           status:
                             type: string

                           group:
                             type: integer

       '400':
         description: Не передан обязательный параметр
         content:
           application/json:
             schema: ErrorSchema
       '401':
         description: Неверный токен
         content:
           application/json:
             schema: ErrorSchema
       '403':
         description: Пользователь заблокирован
         content:
           application/json:
             schema: ErrorSchema
     tags:
       - DB

    '''
    arg = request.args.get('arg')
    value = request.args.get('value')
    if arg not in user_mapping:
        return current_app.response_class(
            response=json.dumps(
                {
                    'result': False,
                    'error': f'ERROR: {arg} is incorrect argument!'
                }
            ),
            status=400,
            mimetype='application/json'
        )
    deleted_user = db2dict([User.query.filter(user_mapping[arg] == value).first()])[0]
    user = User.query.filter(user_mapping[arg] == value).delete()
    db.session.commit()
    return current_app.response_class(
        response=json.dumps(
            {
                'result': True,
                'deleted_user': deleted_user
            }
        ),
        status=200,
        mimetype='application/json'
    )
