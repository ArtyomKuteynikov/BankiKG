# user.py
import datetime
import json
from flask import Blueprint, request, current_app, url_for
from flask_login import current_user
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from .models import User, Codes, ResPass, Banks, Revues, BanksOffices, Cards, Promotions, News, Deposits, Credits, \
    InvestNews, Brokers, Markets, Mortgage, BrokerTariffs
from iqsms_rest import Gate
import random, string
import time
from .config import *

import pandas as pd
from .helpers import send_email, send_notification


def generate_password(length=8):
    characters = string.ascii_letters + string.digits
    password = ''.join(random.choice(characters) for _ in range(length))
    return password


def db2dict(data):
    result = []
    for i in data:
        d = i.__dict__
        d.pop('_sa_instance_state')
        result.append(d)
    return result


auth_api = Blueprint('auth_api', __name__)


@auth_api.route('/api/roles')
def roles():
    '''
    ---
   get:
     summary: Роли
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   0:
                     type: string
                   1:
                     type: string
                   2:
                     type: string
     tags:
           - mobile
    '''
    return current_app.response_class(
        response=json.dumps(
            {
                0: 'Пользователь',
                1: 'Админ'
            }
        ),
        status=200,
        mimetype='application/json'
    )


@auth_api.route('/api/auth')
def auth():
    '''
    ---
       get:
         summary: Вход
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
           - mobile
        '''
    try:
        email = request.args.get('email')
        password = request.args.get('password')
        remember = True if request.args.get('remember') else False
        user = User.query.filter_by(email=email).first()
        print(User.query.filter_by().first().email)
        print(password)
        if user:
            msg = ''
            if user.confirmed == 0:
                msg = 'Номер телефона не подтверждкен'
            if user.status == 'blocked':
                return current_app.response_class(
                    response=json.dumps(
                        {
                            'error': "USER BLOCKED",
                            'role': '',
                            'token': ''
                        }
                    ),
                    status=403,
                    mimetype='application/json'
                )
            if check_password_hash(user.password, password):
                return current_app.response_class(
                    response=json.dumps(
                        {
                            'result': True,
                            'token': user.generate_auth_token(expiration=86400 if remember else 3600),
                            'role': user.role,
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
                    status=401,
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
                status=401,
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


@auth_api.route('/api/profile')
def profile():
    '''
    ---
       get:
         summary: Профиль
         parameters:
             - in: query
               name: token
               schema:
                 type: string
                 example: eyJpZCI6MX0.ZLpqAg.CtaNAVLpWRvUBlWsPYCFwx4YOqI
                 description: token
         responses:
           '200':
             description: Результат
             content:
               application/json:
                 schema:      # Request body contents
                   type: object
                   properties:
                       id:
                         type: integer
                       email:
                         type: string
                       phone:
                         type: string
                       name:
                         type: string
                       status:
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
           - mobile
        '''
    try:
        token = request.args.get('token')
        user = User.verify_auth_token(token)
        if not user:
            return current_app.response_class(
                response=json.dumps(
                    {'error': f'USER DOES NOT EXIST'}
                ),
                status=403,
                mimetype='application/json'
            )
        msg = ''
        if user.confirmed == 0:
            msg = 'Номер телефона не подтверждкен'
        if user.status == "blocked":
            return current_app.response_class(
                response=json.dumps(
                    {'error': "USER BLOCKED"}
                ),
                status=403,
                mimetype='application/json'
            )
        return current_app.response_class(
            response=json.dumps(
                {
                    "id": user.id,
                    "email": user.email,
                    "phone": user.phone,
                    "name": user.name,
                    "status": user.status,
                    "role": user.role,
                    'msg': msg
                }
            ),
            status=200,
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


@auth_api.route('/api/sign_up', methods=['GET', 'POST'])
def sign_up():
    '''
   ---
  post:
    summary: Регистрация
    requestBody:
       content:
         application/json:
             schema:
               type: object
               properties:
                  name:
                    type: string
                  email:
                    type: string
                  phone:
                    type: string
                  password:
                    type: string
               example:   # Sample object
                 name: Ivan
                 email: example@gmail.com
                 phone: 79151290130
                 password: 123
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
           - mobile
   '''
    email = request.json.get('email')
    phone = str(request.json.get('phone')).replace('(', '').replace(')', '').replace('-', '').replace('+', '').replace(
        ' ', '')
    name = request.json.get('name')
    password = request.json.get('password')
    if User.query.filter_by(phone=phone).first():
        return current_app.response_class(
            response=json.dumps(
                {
                    'result': False,
                    'error': f'USER EXIST'
                }
            ),
            status=403,
            mimetype='application/json'
        )
    if User.query.filter_by(email=email).first():
        return current_app.response_class(
            response=json.dumps(
                {
                    'result': False,
                    'error': f'USER EXIST'
                }
            ),
            status=403,
            mimetype='application/json'
        )
    token = generate_password_hash(str(phone), method='sha256').replace('sha256$', '')
    new_user = User(email=email, phone=phone, name=name,
                    password=generate_password_hash(str(password), method='sha256'),
                    status="active", token=token, registered=int(time.time()), role=0)
    db.session.add(new_user)
    db.session.commit()
    code = 1234  # random.randint(1001, 9999)
    new_code = Codes(code=code, phone=phone)
    db.session.add(new_code)
    db.session.commit()
    sender = Gate(SMS_LOGIN, SMS_PASSWORD)
    status = sender.send_message(phone, f'Ваш код для авторизации в приложении\n{code}', 'SMS DUCKOHT')
    return current_app.response_class(
        response=json.dumps(
            {
                'result': True,
                'token': token
            }
        ),
        status=200,
        mimetype='application/json'
    )
    try:
        pass
    except Exception as e:
        return current_app.response_class(
            response=json.dumps(
                {
                    'error': f'ERROR: {e}!'
                }
            ),
            status=400,
            mimetype='application/json'
        )


@auth_api.route('/api/check-code')
def check_code():
    '''
---
   get:
     summary: Подтверждение номера
     parameters:
         - in: query
           name: token
           schema:
             type: string
             example: eyJpZCI6MX0.ZLpqAg.CtaNAVLpWRvUBlWsPYCFwx4YOqI
           description: token
         - in: query
           name: code
           schema:
             type: integer
             example: 1234
           description: code
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   status:
                     type: boolean
                   user:
                     type: string
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
           - mobile
    '''
    try:
        token = request.args.get('token')
        user = User.verify_auth_token(token)
        if not user:
            return current_app.response_class(
                response=json.dumps(
                    {
                        'result': 'USER DOES NOT EXIST',
                        'token': '',
                        'role': ''
                    }
                ),
                status=401,
                mimetype='application/json'
            )
        if user.status == "blocked":
            return current_app.response_class(
                response=json.dumps(
                    {'error': "USER BLOCKED"}
                ),
                status=403,
                mimetype='application/json'
            )
        code = request.args.get('code')
        if Codes.query.filter_by(phone=user.phone).all()[-1].code == code:
            _ = User.query.filter_by(token=token).update({'confirmed': 1})
            db.session.commit()
            return current_app.response_class(
                response=json.dumps(
                    {'status': True,
                     'user': token}
                ),
                status=200,
                mimetype='application/json'
            )
        else:
            return current_app.response_class(
                response=json.dumps(
                    {
                        'status': False,
                        'error': "Invalid code"
                    }
                ),
                status=401,
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


@auth_api.route('/api/edit_profile', methods=['POST'])
def edit_profile():
    '''
---
   post:
     summary: Изменить профиль
     parameters:
         - in: query
           name: token
           schema:
             type: string
             example: eyJpZCI6MX0.ZLpqAg.CtaNAVLpWRvUBlWsPYCFwx4YOqI
           description: token
     requestBody:
        content:
          application/json:
              schema:
                type: object
                properties:

                   phone:
                     type: string
                   email:
                     type: string
                   name:
                     type: string
                example:   # Sample object

                  phone: 79151290131
                  email: example2@gmail.com
                  name: Иван Иванов
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   status:
                     type: string
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
           - mobile
    '''
    try:
        token = request.args.get('token')
        user = User.verify_auth_token(token)
        name = request.json.get('name')
        email = request.json.get('email')
        phone = str(request.json.get('phone')).replace('(', '').replace(')', '').replace('-', '').replace('+',
                                                                                                          '').replace(
            ' ', '')
        if not user:
            return current_app.response_class(
                response=json.dumps(
                    {'error': f'Incorrect TOKEN'}
                ),
                status=401,
                mimetype='application/json'
            )
        if User.verify_auth_token(token).status == "blocked":
            return current_app.response_class(
                response=json.dumps(
                    {'error': "USER BLOCKED"}
                ),
                status=403,
                mimetype='application/json'
            )
        if user.phone != phone:
            code = 1234  # random.randint(1001, 9999)
            new_code = Codes(code=code, phone=phone)
            db.session.add(new_code)
            db.session.commit()
            sender = Gate(SMS_LOGIN, SMS_PASSWORD)
            status = sender.send_message(phone, f'Ваш код для авторизации в приложении\n{code}', 'SMS DUCKOHT')
            _ = User.query.filter_by(id=user.id).update(
                {'name': name, 'phone': phone, 'email': email, 'confirmed': 0})
        else:
            _ = User.query.filter_by(id=user.id).update(
                {'name': name, 'email': email})
        db.session.commit()
        return current_app.response_class(
            response=json.dumps(
                {'status': f'ok'}
            ),
            status=200,
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


@auth_api.route('/api/res-pass', methods=['GET', 'POST'])
def res_pass():
    '''
   ---
   get:
     summary: Запросить сброс пароля
     parameters:
         - in: query
           name: phone
           schema:
             type: string
             example: 79151290130
           description: phone
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   status:
                     type: string
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
           - mobile
    '''
    try:
        phone = str(request.args.get('phone')).replace('(', '').replace(')', '').replace('-', '').replace('+',
                                                                                                          '').replace(
            ' ', '')
        print(phone)
        if not User.query.filter_by(phone=phone).first():
            return current_app.response_class(
                response=json.dumps(
                    {'error': f'USER DOES NOT EXIST'}
                ),
                status=403,
                mimetype='application/json'
            )
        code = 1234  # random.randint(1001, 9999)
        new_code = ResPass(code=code, phone=phone)
        db.session.add(new_code)
        db.session.commit()
        sender = Gate(SMS_LOGIN, SMS_PASSWORD)
        status = sender.send_message(phone, f'Ваш код для авторизации в приложении\n{code}', 'SMS DUCKOHT')
        db.session.commit()
        return current_app.response_class(
            response=json.dumps(
                {'status': f'ok'}
            ),
            status=200,
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


@auth_api.route('/api/check-code-res-pass')
def check_code_res_pass():
    '''
   ---
   get:
     summary: Проверить код для сброса пароля
     parameters:
         - in: query
           name: phone
           schema:
             type: string
             example: 79151290130
           description: phone
         - in: query
           name: code
           schema:
             type: integer
             example: 1234
           description: code
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   status:
                     type: boolean
                   token:
                     type: string
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
           - mobile
    '''
    try:
        code = request.args.get('code')
        phone = request.args.get('phone')
        user = User.query.filter_by(phone=phone).first()
        if not user:
            return current_app.response_class(
                response=json.dumps(
                    {
                        'result': 'USER DOES NOT EXIST',
                        'token': '',
                        'role': ''
                    }
                ),
                status=401,
                mimetype='application/json'
            )
        if user.status == "blocked":
            return current_app.response_class(
                response=json.dumps(
                    {'error': "USER BLOCKED"}
                ),
                status=403,
                mimetype='application/json'
            )
        if ResPass.query.filter_by(phone=user.phone).all()[-1].code == code:
            return current_app.response_class(
                response=json.dumps(
                    {'status': True,
                     'token': user.token}
                ),
                status=200,
                mimetype='application/json'
            )
        else:
            return current_app.response_class(
                response=json.dumps(
                    {
                        'status': False,
                        'error': "Invalid code"
                    }
                ),
                status=401,
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


@auth_api.route('/api/set-password', methods=['POST'])
def set_password():
    '''
   ---
   post:
     summary: Задать пароль
     parameters:
         - in: query
           name: token
           schema:
             type: string
             example: oD7MgOrsO9hIVXa8$7552d24bf84b3eb71f8f185ce723409ec6e8a08c63f90789d6b7f389e738d952
           description: token
     requestBody:
        content:
          application/json:
              schema:
                type: object
                properties:

                   password:
                     type: integer
                example:   # Sample object

                  password: 1234
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   status:
                     type: string
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
           - mobile
    '''
    try:
        token = request.args.get('token')
        user = User.verify_auth_token(token)
        password = request.json.get('password')
        if not user:
            return current_app.response_class(
                response=json.dumps(
                    {'error': f'Incorrect TOKEN'}
                ),
                status=401,
                mimetype='application/json'
            )
        if User.verify_auth_token(token).status == "blocked":
            return current_app.response_class(
                response=json.dumps(
                    {'error': "USER BLOCKED"}
                ),
                status=403,
                mimetype='application/json'
            )
        _ = User.query.filter_by(id=user.id).update(
            {'password': password})
        db.session.commit()
        return current_app.response_class(
            response=json.dumps(
                {'status': f'ok'}
            ),
            status=200,
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


@auth_api.route('/api/banks', methods=['GET'])
def banks():
    '''
    ---
   get:
     summary: Все банки
     parameters:
         - in: query
           name: search
           schema:
             type: string
             example:
           description: search
         - in: query
           name: region
           schema:
             type: string
             example:
           description: region
         - in: query
           name: form
           schema:
             type: string
             example:
           description: form
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   banks:
                     type: array
                     items:
                       type: object
                       properties:
                           license:
                             type: integer
                           id:
                             type: integer
                           form:
                             type: string
                           address:
                             type: string
                           region:
                             type: integer
                           since:
                             type: integer
                           image:
                             type: string
                           name:
                             type: string
                           rating:
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
       - banks
    '''
    search_query = request.args.get('search', '')
    search_region = request.args.get('region', '')
    search_form = request.args.get('form', '')
    if search_query:
        query = Banks.query.filter(Banks.name.contains(search_query))
    elif search_region or search_form:
        query = Banks.query.filter((Banks.region == search_region) | (Banks.form == search_form))
    else:
        query = Banks.query.filter()
    data = query.all()
    data = db2dict(data)
    data_result = []
    for i in data:
        rating = [i.rating for i in Revues.query.filter_by(product_id=i['id'], product='bank').all()]
        i.update({'rating': round(sum(rating)/len(rating) if len(rating) else 0, 5)})
        i.update({'image': f"{url_for('static', filename=f'banks/'+i['image'])}" if i['image'] else ''})
        data_result.append(i)
    return current_app.response_class(
        response=json.dumps(
            {
                'banks': data_result,
                'result': True,
                'len': len(data_result)
            }
        ),
        status=200,
        mimetype='application/json'
    )


@auth_api.route('/helper')
def helper():
    df = pd.read_excel('app/banks.xlsx', sheet_name='banks')
    for i in df.values:
        new_bank = Banks(name=i[0], image='1.png', region='Бишкек', license=i[5], address=i[2], phones=i[1])
        db.session.add(new_bank)
        db.session.commit()
        for j in range(i[3]):
            new_bank_office = BanksOffices(bank_id=new_bank.id, name=f'ДО {i[0]}', region='Бишкек', address=i[2])
            db.session.add(new_bank_office)
            db.session.commit()
    return 'ok'


@auth_api.route('/api/banks-offices', methods=['GET'])
def banks_offices():
    '''
    ---
   get:
     summary: Все офисы банков
     parameters:
         - in: query
           name: bank
           schema:
             type: string
             example:
           description: bank
         - in: query
           name: region
           schema:
             type: string
             example:
           description: region
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   offices:
                     type: array
                     items:
                       type: object
                       properties:
                           id:
                             type: integer
                           region:
                             type: integer
                           address:
                             type: string
                           lon:
                             type: number
                           name:
                             type: string
                           bank_id:
                             type: integer
                           lat:
                             type: number
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
       - banks
    '''
    search_bank = request.args.get('bank', '')
    search_region = request.args.get('region', '')
    if search_bank and search_region:
        query = BanksOffices.query.filter((BanksOffices.bank_id == search_bank) & (BanksOffices.region == search_region))
    else:
        query = BanksOffices.query.filter()
    data = query.all()
    return current_app.response_class(
        response=json.dumps(
            {
                'offices': db2dict(data),
                'result': True,
                'len': len(data)
            }
        ),
        status=200,
        mimetype='application/json'
    )


@auth_api.route('/api/bank', methods=['GET'])
def bank():
    '''
    ---
   get:
     summary: Банк
     parameters:
         - in: query
           name: bank
           schema:
             type: integer
             example: 1
           description: bank
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   bank:
                     type: object
                     properties:
                           license:
                             type: integer

                           id:
                             type: integer

                           form:
                             type: string

                           address:
                             type: string

                           region:
                             type: integer

                           since:
                             type: integer

                           image:
                             type: string

                           name:
                             type: string

                           rating:
                             type: integer

                   result:
                     type: boolean
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
       - banks
    '''
    bank = request.args.get('bank')
    query = Banks.query.filter_by(id=bank)
    data = query.all()
    if not data:
        return current_app.response_class(
            response=json.dumps(
                {
                    'result': False,
                }
            ),
            status=404,
            mimetype='application/json'
        )
    data = db2dict(data)
    data_result = []
    for i in data:
        rating = [i.rating for i in Revues.query.filter_by(product_id=i['id'], product='bank').all()]
        i.update({'rating': round(sum(rating)/len(rating) if len(rating) else 0, 5)})
        data_result.append(i)
    return current_app.response_class(
        response=json.dumps(
            {
                'bank': data_result[0],
                'result': True,
            }
        ),
        status=200,
        mimetype='application/json'
    )


@auth_api.route('/api/cards', methods=['GET'])
def cards():
    '''
    ---
   get:
     summary: Карты
     parameters:
         - in: query
           name: bank
           schema:
             type: integer
             example: 1
           description: bank
         - in: query
           name: type
           schema:
             type: string
             example:
           description: type
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   cards:
                     type: array
                     items:
                       type: object
                       properties:
                           license:
                             type: integer
                           id:
                             type: integer
                           form:
                             type: string
                           address:
                             type: string
                           region:
                             type: integer
                           since:
                             type: integer
                           image:
                             type: string
                           name:
                             type: string
                           rating:
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
       - cards
    '''
    search_type = request.args.get('type', '')
    search_bank = request.args.get('bank', '')
    query = Banks.query.filter((Cards.type == search_type) if search_type else Cards.type.contains(search_type) &
                                                                               (Cards.bank_id == search_bank) if search_bank else Cards.type.contains(search_bank))
    data = query.all()
    data = db2dict(data)
    data_result = []
    for i in data:
        rating = [i.rating for i in Revues.query.filter_by(product_id=i['id'], product='card').all()]
        i.update({'rating': round(sum(rating)/len(rating) if len(rating) else 0, 5)})
        data_result.append(i)
    return current_app.response_class(
        response=json.dumps(
            {
                'cards': data_result,
                'result': True,
                'len': len(data_result)
            }
        ),
        status=200,
        mimetype='application/json'
    )


@auth_api.route('/api/card', methods=['GET'])
def card():
    '''
    ---
   get:
     summary: Карта
     parameters:
         - in: query
           name: card
           schema:
             type: integer
             example: 1
           description: card
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   card:
                     type: object
                     properties:
                           price:
                             type: number

                           id:
                             type: integer

                           cashback:
                             type: number

                           min_amount:
                             type: string

                           rate:
                             type: number

                           timeframe_max:
                             type: string

                           description:
                             type: string

                           max_points:
                             type: integer

                           bank_id:
                             type: integer

                           type:
                             type: string

                           max_amount:
                             type: string

                           timeframe_min:
                             type: string

                           name:
                             type: string

                           rating:
                             type: integer

                   result:
                     type: boolean
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
       - cards
    '''
    card = request.args.get('card')
    query = Cards.query.filter_by(id=card)
    data = query.all()
    if not data:
        return current_app.response_class(
            response=json.dumps(
                {
                    'result': False,
                }
            ),
            status=404,
            mimetype='application/json'
        )
    data = db2dict(data)
    data_result = []
    for i in data:
        rating = [i.rating for i in Revues.query.filter_by(product_id=i['id'], product='card').all()]
        i.update({'rating': round(sum(rating)/len(rating) if len(rating) else 0, 5)})
        data_result.append(i)
    return current_app.response_class(
        response=json.dumps(
            {
                'card': data_result[0],
                'result': True,
            }
        ),
        status=200,
        mimetype='application/json'
    )


@auth_api.route('/api/promotions', methods=['GET'])
def promotions():
    '''
    ---
   get:
     summary: Акции
     parameters:
         - in: query
           name: search
           schema:
             type: string
             example:
           description: search
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   cards:
                     type: array
                     items:
                       type: object
                       properties:
                           title:
                             type: string
                           subtitle:
                             type: string
                           text:
                             type: string
                           id:
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
       - promotions
    '''
    search = request.args.get('search', '')
    query = Promotions.query.filter(Promotions.title.contains(search))
    data = query.all()
    data = db2dict(data)
    return current_app.response_class(
        response=json.dumps(
            {
                'cards': data,
                'result': True,
                'len': len(data)
            }
        ),
        status=200,
        mimetype='application/json'
    )


@auth_api.route('/api/promotion', methods=['GET'])
def promotion():
    '''
    ---
   get:
     summary: Акция
     parameters:
         - in: query
           name: promo
           schema:
             type: integer
             example: 1
           description: promo
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   card:
                     type: object
                     properties:
                           title:
                             type: string

                           subtitle:
                             type: string

                           text:
                             type: string

                           id:
                             type: integer

                   result:
                     type: boolean
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
       - promotions
    '''
    promo = request.args.get('promo')
    query = Promotions.query.filter_by(id=promo)
    data = query.all()
    if not data:
        return current_app.response_class(
            response=json.dumps(
                {
                    'result': False,
                }
            ),
            status=404,
            mimetype='application/json'
        )
    data = db2dict(data)
    return current_app.response_class(
        response=json.dumps(
            {
                'card': data[0],
                'result': True,
            }
        ),
        status=200,
        mimetype='application/json'
    )


@auth_api.route('/api/news', methods=['GET'])
def news():
    '''
    ---
   get:
     summary: Новости
     parameters:
         - in: query
           name: search
           schema:
             type: string
             example:
           description: search
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   cards:
                     type: array
                     items:
                       type: object
                       properties:
                           subtitle:
                             type: string
                           id:
                             type: integer
                           image:
                             type: string
                           title:
                             type: string
                           text:
                             type: string
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
       - news
    '''
    search = request.args.get('search', '')
    query = News.query.filter(News.title.contains(search))
    data = query.all()
    data = db2dict(data)
    return current_app.response_class(
        response=json.dumps(
            {
                'cards': data,
                'result': True,
                'len': len(data)
            }
        ),
        status=200,
        mimetype='application/json'
    )


@auth_api.route('/api/new', methods=['GET'])
def new():
    '''
    ---
   get:
     summary: Новость
     parameters:
         - in: query
           name: new
           schema:
             type: integer
             example: 1
           description: new
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   card:
                     type: object
                     properties:
                           subtitle:
                             type: string

                           id:
                             type: integer

                           image:
                             type: string

                           title:
                             type: string

                           text:
                             type: string

                   result:
                     type: boolean
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
       - news
    '''
    new = request.args.get('new')
    query = News.query.filter_by(id=new)
    data = query.all()
    if not data:
        return current_app.response_class(
            response=json.dumps(
                {
                    'result': False,
                }
            ),
            status=404,
            mimetype='application/json'
        )
    data = db2dict(data)
    return current_app.response_class(
        response=json.dumps(
            {
                'card': data[0],
                'result': True,
            }
        ),
        status=200,
        mimetype='application/json'
    )


@auth_api.route('/api/investing/news', methods=['GET'])
def invest_news():
    '''
    ---
   get:
     summary: Инвестиционные новости
     parameters:
         - in: query
           name: search
           schema:
             type: string
             example:
           description: search
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   cards:
                     type: array
                     items:
                       type: object
                       properties:
                           subtitle:
                             type: string
                           id:
                             type: integer
                           image:
                             type: string
                           title:
                             type: string
                           text:
                             type: string
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
       - investing
    '''
    search = request.args.get('search', '')
    query = InvestNews.query.filter(InvestNews.title.contains(search))
    data = query.all()
    data = db2dict(data)
    return current_app.response_class(
        response=json.dumps(
            {
                'cards': data,
                'result': True,
                'len': len(data)
            }
        ),
        status=200,
        mimetype='application/json'
    )


@auth_api.route('/api/investing/new', methods=['GET'])
def invest_new():
    '''
    ---
   get:
     summary: Инвестиционная новость
     parameters:
         - in: query
           name: new
           schema:
             type: integer
             example: 1
           description: new
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   card:
                     type: object
                     properties:
                           subtitle:
                             type: string

                           id:
                             type: integer

                           image:
                             type: string

                           title:
                             type: string

                           text:
                             type: string

                   result:
                     type: boolean
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
       - investing
    '''
    new = request.args.get('new')
    query = (InvestNews.query.filter_by(id=new))
    data = query.all()
    if not data:
        return current_app.response_class(
            response=json.dumps(
                {
                    'result': False,
                }
            ),
            status=404,
            mimetype='application/json'
        )
    data = db2dict(data)
    return current_app.response_class(
        response=json.dumps(
            {
                'card': data[0],
                'result': True,
            }
        ),
        status=200,
        mimetype='application/json'
    )


@auth_api.route('/api/deposits', methods=['GET'])
def deposits():
    '''
    ---
   get:
     summary: Вклады
     parameters:
         - in: query
           name: amount
           schema:
             type: integer
             example: 10000
           description: amount
         - in: query
           name: bank
           schema:
             type: string
             example:
           description: bank
         - in: query
           name: timeframe
           schema:
             type: integer
             example: 11
           description: timeframe
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   cards:
                     type: array
                     items:
                       type: object
                       properties:
                           max_amount:
                             type: integer
                           id:
                             type: integer
                           timeframe_min:
                             type: integer
                           name:
                             type: string
                           min_amount:
                             type: integer
                           rate:
                             type: number
                           bank_id:
                             type: integer
                           timeframe_max:
                             type: integer
                           description:
                             type: string
                           rating:
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
       - deposits
    '''
    search_type = request.args.get('amount', 0)
    search_bank = request.args.get('bank', '')
    search_timeframe = request.args.get('timeframe', 0)
    query = Deposits.query.filter()
    if search_type:
        query = query.filter((Deposits.min_amount < search_type) & (Deposits.max_amount > search_type))
    if search_timeframe:
        query = query.filter((Deposits.timeframe_min < search_timeframe) & (Deposits.timeframe_max > search_timeframe))
    if search_bank:
        query = query.filter(Deposits.bank_id == search_bank)
    data = query.all()
    data = db2dict(data)
    data_result = []
    for i in data:
        rating = [i.rating for i in Revues.query.filter_by(product_id=i['id'], product='deposit').all()]
        i.update({'rating': round(sum(rating)/len(rating) if len(rating) else 0, 5)})
        data_result.append(i)
    return current_app.response_class(
        response=json.dumps(
            {
                'cards': data_result,
                'result': True,
                'len': len(data_result)
            }
        ),
        status=200,
        mimetype='application/json'
    )


@auth_api.route('/api/deposit', methods=['GET'])
def deposit():
    '''
    ---
   get:
     summary: Вклад
     parameters:
         - in: query
           name: deposit
           schema:
             type: integer
             example: 1
           description: deposit
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   card:
                     type: object
                     properties:
                           max_amount:
                             type: integer

                           id:
                             type: integer

                           timeframe_min:
                             type: integer

                           name:
                             type: string

                           min_amount:
                             type: integer

                           rate:
                             type: number

                           bank_id:
                             type: integer

                           timeframe_max:
                             type: integer

                           description:
                             type: string

                           rating:
                             type: integer

                   result:
                     type: boolean
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
       - deposits
    '''
    deposit = request.args.get('deposit')
    query = Deposits.query.filter_by(id=deposit)
    data = query.all()
    if not data:
        return current_app.response_class(
            response=json.dumps(
                {
                    'result': False,
                }
            ),
            status=404,
            mimetype='application/json'
        )
    data = db2dict(data)
    data_result = []
    for i in data:
        rating = [i.rating for i in Revues.query.filter_by(product_id=i['id'], product='card').all()]
        i.update({'rating': round(sum(rating)/len(rating) if len(rating) else 0, 5)})
        data_result.append(i)
    return current_app.response_class(
        response=json.dumps(
            {
                'card': data_result[0],
                'result': True,
            }
        ),
        status=200,
        mimetype='application/json'
    )


@auth_api.route('/api/credits', methods=['GET'])
def credits():
    '''
    ---
   get:
     summary: Кредиты
     parameters:
         - in: query
           name: amount
           schema:
             type: integer
             example: 100000
           description: amount
         - in: query
           name: bank
           schema:
             type: string
             example:
           description: bank
         - in: query
           name: timeframe
           schema:
             type: integer
             example: 51
           description: timeframe
         - in: query
           name: type
           schema:
             type: string
             example:
           description: type
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   cards:
                     type: array
                     items:
                       type: object
                       properties:
                           max_amount:
                             type: integer
                           id:
                             type: integer
                           timeframe_min:
                             type: integer
                           name:
                             type: string
                           min_amount:
                             type: integer
                           rate:
                             type: number
                           bank_id:
                             type: integer
                           timeframe_max:
                             type: integer
                           description:
                             type: string
                           rating:
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
       - credits
    '''
    search_amount = request.args.get('amount', 0)
    search_bank = request.args.get('bank', '')
    search_type = request.args.get('type', '')
    search_timeframe = request.args.get('timeframe', 0)
    query = Deposits.query.filter()
    if search_amount:
        query = query.filter((Deposits.min_amount < search_amount) & (Deposits.max_amount > search_amount))
    if search_timeframe:
        query = query.filter((Deposits.timeframe_min < search_timeframe) & (Deposits.timeframe_max > search_timeframe))
    if search_bank:
        query = query.filter(Deposits.bank_id == search_bank)
    if search_type:
        query = query.filter(Deposits.type == search_type)
    data = query.all()
    data = db2dict(data)
    data_result = []
    for i in data:
        rating = [i.rating for i in Revues.query.filter_by(product_id=i['id'], product='deposit').all()]
        i.update({'rating': round(sum(rating)/len(rating) if len(rating) else 0, 5)})
        data_result.append(i)
    return current_app.response_class(
        response=json.dumps(
            {
                'cards': data_result,
                'result': True,
                'len': len(data_result)
            }
        ),
        status=200,
        mimetype='application/json'
    )


@auth_api.route('/api/credit', methods=['GET'])
def credit():
    '''
    ---
   get:
     summary: Кредит
     parameters:
         - in: query
           name: credit
           schema:
             type: integer
             example: 1
           description: credit
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   card:
                     type: object
                     properties:
                           id:
                             type: integer

                           bank_id:
                             type: integer

                           min_amount:
                             type: integer

                           rate:
                             type: number

                           timeframe_max:
                             type: integer

                           description:
                             type: string

                           type:
                             type: string

                           max_amount:
                             type: integer

                           timeframe_min:
                             type: integer

                           name:
                             type: string

                           rating:
                             type: integer

                   result:
                     type: boolean
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
       - credits
    '''
    credit = request.args.get('credit')
    query = Credits.query.filter_by(id=credit)
    data = query.all()
    if not data:
        return current_app.response_class(
            response=json.dumps(
                {
                    'result': False,
                }
            ),
            status=404,
            mimetype='application/json'
        )
    data = db2dict(data)
    data_result = []
    for i in data:
        rating = [i.rating for i in Revues.query.filter_by(product_id=i['id'], product='card').all()]
        i.update({'rating': round(sum(rating)/len(rating) if len(rating) else 0, 5)})
        data_result.append(i)
    return current_app.response_class(
        response=json.dumps(
            {
                'card': data_result[0],
                'result': True,
            }
        ),
        status=200,
        mimetype='application/json'
    )


@auth_api.route('/api/markets', methods=['GET'])
def markets():
    '''
    ---
   get:
     summary: Рынки
     parameters:
         - in: query
           name: search
           schema:
             type: string
             example:
           description: search
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   markets:
                     type: array
                     items:
                       type: object
                       properties:
                           name:
                             type: string
                           description:
                             type: string
                           id:
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
       - investing
    '''
    search = request.args.get('search', '')
    query = Markets.query.filter(Markets.name.contains(search))
    data = query.all()
    data = db2dict(data)
    return current_app.response_class(
        response=json.dumps(
            {
                'markets': data,
                'result': True,
                'len': len(data)
            }
        ),
        status=200,
        mimetype='application/json'
    )


@auth_api.route('/api/brokers', methods=['GET'])
def brokers():
    '''
    ---
   get:
     summary: Брокеры
     parameters:
         - in: query
           name: search
           schema:
             type: string
             example:
           description: search
         - in: query
           name: market
           schema:
             type: string
             example:
           description: market
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   brokers:
                     type: array
                     items:
                       type: object
                       properties:
                           bank_id:
                             type: integer
                           id:
                             type: integer
                           market:
                             type: integer
                           link:
                             type: string
                           image:
                             type: string
                           license:
                             type: string
                           name:
                             type: string
                           description:
                             type: string
                           rating:
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
       - investing
    '''
    search_query = request.args.get('search', '')
    search_market = request.args.get('market', '')
    query = Brokers.query.filter()
    if search_query:
        query = query.filter(Brokers.name.contains(search_query))
    if search_market:
        query = query.filter((Brokers.market == search_market))
    data = query.all()
    data = db2dict(data)
    data_result = []
    for i in data:
        rating = [i.rating for i in Revues.query.filter_by(product_id=i['id'], product='broker').all()]
        i.update({'rating': round(sum(rating)/len(rating) if len(rating) else 0, 5)})
        data_result.append(i)
    return current_app.response_class(
        response=json.dumps(
            {
                'brokers': data_result,
                'result': True,
                'len': len(data_result)
            }
        ),
        status=200,
        mimetype='application/json'
    )


@auth_api.route('/api/broker', methods=['GET'])
def broker():
    '''
    ---
   get:
     summary: Брокер
     parameters:
         - in: query
           name: broker
           schema:
             type: integer
             example: 1
           description: broker
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   broker:
                     type: object
                     properties:
                           id:
                             type: integer

                           market:
                             type: integer

                           bank_id:
                             type: integer

                           link:
                             type: string

                           image:
                             type: string

                           license:
                             type: string

                           name:
                             type: string

                           description:
                             type: string

                           rating:
                             type: integer

                   tariffs:
                     type: array
                     items:
                       type: object
                       properties:
                           broker_id:
                             type: integer
                           name:
                             type: string
                           payment:
                             type: integer
                           description:
                             type: string
                           commission:
                             type: integer
                           id:
                             type: integer
                           link:
                             type: string
                           rating:
                             type: integer
                   result:
                     type: boolean
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
       - investing
    '''
    broker = request.args.get('broker')
    query = Brokers.query.filter_by(id=broker)
    data = query.all()
    if not data:
        return current_app.response_class(
            response=json.dumps(
                {
                    'result': False,
                }
            ),
            status=404,
            mimetype='application/json'
        )
    data = db2dict(data)
    data_result = []
    for i in data:
        rating = [i.rating for i in Revues.query.filter_by(product_id=i['id'], product='broker').all()]
        i.update({'rating': round(sum(rating)/len(rating) if len(rating) else 0, 5)})
        data_result.append(i)
    query = BrokerTariffs.query.filter_by()
    data = query.all()
    data = db2dict(data)
    data_tariffs = []
    if data:
        for i in data:
            rating = [j.rating for j in Revues.query.filter_by(product_id=i['id'], product='tariff').all()]
            i.update({'rating': round(sum(rating) / len(rating) if len(rating) else 0, 5)})
            data_tariffs.append(i)
    return current_app.response_class(
        response=json.dumps(
            {
                'broker': data_result[0],
                'tariffs': data_tariffs,
                'result': True,
            }
        ),
        status=200,
        mimetype='application/json'
    )


@auth_api.route('/api/tariff', methods=['GET'])
def tariff():
    '''
    ---
   get:
     summary: Тарифы брокера
     parameters:
         - in: query
           name: tariff
           schema:
             type: integer
             example: 1
           description: tariff
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   tariff:
                     type: object
                     properties:
                           broker_id:
                             type: integer

                           name:
                             type: string

                           payment:
                             type: integer

                           description:
                             type: string

                           commission:
                             type: integer

                           id:
                             type: integer

                           link:
                             type: string

                           rating:
                             type: integer

                   result:
                     type: boolean
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
       - investing
    '''
    tariff = request.args.get('tariff')
    query = BrokerTariffs.query.filter_by(id=tariff)
    data = query.all()
    data = db2dict(data)
    data_tariffs = []
    if not data:
        return current_app.response_class(
            response=json.dumps(
                {
                    'result': False,
                }
            ),
            status=404,
            mimetype='application/json'
        )
    for i in data:
        rating = [j.rating for j in Revues.query.filter_by(product_id=i['id'], product='tariff').all()]
        i.update({'rating': round(sum(rating) / len(rating) if len(rating) else 0, 5)})
        data_tariffs.append(i)
    return current_app.response_class(
        response=json.dumps(
            {
                'tariff': data_tariffs[0],
                'result': True,
            }
        ),
        status=200,
        mimetype='application/json'
    )


@auth_api.route('/api/mortgages', methods=['GET'])
def mortgages():
    '''
    ---
   get:
     summary: Ипотека
     parameters:
         - in: query
           name: amount
           schema:
             type: integer
             example: 4000000
           description: amount
         - in: query
           name: first-payment
           schema:
             type: integer
             example: 2000000
           description: first-payment
         - in: query
           name: bank
           schema:
             type: string
             example:
           description: bank
         - in: query
           name: type
           schema:
             type: string
             example:
           description: type
         - in: query
           name: timeframe
           schema:
             type: integer
             example: 15
           description: timeframe
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   cards:
                     type: array
                     items:
                       type: object
                       properties:
                           id:
                             type: integer
                           type:
                             type: string
                           max_amount:
                             type: integer
                           timeframe_min:
                             type: integer
                           name:
                             type: string
                           min_amount:
                             type: integer
                           bank_id:
                             type: integer
                           rate:
                             type: number
                           timeframe_max:
                             type: integer
                           description:
                             type: string
                           rating:
                             type: integer
                           monthly_payment:
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
       - mortgage
    '''
    search_amount = float(request.args.get('amount', 0))
    search_first = float(request.args.get('first-payment', 0))
    search_bank = request.args.get('bank', '')
    search_type = request.args.get('type', '')
    search_timeframe = float(request.args.get('timeframe', 0))
    query = Mortgage.query.filter()
    search_amount = search_amount-search_first
    if search_amount:
        query = query.filter((Mortgage.min_amount < search_amount) & (Mortgage.max_amount > search_amount))
    if search_timeframe:
        query = query.filter((Mortgage.timeframe_min < search_timeframe) & (Mortgage.timeframe_max > search_timeframe))
    if search_bank:
        query = query.filter(Mortgage.bank_id == search_bank)
    if search_type:
        query = query.filter(Mortgage.type == search_type)
    data = query.all()
    print(data, search_amount, search_first, search_bank, search_type, search_timeframe)
    data = db2dict(data)
    data_result = []
    for i in data:
        rating = [i.rating for i in Revues.query.filter_by(product_id=i['id'], product='mortgage').all()]
        i.update({'rating': round(sum(rating)/len(rating) if len(rating) else 0, 5)})
        i.update({'monthly_payment': round(search_amount*((float(i['rate'])/1200)/(1-(1+(float(i['rate'])/1200))**(-search_timeframe*12-1))))})
        data_result.append(i)
    return current_app.response_class(
        response=json.dumps(
            {
                'cards': data_result,
                'result': True,
                'len': len(data_result)
            }
        ),
        status=200,
        mimetype='application/json'
    )


@auth_api.route('/api/mortgage', methods=['GET'])
def mortgage():
    '''
    ---
   get:
     summary: Ипотека
     parameters:
         - in: query
           name: mortgage
           schema:
             type: integer
             example: 1
           description: mortgage
         - in: query
           name: amount
           schema:
             type: integer
             example: 4000000
           description: amount
         - in: query
           name: first-payment
           schema:
             type: integer
             example: 2000000
           description: first-payment
         - in: query
           name: timeframe
           schema:
             type: integer
             example: 15
           description: timeframe
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   card:
                     type: object
                     properties:
                           max_amount:
                             type: integer

                           id:
                             type: integer

                           type:
                             type: string

                           timeframe_min:
                             type: integer

                           name:
                             type: string

                           bank_id:
                             type: integer

                           min_amount:
                             type: integer

                           rate:
                             type: number

                           timeframe_max:
                             type: integer

                           description:
                             type: string

                           rating:
                             type: integer

                           monthly_payment:
                             type: integer

                   result:
                     type: boolean
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
       - mortgage
    '''
    mortgage = request.args.get('mortgage')
    amount = float(request.args.get('amount', 0))
    first = float(request.args.get('first-payment', 0))
    timeframe = float(request.args.get('timeframe', 0))
    amount = amount - first
    query = Mortgage.query.filter_by(id=mortgage)
    data = query.all()
    if not data:
        return current_app.response_class(
            response=json.dumps(
                {
                    'result': False,
                }
            ),
            status=404,
            mimetype='application/json'
        )
    data = db2dict(data)
    data_result = []
    for i in data:
        rating = [i.rating for i in Revues.query.filter_by(product_id=i['id'], product='mortgage').all()]
        i.update({'rating': round(sum(rating)/len(rating) if len(rating) else 0, 5)})
        i.update({'monthly_payment': round(amount*((float(i['rate'])/1200)/(1-(1+(float(i['rate'])/1200))**(-timeframe*12-1))))})
        data_result.append(i)
    return current_app.response_class(
        response=json.dumps(
            {
                'card': data_result[0],
                'result': True,
            }
        ),
        status=200,
        mimetype='application/json'
    )


@auth_api.route('/api/business-cards', methods=['GET'])
def business_cards():
    '''
    ---
   get:
     summary: Бизнес карты
     parameters:
         - in: query
           name: bank
           schema:
             type: integer
             example: 1
           description: bank
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   cards:
                     type: array
                     items:
                       type: object
                       properties:
                           license:
                             type: integer
                           id:
                             type: integer
                           form:
                             type: string
                           address:
                             type: string
                           region:
                             type: integer
                           since:
                             type: integer
                           image:
                             type: string
                           name:
                             type: string
                           rating:
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
       - business
    '''
    search_bank = request.args.get('bank', '')
    query = Banks.query.filter((Cards.type == 'business') & (Cards.bank_id == search_bank) if search_bank else Cards.type.contains(search_bank))
    data = query.all()
    data = db2dict(data)
    data_result = []
    for i in data:
        rating = [i.rating for i in Revues.query.filter_by(product_id=i['id'], product='card').all()]
        i.update({'rating': round(sum(rating)/len(rating) if len(rating) else 0, 5)})
        data_result.append(i)
    return current_app.response_class(
        response=json.dumps(
            {
                'cards': data_result,
                'result': True,
                'len': len(data_result)
            }
        ),
        status=200,
        mimetype='application/json'
    )


@auth_api.route('/api/business-card', methods=['GET'])
def business_card():
    '''
    ---
   get:
     summary: Бизнес карта
     parameters:
         - in: query
           name: card
           schema:
             type: integer
             example: 1
           description: card
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   card:
                     type: object
                     properties:
                           price:
                             type: number

                           id:
                             type: integer

                           cashback:
                             type: number

                           min_amount:
                             type: string

                           rate:
                             type: number

                           timeframe_max:
                             type: string

                           description:
                             type: string

                           max_points:
                             type: integer

                           bank_id:
                             type: integer

                           type:
                             type: string

                           max_amount:
                             type: string

                           timeframe_min:
                             type: string

                           name:
                             type: string

                           rating:
                             type: integer

                   result:
                     type: boolean
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
       - business
    '''
    card = request.args.get('card')
    query = Cards.query.filter_by(id=card)
    data = query.all()
    if not data:
        return current_app.response_class(
            response=json.dumps(
                {
                    'result': False,
                }
            ),
            status=404,
            mimetype='application/json'
        )
    data = db2dict(data)
    data_result = []
    for i in data:
        rating = [i.rating for i in Revues.query.filter_by(product_id=i['id'], product='card').all()]
        i.update({'rating': round(sum(rating)/len(rating) if len(rating) else 0, 5)})
        data_result.append(i)
    return current_app.response_class(
        response=json.dumps(
            {
                'card': data_result[0],
                'result': True,
            }
        ),
        status=200,
        mimetype='application/json'
    )


@auth_api.route('/api/business-credits', methods=['GET'])
def business_credits():
    '''
    ---
   get:
     summary: Кредиты для бизнеса
     parameters:
         - in: query
           name: amount
           schema:
             type: integer
             example: 100000
           description: amount
         - in: query
           name: bank
           schema:
             type: string
             example:
           description: bank
         - in: query
           name: timeframe
           schema:
             type: integer
             example: 51
           description: timeframe
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   cards:
                     type: array
                     items:
                       type: object
                       properties:
                           max_amount:
                             type: integer
                           id:
                             type: integer
                           timeframe_min:
                             type: integer
                           name:
                             type: string
                           min_amount:
                             type: integer
                           rate:
                             type: number
                           bank_id:
                             type: integer
                           timeframe_max:
                             type: integer
                           description:
                             type: string
                           rating:
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
       - business
    '''
    search_amount = request.args.get('amount', 0)
    search_bank = request.args.get('bank', '')
    search_type = 'business'
    search_timeframe = request.args.get('timeframe', 0)
    query = Credits.query.filter()
    if search_amount:
        query = query.filter((Credits.min_amount < search_amount) & (Credits.max_amount > search_amount))
    if search_timeframe:
        query = query.filter((Credits.timeframe_min < search_timeframe) & (Credits.timeframe_max > search_timeframe))
    if search_bank:
        query = query.filter(Credits.bank_id == search_bank)
    if search_type:
        query = query.filter(Credits.type == search_type)
    data = query.all()
    data = db2dict(data)
    data_result = []
    for i in data:
        rating = [i.rating for i in Revues.query.filter_by(product_id=i['id'], product='credit').all()]
        i.update({'rating': round(sum(rating)/len(rating) if len(rating) else 0, 5)})
        data_result.append(i)
    return current_app.response_class(
        response=json.dumps(
            {
                'cards': data_result,
                'result': True,
                'len': len(data_result)
            }
        ),
        status=200,
        mimetype='application/json'
    )


@auth_api.route('/api/business-credit', methods=['GET'])
def business_credit():
    '''
    ---
   get:
     summary: Кредит
     parameters:
         - in: query
           name: credit
           schema:
             type: integer
             example: 2
           description: credit
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   card:
                     type: object
                     properties:
                           id:
                             type: integer

                           bank_id:
                             type: integer

                           min_amount:
                             type: integer

                           rate:
                             type: number

                           timeframe_max:
                             type: integer

                           description:
                             type: string

                           type:
                             type: string

                           max_amount:
                             type: integer

                           timeframe_min:
                             type: integer

                           name:
                             type: string

                           rating:
                             type: integer

                   result:
                     type: boolean
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
       - business
    '''
    credit = request.args.get('credit')
    query = Credits.query.filter_by(id=credit)
    data = query.all()
    if not data:
        return current_app.response_class(
            response=json.dumps(
                {
                    'result': False,
                }
            ),
            status=404,
            mimetype='application/json'
        )
    data = db2dict(data)
    data_result = []
    for i in data:
        rating = [i.rating for i in Revues.query.filter_by(product_id=i['id'], product='credit').all()]
        i.update({'rating': round(sum(rating)/len(rating) if len(rating) else 0, 5)})
        data_result.append(i)
    return current_app.response_class(
        response=json.dumps(
            {
                'card': data_result[0],
                'result': True,
            }
        ),
        status=200,
        mimetype='application/json'
    )
