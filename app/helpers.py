# -*- coding: utf-8 -*-
import requests
import json
import time
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pyfcm import FCMNotification
from flask import url_for

MAIL_USERNAME = 'expo.platform.testing@gmail.com'
MAIL_PASSWORD = 'rdnyhnzxxvvxwqtw'
FCM_KEY = "AIzaSyApzBLvb4paaieK3cUn5EkGFU3nANDjMpg"


def send_sms(phones, text, total_price=0):
    login = 'InfoDomDev'  # Логин в smsc
    password = 'yBEgupqPBrPK37Z'  # Пароль в smsc
    sender = 'Test'  # Имя отправителя
    # Возможные ошибки
    errors = {
        1: 'Ошибка в параметрах.',
        2: 'Неверный логин или пароль.',
        3: 'Недостаточно средств на счете Клиента.',
        4: 'IP-адрес временно заблокирован из-за частых ошибок в запросах. Подробнее',
        5: 'Неверный формат даты.',
        6: 'Сообщение запрещено (по тексту или по имени отправителя).',
        7: 'Неверный формат номера телефона.',
        8: 'Сообщение на указанный номер не может быть доставлено.',
        9: 'Отправка более одного одинакового запроса на передачу SMS-сообщения либо более пяти одинаковых запросов на получение стоимости сообщения в течение минуты. '
    }
    # Отправка запроса
    url = f"https://smsc.ru/sys/send.php?login={login}&psw={password}&phones={phones}&mes={text}&cost={total_price}&fmt=3&sender={sender}"
    answer = json.loads(requests.get(url).text)
    print(answer)
    if 'error_code' in answer:
        # Возникла ошибка
        return {
            'status': 'error',
            'response': errors[answer['error_code']],
        }
    else:
        if total_price == 1:
            # Не отправлять, узнать только цену
            print('Будут отправлены: %d SMS, цена рассылки: %s' % (answer['cnt'], answer['cost'].encode('utf-8')))
        else:
            # СМС отправлен, ответ сервера
            return {
                'status': 'ok',
                'response': answer,
            }


def send_email(recipient_email, subject, message, sender_email=MAIL_USERNAME, sender_password=MAIL_PASSWORD):
    # Создание объекта сообщения
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = subject

    # Добавление текстового содержимого письма
    msg.attach(MIMEText(message, 'plain'))

    # Установка соединения с SMTP-сервером
    with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
        smtp.starttls()
        smtp.login(sender_email, sender_password)

        # Отправка письма
        smtp.send_message(msg)

    print('Письмо успешно отправлено')


def send_notification(notification, deviceId):
    push_service = FCMNotification(api_key=FCM_KEY)

    # Данные для отправки уведомления
    message_title = notification.title
    message_body = notification.text
    data_message = {
        "pdf_url": url_for('static', filename='files/' + notification.attachment)
    }

    # Отправка уведомления
    registration_id = deviceId
    result = push_service.notify_single_device(
        registration_id=registration_id,
        message_title=message_title,
        message_body=message_body,
        data_message=data_message
    )
    return result
