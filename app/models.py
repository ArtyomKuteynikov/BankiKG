# models.py
import time

from flask_login import UserMixin
from . import db
from itsdangerous import URLSafeTimedSerializer as Serializer
from . import config


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  # primary keys are required by SQLAlchemy
    email = db.Column(db.String(100), unique=True)
    phone = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    status = db.Column(db.String(10), default='active')
    role = db.Column(db.Integer)
    registered = db.Column(db.Integer)
    confirmed = db.Column(db.Integer, default=0)

    def generate_auth_token(self, expiration=3600):
        s = Serializer(config.SECRET_KEY)
        return s.dumps({'id': self.id, 'expiry_date': time.time() + expiration})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(config.SECRET_KEY)
        try:
            data = s.loads(token)
            if data['expiry_date'] < time.time():
                return None
        except:
            return None
        user = User.query.get(data['id'])
        return user


user_mapping = {
    'id': User.id,
    'name': User.name,
    'email': User.email,
    'phone': User.phone,
    'status': User.status,
    'role': User.role,
}


class Codes(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  # primary keys are required by SQLAlchemy
    phone = db.Column(db.String(100))
    code = db.Column(db.String(10))


class ResPass(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  # primary keys are required by SQLAlchemy
    phone = db.Column(db.String(100))
    code = db.Column(db.String(10))


class Promotions(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  # primary keys are required by SQLAlchemy
    title = db.Column(db.String(100))
    subtitle = db.Column(db.String(100))
    text = db.Column(db.String(1000))


class Revues(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  # primary keys are required by SQLAlchemy
    user_id = db.Column(db.Integer)
    product = db.Column(db.String(100))
    product_id = db.Column(db.Integer)
    title = db.Column(db.String(100))
    description = db.Column(db.String(100))
    rating = db.Column(db.Integer)


class Banks(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  # primary keys are required by SQLAlchemy
    image = db.Column(db.String(100))
    region = db.Column(db.Integer)
    license = db.Column(db.Integer)
    since = db.Column(db.Integer)
    form = db.Column(db.String(100))
    name = db.Column(db.String(100))
    address = db.Column(db.String(100))
    phones = db.Column(db.String(10000))


class BanksOffices(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  # primary keys are required by SQLAlchemy
    bank_id = db.Column(db.Integer)
    region = db.Column(db.Integer)
    name = db.Column(db.String(100))
    address = db.Column(db.String(100))
    lat = db.Column(db.REAL)
    lon = db.Column(db.REAL)


class Deposits(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  # primary keys are required by SQLAlchemy
    bank_id = db.Column(db.Integer)
    min_amount = db.Column(db.Integer)
    max_amount = db.Column(db.Integer)
    rate = db.Column(db.REAL)
    timeframe_min = db.Column(db.Integer)
    timeframe_max = db.Column(db.Integer)
    name = db.Column(db.String(100))
    description = db.Column(db.String(100))


class Credits(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  # primary keys are required by SQLAlchemy
    bank_id = db.Column(db.Integer)
    type = db.Column(db.String(100))
    min_amount = db.Column(db.Integer)
    max_amount = db.Column(db.Integer)
    rate = db.Column(db.REAL)
    timeframe_min = db.Column(db.Integer)
    timeframe_max = db.Column(db.Integer)
    name = db.Column(db.String(100))
    description = db.Column(db.String(100))


class Cards(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  # primary keys are required by SQLAlchemy
    bank_id = db.Column(db.Integer)
    type = db.Column(db.String(100))
    price = db.Column(db.REAL)
    max_points = db.Column(db.Integer)
    cashback = db.Column(db.REAL)
    min_amount = db.Column(db.Integer)
    max_amount = db.Column(db.Integer)
    rate = db.Column(db.REAL)
    timeframe_min = db.Column(db.Integer)
    timeframe_max = db.Column(db.Integer)
    name = db.Column(db.String(100))
    description = db.Column(db.String(100))


class News(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  # primary keys are required by SQLAlchemy
    image = db.Column(db.String(100))
    title = db.Column(db.String(100))
    subtitle = db.Column(db.String(100))
    text = db.Column(db.String(1000))


class InvestNews(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  # primary keys are required by SQLAlchemy
    image = db.Column(db.String(100))
    title = db.Column(db.String(100))
    subtitle = db.Column(db.String(100))
    text = db.Column(db.String(1000))


class Mortgage(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  # primary keys are required by SQLAlchemy
    bank_id = db.Column(db.Integer)
    type = db.Column(db.String(100))
    min_amount = db.Column(db.Integer)
    max_amount = db.Column(db.Integer)
    rate = db.Column(db.REAL)
    timeframe_min = db.Column(db.Integer)
    timeframe_max = db.Column(db.Integer)
    name = db.Column(db.String(100))
    description = db.Column(db.String(100))

    def monthly_payment(self, timeframe=10, amount=4000000, first_payment=2500000):
        return (amount-first_payment)*(self.rate/(1-(1+self.rate)**(timeframe-1)))


class Markets(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  # primary keys are required by SQLAlchemy
    name = db.Column(db.String(100))
    description = db.Column(db.String(100))


class Brokers(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  # primary keys are required by SQLAlchemy
    image = db.Column(db.String(100))
    market = db.Column(db.Integer)
    license = db.Column(db.String(100))
    bank_id = db.Column(db.Integer)
    name = db.Column(db.String(100))
    link = db.Column(db.String(1000))
    description = db.Column(db.String(100))


class BrokerTariffs(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  # primary keys are required by SQLAlchemy
    broker_id = db.Column(db.Integer)
    name = db.Column(db.String(100))
    commission = db.Column(db.Integer)
    payment = db.Column(db.Integer)
    link = db.Column(db.String(1000))
    description = db.Column(db.String(100))


class BusinessTariffs(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  # primary keys are required by SQLAlchemy
    bank_id = db.Column(db.Integer)
    name = db.Column(db.String(100))
    description = db.Column(db.String(100))
    commission = db.Column(db.Integer)
    payment = db.Column(db.Integer)
    link = db.Column(db.String(1000))
