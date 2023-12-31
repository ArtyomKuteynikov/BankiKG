# init.py
import json
from flask import Flask, render_template
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from app.swagger import get_apispec
from flask_swagger_ui import get_swaggerui_blueprint
from flask_cors import CORS
from . import config
import mimetypes

SWAGGER_URL = '/docs'
API_URL = '/swagger'

db = SQLAlchemy()


def create_app():
    mimetypes.add_type('application/javascript', '.js')
    mimetypes.add_type('text/css', '.css')
    app = Flask(__name__)
    CORS(app)

    app.config['SECRET_KEY'] = config.SECRET_KEY
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///DB.db'

    db.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    from .models import User

    @login_manager.user_loader
    def load_user(user_id):
        # since the user_id is just the primary key of our user table, use it in the query for the user
        return User.query.get(int(user_id))

    @app.route('/swagger')
    def create_swagger_spec():
        return json.dumps(get_apispec(app).to_dict())  # blueprint for auth routes in our app

    swagger_ui_blueprint = get_swaggerui_blueprint(
        SWAGGER_URL,
        API_URL,
        config={
            'app_name': 'Banki-RU'
        }
    )
    app.register_blueprint(swagger_ui_blueprint)

    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    # blueprint for non-auth parts of app
    from .admin import main as main_blueprint
    app.register_blueprint(main_blueprint)

    # blueprint for api
    from .user import auth_api as api_blueprint
    app.register_blueprint(api_blueprint)

    from .conneсt import connect as api_blueprint
    app.register_blueprint(api_blueprint)
    '''
    from .complaints_api import api as api_blueprint
    app.register_blueprint(api_blueprint)

    from .main_api import api as api_blueprint
    app.register_blueprint(api_blueprint)

    from .promotions_api import promotions_api as api_blueprint
    app.register_blueprint(api_blueprint)

    from .payment_api import payment_api as api_blueprint
    app.register_blueprint(api_blueprint)

    from .chats_api import api as api_blueprint
    app.register_blueprint(api_blueprint)
    '''

    def page_not_found(e):
        return render_template('404.html'), 404

    app.register_error_handler(404, page_not_found)

    from .chats import main as main_blueprint
    app.register_blueprint(main_blueprint)

    return app
