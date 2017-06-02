from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from urllib.parse import urlparse, urljoin
from flask_bcrypt import Bcrypt
from  flask_mail import Mail
from config import config

db = SQLAlchemy()
mail = Mail()
flask_bcrypt = Bcrypt()
login_manager = LoginManager()

def create_app(config_name):
	app = Flask(__name__)
	app.config.from_object(config[config_name])
	config[config_name].init_app(app)

	db.init_app(app)
	mail.init_app(app)
	flask_bcrypt.init_app(app)
	login_manager.init_app(app)

	from . import main as main_blueprint
	app.register_blueprint(main_blueprint.main)

	return app
