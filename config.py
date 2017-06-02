import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
	SECRET_KEY = os.environ.get("SECRET_KEY")
	SQLALCHEMY_TRACK_MODIFICATIONS = False

	@staticmethod
	def init_app(app):
		pass


class DevelopmentConfig(Config):
	DEBUG = True
	MAIL_SERVER = "smtp.gmail.com"
	MAIL_PORT = 465
	MAIL_USERNAME = os.environ.get("MAIL_USERNAME")
	MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")
	MAIL_USE_TSL = False
	MAIL_USE_SSL = True
	SQLALCHEMY_DATABASE_URI = os.environ.get("DEV_DATABASE_URI") or \
		"sqlite:///" + os.path.join(basedir, "development.db")


class TestingConfig(Config):
	TESTING = True
	SQLALCHEMY_DATABASE_URI = os.environ.get("TEST_DATABASE_URI") or \
		"sqlite:///" + os.path.join(basedir, "testing.db")


class ProductionConfig(Config):
	DEBUG = False
	SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URI") or \
		"sqlite:///" + os.path.join(basedir, "database.db")


config = {
	"development": DevelopmentConfig,
	"testing": TestingConfig,
	"production": ProductionConfig,
	"default": DevelopmentConfig
}

