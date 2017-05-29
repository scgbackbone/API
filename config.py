# app.config.from_pyfile
import os

SQLALCHEMY_DATABASE_URI="sqlite:///database.db"
SQLALCHEMY_TRACK_MODIFICATIONS=False
SECRET_KEY=os.environ.get("SECRET_KEY")
USE_SESSION_FOR_NEXT=True
MAIL_SERVER='smtp.gmail.com'
MAIL_PORT=465
MAIL_USERNAME=os.environ.get("MAIL_USERNAME")
MAIL_PASSWORD=os.environ.get("MAIL_PASSWORD")
MAIL_USE_TLS=False
MAIL_USE_SSL=True
