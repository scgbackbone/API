from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length

class RegisterForm(FlaskForm):
	username = StringField("username", validators=[InputRequired(message="username is required"), Length(min=5, max=15, message="min 5 chars max 15chars")])
	email = StringField("email", validators=[InputRequired(message="email is required")])
	password = PasswordField("password", validators=[InputRequired(message="password is required"), Length(min=8, message="password has to be at least 8 chars long")])
	confirm_password = PasswordField("confirm password", validators=[InputRequired(message="confirmation password is required"), Length(min=8)])
	submit = SubmitField()


class LoginForm(FlaskForm):
	username = StringField("username", validators=[InputRequired(message="username is required"), Length(min=5, max=15, message="min 5 chars max 15chars")])
	password = PasswordField("password", validators=[InputRequired(message="password is required"), Length(min=8, message="password has to be at least 8 chars long")])
