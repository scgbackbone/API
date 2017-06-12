from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, ValidationError
from wtforms.validators import InputRequired, Length, EqualTo, Email
from ..models.user import User

class RegisterForm(FlaskForm):
	username = StringField("username", validators=[InputRequired(message="username is required"), Length(min=5, max=15, message="min 5 chars max 15chars")])
	email = StringField("email", validators=[InputRequired(message="email is required"), Email()])
	password = PasswordField("password", validators=[InputRequired(message="password is required"), Length(min=8, message="password has to be at least 8 chars long")])
	confirm_password = PasswordField("confirm password", validators=[InputRequired(message="confirmation password is required"), Length(min=8), EqualTo("password", message="Passwords must match")])
	submit = SubmitField("Register me")

	def validate_username(self, field):
		if User.find_by_username(field.data):
			raise ValidationError("Username already in use.")

	def validate_email(self, field):
		if User.find_by_email(field.data):
			raise ValidationError("Email already registered.")


class LoginForm(FlaskForm):
	username = StringField("username", validators=[InputRequired(message="username is required"), Length(min=5, max=15, message="min 5 chars max 15chars")])
	password = PasswordField("password", validators=[InputRequired(message="password is required"), Length(min=8, message="password has to be at least 8 chars long")])
	remember_me = BooleanField("Keep me logged in")
	submit = SubmitField("Log In")

	def validate_username(self, field):
		if User.find_by_username is None:
			raise ValidationError("Incorrect username - user with provided username does not exist")

class UpdateProfileForm(FlaskForm):
	username = StringField("username", validators=[InputRequired(message="username is required"), Length(min=5, max=15, message="min 5 chars max 15chars")])
	old_password = PasswordField("old password", validators=[InputRequired(message="old password is required"), Length(min=8, message="password has to be at least 8 chars long")])
	new_password = PasswordField("new password", validators=[InputRequired(message="new password is required"), Length(min=8, message="password has to be at least 8 chars long")])
	confirm_password = PasswordField("confirm password", validators=[InputRequired(message="confirmation password is required"), Length(min=8), EqualTo("new_password", message="Passwords must match!")])
	submit = SubmitField("Save")

	def validate_username(self, field):
		if User.find_by_username(field.data) is None:
			raise ValidationError("Incorrect username - user with provided username does not exist")
