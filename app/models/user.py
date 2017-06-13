from app import db, flask_bcrypt, login_manager
from flask_login import UserMixin, AnonymousUserMixin
from .roles import Role, Permission

class User(UserMixin, db.Model):
	__tablename__ = 'users'

	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(30), unique=True)
	email = db.Column(db.String(100))
	password_hash = db.Column(db.String(128))
	role_id = db.Column(db.Integer, db.ForeignKey('roles.name'))
	verified = db.Column(db.Boolean, default=False)

	def __init__(self, **kwargs):
		super(User, self).__init__(**kwargs)
		if self.role == None:
			if self.email == current_app.config["MAIL_USERNAME"]:
				self.role = Role.query.filter_by(permissions=0xff).first()
			else:
				self.role = Role.query.filter_by(default=True).first()


	def __repr__(self):
		return "<User %r>" % self.username

	def save_to_db(self):
		db.session.add(self)
		db.session.commit()

	def delete_from_db(self):
		db.session.delete(self)
		db.session.commit()

	@property
	def password(self):
		raise AttributeError("password is not a readable attribute")

	@password.setter
	def password(self, passwd):
		self.password_hash = flask_bcrypt.generate_password_hash(passwd)

	def verify_password(self, passwd):
		return flask_bcrypt.check_password_hash(self.password_hash, passwd)

	def can(self, permissions):
		return self.role is not None and (self.role.permissions & permissions) == permissions

	def is_admin(self):
		return self.can(Permission.ADMINISTER)

	@classmethod                                                 # withou classmethod (self)
	def find_by_username(cls, username):
		return cls.query.filter_by(username=username).first()

	@classmethod
	def find_by_id(cls, _id):
		return cls.query.filter_by(id=_id).first()

	@classmethod
	def find_by_email(cls, email):
		return cls.query.filter_by(email=email).first()

	@classmethod
	def show_all_users(cls):
		def functional(some_object):
			return {"username: ": some_object.username, "email: ": some_object.email, "verified: ": some_object.verified, "passwd": some_object.password_hash}

		return list(map(functional, (i for i in cls.query.all())))

	@classmethod
	def show_all_users_rec(cls, list_of_all_users):
		def functional(some_object):
			return {"username: ": some_object.username, "email: ": some_object.email, "verified: ": some_object.verified}
		try:
			if len(list_of_all_users) > 0:
				return [functional(list_of_all_users[0])] + cls.show_all_users_rec(list_of_all_users[1:])
			else:
				return []
		except IndexError as e:
			print(e)
			return []

	@classmethod
	def delete_all_users(cls):
		def delete_from_db(some_object):
			db.session.delete(some_object)
			db.session.commit()
		list(map(delete_from_db, (i for i in cls.query.all())))
		return "Done; Success..."


class AnonymousUser(AnonymousUserMixin):
	def can(self, permissions):
		return False

	def is_admin(self):
		return False

login_manager.anonymous_user = AnonymousUser
