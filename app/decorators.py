from functools import wraps
from flask import abort
from flask_login import current_user
from app.models.roles import Permission

def permission_required(permission):
	def decorator(f):
		@wraps(f)
		def decorated_function(*args, **kwargs):
			if not current_user.can(permission):
				abort(403)
			return f(*args, **kwargs)
		return decorated_function
	return decorator

def permission_required1(permission):
	def wrap(function):
		@wraps(function)
		def wrapped_function(*args, **kwargs):
			if not current_user.can(permission):
				abort(403)
			return function(*args, **kwargs)
		return wrapped_function
	return wrap


class Permission_required(object):

	def __init__(self, permission):
		self.permission = permission

	def __call__(self, function):
		@wraps(function)
		def wrapped_func(*args, **kwargs):
			if not current_user.can(self.permission):
				abort(403)
			return function(*args, **kwargs)
		return wrapped_func


def admin_required(f):
	return permission_required(Permission.ADMINISTER)(f)


