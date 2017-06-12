import os
from flask import render_template, redirect, url_for, request, session, flash
from flask_login import login_user, logout_user, current_user, login_required, fresh_login_required
from urllib.parse import urlparse, urljoin
from flask_mail import Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from .auth_forms import RegisterForm, LoginForm, UpdateProfileForm
from ..models.user import User
from .. import login_manager, mail
from . import auth

s = URLSafeTimedSerializer(os.environ.get("SECRET_KEY"))

# return whole object from database
@auth.route("/user-loader")
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ("http", "https") and \
            ref_url.netloc == test_url.netloc


@auth.route("/register", methods=["GET", "POST"])
def register():
	status_code = 200
	error = None
	form = RegisterForm()
	if form.validate_on_submit():
			status_code = 201
		#if User.find_by_username(form.username.data):
		#	error = "User with such username already exists."
		#	form.username.data = ""
		#elif User.find_by_email(form.email.data):
		#	error = "This email is already used with different user."
		#	form.email.data = ""
		#else:
			user = User(username=form.username.data, email=form.email.data, password=form.password.data)
			token = s.dumps(form.email.data, salt="email-confirm")
			token = token + "@" + str(user.username)
			link = url_for("auth.confirmemail", token=token, _external=True)
			msg = Message(
				subject="Confirmation Email",
				sender="virgovica@gmail.com",
				recipients=[form.email.data]
			)
			msg.body = "Your confirmation link is {}".format(link)
			mail.send(msg)
			try:
				user.save_to_db()
			except:
				error = "Oops, internal server error"
			flash("User created successfully, check provided mailbox where you will find confirmation link."\
					+ "\n click on the confirmation link and you'll be redirected to login page.")
	return render_template("auth/register.html", form=form, error=error), status_code



@auth.route("/login", methods=["GET", "POST"])
def login():
	name = session.get("name")
	error = None
	status_code = 200
	form = LoginForm()
	if form.validate_on_submit():
		status_code = 201
		user = User.find_by_username(form.username.data)
		if user is None:
			error = "Incorrect username... user with provided username does not exist!"
			form.username.data = ""
		elif not user.verified:
			error = "Not verified"
		elif user is not None and user.verify_password(form.password.data):
			login_user(user, remember=form.remember_me.data)
			session["name"] = user.username
			return redirect(request.args.get("next") or url_for("main.home"))
		else:
			error = "Invalid password"
	return render_template("auth/login.html", form=form, error=error, name=name), status_code


@auth.route("/changepasswd", methods=["GET", "POST"])
@fresh_login_required
def update_profile():
	error = None
	status_code = 200
	form = UpdateProfileForm()
	if form.validate_on_submit():
		status_code = 201
		user = User.find_by_username(form.username.data)
		if user is None:
			error = "Incorrect username... user with provided username does not exist!"
			form.username.data = ""
		elif user and user.verify_password(form.old_password.data):
			user.password = form.new_password.data
			try:
				user.save_to_db()
				flash("update = success")
				return render_template("auth/updateprofile.html", form=form), status_code
			except Exception as e:
				print("Exception thrown >>> {}".format(e))
				error = "internal server error"
				return render_template("auth/updateprofile.html", error=error, form=form), 500
		else:
			error = "Wrong current password"
	return render_template("auth/updateprofile.html", form=form, error=error), status_code


@auth.route("/confirmemail/<token>")
def confirmemail(token):
    token, username = token.split("@")
    #print(token)
    #print(username)
    try:
        email = s.loads(token, salt="email-confirm", max_age=1800)
    except SignatureExpired as e:
        print(e)
        return "<h1>Token is expired</h1>"
    except BadTimeSignature as e:
        print(e)
        return "<h1>Bad token</h1>"
    user = User.find_by_username(username=username)
    user.verified = True
    try:
        user.save_to_db()
    except Exception as e:
        print(e)
        return "<h1>Internal server error</h1>"
    return redirect(url_for("auth.login"))


@auth.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
	logout_user()
	session["name"] = ""
	return "you're now logged out"

#################################################################################
## obsolete register method; if to use, only with auth/register1.html template ##
#################################################################################

#@auth.route("/register", methods=["GET", "POST"])
#def register():
#    error = None
#    if request.method == "POST":
#        if User.find_by_username(request.form["username"]):
#            error = "User with this username already exists"
#        elif User.find_by_email(request.form["email"]):
#            error = "User with this email already exists"
#        else:
#            password = request.form["password"]
#            pw_hash = flask_bcrypt.generate_password_hash(password)
#            user = User(request.form["username"], request.form["email"], pw_hash)
#            token = s.dumps(request.form["email"], salt="email-confirm")
#            token = token + "@" + str(user.username)
#            link = url_for("auth.confirmemail", token=token, _external=True)
#            msg = Message(
#                subject="Confirmation Email",
#                sender="virgovica@gmail.com",
#                recipients=[request.form["email"]]
#            )
#            msg.body = "Your confirmation link is {}".format(link)
#            mail.send(msg)
#            try:
#                user.save_to_db()
#            except:
#                flash("internal servererrrrrrrrrrrrrrrrror")
#            flash("user created successfully, check provided mailbox where you find confirmation link\nlast registration step, I promise..."\
#                    + "\nclick on the confirmation link and you'll be redirected to login page...")
#            return render_template("register1.html")
#    return render_template("auth/register1.html", error=error)

###########################################################################
## obsolete login method; if to use, only with auth/login1.html template ##
###########################################################################

#@auth.route("/login", methods=["GET", "POST"])
#def login():
#	name = session.get("name")
#	error = None
#	if request.method == "POST":
#		if not User.find_by_username(request.form["username"]):
#			error = "Invalid username. Try again"
#		else:
#			user = User.find_by_username(request.form["username"])
#			if not user.verified:
#				return render_template("auth/login1.html", error="ERROR not verified"), 201
#			candid_password = request.form["password"]
#			if flask_bcrypt.check_password_hash(user.password, candid_password):
#				login_user(user, remember=True)
#				if "next" in session:
#					next_url = session["next"]
#					if is_safe_url(next_url):  # I did have next_urls here before - why?
#						return redirect(next_url)
#				return "<h1>You're now logged in</h1>"
#			error = "Invalid password"
#	return render_template("auth/login1.html", error=error, name=name)

############################################################################################
## obsolete update_profile method; if to use, only with auth/updateprofile1.html template ##
############################################################################################

#@auth.route("/changepasswd", methods=["GET", "POST"])
#@fresh_login_required
#def update_profile():
#    error = None
#    if request.method == "POST":
#        if not User.find_by_username(request.form["username"]):
#            error = "User with this username doesn't exist"
#        else:
#            user = User.find_by_username(request.form["username"])
#            candid_passwd = request.form["password"]
#            if flask_bcrypt.check_password_hash(user.password, candid_passwd):
#                if request.form["password1"] != request.form["password2"]:
#                    error = "New password 1 doesn't match new password 2"
#                else:
#                    new_passwd = flask_bcrypt.generate_password_hash(request.form["password1"])
#                    user.password = new_passwd
#                    try:
#                        user.save_to_db()
#                        flash("Update = Success")
#                        return render_template("auth/updateprofile.html", error=error), 201
#                    except Exception as e:
#                        print("Exception thrown from application.py:\n {}".foramt(str(e)))
#                        flash("internat server error")
#                        return render_template("auth/updateprofile.html", error=error), 500
#            else:
#                error = "Invalid password"
#        return render_template("auth/updateprofile.html", error=error)
#    return render_template("auth/updateprofile.html", error=error), 200

