from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required, fresh_login_required
#from werkzeug.security import safe_str_cmp
from flask_bcrypt import Bcrypt
from urllib.parse import urlparse, urljoin
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature


app = Flask(__name__)
app.config.from_pyfile("app.cfg")
db = SQLAlchemy(app)
flask_bcrypt = Bcrypt(app)
mail = Mail(app)
s = URLSafeTimedSerializer(app.config["SECRET_KEY"])

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "In order to access this endpoint - log in"
login_manager.refresh_view = "login"
login_manager.needs_refresh_message = "Please, perform fresh login. You're accessing route with increased protection."

from models.user import *
from models.stores import *
from models.items import *

# return whole object from database
@app.route("/user-loader")
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ("http", "https") and \
            ref_url.netloc == test_url.netloc


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        if User.find_by_username(request.form["username"]):
            error = "User with this username already exists"
        elif User.find_by_email(request.form["email"]):
            error = "User with this email already exists"
        else:
            password = request.form["password"]
            pw_hash = flask_bcrypt.generate_password_hash(password)
            user = User(request.form["username"], request.form["email"], pw_hash)
            token = s.dumps(request.form["email"], salt="email-confirm")
            token = token + "@" + str(user.username)
            link = url_for("confirmemail", token=token, _external=True)
            msg = Message(
                subject="Confirmation Email",
                sender="virgovica@gmail.com",
                recipients=[request.form["email"]]
            )
            msg.body = "Your confirmation link is {}".format(link)
            mail.send(msg)
            try:
                user.save_to_db()
            except:
                flash("internal servererrrrrrrrrrrrrrrrror")
            flash("user created successfully, check provided mailbox where you find confirmation link\nlast registration step, I promise..."\
                    + "\nclick on the confirmation link and you'll be redirected to login page...")
            return render_template("register.html")
    return render_template("register.html", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        if not User.find_by_username(request.form["username"]):
            error = "Invalid username. Try again"
        else:
            user = User.find_by_username(request.form["username"])
            if not user.verified:
                return render_template("login.html", error="error - not verified"), 201
            candid_password = request.form["password"]
            if flask_bcrypt.check_password_hash(user.password, candid_password):
                login_user(user, remember=True)
                if "next" in session:
                    next_url = session["next"]
                    if is_safe_url(next_urls):
                        return redirect(next_url)
                return "<h1>You're now logged in...</h1>", 201#redirect(url_for("updateprofile"))
            error = "Invalid password"
    return render_template("login.html", error=error)

@app.route("/changepasswd", methods=["GET", "POST"])
@fresh_login_required
def update_profile():
    error = None
    if request.method == "POST":
        if not User.find_by_username(request.form["username"]):
            error = "User with this username doesn't exist"
        else:
            user = User.find_by_username(request.form["username"])
            candid_passwd = request.form["password"]
            if flask_bcrypt.check_password_hash(user.password, candid_passwd):
                if request.form["password1"] != request.form["password2"]:
                    error = "New password 1 doesn't match new password 2"
                else:
                    new_passwd = flask_bcrypt.generate_password_hash(request.form["password1"])
                    user.password = new_passwd
                    try:
                        user.save_to_db()
                        flash("Update = Success")
                        return render_template("updateprofile.html", error=error), 201
                    except Exception as e:
                        print("Exception thrown from application.py:\n {}".formt(str(e)))
                        flash("internat server error")
                        return render_template("profileUpdate.html", error=error), 500
            else:
                error = "Invalid password"
        return render_template("updateprofile.html", error=error)
    return render_template("updateprofile.html", error=error), 200

@app.route("/emailconf", methods=["GET", "POST"])
def email_confirmation():
    if request.method == "GET":
        return '<form action="/emailconf" method="POST"><input name="email"><input type="submit"></form>'
    token = s.dumps(request.form["email"], salt="email-confirm")
    link = url_for("confirmemail", token=token, _external=True)
    current_usr = load_user(str(current_user.id))
    msg = Message(
        subject="Confirmation Email",
        sender="virgovica@gmail.com",
        recipients=[request.form["email"]]
    )
    msg.body = "Your confirmation link is {}".format(link + "@" + current_usr.username)
    mail.send(msg)
    return ("the email you entered is " + (request.form["email"]) + "  The token is:  " + token), 201

@app.route("/confirmemail/<token>")
def confirmemail(token):
    token, username = token.split("@")
    print(token)
    print(username)
    try:
        email = s.loads(token, salt="email-confirm", max_age=600)
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
    return redirect(url_for("login"))

@app.route("/")
def index():
    user = User.query.filter_by(username="andrej").first()
    if user != None:
        login_user(user)
        return redirect(url_for("home"))
    else:
        return redirect(url_for("login"))


@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return "you're now logged out"


@app.route("/home")
@login_required
def home():
    x = load_user(str(current_user.id))
    return "username: " + str(x.username) + "\nemail: " + str(x.email) + "\npassword: " + str(x.password) + " verified=" + str(x.verified)


@app.route("/store-post", methods=["GET", "POST"])
@login_required
def store_post():
    error = None
    if request.method == "POST":
        if Store.find_by_name(request.form["name"]):
            error = "Store with this name already exists"
            return render_template("store.html", error=error)
        storex = Store(request.form["name"], current_user.username)
        try:
            storex.save_to_db()
            flash("Store added == True")
        except:
            flash("internal server errror")
    return render_template("store.html", error=error)


@app.route("/store-update", methods=["GET", "POST"])
@login_required
def store_post_update():
    error = None
    if request.method == "POST":
        if not Store.find_by_name(request.form["name"]):
            error = "Store with this name doesn't exist"
            return render_template("store-update.html", error=error)
        storex = Store.find_by_name(request.form["name"])
        if storex.ownership == current_user.username:
            if Store.find_by_name(request.form["new_name"]):
                error = "store with this name already exists"
                return render_template("store-update.html", error=error)
            try:
                storex.name = request.form["new_name"]
                storex.save_to_db()
                flash("store name updated")
            except:
                flash("internal server error")
            return render_template("store-update.html", error=error)
        error = "permission denied"
    return render_template("store-update.html", error=error)


@app.route("/item-post", methods=["GET", "POST"])
@login_required
def item_post():
    error = None
    if request.method == "POST":
        if not Store.find_by_name(request.form["storename"]):
            error = "Store with this name doesn't exist"
            return render_template("item.html", error=error)
        storex = Store.find_by_name(request.form["storename"])
        if storex.ownership == current_user.username:
            if Item.find_by_name(request.form["name"]):
                error = "Item with this name already exists"
                return render_template("item.html", error=error)
            itemx = Item(request.form["name"], request.form["price"], current_user.username, storex.name)
            try:
                itemx.save_to_db()
                flash("item added == True")
            except:
                flash("internal server errror")
            return render_template("item.html", error=error)
        error = "permission denied - you cannot modify store which you do not own"
    return render_template("item.html", error=error)


@app.route("/items", methods=["GET", "POST"])
@login_required
def items():
    items = Item.query.all()
    if request.method == "POST":
        if not Store.find_by_name(request.form["storename"]):
            error = "Store with this name doesn't exist"
            return render_template("index.html", error=error)
        concrete_items = [item for item in items if item.store == request.form["storename"]]
        return render_template("index.html", items=concrete_items)
    return render_template("index.html", items=items)


if __name__ == "__main__":
    db.create_all()
    app.run(port=5000, debug=True)
