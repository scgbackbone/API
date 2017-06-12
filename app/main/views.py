import os
from flask import render_template, redirect, url_for, request, session, flash
from flask_login import current_user, login_required
from urllib.parse import urlparse, urljoin
from ..models.user import User
from ..models.items import Item
from ..models.stores import Store
from . import main
from .. import login_manager, flask_bcrypt, mail
from ..auth.auth_views import load_user


@main.route("/emailconf", methods=["GET", "POST"])
def email_confirmation():
    if request.method == "GET":
        return '<form action="/emailconf" method="POST"><input name="email"><input type="submit"></form>'
    token = s.dumps(request.form["email"], salt="email-confirm")
    link = url_for("main.confirmemail", token=token, _external=True)
    current_usr = load_user(str(current_user.id))
    msg = Message(
        subject="Confirmation Email",
        sender="virgovica@gmail.com",
        recipients=[request.form["email"]]
    )
    msg.body = "Your confirmation link is {}".format(link + "@" + current_usr.username)
    mail.send(msg)
    return ("the email you entered is " + (request.form["email"]) + "  The token is:  " + token), 201


@main.route("/")
def index():
    user = User.query.filter_by(username="andrej").first()
    if user != None:
        login_user(user)
        return redirect(url_for("main.home"))
    else:
        return redirect(url_for("auth.login"))


@main.route("/home")
@login_required
def home():
	x = load_user(str(current_user.id))
	y = request.headers
	z = request.args
	qq = session
	return "username: " + str(x.username) + "\nemail: " + str(x.email) + "\npassword: " + str(x.password_hash) + " verified=" + str(x.verified) + "      " + str(y) + "           " + str(["{}:{}".format(i,j) for i,j in z]) + "  " + str(qq)


@main.route("/store-post", methods=["GET", "POST"])
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


@main.route("/store-update", methods=["GET", "POST"])
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


@main.route("/item-post", methods=["GET", "POST"])
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


@main.route("/items", methods=["GET", "POST"])
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


