from application import db
from flask_login import UserMixin

class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True)
    email = db.Column(db.String(100))
    password = db.Column(db.String(100))
    verified = db.Column(db.Boolean)

    def __init__(self, username, email, password, verified=False):
        self.username = username
        self.email = email
        self.password = password
        self.verified = verified

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()

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
            return {"username: ": some_object.username, "email: ": some_object.email, "verified: ": some_object.verified}

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
        return map(delete_from_db, (i for i in cls.query.all()))
