from application import db

class Item(db.Model):
    __tablename__ = "items"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30))
    price = db.Column(db.Float(precision=2))
    ownership = db.Column(db.String)
    store = db.Column(db.String)


    def __init__(self, name, price, ownership, store):
        self.name = name
        self.price = price
        self.ownership = ownership
        self.store = store

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()

    @classmethod
    def find_by_name(cls, name):
        return cls.query.filter_by(name=name).first()
