import os
from app import create_app, db
from app.models.user import User
from app.models.items import Item
from app.models.stores import Store
from app.models.roles import Role
from flask_script import Manager, Shell
from flask_migrate import Migrate, MigrateCommand

app = create_app(os.environ.get("FLASK_CONFIG") or "default")
manager = Manager(app)
migrate = Migrate(app, db)

def make_shell_context():
	return dict(app=app, db=db, User=User, Store=Store, Item=Item, Role=Role)

manager.add_command("shell", Shell(make_context=make_shell_context))
manager.add_command("db", MigrateCommand)

if __name__ == "__main__":
	manager.run()
