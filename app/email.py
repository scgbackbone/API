from flask_mail import Message
from threading import Thread

app.config["FLASKY_ADMIN"] = "youremail@address.com"

def send_async_email(app, msg):
	with app.app_context():
		mail.send(msg)

def send_email(to, subject, template, **kwargs):
	msg = Message(subject,sender=app.config["MAIL_USERNAME"],
			recipients=[to])
	msg.body = render_template(template + ".txt", **kwargs)
	msg.html = render_template(template + ".html", **kwargs)
	thrd = Thread(target=send_async_email, args=[app, msg])
	thrd.start()
	return thrd
