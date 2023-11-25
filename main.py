import flask
import flask_login
from django.utils.http import url_has_allowed_host_and_scheme
from wtforms import StringField, SubmitField, PasswordField
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'
app.config['UPLOAD_FOLDER'] = 'static/files/'

login_manager = LoginManager()
login_manager.init_app(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy()


# CREATE TABLE IN DB
class User(db.Model,UserMixin):  # ADD usermixin from the example
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


db.init_app(app)
with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(id):
    print(id)
    return User.query.get(int(id))


@app.route('/')
def home():
    f = generate_password_hash(password='123456', method="pbkdf2", salt_length=2)
    print(f)
    return render_template("index.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    # .is_authenticated:
    if request.method == "POST":  #:works also ...

        new_user = User(name=request.form.get('name'),
                        email=request.form.get('email'),
                        password=request.form.get('password'))

        exist = db.session.query(User).filter_by(email=new_user.email).first()
        if exist:
            flash("Email address have already exist")
            print("noooooo")

        else:
            new_user.password = generate_password_hash(new_user.password, method="pbkdf2", salt_length=2)

            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            first_time = new_user.name
            flask.flash('Your account has been created! You are now able to log in', 'success')
            # return redirect(f'/secrets/{first_time}')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        exist_user = User.query.all()  # CALL ALL RECORDS IN DATABASE
        user_login = User.query.filter_by(email=request.form.get('email')).first()
        #load_user(user_login(user_login))

        if user_login:
            if check_password_hash(user_login.password, request.form.get('password')):
                login_user(user_login,remember=True)
                name_login = user_login.name
                return redirect(url_for('secrets'))  # return redirect(f'/secrets/')  # TODO load_user(22)
    return flask.render_template('login.html')


# print(request.form.get('email'))
# print(request.form.get('password'))
# print(exist_user[4].name, user_login.password)
# next = flask.request.args.get('next')

# # Login and validate the user.
# # user should be an instance of your `User` class
# #
# flash('Logged in successfully.')
#
# next = flask.request.args.get('next')
# # url_has_allowed_host_and_scheme should check if the url is safe
# # for redirects, meaning it matches the request host.
# # See Django's url_has_allowed_host_and_scheme for an example.
# if not url_has_allowed_host_and_scheme(next, request.host):
#     return flask.abort(400)
#
# return flask.redirect(next or flask.url_for('index'))


@app.route('/secrets/')
# @login_required
def secrets():
    return render_template("secrets.html", var=current_user.name)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))





@app.route('/download/<filename>')
def download(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    # return send_from_directory('static', path="files/cheat_sheet.pdf")


if __name__ == "__main__":
    app.run(debug=True)

# for key, value in request.form.items():
#     print("key: {0}, value: {1}".format(key, value))
