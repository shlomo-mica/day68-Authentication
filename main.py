import wtforms
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user,
from wtforms.validators import ValidationError, DataRequired
from wtforms import Form
login_manager=LoginManager()
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'
app.config['UPLOAD_FOLDER'] = 'static/files/'
login_manager.init_app(app)
# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy()
db.init_app(app)


# CREATE TABLE IN DB
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


with app.app_context():
    db.create_all()


@app.route('/')
def home():
    f = generate_password_hash(password='123456', method="pbkdf2", salt_length=2)
    print(f)
    return render_template("index.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    # if request.method == "POST":works also ...
    new_user = User(name=request.form.get('name'),
                    email=request.form.get('email'),
                    password=request.form.get('password'))
    exist = db.session.query(User).filter_by(name=new_user.name).first()
    if exist:
        print("noooooo")

    else:
        new_user.password = generate_password_hash(new_user.password, method="pbkdf2", salt_length=2)

        db.session.add(new_user)
        db.session.commit()
        first_time = new_user.name
        return redirect(f'/secrets/{first_time}')

    return render_template('register.html')


@app.route('/login',methods=['GET','POST'])

def login():
    form = LoginForm()

    return render_template("login.html")


@app.route('/secrets/<var>')
def secrets(var):
    var = var
    return render_template("secrets.html", var=var)


@app.route('/logout')
def logout():
    pass


@app.route('/download/<filename>')
def download(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    # return send_from_directory('static', path="files/cheat_sheet.pdf")


if __name__ == "__main__":
    app.run(debug=True)

# for key, value in request.form.items():
#     print("key: {0}, value: {1}".format(key, value))
