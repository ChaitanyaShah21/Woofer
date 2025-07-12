import os
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from helpers import login_required
import re
from werkzeug.security import check_password_hash, generate_password_hash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from dotenv import load_dotenv



load_dotenv()



# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = True
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# use render postgres

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.Text, nullable=False)
    lastName = db.Column(db.Text, nullable=False)
    username = db.Column(db.Text, nullable=False, unique=True)
    hash = db.Column(db.Text, nullable=False)
    followers = db.Column(db.Integer, nullable=False, default=0)
    following = db.Column(db.Integer, nullable=False, default=0)
    email = db.Column(db.String(320), nullable=False)
    woofs = db.relationship('Woof', backref='author', lazy=True)

class Woof(db.Model):
    __tablename__ = 'woofs'
    id = db.Column(db.Integer, primary_key=True)
    woof = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)





# ## RUN ONCE AFTER DATABASE RESET
# with app.app_context():
#     db.create_all()






# # Make sure API key is set
# if not os.environ.get("API_KEY"):
#     raise RuntimeError("API_KEY not set")

# Function for validating an Email
def check_email(email):
    # Make a regular expression
    # for validating an Email
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

    # pass the regular expression and the string into the fullmatch() method
    if re.fullmatch(regex, email):
        return True

    else:
        return False

# Function for validating password acc to:
#     Minimum 8 characters.
#     The alphabet must be between [a-z]
#     At least one alphabet should be of Upper Case [A-Z]
#     At least 1 number or digit between [0-9].
#     At least 1 character from [ _ or @ or $ ].


def check_password(password):
    flag = 0
    while True:
        if len(password) <= 8:
            flag = -1
            break
        elif not re.search("[a-z]", password):
            flag = -1
            break
        elif not re.search("[A-Z]", password):
            flag = -1
            break
        elif not re.search("[0-9]", password):
            flag = -1
            break
        elif not re.search("[_@$]", password):
            flag = -1
            break
        elif re.search(r"\s", password):
            flag = -1
            break
        else:
            flag = 0
            return True

    if flag == -1:
        return False


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.before_request
def make_session_permanent():
    session.permanent = True


@app.route("/", methods=["GET", "POST"])
# homepage
@login_required
def index():
    data = {
        'woof': '',
    }
    all_woofs = Woof.query.order_by(Woof.timestamp.desc()).all()
    woof_data = []
    for woof in all_woofs:
        entry = {
            'woof': woof.woof,
            'timestamp':woof.timestamp.isoformat(),
            'username': woof.author.username,
            'firstName': woof.author.firstName,
            'lastName': woof.author.lastName,
        }
        woof_data.append(entry)
    if request.method == "GET":
        return render_template("index.html", error="", woof_data=woof_data)

    elif request.method == "POST":
        woof = request.form.get("send-woof")
        if not woof:
            error = "You cannot send a blank WOOF!"
            return render_template("index.html", error=error, woof_data=woof_data)
        else:

            data['woof'] = ""
            new_woof = Woof(woof=woof, user_id=session["user_id"])
            db.session.add(new_woof)
            db.session.commit()
            return redirect("/")


            all_woofs = Woof.query.order_by(Woof.timestamp.desc()).all()
            woof_data = []
            for woof in all_woofs:
                entry = {
                    'woof': woof.woof,
                    'timestamp': woof.timestamp,
                    'username': woof.author.username,
                    'firstName': woof.author.firstName,
                    'lastName': woof.author.lastName,
                }
                woof_data.append(entry)

            return render_template("index.html", error="", woof_data=woof_data)


@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()
    """Log user in"""
    if request.method == "GET":

        return render_template("login.html", error="")

    elif request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            error = "Please enter a username and password."
            return render_template("login.html", error=error)

        else:
            user_search = User.query.filter_by(username=username).first()
            if not user_search or not check_password_hash(user_search.hash, password):
                error = "Invalid username and/or password"
                return render_template("login.html", error=error)
            session["user_id"] = user_search.id
            return redirect("/")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/my-woofs", methods=["GET"])
# woofs by current user
@login_required
def my_woofs():

    user = User.query.get(session['user_id'])
    all_woofs = Woof.query.filter_by(user_id=user.id).order_by(Woof.timestamp.desc()).all()
    woof_data = []
    for woofs in all_woofs:

        entry = {
            'id': woofs.id,
            'woof': woofs.woof,
            'timestamp': woofs.timestamp.isoformat(),
            'username': user.username,
            'firstName': user.firstName,
            'lastName': user.lastName,
        }
        woof_data.append(entry)
    if request.method == "GET":
        return render_template("my_woofs.html", woof_data=woof_data)


@app.route("/profile", methods=["GET", "POST"])
# woofs by current user
@login_required
def profile():

    error = ""
    success = ""
    user = User.query.get(session["user_id"])
    woof_num = Woof.query.filter_by(user_id=session["user_id"]).count()
    if request.method == "GET":
        return render_template("profile.html", user=user, woof_num=woof_num, error=error, success=success)
    elif request.method == "POST":
        old_password = request.form.get("old_password")
        new_password = request.form.get("new_password")

        if not old_password or not new_password:
            flash("Please fill both old and new passwords!", "danger")
            return redirect("/profile")

        if not check_password_hash(user.hash, old_password):
            flash("Incorrect Old Password", "danger")
            return redirect("/profile")

        if not check_password(new_password):
            flash("New password must contain a minimum of 8 characters, including at least 1 uppercase and lowercase letter, at least 1 number and at least one symbol.", "danger")
            return redirect("/profile")

        if old_password == new_password:
            flash("New password cannot be the same as the old password.", "warning")
            return redirect("/profile")

        user.hash = generate_password_hash(new_password)
        db.session.commit()
        flash("Password successfully updated!", "success")
        return redirect("/profile")

@app.route("/register", methods=["GET", "POST"])
def register():
    session.clear()
    if request.method == "GET":
        register_data = {
            'fname': '',
            'first_name': '',
            'lname': '',
            'last_name': '',
            'uname': '',
            'username': '',
            'uname_error': 'Required.',
            'mail': '',
            'email': '',
            'email_error': 'Please enter a valid email address.',
            'pword': '',
            'password': '',
        }
        return render_template("register.html", data=register_data)

    elif request.method == "POST":

        first_name = request.form.get("firstName")
        last_name = request.form.get("lastName")
        username = request.form.get("username")
        email = request.form.get("registerEmail")
        password = request.form.get("password")

        if not first_name or not first_name.isalpha():
            fname = "is-invalid"
        else:
            fname = "is-valid"
        if not last_name or not last_name.isalpha():
            lname = "is-invalid"
        else:
            lname = "is-valid"

        if not username:
            uname = "is-invalid"
            uname_error = "Required."
        else:
            user_search = User.query.filter_by(username=username).first()
            if user_search:
                uname = "is-invalid"
                uname_error = "Username already taken!"
            else:
                uname = "is-valid"
                uname_error = ""
        if not email or not check_email(email):
            mail = "is-invalid"
            email_error = "Please enter a valid email address."
        else:
            email_search = User.query.filter_by(email=email).first()
            if email_search:
                mail = "is-invalid"
                email_error = "Email already linked to an existing account."
            else:
                mail = "is-valid"
                email_error = ""
        if not password or not check_password(password):
            pword = "is-invalid"
        else:
            pword = "is-valid"

        # data to be re-entered in case invalid
        register_data = {
            'fname': fname,
            'first_name': first_name,
            'lname': lname,
            'last_name': last_name,
            'uname': uname,
            'username': username,
            'uname_error': uname_error,
            'mail': mail,
            'email_error': email_error,
            'email': email,
            'pword': pword,
            'password': password,
        }

        if fname == 'is-invalid' or lname == 'is-invalid' or uname == 'is-invalid' or mail == 'is-invalid' or pword == 'is-invalid':

            return render_template("register.html", data=register_data)
        else:
            password_hash = generate_password_hash(password)
            new_user = User(firstName=first_name, lastName=last_name,
                username=username, email=email, hash=generate_password_hash(password))
            db.session.add(new_user)
            db.session.commit()
            return redirect("/login")
        

@app.route("/delete-woof", methods=["POST"])
@login_required
def delete_woof():
    woof_id = request.form.get("woof_id")
    woof = Woof.query.get(woof_id)

    if woof and woof.user_id == session["user_id"]:
        db.session.delete(woof)
        db.session.commit()
        flash("Woof deleted successfully!", "success")
    else:
        flash("Woof doesnt exist or You are not authorized to delete this woof", "danger")    
    return redirect("/my-woofs")    


if __name__ == '__main__':
    app.run(
        # host='127.0.0.1',
        # port=5001,
        # debug=True
    )
