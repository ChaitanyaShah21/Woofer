import os
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
import sqlite3
from helpers import login_required
import re
from werkzeug.security import check_password_hash, generate_password_hash

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = True
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# use SQLite database
con = sqlite3.connect("woofer.db", check_same_thread=False)
con.row_factory = sqlite3.Row
cur = con.cursor()

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
        elif re.search("\s", password):
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
    all_woofs = cur.execute("SELECT * FROM woofs ORDER BY timestamp DESC").fetchall()
    woof_data = []
    for woofs in all_woofs:
        user = cur.execute("SELECT * FROM users WHERE id = ?", (woofs['user_id'],)).fetchone()
        entry = {
            'woof': woofs['woof'],
            'timestamp': woofs['timestamp'],
            'username': user['username'],
            'firstName': user['firstName'],
            'lastName': user['lastName'],
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
            cur.execute("INSERT INTO woofs (woof, user_id) VALUES(?, ?)",
                       (woof, session["user_id"],))
            con.commit()

            all_woofs = cur.execute("SELECT * FROM woofs ORDER BY timestamp DESC").fetchall()
            woof_data = []
            for woofs in all_woofs:
                user = cur.execute("SELECT * FROM users WHERE id = ?", (woofs['user_id'],)).fetchone()
                entry = {
                    'woof': woofs['woof'],
                    'timestamp': woofs['timestamp'],
                    'username': user['username'],
                    'firstName': user['firstName'],
                    'lastName': user['lastName'],
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
            user_search = cur.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchall()
            if len(user_search) != 1 or not check_password_hash(user_search[0]["hash"], password):
                error = "Invalid username and/or password"
                return render_template("login.html", error=error)
            session["user_id"] = user_search[0]["id"]
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

    all_woofs = cur.execute("SELECT * FROM woofs WHERE user_id = ? ORDER BY timestamp DESC", (session['user_id'],)).fetchall()
    user = cur.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    woof_data = []
    for woofs in all_woofs:

        entry = {
            'woof': woofs['woof'],
            'timestamp': woofs['timestamp'],
            'username': user['username'],
            'firstName': user['firstName'],
            'lastName': user['lastName'],
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
    user = cur.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    woof_num = cur.execute("SELECT COUNT(*) FROM woofs WHERE user_id = ?", (session["user_id"],)).fetchone()['COUNT(*)']
    if request.method == "GET":
        return render_template("profile.html", user=user, woof_num=woof_num, error=error, success=success)
    elif request.method == "POST":
        old_password = request.form.get("old_password")
        new_password = request.form.get("new_password")

        if not old_password or not new_password:
            error = "Please fill both old and new passwords!"
            return render_template("profile.html", user=user, woof_num=woof_num, error=error, success=success)

        correct_hash = cur.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()["hash"]

        if not check_password_hash(correct_hash, old_password):
            error = "Incorrect Old Password"
            return render_template("profile.html", user=user, woof_num=woof_num, error=error, success=success)

        elif not check_password(new_password):
            error = "New password must contain a minimum of 8 characters, including at least 1 uppercase and lowercase" \
                    " letter, at least 1 number and at least one symbol cd ."
            return render_template("profile.html", user=user, woof_num=woof_num, error=error, success=success)

        if old_password == new_password:
            error = "New password cannot be same as the old password"
            success = ""
            return render_template("profile.html", user=user, woof_num=woof_num, error=error, success=success)
        # generate new hash
        password_hash = generate_password_hash(new_password)
        cur.execute("UPDATE users SET hash = ? WHERE id = ?", (password_hash, session["user_id"],))
        con.commit()
        error = ""
        success = "Password Successfully updated!"
        return render_template("profile.html", user=user, woof_num=woof_num, error=error, success=success)


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
            user_search = cur.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchall()
            if len(user_search) != 0:
                uname = "is-invalid"
                uname_error = "Username already taken!"
            else:
                uname = "is-valid"
                uname_error = ""
        if not email or not check_email(email):
            mail = "is-invalid"
            email_error = "Please enter a valid email address."
        else:
            email_search = cur.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchall()
            if len(email_search) != 0:
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
            cur.execute("INSERT INTO users (firstName, lastName, username, hash, email) VALUES(?, ?, ?, ?, ?)",
                       (first_name, last_name, username, password_hash, email,))
            con.commit()
            return redirect("/login")


if __name__ == '__main__':
    app.run(
        host='127.0.0.1',
        port=5001,
        debug=True
    )
