import os
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from flask_mail import Mail,Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from helpers import login_required
import re
from werkzeug.security import check_password_hash, generate_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from datetime import datetime,timedelta,timezone
from dotenv import load_dotenv



load_dotenv()



# Configure application
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
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

# Mail Config
app.config.update(
    MAIL_SERVER=os.getenv("MAIL_SERVER"),
    MAIL_PORT=int(os.getenv("MAIL_PORT")),
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
    MAIL_DEFAULT_SENDER=os.getenv("MAIL_DEFAULT_SENDER"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),

)

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.secret_key)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.Text, nullable=False)
    lastName = db.Column(db.Text, nullable=False)
    username = db.Column(db.Text, nullable=False, unique=True)
    hash = db.Column(db.Text, nullable=False)
    is_verified = db.Column(db.Boolean, nullable=False, default=False)
    reset_token_used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda:datetime.now(timezone.utc))
    followers = db.Column(db.Integer, nullable=False, default=0)
    following = db.Column(db.Integer, nullable=False, default=0)
    email = db.Column(db.String(320), nullable=False)
    woofs = db.relationship('Woof', backref='author', lazy=True)

class Woof(db.Model):
    __tablename__ = 'woofs'
    id = db.Column(db.Integer, primary_key=True)
    woof = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda:datetime.now(timezone.utc))
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


# delete old unverified users
@app.before_request
def delete_unverified_users():
    expiry= datetime.now(timezone.utc) - timedelta(hours=24)
    unverified = User.query.filter_by(is_verified=False).filter(User.created_at <expiry).all()
    for user in unverified:
        db.session.delete(user)
    if unverified:
        db.session.commit()
    # Make session permanent    
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


# Verify email
@app.route("/confirm/<token>")
def confirm_email(token):
    try:
        email = serializer.loads(token, salt="email-confirm", max_age = 3600)
    except (SignatureExpired, BadSignature):
        return "Confirmation link is invalid or expired.", 400
    
    user = User.query.filter_by(email=email).first()
    if not user:
        return "user not found", 404
    
    user.is_verified = True
    db.session.commit()
    flash("Email verified successfully!", "success")
    return redirect("/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    
    """Log user in"""
    if request.method == "GET":

        return render_template("login.html", error="")

    elif request.method == "POST":
        session.clear()
        username = request.form.get("username").lower()
        password = request.form.get("password")

        if not username or not password:
            error = "Please enter a username and password."
            return render_template("login.html", error=error)

        else:
            user_search = User.query.filter(func.lower(User.username)==username).first()
            if not user_search or not check_password_hash(user_search.hash, password):
                error = "Invalid username and/or password"
                return render_template("login.html", error=error)
            if not user_search.is_verified:
                error = "Email not verified. Check your inbox for verification mail"
                return render_template("login.html", error=error)

            session["user_id"] = user_search.id
            return redirect("/")
        
#forgot password and password reset via email
@app.route("/forgot-password", methods=["GET","POST"])
def forgot_password():

    error = ""
    email = ""
    if request.method == "POST":
        email = request.form.get("email")

        if not email:
            error = "Please enter your email."
        elif not check_email(email):   
            error = "Invalid email address."

        if error:
            return render_template("forgot_password.html", error=error, email=email)     

        user = User.query.filter_by(email=email).first()
        if(user):
            user.reset_token_used = False
            db.session.commit()
            token = serializer.dumps(email, salt="reset-password")
            link = url_for("reset_password", token=token, _external=True)
            msg= Message("Woofer Password Reset", recipients=[email])
            msg.body = f"""
            Hi {user.firstName}
            Click to reset your password:
            {link}
            This link will expire in 1 hour."""
            mail.send(msg)
        flash("If the email exists, a reset link has been sent.", "info")
        return redirect("/login")
    return render_template("forgot_password.html",error=error, email=email)    


@app.route("/reset-password/<token>", methods=["POST", "GET"])
def reset_password(token):
    try:
        email = serializer.loads(token, salt="reset-password", max_age=3600)
    except(SignatureExpired, BadSignature):
        return "Invalid or expired token", 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return "Invalid user", 404
    
    if user.reset_token_used:
        return "This reset link has already been used.", 403
    
    error = ""
    confirm_error = ""
    if request.method == "POST":
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        if not new_password:
            error ="Please enter a new password"    

        elif not check_password(new_password):
            error = "Password must be atleast 8 characters with 1 each of uppercase, lowercase, number and symbol. " 
        elif check_password_hash(user.hash, new_password):
            error = "New password cannot be the same as the old password."

        if not confirm_password or confirm_password != new_password:
            confirm_error="Passwords do not match."
        if error or confirm_error:
            return render_template("reset_password.html",token=token,error=error, confirm_error=confirm_error)        

        user.hash = generate_password_hash(new_password)
        user.reset_token_used =True
        db.session.commit()
        flash("Password successfully reset!", "success")
        return redirect("/login")
    
    return render_template("reset_password.html", token=token, error=error)


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
        username = request.form.get("username").lower()
        email = request.form.get("registerEmail")
        password = request.form.get("password")

        fname = lname = uname = pword = mail_status = "is-valid"
        uname_error = email_error = ""

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
            user_search = User.query.filter(func.lower(User.username)==username).first()
            if user_search:
                uname = "is-invalid"
                uname_error = "Username already taken!"
            else:
                uname = "is-valid"
                uname_error = ""
        if not email or not check_email(email):
            mail_status = "is-invalid"
            email_error = "Please enter a valid email address."
        else:
            email_search = User.query.filter_by(email=email).first()
            if email_search:
                mail_status = "is-invalid"
                email_error = "Email already linked to an existing account."
            else:
                mail_status = "is-valid"
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
            'mail': mail_status,
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

            token = serializer.dumps(email, salt='email-confirm')
            link = url_for('confirm_email', token=token, _external=True)
            msg = Message("Verify your Woofer Account", recipients=[email])
            msg.body = f"""
            Hi {first_name},
            Click to verify your email:
            {link}
            Expires in 1 hour."""
            mail.send(msg)
            flash("Verification link sent to your email.", "info")
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
