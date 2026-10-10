<div align='center' classname="text-3xl font-mono font-bold">
<h1>🐶 Woofer - A Microblogging Platform </h1>
</div>
<div align='center' classname="text-3xl font-mono font-bold">
  https://woofer-rsb9.onrender.com/
</div>

## 📝 Description

Woofer is a microblogging web application built with Flask, SQLAlchemy, and PostgreSQL. Users can register, log in, create short "woofs" (posts), view woofs from other users, manage their profile, and reset their password via email verification.  The application emphasizes a clean user interface and a straightforward user experience.

## 🚀 Features

*   **User Authentication:** 🔒 Secure registration and login system with password hashing.
*   **Email Verification:** ✅ Users must verify their email address upon registration.
*   **Verification Recovery:** 🔁 Unverified users can request a new verification email from the login page.
*   **Password Reset:** ✉️ Users can reset their passwords via email.
*   **Woofing (Posting):** 📝 Users can create and post "woofs" (short messages).
*   **Woof Display:** 📰 Displays woofs from all users in reverse chronological order.
*   **My Woofs:** 🐾 Users can view only their own woofs.
*   **Profile Management:** 👤 Users can view and update their profile information, including changing their password.
*   **Woof Deletion:** 🗑️ Users can delete their own woofs.
*   **Responsive Design:**📱 Utilizes Bootstrap for a responsive and user-friendly interface.

## 🛠️ Technologies Used

*   **Backend:**
    *   Python 🐍
    *   Flask 🌐
    *   Flask-SQLAlchemy 🗄️
    *   PostgreSQL 🐘
    *   Flask-Session 🍪
    *   Flask-Mail ✉️
    *   Brevo API 📬
    *   itsdangerous 🔑
    *   dotenv ⚙️
    *   Werkzeug 🛠️
    *   gunicorn ⚙️
*   **Frontend:**
    *   HTML 🧱
    *   CSS 🎨
    *   JavaScript 📜
    *   Bootstrap 💙
*   **Other:**
    *   psycopg2-binary 💿
    *   gunicorn ⚙️

## ⚙️ Local Setup

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/ChaitanyaShah21/Woofer.git
    cd Woofer
    ```

2.  **Create and activate a virtual environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Set up environment variables:**
    *   Copy `.env.example` to `.env` and replace every placeholder.
    *   Ensure your PostgreSQL database is running and accessible.

5.  **Initialize the database:**

    *   Start the python interpreter
        ```bash
        python
        ```
    *   Run the following code to create the database tables:
        ```python
        from app import app, db
        with app.app_context():
            db.create_all()
        ```

6.  **Run the application:**
    ```bash
    python app.py
    ```
    Or using gunicorn
     ```bash
    gunicorn --bind 0.0.0.0:5000 app:app
    ```

## 🚀 Deploy on Render

Create the PostgreSQL database and web service in Render, then configure the web
service as follows:

* **Runtime:** Python 3
* **Build Command:** `pip install -r requirements.txt`
* **Start Command:** `gunicorn --bind 0.0.0.0:$PORT app:app`
* **Health Check Path:** `/login`

In the web service's **Environment** settings, add:

```
APP_ENV=production
SECRET_KEY=<long-random-secret>
DATABASE_URL=<Internal Database URL copied from the Render PostgreSQL service>
BREVO_API_KEY=<Brevo API Key (Recommended for Render free tier)>
MAIL_SERVER=<SMTP server (Fallback / Paid plans)>
MAIL_PORT=587
MAIL_USERNAME=<SMTP username>
MAIL_PASSWORD=<SMTP password>
MAIL_DEFAULT_SENDER=<verified sender email>
```

> **Note on Email on Render Free Tier:** Render blocks outbound SMTP ports (25, 465, 587) on free tier services. Setting `BREVO_API_KEY` routes email delivery through Brevo's HTTP API (over HTTPS port 443), which works reliably on Render's free tier. Standard SMTP is retained as a fallback.

Use the database service's **Internal Database URL**, not its external URL,
when the web service and database are in the same Render region. Never commit
these values or a `.env` file.

After the first successful deploy, initialize the tables once from the Render
web service's shell:

```bash
python -c "from app import app, db; app.app_context().push(); db.create_all()"
```

Then open the generated `onrender.com` URL and test registration, email
verification, login, posting, logout, and password reset. If using Brevo, verify your
sender email in the Brevo dashboard before testing. If an email is not received, use
**Resend verification email** on the login page and check the Render service logs.

## 💻 Usage

1.  **Register:** Navigate to `/register` to create a new account.  Ensure you use a valid email address for verification.
2.  **Verify Email:** Click the verification link sent to your email address.
3.  **Login:** Navigate to `/login` to log in with your username and password.
4.  **Home:** The home page (`/`) displays woofs from all users.  Use the text area to create and send your own woofs.
5.  **My Woofs:** Navigate to `/my-woofs` to view and delete your own woofs.
6.  **Profile:** Navigate to `/profile` to view your profile information and change your password.
7.  **Logout:** Navigate to `/logout` to log out of the application.
8.  **Forgot Password:** If you forgot password navigate to `/forgot-password` and follow instructions

## 📄 License

MIT License

```
