from flask import Flask, render_template, redirect, url_for, request, session
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import random
import bcrypt
from database import db  # Assuming your MySQL connection is defined here

app = Flask(__name__)
app.secret_key = 'notes@123'
s = URLSafeTimedSerializer(app.secret_key)

# Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'kandukurishivani260@gmail.com'
app.config['MAIL_PASSWORD'] = 'isgw uwfy jopw cwri'  # Consider using env variables
app.config['MAIL_DEFAULT_SENDER'] = 'kandukurishivani260@gmail.com'
mail = Mail(app)

# Helper Functions
def generateotp():
    return str(random.randint(100000, 999999))

def send_otp_email(name, email, otp):
    try:
        msg = Message('OTP for Login', recipients=[email])
        msg.body = f"Hello {name},\nYour OTP is: {otp}\nPlease use this to complete your login."
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False

# Routes
@app.route('/')
def home():
    return render_template("home.html")

@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        email = request.form.get("email")
        password = request.form.get("password")

        cursor = db.cursor()
        cursor.execute("SELECT id, username, password FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user and bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
            session['uname'] = user[1]
            session['user_id'] = user[0]
            session['otp'] = generateotp()

            if send_otp_email(session['uname'], email, session['otp']):
                return redirect(url_for('verify'))
            else:
                return render_template("login.html", info="Unable to send OTP")
        else:
            return render_template("login.html", info="Invalid email or password")

    return render_template("login.html")

@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == 'POST':
        username = request.form.get("uname")
        email = request.form.get("email")
        password = request.form.get("password")
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        cursor = db.cursor()
        cursor.execute("SELECT username FROM users WHERE email=%s", (email,))
        if cursor.fetchone():
            return render_template("register.html", info="Email is already registered")

        cursor.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                       (username, email, hashed_password))
        db.commit()
        return redirect(url_for('login'))

    return render_template("register.html")

@app.route('/forgotpassword', methods=["GET", "POST"])
def forgotpassword():
    if request.method == 'POST':
        email = request.form.get("email")
        cursor = db.cursor()
        cursor.execute("SELECT username FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()

        if user:
            session['email'] = email
            token = s.dumps(email, salt='password-reset-salt')
            reset_url = url_for('resetpassword', token=token, _external=True)

            msg = Message('Password Reset Request', recipients=[email])
            msg.body = f'Click the link to reset your password: {reset_url}\n\nThis link will expire in 1 hour.'
            mail.send(msg)

            return render_template('forgotpassword.html', info="Link sent to your email, please check")
        else:
            return render_template('forgotpassword.html', info='Email is not registered')

    return render_template('forgotpassword.html')

@app.route('/resetpassword/<token>', methods=['GET', 'POST'])
def resetpassword(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except SignatureExpired:
        return render_template('forgotpassword.html', info="Token expired. Request a new link.")

    if request.method == 'POST':
        newpassword = request.form.get("newpassword")
        confirmpassword = request.form.get("confirmpassword")

        if newpassword == confirmpassword:
            hashed_password = bcrypt.hashpw(newpassword.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            cursor = db.cursor()
            cursor.execute("UPDATE users SET password=%s WHERE email=%s", (hashed_password, email))
            db.commit()
            return redirect(url_for('login'))
        else:
            return render_template('resetpassword.html', info="Passwords do not match")

    return render_template('resetpassword.html')

@app.route('/verify', methods=["GET", "POST"])
def verify():
    if request.method == 'POST':
        enteredotp = request.form.get('otp')
        if enteredotp == session.get('otp'):
            return redirect(url_for('dashboard'))
        else:
            return render_template('verify.html', info='Incorrect OTP')

    return render_template('verify.html')

@app.route('/dashboard', methods=["GET", "POST"])
def dashboard():
    if 'uname' not in session or 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    cursor = db.cursor()

    if request.method == 'POST':
        content = request.form.get("note")
        if content:
            cursor.execute("INSERT INTO notes (user_id, content) VALUES (%s, %s)", (user_id, content))
            db.commit()

    cursor.execute("SELECT id, content FROM notes WHERE user_id = %s", (user_id,))
    notes = [{"id": n[0], "content": n[1]} for n in cursor.fetchall()]
    return render_template("dashboard.html", notes=notes)

@app.route('/delete_note/<int:note_id>', methods=["POST"])
def delete_note(note_id):
    if 'user_id' not in session:
        return redirect('/login')

    cursor = db.cursor()
    cursor.execute("DELETE FROM notes WHERE id = %s AND user_id = %s", (note_id, session['user_id']))
    db.commit()
    return redirect(url_for('dashboard'))

@app.route('/edit_note/<int:note_id>', methods=["GET", "POST"])
def edit_note(note_id):
    if 'user_id' not in session:
        return redirect('/login')

    cursor = db.cursor()
    user_id = session['user_id']

    if request.method == "POST":
        new_content = request.form.get("content")
        if new_content:
            cursor.execute("UPDATE notes SET content = %s WHERE id = %s AND user_id = %s",
                           (new_content, note_id, user_id))
            db.commit()
            return redirect(url_for('dashboard'))

    cursor.execute("SELECT id, content FROM notes WHERE id = %s AND user_id = %s", (note_id, user_id))
    note = cursor.fetchone()
    if not note:
        return "Note not found", 404

    return render_template("edit_note.html", note={"id": note[0], "content": note[1]})

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
