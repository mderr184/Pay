from flask import Flask, render_template_string, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a secure value!

DATABASE = 'users.db'

LOGIN_HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login or Create Account</title>
</head>
<body>
    <h2>Login or Create Account</h2>
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        <ul>
        {% for category, message in messages %}
          <li style="color: {% if category == 'danger' %}red{% else %}green{% endif %};">{{ message }}</li>
        {% endfor %}
        </ul>
      {% endif %}
    {% endwith %}
    <form method="POST">
        <label>Username:</label><br>
        <input type="text" name="username" required><br>
        <label>Password:</label><br>
        <input type="password" name="password" required><br><br>
        <button type="submit" name="login">Login</button>
        <button type="submit" name="register">Create Account</button>
    </form>
</body>
</html>
'''

HOME_HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Home</title>
</head>
<body>
    <h2>Welcome, {{ username }}!</h2>
    <p>You are now logged in.</p>
    <a href="{{ url_for('logout') }}">Logout</a>
</body>
</html>
'''

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    with conn:
        conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );
        ''')
    conn.close()

init_db()

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if 'login' in request.form:
            username = request.form['username']
            password = request.form['password']
            conn = get_db_connection()
            user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            conn.close()
            if user and check_password_hash(user['password'], password):
                session['username'] = username
                return redirect(url_for('home'))
            else:
                flash('Incorrect username or password.', 'danger')
                return redirect(url_for('login'))
        elif 'register' in request.form:
            username = request.form['username']
            password = request.form['password']
            conn = get_db_connection()
            try:
                conn.execute(
                    'INSERT INTO users (username, password) VALUES (?, ?)',
                    (username, generate_password_hash(password))
                )
                conn.commit()
                flash('Account created. Please log in.', 'success')
            except sqlite3.IntegrityError:
                flash('Username already exists.', 'danger')
            finally:
                conn.close()
            return redirect(url_for('login'))
    return render_template_string(LOGIN_HTML)

@app.route('/home')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template_string(HOME_HTML, username=session['username'])

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)