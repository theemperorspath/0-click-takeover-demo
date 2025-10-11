# app.py
msg.set_content(body)
with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
s.send_message(msg)


# Templates
T_INDEX = '<h2>Vulnerable IDN ATO Lab</h2>\n<p><a href="/signup">Signup</a> • <a href="/login">Login</a> • <a href="/forgot">Forgot Password</a></p>'
T_SIGNUP = '<h3>Signup</h3>\n<form method="post">\n Email: <input name="email" required><br>\n Password: <input name="password" required type="password"><br>\n <button type="submit">Signup</button>\n</form>\n<p><a href="/">Home</a></p>'
T_LOGIN = '<h3>Login</h3>\n<form method="post">\n Email: <input name="email" required><br>\n Password: <input name="password" required type="password"><br>\n <button type="submit">Login</button>\n</form>\n<p><a href="/">Home</a></p>'
T_FORGOT = '<h3>Forgot Password</h3>\n<form method="post">\n Email: <input name="email" required><br>\n <button type="submit">Send reset</button>\n</form>\n<p><a href="/">Home</a></p>'
T_RESET = '<h3>Reset Password</h3>\n<form method="post">\n New password: <input name="password" required type="password"><br>\n <button type="submit">Reset</button>\n</form>'


# Routes
@app.route('/')
def index():
return render_template_string(T_INDEX)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
if request.method == 'POST':
email = request.form['email'].strip()
password = request.form['password'].strip()
ok = create_user(email, password)
if not ok:
flash('Email already exists')
return redirect(url_for('signup'))
flash('Account created')
return redirect(url_for('index'))
return render_template_string(T_SIGNUP)


@app.route('/login', methods=['GET', 'POST'])
def login():
if request.method == 'POST':
email = request.form['email'].strip()
password = request.form['password'].strip()
row = get_user_by_email(email)
if row and row[2] == password:
flash('Login successful for: %s' % email)
return redirect(url_for('index'))
flash('Invalid credentials')
return redirect(url_for('login'))
return render_template_string(T_LOGIN)


@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
if request.method == 'POST':
email = request.form['email'].strip()
row = get_user_by_email_normalized_for_reset(email)
if row:
user_id = row[0]
stored_email = row[1]
token = secrets.token_urlsafe(16)
set_reset_token(user_id, token)
reset_link = f"{BASE_URL}/reset/{token}"
body = f"Password reset link:\n\n{reset_link}\n\nIf you did not request this, ignore."
send_email(stored_email, 'Password reset', body)
flash('If an account exists, a reset has been sent (check MailHog)')
return redirect(url_for('index'))
else:
flash('If an account exists, a reset has been sent (check MailHog)')
return redirect(url_for('index'))
return render_template_string(T_FORGOT)


@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset(token):
conn = sqlite3.connect(DB)
c = conn.cursor()
c.execute('SELECT id FROM users WHERE reset_token = ?', (token,))
r = c.fetchone()
conn.close()
if not r:
return 'Invalid or expired token', 404
if request.method == 'POST':
newpw = request.form['password'].strip()
set_password(r[0], newpw)
flash('Password updated')
return redirect(url_for('index'))
return render_template_string(T_RESET)


if __name__ == '__main__':
init_db()
print('Starting vulnerable app on http://127.0.0.1:5000')
print('SMTP configured to %s:%s' % (SMTP_HOST, SMTP_PORT))
app.run(debug=True)
