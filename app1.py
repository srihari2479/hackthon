import os
import re
from flask import Flask, render_template, request, redirect, flash, url_for, g
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from cryptography.fernet import Fernet
from passwordmanager import save_password, get_saved_passwords, update_password, delete_password_entry
from database import get_db, close_db, init_db  

# Initialize Flask app
app = Flask(__name__)
app.secret_key = "supersecretkey"

# Initialize Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = "login"  # Redirect users to login page if not logged in

# Load encryption key
def load_encryption_key():
    key_path = "key.env"
    if os.path.exists(key_path):
        with open(key_path, "rb") as file:
            key = file.read()
        try:
            Fernet(key)  # Validate key
            return key
        except ValueError:
            print("Invalid key format, generating a new key...")
            os.remove(key_path)
    key = Fernet.generate_key()
    with open(key_path, "wb") as file:
        file.write(key)
    return key

# Initialize cipher
fernet_key = load_encryption_key()
cipher = Fernet(fernet_key)

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, email):
        self.id = id
        self.username = username
        self.email = email

# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    cursor.close()
    close_db(db)

    if user:
        return User(id=user[0], username=user[1], email=user[2])
    return None

@app.route('/')
def home():
    return redirect(url_for('login'))  # Always go to login page first

# ✅ Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))  

    if request.method == 'POST':
        entered_username = request.form['username']
        entered_password = request.form['password']

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (entered_username,))
        user = cursor.fetchone()
        cursor.close()
        close_db(db)

        if user:
            try:
                decrypted_password = cipher.decrypt(user[3].encode()).decode()
                if decrypted_password == entered_password:
                    logged_in_user = User(id=user[0], username=user[1], email=user[2])
                    login_user(logged_in_user)
                    flash("Login successful!", "success")
                    return redirect(url_for('dashboard'))  
                else:
                    flash("Invalid username or password.", "error")
            except Exception:
                flash("Decryption failed! Invalid password or corrupted data.", "error")
        else:
            flash("Invalid username or password.", "error")

    return render_template('login.html')

# ✅ Signup Route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))  

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        db = get_db()
        cursor = db.cursor()

        try:
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                flash("Username already exists.", "error")
                return redirect(url_for('signup'))

            cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
            if cursor.fetchone():
                flash("Email already exists.", "error")
                return redirect(url_for('signup'))

            encrypted_password = cipher.encrypt(password.encode()).decode()
            cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", (username, email, encrypted_password))
            db.commit()

            flash("Account created successfully! Please log in.", "success")
            return redirect(url_for('login'))

        except Exception as e:
            flash(f"Error: {e}", "error")
            db.rollback()

        finally:
            cursor.close()
            close_db(db)

    return render_template('signup.html')

# ✅ Dashboard Route
@app.route('/dashboard')
@login_required  
def dashboard():
    passwords = get_saved_passwords(current_user.id)
    return render_template('dashboard.html', user=current_user.username, passwords=passwords)

# ✅ Save Password Route
@app.route('/save_password', methods=['POST'])
@login_required
def save_password_route():
    website = request.form['website']
    username = request.form['username']
    password = request.form['password']

    try:
        save_password(current_user.id, website, username, password)
        flash("Password saved successfully!", "success")
    except Exception as e:
        flash(f"Error: {e}", "error")

    return redirect(url_for('dashboard'))

# ✅ Edit Password Route
@app.route('/edit_password/<int:password_id>', methods=['GET', 'POST'])
@login_required
def edit_password(password_id):
    db = get_db()
    cursor = db.cursor()

    # Fetch existing password details
    cursor.execute("SELECT id, website, username, password FROM passwords WHERE id = ? AND user_id = ?", 
                   (password_id, current_user.id))
    password_entry = cursor.fetchone()

    if not password_entry:
        flash("Password entry not found.", "error")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        new_password = request.form['password']
        
        # Encrypt the new password
        encrypted_password = cipher.encrypt(new_password.encode()).decode()

        try:
            cursor.execute("UPDATE passwords SET password = ? WHERE id = ? AND user_id = ?", 
                           (encrypted_password, password_id, current_user.id))
            db.commit()
            flash("Password updated successfully!", "success")
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash(f"Error updating password: {e}", "error")
            db.rollback()

    cursor.close()
    close_db(db)

    return render_template('edit_password.html', password=password_entry)

# ✅ Delete Password Route
@app.route('/delete_password/<int:password_id>', methods=['POST'])
@login_required
def delete_password(password_id):
    db = get_db()
    cursor = db.cursor()

    try:
        cursor.execute("DELETE FROM passwords WHERE id = ? AND user_id = ?", (password_id, current_user.id))
        db.commit()
        flash("Password deleted successfully!", "success")
    except Exception as e:
        flash(f"Error deleting password: {e}", "error")
        db.rollback()

    cursor.close()
    close_db(db)

    return redirect(url_for('dashboard'))

# ✅ Logout Route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully!", "success")
    return redirect(url_for('login'))  

# Close DB Connection After Request
@app.teardown_appcontext
def close_db_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        close_db(db)

if __name__ == '__main__':
    app.run(debug=False)
