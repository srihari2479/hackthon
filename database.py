import sqlite3
from flask import Flask, g

app = Flask(__name__)

DATABASE = 'passwords.db'

# Function to get the database connection
def get_db():
    """Connect to the database."""
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row  # Allows column access by name
    return g.db

# Function to close the database connection
@app.teardown_appcontext
def close_db(error=None):
    """Close the database connection when the request ends."""
    db = g.pop('db', None)
    if db is not None:
        db.close()

# Function to initialize the database
def init_db():
    """Create necessary tables in the database."""
    with app.app_context():  # Ensure we are inside Flask app context
        db = get_db()
        cursor = db.cursor()

        # Create users table
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT NOT NULL UNIQUE,
                            email TEXT NOT NULL UNIQUE,
                            password TEXT NOT NULL
                        )''')

        # Create passwords table
        cursor.execute('''CREATE TABLE IF NOT EXISTS passwords (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            user_id INTEGER NOT NULL,
                            website TEXT NOT NULL,
                            username TEXT NOT NULL,
                            password TEXT NOT NULL,
                            FOREIGN KEY(user_id) REFERENCES users(id)
                        )''')

        db.commit()
        print("✅ Database initialized successfully!")

# Run the initialization script
if __name__ == "__main__":
    init_db()
