import sqlite3

# Function to initialize the database
def init_db():
    # Connect to the SQLite database (creates the database file if it doesn't exist)
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Create the 'users' table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('gym-goer', 'trainer', 'athlete'))
        )
    ''')

    # Create the 'bmi_logs' table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS bmi_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            bmi REAL NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')

    # Create the 'workout_logs' table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS workout_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            log_text TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')

    # Create the 'diet_logs' table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS diet_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            log_text TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')

    # Create the 'trainer_pages' table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS trainer_pages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            full_name TEXT NOT NULL,
            credentials TEXT NOT NULL,
            training_style TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')

    # Create the 'athlete_trainer_mapping' table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS athlete_trainer_mapping (
            athlete_id INTEGER NOT NULL,
            trainer_id INTEGER NOT NULL,
            assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (athlete_id, trainer_id),
            FOREIGN KEY (athlete_id) REFERENCES users (id) ON DELETE CASCADE,
            FOREIGN KEY (trainer_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')

    # Create the 'messages' table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            recipient_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender_id) REFERENCES users (id) ON DELETE CASCADE,
            FOREIGN KEY (recipient_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')

    # Create the 'training_requests' table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS training_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            athlete_id INTEGER NOT NULL,
            trainer_id INTEGER NOT NULL,
            request_status TEXT DEFAULT 'pending' CHECK (request_status IN ('pending', 'accepted', 'declined')),
            requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (athlete_id) REFERENCES users (id) ON DELETE CASCADE,
            FOREIGN KEY (trainer_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')

    # Create the 'trainer_goals' table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS trainer_goals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            trainer_id INTEGER NOT NULL,
            athlete_id INTEGER NOT NULL,
            goal_description TEXT NOT NULL,
            set_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (trainer_id) REFERENCES users (id) ON DELETE CASCADE,
            FOREIGN KEY (athlete_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')

    # Commit changes and close the connection
    conn.commit()
    conn.close()

# Reusable function to connect to the database
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row  # Enables dictionary-like access to rows
    return conn

# Main entry point to initialize the database when the script is run
if __name__ == "__main__":
    init_db()