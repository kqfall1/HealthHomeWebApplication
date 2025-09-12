from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, session
import sqlite3
import bcrypt

app = Flask(__name__)
app.secret_key = 'your_secret_key'

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row  # Access rows as dictionaries
    return conn

@app.route('/')
def home():
    role = session.get('role')  # Get the role from the session (if logged in)
    return render_template('index.html', role=role)

@app.route('/register/', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')  # Only get email
        password = request.form.get('password')
        role = request.form.get('role')

        # Check for existing email
        conn = get_db_connection()
        existing_user = conn.execute(
            'SELECT * FROM users WHERE email = ?', (email,)
        ).fetchone()
        conn.close()

        if existing_user:
            flash('Email already exists. Please try again.', 'error')
            return render_template('register.html')

        # Hash the password and save the user
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        conn = get_db_connection()
        print(f"Role: {role}, Email: {email}, Password Hash: {password_hash}")
        conn.execute(
            'INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)',
            (email, password_hash, role)
        )
        conn.commit()
        conn.close()

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash']):
            session['user_id'] = user['id']  # Save user ID to session
            print("Session User ID after login:", session.get('user_id'))
            session['role'] = user['role']  # Save user role to session
            flash('Login successful! Welcome back.', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password.', 'error')

    return render_template('login.html')

@app.route('/about/', methods=['GET'])
def about():
    # Check if the user is logged in
    if 'user_id' in session:
        # Redirect logged-in users to the home page (or any other appropriate page)
        return redirect('/')
    
    # Render about.html for users who are not logged in
    return render_template('about.html')

@app.route('/logout/')
def logout():
    session.clear()  # Clear the session to log out the user
    flash('Logout successful!', 'success')  # Add the flash message
    return redirect(url_for('home'))  # Redirect to index.html

# Route for BMI calculation
@app.route('/bmi/', methods=['GET', 'POST'])
def bmi():
    if 'user_id' not in session or session['role'] not in ['gym-goer', 'athlete']:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            # Get form data
            weight = float(request.form.get('weight'))
            height_feet = float(request.form.get('height-feet'))
            height_inches = float(request.form.get('height-inches'))

            # Calculate BMI
            total_height_inches = (height_feet * 12) + height_inches
            height_meters = total_height_inches * 0.0254
            weight_kg = weight * 0.453592
            bmi = round(weight_kg / (height_meters ** 2), 2)

            # Debug: Output calculated BMI
            print(f"Calculated BMI: {bmi}")

            # Save BMI to the database
            user_id = session.get('user_id')  # Retrieve user ID from session
            if user_id:
                conn = get_db_connection()
                cursor = conn.cursor()

                # Insert a new BMI log (always create a new record)
                print(f"Inserting new BMI log for user_id: {user_id} with BMI: {bmi}")
                cursor.execute(
                    'INSERT INTO bmi_logs (user_id, bmi, created_at) VALUES (?, ?, CURRENT_TIMESTAMP)',
                    (user_id, bmi)
                )

                conn.commit()
                conn.close()
                print("BMI log successfully saved!")
            else:
                print("User is not logged in. Cannot save BMI.")

            # Return the calculated BMI as a JSON response
            return jsonify({'bmi': bmi})

        except Exception as e:
            print(f"An error occurred while processing BMI: {e}")
            return jsonify({'error': 'An error occurred while calculating BMI.'}), 500

    # Render the BMI page on GET request
    return render_template('bmi.html')


@app.route('/bmi-history/')
def bmi_history():
    if 'user_id' not in session or session['role'] not in ['gym-goer', 'athlete']:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('login'))
    
    return render_template('bmiHistory.html')

@app.route('/bmi-history-data/')
def bmi_history_data():
    # Ensure the user is logged in
    if 'user_id' not in session:
        flash('Unauthorized access. Please log in.', 'error')
        return redirect(url_for('login'))

    # Retrieve user_id from session
    user_id = session.get('user_id')
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Retrieve all BMI entries for the user
    cursor.execute('SELECT bmi, created_at FROM bmi_logs WHERE user_id = ? ORDER BY created_at ASC', (user_id,))
    history = cursor.fetchall()
    conn.close()

    # Format the data as JSON
    bmi_data = [{'bmi': row[0], 'date': row[1]} for row in history]
    return jsonify(bmi_data)

@app.route('/logs/')
def logs():
    if 'user_id' not in session or session['role'] not in ['gym-goer', 'athlete']:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('login'))
    return render_template('logs.html')

@app.route('/add-workout-log/', methods=['GET', 'POST'])
def add_workout_log():
    # Check unauthorized access for both GET and POST requests first.
    if 'user_id' not in session or session.get('role') not in ['gym-goer', 'athlete']:
        if request.method == 'POST':
            return jsonify({'success': False, 'message': 'Unauthorized access.'}), 403
        else:
            flash('Unauthorized access.', 'error')
            return redirect(url_for('login'))
    
    # Render the log page for GET requests.
    if request.method == 'GET':
        return render_template('addWorkoutLog.html')
    
    # Process POST requests.
    workout_log = request.form.get('workout_log', '').strip()
    if not workout_log:
        return jsonify({'success': False, 'message': 'Workout log is empty.'}), 400

    user_id = session.get('user_id')
    
    try:
        conn = get_db_connection()
        conn.execute(
            'INSERT INTO workout_logs (user_id, log_text) VALUES (?, ?)',
            (user_id, workout_log)
        )
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'Workout log added successfully!'}), 200
    except Exception as e:
        # Optionally log the error: print(e)
        return jsonify({'success': False, 'message': 'An error occurred while saving the log.'}), 500

from flask import jsonify, request, redirect, url_for, render_template, session, flash

@app.route('/add-diet-log/', methods=['GET', 'POST'])
def add_diet_log():
    # Check unauthorized access for both GET and POST requests.
    if 'user_id' not in session or session.get('role') not in ['gym-goer', 'athlete']:
        if request.method == 'POST':
            return jsonify({'success': False, 'message': 'Unauthorized access.'}), 403
        else:
            flash('Unauthorized access.', 'error')
            return redirect(url_for('login'))

    if request.method == 'GET':
        return render_template('addDietLog.html')
    
    # Process POST request.
    diet_log = request.form.get('diet_log', '').strip()
    user_id = session.get('user_id')

    if not diet_log:
        return jsonify({'success': False, 'message': 'Diet log is empty.'}), 400

    try:
        conn = get_db_connection()
        conn.execute('INSERT INTO diet_logs (user_id, log_text) VALUES (?, ?)', (user_id, diet_log))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'Diet log added successfully!'}), 200
    except Exception as e:
        # Optionally log the exception for debugging.
        print("Error while saving diet log:", e)
        return jsonify({'success': False, 'message': 'An error occurred while saving the log.'}), 500

@app.route('/view-workout-logs/')
def view_workout_logs():
    if 'user_id' not in session:
        flash('Unauthorized access. Please log in.', 'error')
        return redirect(url_for('login'))
    
    user_id = session.get('user_id')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    print(f"User ID: {user_id}")
    cursor.execute('SELECT log_text, created_at FROM workout_logs WHERE user_id = ? ORDER BY created_at ASC', (user_id,))
    logs = cursor.fetchall()
    print(f"Workout Logs: {logs}")
    conn.close()

    return render_template('viewWorkoutLogs.html', logs=logs)

@app.route('/view-diet-logs/')
def view_diet_logs():
    if 'user_id' not in session:
        flash('Unauthorized access. Please log in.', 'error')
        return redirect(url_for('login'))
    
    user_id = session.get('user_id')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    print(f"User ID: {user_id}")
    cursor.execute('SELECT log_text, created_at FROM diet_logs WHERE user_id = ? ORDER BY created_at ASC', (user_id,))
    logs = cursor.fetchall()
    print(f"Diet Logs: {logs}")
    conn.close()

    return render_template('viewDietLogs.html', logs=logs)

@app.route('/view-trainers/')
def view_trainers():
    # Check if the user is logged in and has the 'athlete' role
    if 'user_id' not in session or session.get('role') != 'athlete':
        flash('Unauthorized access. Only athletes can view trainers.', 'error')
        return redirect(url_for('login'))

    user_id = session.get('user_id')
    
    # Connect to the database
    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if the logged-in athlete has a trainer mapping
    cursor.execute('SELECT trainer_id FROM athlete_trainer_mapping WHERE athlete_id = ?', (user_id,))
    mapping = cursor.fetchone()

    athlete_has_mapping = bool(mapping)  # True if mapping exists, False otherwise
    athlete_trainer_id = mapping['trainer_id'] if mapping else None  # Get trainer ID if mapping exists

    # Retrieve all valid trainers from trainer_pages
    cursor.execute('''
        SELECT user_id AS id, full_name, credentials, training_style
        FROM trainer_pages
        ORDER BY full_name ASC
    ''')
    trainers = cursor.fetchall()

    conn.close()

    # Render the viewTrainers.html template with trainers and mapping status
    return render_template(
        'viewTrainers.html',
        trainers=trainers,
        athlete_has_mapping=athlete_has_mapping,
        athlete_trainer_id=athlete_trainer_id
    )

@app.route('/message-trainer/<int:trainer_id>/', methods=['GET'])
def message_trainer(trainer_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Debug to check trainer ID
    print(f"DEBUG: Handling trainer ID - {trainer_id}")

    # Fetch trainer details using their ID
    cursor.execute('SELECT full_name FROM trainer_pages WHERE user_id = ?', (trainer_id,))
    trainer = cursor.fetchone()

    if not trainer:
        print(f"DEBUG: Trainer with ID {trainer_id} not found.")
        flash('Trainer not found.', 'error')
        conn.close()
        return redirect(url_for('view_trainers'))

    trainer_name = trainer['full_name']
    conn.close()

    print(f"DEBUG: Found trainer - {trainer_name}")
    return render_template('messageTrainer.html', trainer_name=trainer_name)

@app.route('/send-message-trainer/<trainer_name>/', methods=['POST'])
def send_message(trainer_name):
    if 'user_id' not in session:
        return jsonify({'error': 'You need to log in to send a message.'}), 403

    # Get the user ID of the sender
    sender_id = session.get('user_id')

    # Get the message content from the form
    message_content = request.form.get('message', '').strip()

    if not message_content:
        return jsonify({'error': 'Message content cannot be empty.'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch the trainer's ID using their name, ignoring whitespace
    cursor.execute('SELECT user_id FROM trainer_pages WHERE TRIM(full_name) = TRIM(?)', (trainer_name,))
    trainer = cursor.fetchone()

    if not trainer:
        conn.close()
        return jsonify({'error': 'Trainer not found.'}), 404

    recipient_id = trainer['user_id']

    # Add the message to the database
    try:
        cursor.execute(
            'INSERT INTO messages (sender_id, recipient_id, content) VALUES (?, ?, ?)',
            (sender_id, recipient_id, message_content)
        )
        conn.commit()
        conn.close()
        return jsonify({'message': 'Message sent successfully!'}), 200
    except Exception as e:
        print(f"Error while sending the message: {e}")
        conn.close()
        return jsonify({'error': 'An error occurred while sending the message.'}), 500

@app.route('/training-request/<int:trainer_id>/', methods=['POST'])
def request_training(trainer_id):
    if 'user_id' not in session or session.get('role') != 'athlete':
        return jsonify({'error': 'Unauthorized access. Only athletes can request training.'}), 403

    athlete_id = session.get('user_id')

    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if the athlete already has a trainer
    cursor.execute('SELECT trainer_id FROM athlete_trainer_mapping WHERE athlete_id = ?', (athlete_id,))
    mapping = cursor.fetchone()

    if mapping:
        conn.close()
        return jsonify({'error': 'You already have a trainer assigned. Cannot send training requests.'}), 400

    # Check if there's already a pending request to the same trainer
    cursor.execute(
        'SELECT id FROM training_requests WHERE athlete_id = ? AND trainer_id = ? AND request_status = ?',
        (athlete_id, trainer_id, 'pending')
    )
    pending_request = cursor.fetchone()

    if pending_request:
        conn.close()
        return jsonify({'error': 'You already have a pending training request for this trainer.'}), 400

    # Add the training request to the database
    try:
        cursor.execute(
            'INSERT INTO training_requests (athlete_id, trainer_id, request_status) VALUES (?, ?, ?)',
            (athlete_id, trainer_id, 'pending')
        )
        conn.commit()
        conn.close()
        return jsonify({'message': 'Training request sent successfully!'}), 200
    except Exception as e:
        print(f"Error occurred while inserting training request: {e}")
        conn.close()
        return jsonify({'error': 'An error occurred while sending your training request.'}), 500

@app.route('/deassign-trainer/<int:trainer_id>/', methods=['POST'])
def deassign_trainer(trainer_id):
    """
    Handles de-assigning an athlete from a trainer.
    """
    if 'user_id' not in session or session.get('role') != 'athlete':
        return jsonify({'error': 'Unauthorized access.'}), 403

    athlete_id = session.get('user_id')  # Get athlete ID from session

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Verify the athlete-trainer mapping exists
        cursor.execute('''
            SELECT * FROM athlete_trainer_mapping
            WHERE athlete_id = ? AND trainer_id = ?
        ''', (athlete_id, trainer_id))
        mapping = cursor.fetchone()

        if not mapping:
            return jsonify({'error': 'Mapping not found.'}), 404

        # Delete the mapping from the database
        cursor.execute('''
            DELETE FROM athlete_trainer_mapping
            WHERE athlete_id = ? AND trainer_id = ?
        ''', (athlete_id, trainer_id))
        print(f"De-assigning trainer {trainer_id} from athlete {athlete_id}")

        conn.commit()
        print(f"Athlete {athlete_id} has been de-assigned from trainer {trainer_id}.")
        return jsonify({'message': 'De-assignment successful!'})

    except Exception as e:
        print(f"Error during de-assignment: {e}")
        conn.rollback()  # Rollback changes in case of error
        return jsonify({'error': 'An error occurred during de-assignment.'}), 500

    finally:
        conn.close()

@app.route('/goals/', methods=['GET'])
def view_goals():
    # Check if the user is logged in and their role is 'athlete'
    if 'user_id' not in session or session.get('role') != 'athlete':
        return "Access Denied", 403  # Restrict access if not an athlete

    # Retrieve the athlete's user ID from the session
    athlete_id = session.get('user_id')

    # Connect to the database
    conn = get_db_connection()
    cursor = conn.cursor()

    # Retrieve goals set for this athlete by their trainer
    cursor.execute('''
        SELECT goal_description, set_at
        FROM trainer_goals
        WHERE athlete_id = ?
        ORDER BY set_at DESC
    ''', (athlete_id,))
    
    goals = cursor.fetchall()
    conn.close()

    # Render goals.html and pass the retrieved goals
    return render_template('goals.html', goals=goals)

@app.route('/messages/')
def view_messages():
    if 'user_id' not in session or session.get('role') != 'athlete':
        return jsonify({'error': 'Unauthorized access.'}), 403
    user_id = session.get('user_id')  # Retrieve athlete's ID from session

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT messages.id, users.email AS sender_email, messages.content, messages.sent_at
        FROM messages
        JOIN users ON messages.sender_id = users.id
        WHERE messages.recipient_id = ?
        ORDER BY messages.sent_at DESC
    ''', (user_id,))
    messages = cursor.fetchall()
    print(f"Messages for user_id {user_id}: {messages}")  # Debugging: Log messages
    conn.close()

    return render_template('messages.html', messages=messages)

@app.route('/reply-athlete/<message_id>/', methods=['GET'])
def reply_athlete(message_id):
    if 'user_id' not in session or session.get('role') != 'athlete':
        return jsonify({'error': 'Unauthorized access.'}), 403

    # Fetch message details from the database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT messages.id, users.email AS sender_email
        FROM messages
        JOIN users ON messages.sender_id = users.id
        WHERE messages.id = ?
    ''', (message_id,))
    message = cursor.fetchone()
    conn.close()

    if not message:
        return "Message not found", 404

    # Render replyAthlete.html with the sender's email
    return render_template('replyAthlete.html', sender_email=message['sender_email'])

@app.route('/my-page/')
def my_page():
    # Ensure the user is logged in and is a trainer
    if 'user_id' not in session or session.get('role') != 'trainer':
        flash('Unauthorized access. This page is only accessible to trainers.', 'error')
        return redirect(url_for('login'))
    
    # Render the trainer's My Page
    return render_template('myPage.html')

@app.route('/save-trainer-page/', methods=['POST'])
def save_trainer_page():
    try:
        # Check if the user is logged in and is a trainer
        if 'user_id' not in session or session.get('role') != 'trainer':
            return jsonify({"status": "error", "message": "Unauthorized access. Only trainers can access this feature."}), 403

        # Get the data from the form
        user_id = session.get('user_id')
        name = request.form.get('name', '').strip()
        credentials = request.form.get('credentials', '').strip()
        training_style = request.form.get('trainingStyle', '').strip()

        # Validate the form data
        if not name or not credentials or not training_style:
            return jsonify({"status": "error", "message": "All fields are required to create or edit your page."}), 400

        # Save or update the trainer page in the database
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if the trainer already has an entry in the trainer_pages table
        cursor.execute('SELECT id FROM trainer_pages WHERE user_id = ?', (user_id,))
        existing_page = cursor.fetchone()

        if existing_page:
            # Update the existing page
            cursor.execute('''
                UPDATE trainer_pages
                SET full_name = ?, credentials = ?, training_style = ?, created_at = CURRENT_TIMESTAMP
                WHERE user_id = ?
            ''', (name, credentials, training_style, user_id))
            message = "Your trainer page has been updated successfully!"
        else:
            # Insert a new page
            cursor.execute('''
                INSERT INTO trainer_pages (user_id, full_name, credentials, training_style)
                VALUES (?, ?, ?, ?)
            ''', (user_id, name, credentials, training_style))
            message = "Your trainer page has been created successfully!"

        # Commit the changes and close the connection
        conn.commit()
        conn.close()

        # Return a JSON response for success
        return jsonify({"status": "success", "message": message}), 200

    except Exception as error:
        # Handle unexpected errors
        return jsonify({"status": "error", "message": f"An unexpected error occurred: {error}"}), 500

@app.route('/my-athletes/')
def my_athletes():
    if 'user_id' not in session or session.get('role') != 'trainer':
        return "Access Denied", 403

    user_id = session['user_id']
    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        query = '''
            SELECT users.email, athlete_trainer_mapping.assigned_at
            FROM athlete_trainer_mapping
            JOIN users ON athlete_trainer_mapping.athlete_id = users.id
            WHERE athlete_trainer_mapping.trainer_id = ?
        '''
        cursor.execute(query, (user_id,))
        athletes = cursor.fetchall()

        athlete_list = [
            {'email': row[0], 'assigned_since': row[1]}
            for row in athletes
        ]

    finally:
        cursor.close()
        connection.close()

    return render_template('myAthletes.html', athletes=athlete_list)

@app.route('/message-athlete/<athlete_email>')
def message_athlete(athlete_email):
    if 'user_id' not in session or session.get('role') != 'trainer':
        return "Access Denied", 403

    # Render the messageAthlete.html template and pass the athlete's email
    return render_template('messageAthlete.html', athlete_email=athlete_email)

@app.route('/send-message-athlete/', methods=['POST'])
def send_message_athlete():
    try:
        # Parse JSON data from the request
        data = request.get_json()
        print("Received data:", data)  # Debugging: Log incoming data

        # Validate incoming data
        if not data or 'message_content' not in data or 'recipient_email' not in data:
            print("Invalid or missing data:", data)  # Log the invalid data
            return jsonify({"error": "Invalid or missing data"}), 400

        # Extract data
        message_content = data['message_content']
        recipient_email = data['recipient_email']

        # Get the sender's user ID from the session
        sender_id = session.get('user_id')
        if not sender_id:
            print("User not logged in")  # Log missing session data
            return jsonify({"error": "User not logged in"}), 401

        # Connect to the database
        conn = get_db_connection()
        cursor = conn.cursor()

        # Retrieve recipient ID using recipient email
        cursor.execute('SELECT id FROM users WHERE email = ?', (recipient_email,))
        recipient = cursor.fetchone()
        if not recipient:
            print("Recipient not found for email:", recipient_email)  # Log missing recipient
            conn.close()
            return jsonify({"error": "Recipient not found"}), 404

        recipient_id = recipient['id']

        # Insert the message into the messages table
        try:
            cursor.execute('''
                INSERT INTO messages (sender_id, recipient_id, content)
                VALUES (?, ?, ?)
            ''', (sender_id, recipient_id, message_content))
            conn.commit()
            print("Message inserted successfully")  # Log successful insertion
        except Exception as db_error:
            print("Database error:", db_error)  # Log the database error
            return jsonify({"error": "Database error occurred"}), 500
        finally:
            conn.close()

        # Respond with success
        return jsonify({"message": "Message sent successfully!"}), 200

    except Exception as error:
        print("Unhandled error:", error)  # Log the unexpected error
        return jsonify({"error": "An unexpected error occurred"}), 500

@app.route('/messages-requests/')
def messages_requests():
    if 'user_id' not in session or session['role'] != 'trainer':
        flash('Unauthorized access.', 'error')
        return redirect(url_for('login'))

    trainer_id = session['user_id']
    messages_and_requests = get_trainer_messages_requests(trainer_id)
    return render_template('messagesRequests.html', messages_and_requests=messages_and_requests)

def get_trainer_messages_requests(trainer_id):
    """
    Retrieve all messages and training requests for the trainer.

    :param trainer_id: The ID of the trainer.
    :return: A list of dictionaries containing messages and training requests.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # Retrieve messages sent to the trainer
    cursor.execute('''
        SELECT
            messages.id AS id,
            users.email AS from_user,
            'Message' AS type,
            messages.content AS content,
            messages.sent_at AS timestamp
        FROM messages
        JOIN users ON messages.sender_id = users.id
        WHERE messages.recipient_id = ?
        ORDER BY messages.sent_at DESC
    ''', (trainer_id,))
    messages = cursor.fetchall()

    # Retrieve training requests sent to the trainer
    cursor.execute('''
        SELECT
            training_requests.id AS id,
            users.email AS from_user,
            'Request' AS type,
            training_requests.request_status AS content,
            training_requests.requested_at AS timestamp
        FROM training_requests
        JOIN users ON training_requests.athlete_id = users.id
        WHERE training_requests.trainer_id = ?
        ORDER BY training_requests.requested_at DESC
    ''', (trainer_id,))
    requests = cursor.fetchall()

    conn.close()

    # Combine messages and requests into a single list and sort by timestamp
    messages_and_requests = [
        {
            'id': item['id'],
            'from_user': item['from_user'],
            'type': item['type'],
            'content': item['content'],
            'timestamp': item['timestamp']
        } for item in messages + requests
    ]

    # Sort the combined list by timestamp (descending)
    messages_and_requests.sort(key=lambda x: x['timestamp'], reverse=True)

    return messages_and_requests

@app.route('/accept-request/<int:request_id>/', methods=['POST'])
def accept_request(request_id):
    """
    Handles accepting a training request.
    """
    if 'user_id' not in session or session['role'] != 'trainer':
        return jsonify({'error': 'Unauthorized access.'}), 403

    trainer_id = session['user_id']  # Get trainer ID from session

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Retrieve athlete ID associated with the request
        cursor.execute('''
            SELECT athlete_id FROM training_requests
            WHERE id = ? AND trainer_id = ? AND request_status = 'pending'
        ''', (request_id, trainer_id))
        result = cursor.fetchone()

        if not result:
            print(f"Request {request_id} not found or unauthorized.")
            return jsonify({'error': 'Request not found or unauthorized.'}), 404

        athlete_id = result['athlete_id']  # Safely assign athlete_id

        # Update the request status to "accepted"
        cursor.execute('''
            UPDATE training_requests
            SET request_status = 'accepted'
            WHERE id = ?
        ''', (request_id,))
        print(f"Request {request_id} accepted by trainer {trainer_id}")

        # Add the athlete-trainer mapping to the database
        cursor.execute('''
            INSERT INTO athlete_trainer_mapping (athlete_id, trainer_id)
            VALUES (?, ?)
        ''', (athlete_id, trainer_id))
        print(f"Athlete {athlete_id} is now mapped to trainer {trainer_id}")

        conn.commit()
        return jsonify({'message': 'Training request accepted successfully!'})

    except Exception as e:
        print(f"Error accepting request: {e}")
        conn.rollback()  # Rollback changes in case of error
        return jsonify({'error': 'An error occurred while processing the request.'}), 500

    finally:
        conn.close()

@app.route('/decline-request/<int:request_id>/', methods=['POST'])
def decline_request(request_id):
    """
    Handles declining a training request.
    """
    # Ensure the user is a logged-in trainer
    if 'user_id' not in session or session['role'] != 'trainer':
        return jsonify({'error': 'Unauthorized access.'}), 403

    trainer_id = session['user_id']  # Get trainer ID from session

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Verify the request belongs to the trainer
        cursor.execute('''
            SELECT id FROM training_requests
            WHERE id = ? AND trainer_id = ? AND request_status = 'pending'
        ''', (request_id, trainer_id))
        result = cursor.fetchone()
        print(f"Request ID: {request_id}, Trainer ID: {trainer_id}")

        if not result:
            return jsonify({'error': 'Request not found or already processed.'}), 404

        # Update the status of the request to 'declined'
        cursor.execute('''
            UPDATE training_requests
            SET request_status = 'declined'
            WHERE id = ?
        ''', (request_id,))
        print(f"Request {request_id} declined by trainer {trainer_id}")

        conn.commit()
        return jsonify({'message': 'Training request declined successfully!'})

    except Exception as e:
        print(f"Error declining request: {e}")
        conn.rollback()  # Rollback any changes in case of error
        return jsonify({'error': 'An error occurred while processing the request.'}), 500

    finally:
        conn.close()

@app.route('/reply-trainer/<message_id>/', methods=['GET'])
def reply_trainer(message_id):
    # Ensure the user is a logged-in trainer
    if 'user_id' not in session or session['role'] != 'trainer':
        return jsonify({'error': 'Unauthorized access.'}), 403
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Query to get the sender's email using sender_id
    cursor.execute('''
        SELECT u.email
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE m.id = ?
    ''', (message_id,))
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        return "Message not found", 404
    
    # Pass sender's email to the replyTrainer.html template
    sender_email = result['email']
    return render_template('replyTrainer.html', sender_email=sender_email)

from flask import request, jsonify

@app.route('/send-reply/', methods=['POST'])
def send_reply():
    try:
        # Parse JSON data from the request
        data = request.get_json()
        print("Received data:", data)  # Debugging: Log incoming data

        # Validate incoming data
        if not data or 'reply_message' not in data or 'recipient_email' not in data:
            print("Invalid or missing data:", data)  # Log the invalid data
            return jsonify({"error": "Invalid or missing data"}), 400

        # Extract data
        reply_content = data['reply_message']
        recipient_email = data['recipient_email']

        # Get the sender's user ID from the session
        sender_id = session.get('user_id')
        if not sender_id:
            print("User not logged in")  # Log missing session data
            return jsonify({"error": "User not logged in"}), 401

        # Connect to the database
        conn = get_db_connection()
        cursor = conn.cursor()

        # Retrieve recipient ID using recipient email
        cursor.execute('SELECT id FROM users WHERE email = ?', (recipient_email,))
        recipient = cursor.fetchone()
        if not recipient:
            print("Recipient not found for email:", recipient_email)  # Log missing recipient
            conn.close()
            return jsonify({"error": "Recipient not found"}), 404

        recipient_id = recipient['id']

        # Insert the reply into the messages table
        try:
            cursor.execute('''
                INSERT INTO messages (sender_id, recipient_id, content)
                VALUES (?, ?, ?)
            ''', (sender_id, recipient_id, reply_content))
            conn.commit()
            print("Reply inserted successfully")  # Log successful insertion
        except Exception as db_error:
            print("Database error:", db_error)  # Log the database error
            return jsonify({"error": "Database error occurred"}), 500
        finally:
            conn.close()

        # Respond with success
        return jsonify({"message": "Reply sent successfully!"}), 200

    except Exception as error:
        print("Unhandled error:", error)  # Log the unexpected error
        return jsonify({"error": "An unexpected error occurred"}), 500

@app.route('/set-goals/<athlete_email>', methods=['GET'])
def set_goals(athlete_email):
    if 'user_id' not in session or session.get('role') != 'trainer':
        return "Access Denied", 403

    # Render the setGoals.html template and pass the athlete's email
    return render_template('setGoals.html', athlete_email=athlete_email)

@app.route('/save-athlete-goals/', methods=['POST'])
def save_athlete_goals():
    try:
        # Retrieve form data from the request
        goals = request.form.get('goals')
        athlete_email = request.form.get('athlete_email')
        
        # Validate the form data
        if not goals or not athlete_email:
            return jsonify({"error": "Missing goals or athlete email"}), 400

        # Get the trainer's user ID from the session
        trainer_id = session.get('user_id')
        if not trainer_id:
            return jsonify({"error": "User not logged in"}), 401

        # Connect to the database
        conn = get_db_connection()
        cursor = conn.cursor()

        # Retrieve athlete ID using the provided email
        cursor.execute('SELECT id FROM users WHERE email = ?', (athlete_email,))
        athlete = cursor.fetchone()
        if not athlete:
            conn.close()
            return jsonify({"error": "Athlete not found"}), 404

        athlete_id = athlete['id']

        # Insert the trainer's goals using the correct column name ("goal_description")
        try:
            cursor.execute('''
                INSERT INTO trainer_goals (trainer_id, athlete_id, goal_description, set_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ''', (trainer_id, athlete_id, goals))
            conn.commit()
        except Exception as db_error:
            return jsonify({"error": f"Database error occurred: {db_error}"}), 500
        finally:
            conn.close()

        # Instead of performing a server-side redirect, return JSON.
        return jsonify({"message": "Goals saved successfully!"}), 200

    except Exception as error:
        return jsonify({"error": f"An unexpected error occurred: {error}"}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')