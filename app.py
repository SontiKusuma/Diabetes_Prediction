from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import joblib
import pandas as pd
import numpy as np
import os
from datetime import datetime
import webbrowser
import threading
import time
import sqlite3

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here_change_me'
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    phone = db.Column(db.String(10), unique=True, nullable=False)  # 10-digit phone number
    password = db.Column(db.String(150), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def load_diabetes_model():
    try:
        model_path = os.path.join(os.path.dirname(__file__), "XGBoost_Diabetes_Model.joblib")
        if not os.path.exists(model_path):
            print(f"❌ Model file not found at: {model_path}")
            return None
        model = joblib.load(model_path)
        print("✅ Diabetes model loaded successfully!")
        return model
    except Exception as e:
        print(f"❌ Error loading model: {e}")
        return None

diabetes_model = load_diabetes_model()

def add_phone_column_to_existing_users():
    """Add phone column to existing users table if it doesn't exist"""
    try:
        # Check if phone column exists
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Get table info
        cursor.execute("PRAGMA table_info(user)")
        columns = cursor.fetchall()
        column_names = [col[1] for col in columns]
        
        if 'phone' not in column_names:
            print("🔄 Adding 'phone' column to existing users table...")
            cursor.execute("ALTER TABLE user ADD COLUMN phone VARCHAR(10)")
            conn.commit()
            print("✅ Added 'phone' column successfully!")
        else:
            print("✅ 'phone' column already exists in the database")
            
        conn.close()
    except Exception as e:
        print(f"⚠️  Could not add phone column: {e}")

def init_database():
    """Initialize database with proper schema"""
    with app.app_context():
        # First check if we need to add phone column to existing DB
        add_phone_column_to_existing_users()
        
        # Now create all tables (this won't affect existing tables)
        db.create_all()
        
        # Get the absolute database path
        db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")
        
        if os.path.exists(db_path):
            print(f"✅ Database exists at: {db_path}")
            file_size = os.path.getsize(db_path)
            print(f"📊 Database size: {file_size / 1024:.2f} KB")
        else:
            print(f"✅ Created new database at: {db_path}")
        
        # Try to count users (handle case where phone column might still cause issues)
        try:
            user_count = User.query.count()
            print(f"👥 Total registered users: {user_count}")
            
            # Show some user info if there are users
            if user_count > 0:
                users = User.query.limit(5).all()
                print("\n📋 Sample of registered users:")
                for user in users:
                    print(f"  - {user.username} ({user.email}) - Phone: {user.phone if user.phone else 'Not set'}")
        except Exception as e:
            print(f"⚠️  Could not count users: {e}")
            print("💡 Try deleting the users.db file and restarting the application")
        
        # Show database information
        print(f"\n📁 To open database in DB Browser:")
        print(f"1. Open DB Browser for SQLite")
        print(f"2. Click 'Open Database'")
        print(f"3. Navigate to: {db_path}")
        print(f"4. Click 'Browse Data' tab")
        print(f"5. Select 'user' table from dropdown")

@app.route('/')
def home():
    return render_template("home.html")

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        phone = request.form.get('phone', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Store the form data to repopulate if there's an error
        form_data = {
            'username': username,
            'email': email,
            'phone': phone
        }
        
        # Basic validation
        errors = []
        
        # Check username
        if not username:
            errors.append("Username is required")
        elif len(username) < 3:
            errors.append("Username must be at least 3 characters")
        else:
            # Check if username already exists
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                errors.append("Username already exists! Please choose a different username.")
        
        # Check email
        if not email:
            errors.append("Email is required")
        elif '@' not in email or '.' not in email.split('@')[-1]:
            errors.append("Please enter a valid email address")
        else:
            # Check if email already exists
            existing_email = User.query.filter_by(email=email).first()
            if existing_email:
                errors.append("Email already registered! Please use a different email or login.")
        
        # Check phone number
        if not phone:
            errors.append("Phone number is required")
        elif not phone.isdigit():
            errors.append("Phone number must contain only digits")
        elif len(phone) != 10:
            errors.append("Phone number must be exactly 10 digits")
        else:
            # Check if phone number already exists
            existing_phone = User.query.filter_by(phone=phone).first()
            if existing_phone:
                errors.append("Phone number already registered! Please use a different phone number or login.")
        
        # Check password
        if not password:
            errors.append("Password is required")
        elif len(password) < 6:
            errors.append("Password must be at least 6 characters")
        elif password != confirm_password:
            errors.append("Passwords do not match")
        
        # If there are errors, show them and return to form with data
        if errors:
            for error in errors:
                flash(error, "danger")
            return render_template("signup.html", form_data=form_data)
        
        # All validations passed, create user
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, phone=phone, password=hashed_pw)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash("✅ Signup successful! Please login.", "success")
            print(f"✅ User '{username}' registered successfully with email: {email} and phone: {phone}")
            return redirect(url_for('login'))
        except Exception as e:
            print(f"Database error: {e}")
            db.session.rollback()
            flash("An error occurred during registration. Please try again.", "danger")
            return render_template("signup.html", form_data=form_data)
    
    # GET request - show empty form
    return render_template("signup.html", form_data={})

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_input = request.form['login_input'].strip()
        password = request.form['password']
        
        # Try to find user by username, email, or phone
        user = None
        
        # Check if input looks like a phone number (all digits, length 10)
        if login_input.isdigit() and len(login_input) == 10:
            user = User.query.filter_by(phone=login_input).first()
            print(f"🔍 Searching by phone: {login_input}")
        
        # If not found by phone, try email
        if not user and '@' in login_input:
            user = User.query.filter_by(email=login_input.lower()).first()
            print(f"🔍 Searching by email: {login_input}")
        
        # If not found by email, try username
        if not user:
            user = User.query.filter_by(username=login_input).first()
            print(f"🔍 Searching by username: {login_input}")
        
        # Check if user was found and password is correct
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash(f"Welcome back, {user.username}!", "success")
            print(f"✅ User '{user.username}' logged in successfully")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials. Please check your username/email/phone and password.", "danger")
            return redirect(url_for('login'))
    
    return render_template("login.html")

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template("dashboard.html", name=current_user.username, user=current_user)

@app.route('/profile')
@login_required
def profile():
    return render_template("profile.html", user=current_user)

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if not check_password_hash(current_user.password, current_password):
            flash("Current password is incorrect", "danger")
            return redirect(url_for('change_password'))
        
        if new_password != confirm_password:
            flash("New passwords do not match", "danger")
            return redirect(url_for('change_password'))
        
        if check_password_hash(current_user.password, new_password):
            flash("New password must be different from current password", "danger")
            return redirect(url_for('change_password'))
        
        current_user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
        db.session.commit()
        flash("Password changed successfully!", "success")
        return redirect(url_for('profile'))
    
    return render_template("change_password.html")

@app.route('/predict', methods=['POST'])
@login_required
def predict_diabetes():
    if diabetes_model is None:
        return jsonify({'error': 'Prediction model not available.'}), 500
    
    try:
        data = request.get_json()
        features = [
            float(data['gender']),
            float(data['age']),
            float(data['hypertension']),
            float(data['heart_disease']),
            float(data['smoking_history']),
            float(data['bmi']),
            float(data['HbA1c_level']),
            float(data['blood_glucose_level'])
        ]
        
        feature_names = ['gender', 'age', 'hypertension', 'heart_disease', 
                        'smoking_history', 'bmi', 'HbA1c_level', 'blood_glucose_level']
        input_data = pd.DataFrame([features], columns=feature_names)
        
        prediction = diabetes_model.predict(input_data)[0]
        probability = diabetes_model.predict_proba(input_data)[0][1]
        
        result = {
            'prediction': int(prediction),
            'probability': float(probability),
            'message': 'High risk of diabetes' if prediction == 1 else 'Low risk of diabetes'
        }
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': f'Prediction failed: {str(e)}'}), 400

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out successfully.", "info")
    return redirect(url_for('login'))

def main():
    # Initialize database
    init_database()
    
    print("\n" + "="*60)
    print("🚀 Diabetes Detection Application")
    print("="*60)
    print("🌐 Application will be available at: http://127.0.0.1:5000")
    print("\n📋 Available routes:")
    print("  - /           -> Home page")
    print("  - /signup     -> Signup page (with phone number)")
    print("  - /login      -> Login page (username/email/phone)")
    print("  - /dashboard  -> User dashboard")
    print("  - /profile    -> User profile")
    print("  - /logout     -> Logout")
    print("="*60 + "\n")
    
    # Start browser in a separate thread
    def start_browser():
        time.sleep(2.5)  # Wait a bit longer for Flask to fully start
        try:
            webbrowser.open_new('http://127.0.0.1:5000/')
            print("✅ Browser opened successfully!")
            print("💡 If browser doesn't open, manually go to: http://127.0.0.1:5000")
        except Exception as e:
            print(f"⚠️  Could not open browser automatically: {e}")
            print("⚠️  Please manually navigate to: http://127.0.0.1:5000")
    
    # Start the browser thread
    browser_thread = threading.Thread(target=start_browser)
    browser_thread.daemon = True
    browser_thread.start()
    
    # Run the Flask app
    print("🔄 Starting Flask server...")
    app.run(debug=True, host='127.0.0.1', port=5000, use_reloader=False)

if __name__ == '__main__':
    main()