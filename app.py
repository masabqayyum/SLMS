import os
import shutil
import pyotp
import smtplib
import ssl
from email.message import EmailMessage
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import datetime, timedelta
import secrets
from functools import wraps
import logging
import base64
import json
from flask_migrate import Migrate
# Other imports at the top of the file
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

# Initialize the Flask app
app = Flask(__name__, instance_relative_config=True)

# Ensure instance folder exists for SQLite DB
os.makedirs(app.instance_path, exist_ok=True)

# Absolute path for SQLite database inside instance folder
db_path = os.path.join(app.instance_path, 'slms.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_path.replace('\\', '/')}"

# Other configs
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the database
db = SQLAlchemy(app)

# Initialize Flask-Migrate
migrate = Migrate(app, db)




# Cryptography imports for AES encryption
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Flask-WTF imports for forms
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, IntegerField, SelectField
from wtforms.validators import DataRequired, Length, Optional, NumberRange

# Initialize Flask app with instance_relative_config=True
app = Flask(__name__, instance_relative_config=True)

# Ensure instance folder exists for SQLite DB
os.makedirs(app.instance_path, exist_ok=True)

# Absolute path for SQLite database inside instance folder
db_path = os.path.join(app.instance_path, 'slms.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_path.replace('\\', '/')}"

# Other configs
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Master encryption key (in production, store this securely, not in code)
MASTER_KEY = os.environ.get('SLMS_MASTER_KEY', 'your-secure-master-key-here-32-chars!')

# Email config for SMTP
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'bilal.ahmed.ja29@gmail.com'
app.config['MAIL_PASSWORD'] = 'ngrr uxds rlai qetu'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

# ==================== AES ENCRYPTION IMPLEMENTATION ====================

class AESCipher:
    """
    Secure AES encryption/decryption class using cryptography library
    """
    
    def __init__(self, master_key=None):
        self.master_key = master_key or MASTER_KEY
        
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive a key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key
            salt=salt,
            iterations=100000,  # Recommended minimum
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    
    def encrypt(self, plaintext: str, user_specific_key: str = None) -> str:
        """
        Encrypt plaintext using AES-256-CBC
        Returns base64 encoded string containing salt:iv:ciphertext
        """
        try:
            # Generate random salt and IV
            salt = os.urandom(16)
            iv = os.urandom(16)
            
            # Use user-specific key or master key
            key_material = user_specific_key or self.master_key
            key = self._derive_key(key_material, salt)
            
            # Pad the plaintext
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext.encode()) + padder.finalize()
            
            # Encrypt
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            # Combine salt, iv, and ciphertext
            encrypted_data = {
                'salt': base64.b64encode(salt).decode('utf-8'),
                'iv': base64.b64encode(iv).decode('utf-8'),
                'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
            }
            
            return base64.b64encode(json.dumps(encrypted_data).encode()).decode('utf-8')
            
        except Exception as e:
            logging.error(f"Encryption error: {str(e)}")
            raise Exception("Encryption failed")
    
    def decrypt(self, encrypted_data: str, user_specific_key: str = None) -> str:
        """
        Decrypt AES-256-CBC encrypted data
        """
        try:
            # Decode the base64 encoded data
            decoded_data = json.loads(base64.b64decode(encrypted_data).decode('utf-8'))
            
            salt = base64.b64decode(decoded_data['salt'])
            iv = base64.b64decode(decoded_data['iv'])
            ciphertext = base64.b64decode(decoded_data['ciphertext'])
            
            # Use user-specific key or master key
            key_material = user_specific_key or self.master_key
            key = self._derive_key(key_material, salt)
            
            # Decrypt
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove padding
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            return plaintext.decode('utf-8')
            
        except Exception as e:
            logging.error(f"Decryption error: {str(e)}")
            raise Exception("Decryption failed")

# Initialize AES cipher
aes_cipher = AESCipher()

def encrypt_sensitive_data(data: str, user_key: str = None) -> str:
    """Helper function to encrypt sensitive data"""
    if not data:
        return data
    return aes_cipher.encrypt(data, user_key)

def decrypt_sensitive_data(encrypted_data: str, user_key: str = None) -> str:
    """Helper function to decrypt sensitive data"""
    if not encrypted_data:
        return encrypted_data
    try:
        return aes_cipher.decrypt(encrypted_data, user_key)
    except:
        return encrypted_data  # Return as-is if decryption fails (for backward compatibility)

# ==================== TEMPLATE FILTERS AND GLOBALS ====================

@app.template_filter('is_overdue')
def is_overdue(due_date):
    return due_date < datetime.utcnow()

@app.template_global()
def now():
    return datetime.utcnow()

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

# Logging setup
logging.basicConfig(
    filename='slms_security.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def role_required(roles):
    if isinstance(roles, str):
        roles = [roles]

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role not in roles:
                flash('Access denied. Insufficient permissions.', 'error')
                logging.warning(f'Unauthorized access attempt by user {current_user.id if current_user.is_authenticated else "Anonymous"} to {roles} endpoint')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ==================== DATABASE MODELS WITH ENCRYPTION ====================

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email_encrypted = db.Column(db.Text, nullable=False)  # Encrypted email
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='student')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    failed_login_attempts = db.Column(db.Integer, default=0)
    last_login = db.Column(db.DateTime)
    otp_secret = db.Column(db.String(16), nullable=True)
    # Relationships
    borrowed_books = db.relationship('BorrowRecord', backref='user', lazy=True)
    reservations = db.relationship('Reservation', backref='user', lazy=True)

    @property
    def email(self):
        """Decrypt email when accessed"""
        try:
            return decrypt_sensitive_data(self.email_encrypted, self.username)
        except:
            return self.email_encrypted  # Fallback for unencrypted data
    
    @email.setter
    def email(self, value):
        """Encrypt email when set"""
        self.email_encrypted = encrypt_sensitive_data(value, self.username)

# Models
class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    isbn = db.Column(db.String(20), unique=True, nullable=False)
    genre = db.Column(db.String(50))
    publication_year = db.Column(db.Integer)
    total_copies = db.Column(db.Integer, default=1)
    available_copies = db.Column(db.Integer, default=1)
    location_encrypted = db.Column(db.Text)  # Encrypted location
    added_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def location(self):
        """Decrypt location when accessed"""
        if not self.location_encrypted:
            return None
        try:
            return decrypt_sensitive_data(self.location_encrypted)
        except Exception as e:
            logging.error(f"Decryption failed for location: {e}")
            return self.location_encrypted

    @location.setter
    def location(self, value):
        """Encrypt location when set"""
        if value:
            self.location_encrypted = encrypt_sensitive_data(value)


# Define the BorrowRecord class after Book
class BorrowRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    borrow_date = db.Column(db.DateTime, default=datetime.utcnow)
    due_date = db.Column(db.DateTime, nullable=False)
    return_date = db.Column(db.DateTime)
    fine_amount = db.Column(db.Float, default=0.0)
    status = db.Column(db.String(20), default='borrowed')

    # Relationship after Book is defined
    book = db.relationship('Book', backref='borrow_records')


class Reservation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    reservation_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='active')
    
    # Relationships
    book = db.relationship('Book', backref='reservations')

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(100), nullable=False)
    details_encrypted = db.Column(db.Text)  # Encrypted details
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address_encrypted = db.Column(db.Text)  # Encrypted IP address
    
    @property
    def details(self):
        """Decrypt details when accessed"""
        if not self.details_encrypted:
            return None
        try:
            return decrypt_sensitive_data(self.details_encrypted)
        except:
            return self.details_encrypted
    
    @details.setter
    def details(self, value):
        """Encrypt details when set"""
        if value:
            self.details_encrypted = encrypt_sensitive_data(value)
    
    @property
    def ip_address(self):
        """Decrypt IP address when accessed"""
        if not self.ip_address_encrypted:
            return None
        try:
            return decrypt_sensitive_data(self.ip_address_encrypted)
        except:
            return self.ip_address_encrypted
    
    @ip_address.setter
    def ip_address(self, value):
        """Encrypt IP address when set"""
        if value:
            self.ip_address_encrypted = encrypt_sensitive_data(value)

class SystemSetting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False)
    value_encrypted = db.Column(db.Text, nullable=False)  # Encrypted value
    
    @property
    def value(self):
        """Decrypt value when accessed"""
        try:
            return decrypt_sensitive_data(self.value_encrypted)
        except:
            return self.value_encrypted
    
    @value.setter
    def value(self, val):
        """Encrypt value when set"""
        self.value_encrypted = encrypt_sensitive_data(val)

# ==================== FORMS ====================

class SettingsForm(FlaskForm):
    site_name = StringField('Site Name', validators=[DataRequired()])
    submit = SubmitField('Save')

class AddBookForm(FlaskForm):
    title = StringField('Book Title', validators=[DataRequired(), Length(max=200)])
    author = StringField('Author', validators=[DataRequired(), Length(max=100)])
    isbn = StringField('ISBN', validators=[DataRequired(), Length(max=20)])
    genre = SelectField('Genre', choices=[
        ('', 'Select Genre'),
        ('Fiction', 'Fiction'),
        ('Non-Fiction', 'Non-Fiction'),
        ('Science', 'Science'),
        ('Technology', 'Technology'),
        ('History', 'History'),
        ('Biography', 'Biography'),
        ('Mystery', 'Mystery'),
        ('Romance', 'Romance'),
        ('Fantasy', 'Fantasy'),
        ('Thriller', 'Thriller')
    ], validators=[Optional()])
    publication_year = IntegerField('Publication Year', validators=[Optional(), NumberRange(min=1000, max=2024)])
    total_copies = IntegerField('Total Copies', validators=[DataRequired(), NumberRange(min=1)])
    location = StringField('Location', validators=[Optional(), Length(max=50)])
    submit = SubmitField('Add Book')

# ==================== HELPER FUNCTIONS ====================

def send_otp_email(to_email, otp_code):
    """Send OTP email with encryption logging"""
    try:
        msg = EmailMessage()
        msg['Subject'] = 'Your SLMS Login OTP Code'
        msg['From'] = app.config['MAIL_USERNAME']
        msg['To'] = to_email
        msg.set_content(f'Your OTP code is: {otp_code}\nIt will expire in 5 minutes.')

        with smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT']) as smtp:
            smtp.starttls()
            smtp.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
            smtp.send_message(msg)
        
        # Log OTP send event (without exposing the OTP)
        log_entry = AuditLog(
            action='OTP Email Sent',
            details=f'OTP sent to email ending in {to_email[-10:]}',
            ip_address=request.remote_addr if request else 'system'
        )
        db.session.add(log_entry)
        db.session.commit()
        
        return True
    except Exception as e:
        logging.error(f"Error sending OTP email: {e}")
        return False

def create_audit_log(user_id, action, details, ip_address):
    """Create encrypted audit log entry"""
    log_entry = AuditLog(
        user_id=user_id,
        action=action,
        details=details,
        ip_address=ip_address
    )
    db.session.add(log_entry)
    db.session.commit()

# ==================== ROUTES ====================

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Validation
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return render_template('register.html')

        if len(password) < 8:
            flash('Password must be at least 8 characters long!', 'error')
            return render_template('register.html')

        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'error')
            return render_template('register.html')

        # Check if email exists (need to decrypt existing emails to compare)
        existing_users = User.query.all()
        for user in existing_users:
            try:
                if user.email == email:
                    flash('Email already registered!', 'error')
                    return render_template('register.html')
            except:
                continue  # Skip if decryption fails

        # Create new user with encrypted data
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(
            username=username,
            password_hash=password_hash,
            role='student'
        )
        new_user.email = email  # This will be encrypted automatically
        
        db.session.add(new_user)
        db.session.commit()

        # Create encrypted audit log
        create_audit_log(
            new_user.id,
            'User Registration',
            f'New user registered: {username}',
            request.remote_addr
        )

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and user.is_active and bcrypt.check_password_hash(user.password_hash, password):
            # Reset failed attempts on successful login
            user.failed_login_attempts = 0
            user.last_login = datetime.utcnow()
            db.session.commit()

            # If admin or librarian, skip OTP
            if user.role in ['admin', 'librarian']:
                login_user(user)
                create_audit_log(
                    user.id,
                    'Successful Login',
                    f'User {username} logged in successfully',
                    request.remote_addr
                )
                flash(f'Logged in as {user.role.title()}.', 'success')
                return redirect(url_for('dashboard'))

            # For students, require OTP
            otp_secret = pyotp.random_base32()
            totp = pyotp.TOTP(otp_secret, interval=300)
            otp_code = totp.now()

            session['otp_user_id'] = user.id
            session['otp_secret'] = otp_secret
            session['otp_expiry'] = (datetime.utcnow() + timedelta(minutes=5)).timestamp()

            if send_otp_email(user.email, otp_code):
                flash('OTP sent to your registered email. Please enter it below.', 'info')
                return redirect(url_for('verify_otp'))
            else:
                flash('Failed to send OTP email. Try again.', 'error')

        else:
            # Handle failed login
            if user:
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= 5:
                    user.is_active = False
                    flash('Account locked due to multiple failed login attempts. Contact administrator.', 'error')
                db.session.commit()

            # Log failed attempt
            create_audit_log(
                None,
                'Failed Login Attempt',
                f'Failed login attempt for username: {username}',
                request.remote_addr
            )

            flash('Invalid username or password!', 'error')

    return render_template('login.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if 'otp_user_id' not in session or 'otp_secret' not in session:
        flash('Session expired or invalid. Please login again.', 'error')
        return redirect(url_for('login'))

    user_id = session.get('otp_user_id')
    otp_secret = session.get('otp_secret')
    expiry_ts = session.get('otp_expiry')
    user = User.query.get(user_id)

    if user.role != 'student':
        session.pop('otp_user_id', None)
        session.pop('otp_secret', None)
        session.pop('otp_expiry', None)
        return redirect(url_for('dashboard'))

    if datetime.utcnow().timestamp() > expiry_ts:
        flash('OTP expired. Please login again.', 'error')
        session.clear()
        return redirect(url_for('login'))

    if request.method == 'POST':
        input_otp = request.form['otp']
        totp = pyotp.TOTP(otp_secret, interval=300)

        if totp.verify(input_otp, valid_window=1):
            login_user(user)
            session.pop('otp_user_id', None)
            session.pop('otp_secret', None)
            session.pop('otp_expiry', None)
            
            create_audit_log(
                user.id,
                'Successful OTP Verification',
                f'User {user.username} verified OTP successfully',
                request.remote_addr
            )
            
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            create_audit_log(
                user.id,
                'Failed OTP Verification',
                f'User {user.username} failed OTP verification',
                request.remote_addr
            )
            flash('Invalid OTP. Please try again.', 'error')

    return render_template('verify_otp.html')

@app.route('/logout')
@login_required
def logout():
    create_audit_log(
        current_user.id,
        'User Logout',
        f'User {current_user.username} logged out',
        request.remote_addr
    )
    
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'student':
        return redirect(url_for('student_dashboard'))
    elif current_user.role == 'librarian':
        return redirect(url_for('librarian_dashboard'))
    elif current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    else:
        flash('Invalid user role!', 'error')
        return redirect(url_for('index'))

@app.route('/student/dashboard')
@login_required
@role_required('student')
def student_dashboard():
    borrowed_books = db.session.query(BorrowRecord, Book).join(Book).filter(
        BorrowRecord.user_id == current_user.id,
        BorrowRecord.status == 'borrowed'
    ).all()

    reservations = db.session.query(Reservation, Book).join(Book).filter(
        Reservation.user_id == current_user.id,
        Reservation.status == 'active'
    ).all()

    return render_template('student_dashboard.html',
                         borrowed_books=borrowed_books,
                         reservations=reservations)

@app.route('/student/borrowing-history')
@login_required
@role_required('student')
def borrowing_history():
    borrowed_books_history = db.session.query(BorrowRecord, Book).join(Book).filter(
        BorrowRecord.user_id == current_user.id
    ).order_by(BorrowRecord.borrow_date.desc()).all()
    
    return render_template('borrowing_history.html', borrowed_books_history=borrowed_books_history)

@app.route('/student/pay-fines', methods=['GET', 'POST'])
@login_required
@role_required('student')
def pay_fines():
    borrowed_books = BorrowRecord.query.filter_by(user_id=current_user.id, status='borrowed').all()
    total_fine = sum(book.fine_amount for book in borrowed_books if book.fine_amount > 0)

    if request.method == 'POST':
        for record in borrowed_books:
            record.fine_amount = 0
        db.session.commit()

        create_audit_log(
            current_user.id,
            'Fines Paid',
            f'User paid total fine of ${total_fine:.2f}',
            request.remote_addr
        )

        flash('Fines have been successfully paid!', 'success')
        return redirect(url_for('student_dashboard'))

    return render_template('pay_fines.html', total_fine=total_fine)

@app.route('/student/update-profile', methods=['GET', 'POST'])
@login_required
@role_required('student')
def update_profile():
    if request.method == 'POST':
        new_email = request.form.get('email')
        if new_email and new_email != current_user.email:
            current_user.email = new_email  # This will be encrypted
            db.session.commit()
            
            create_audit_log(
                current_user.id,
                'Profile Updated',
                'User updated email address',
                request.remote_addr
            )
            
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('student_dashboard'))
    
    return render_template('update_profile.html')

@app.route('/librarian/dashboard')
@login_required
@role_required('librarian')
def librarian_dashboard():
    overdue_books_raw = (
        db.session.query(BorrowRecord, Book, User)
        .join(Book, BorrowRecord.book_id == Book.id)
        .join(User, BorrowRecord.user_id == User.id)
        .filter(
            BorrowRecord.due_date < datetime.utcnow(),
            BorrowRecord.status == 'borrowed'
        )
        .all()
    )
    
    overdue_books = []
    for record, book, user in overdue_books_raw:
        days_overdue = (datetime.utcnow() - record.due_date).days
        overdue_books.append({
            'record': record,
            'book': book,
            'user': user,
            'days_overdue': days_overdue
        })

    recent_books = Book.query.order_by(Book.created_at.desc()).limit(5).all()

    return render_template('librarian_dashboard.html',
                         overdue_books=overdue_books,
                         recent_books=recent_books)

@app.route('/librarian/view-borrow-history')
@login_required
@role_required('librarian')
def view_borrow_history():
    borrow_history = db.session.query(BorrowRecord, Book, User).join(Book).join(User).order_by(
        BorrowRecord.borrow_date.desc()
    ).all()

    return render_template('view_borrow_history.html', borrow_history=borrow_history)

@app.route('/librarian/manage-members')
@login_required
@role_required('librarian')
def manage_members():
    students = User.query.filter_by(role='student').all()
    return render_template('manage_members.html', students=students)

@app.route('/librarian/toggle_user_status/<int:user_id>', methods=['POST'])
@login_required
@role_required('librarian')
def toggle_user_status_librarian(user_id):
    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        flash('Cannot modify your own account status.', 'error')
        return redirect(url_for('manage_members'))

    user.is_active = not user.is_active
    user.failed_login_attempts = 0
    db.session.commit()

    action = 'User Activated' if user.is_active else 'User Deactivated'
    create_audit_log(
        current_user.id,
        action,
        f'{action}: {user.username}',
        request.remote_addr
    )

    status = 'activated' if user.is_active else 'deactivated'
    flash(f'User {user.username} has been {status}.', 'success')
    return redirect(url_for('manage_members'))

@app.route('/librarian/generate_reports')
@login_required
@role_required(['librarian', 'admin'])
def generate_reports():
    total_books = Book.query.count()
    total_users = User.query.count()
    total_borrows = BorrowRecord.query.filter_by(status='borrowed').count()
    
    overdue_books_raw = (
        db.session.query(BorrowRecord, Book, User)
        .join(Book, BorrowRecord.book_id == Book.id)
        .join(User, BorrowRecord.user_id == User.id)
        .filter(BorrowRecord.due_date < datetime.utcnow(), BorrowRecord.status == 'borrowed')
        .all()
    )
    
    overdue_books = []
    for record, book, user in overdue_books_raw:
        days_overdue = (datetime.utcnow() - record.due_date).days
        overdue_books.append({
            'book_title': book.title,
            'user_username': user.username,
            'due_date': record.due_date,
            'days_overdue': days_overdue
        })

    return render_template('generate_reports.html', 
                         total_books=total_books, 
                         total_users=total_users, 
                         total_borrows=total_borrows, 
                         overdue_books=overdue_books)

@app.route('/librarian/add_book', methods=['GET', 'POST'])
@login_required
@role_required('librarian')
def add_book():
    form = AddBookForm()
    if form.validate_on_submit():
        if Book.query.filter_by(isbn=form.isbn.data).first():
            flash('Book with this ISBN already exists!', 'error')
            return render_template('add_book.html', form=form)

        new_book = Book(
            title=form.title.data,
            author=form.author.data,
            isbn=form.isbn.data,
            genre=form.genre.data,
            publication_year=form.publication_year.data,
            total_copies=form.total_copies.data,
            available_copies=form.total_copies.data,
            added_by=current_user.id
        )
        new_book.location = form.location.data  # This will be encrypted

        db.session.add(new_book)
        db.session.commit()

        create_audit_log(
            current_user.id,
            'Book Added',
            f'Added new book: {form.title.data} by {form.author.data}',
            request.remote_addr
        )

        flash('Book added successfully!', 'success')
        return redirect(url_for('librarian_dashboard'))

    return render_template('add_book.html', form=form)

@app.route('/books/delete/<int:book_id>', methods=['POST'])
@login_required
@role_required('librarian')
def delete_book(book_id):
    book = Book.query.get_or_404(book_id)

    active_borrows = BorrowRecord.query.filter_by(book_id=book_id, status='borrowed').count()
    if active_borrows > 0:
        flash('Cannot delete book that is currently borrowed by users.', 'error')
        return redirect(url_for('librarian_dashboard'))

    db.session.delete(book)
    db.session.commit()

    create_audit_log(
        current_user.id,
        'Book Deleted',
        f'Book deleted: {book.title}',
        request.remote_addr
    )

    flash(f'Book "{book.title}" has been removed successfully.', 'success')
    return redirect(url_for('librarian_dashboard'))

@app.route('/admin/dashboard')
@login_required
@role_required('admin')
def admin_dashboard():
    total_users = User.query.count()
    total_books = Book.query.count()
    active_borrows = BorrowRecord.query.filter_by(status='borrowed').count()

    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()

    return render_template('admin_dashboard.html',
                         total_users=total_users,
                         total_books=total_books,
                         active_borrows=active_borrows,
                         recent_logs=recent_logs)

@app.route('/admin/users')
@login_required
@role_required('admin')
def manage_users():
    users = User.query.all()
    return render_template('manage_users.html', users=users)

@app.route('/admin/toggle_user/<int:user_id>')
@login_required
@role_required('admin')
def toggle_user_status(user_id):
    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        flash('Cannot modify your own account status.', 'error')
        return redirect(url_for('manage_users'))

    user.is_active = not user.is_active
    user.failed_login_attempts = 0
    db.session.commit()

    action = 'User Activated' if user.is_active else 'User Deactivated'
    create_audit_log(
        current_user.id,
        action,
        f'{action}: {user.username}',
        request.remote_addr
    )

    status = 'activated' if user.is_active else 'deactivated'
    flash(f'User {user.username} has been {status}.', 'success')
    return redirect(url_for('manage_users'))

@app.route('/admin/backup', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def backup_system():
    backup_path = 'backup'
    os.makedirs(backup_path, exist_ok=True)
    backup_file = os.path.join(backup_path, f'slms_backup_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.db')

    if request.method == 'POST':
        try:
            shutil.copy(db_path, backup_file)
            
            create_audit_log(
                current_user.id,
                'System Backup Created',
                f'Database backup created: {backup_file}',
                request.remote_addr
            )
            
            flash(f'Backup created: {backup_file}', 'success')
        except Exception as e:
            flash(f'Backup failed: {str(e)}', 'error')

    backups = sorted(os.listdir(backup_path), reverse=True) if os.path.exists(backup_path) else []
    return render_template('backup_system.html', backups=backups, backup_folder=backup_path)

@app.route('/admin/backup/download/<filename>')
@login_required
@role_required('admin')
def download_backup(filename):
    backup_path = 'backup'
    filepath = os.path.join(backup_path, filename)
    if os.path.exists(filepath):
        create_audit_log(
            current_user.id,
            'Backup Downloaded',
            f'Downloaded backup file: {filename}',
            request.remote_addr
        )
        return send_file(filepath, as_attachment=True)
    else:
        flash('Backup file not found.', 'error')
        return redirect(url_for('backup_system'))

@app.route('/admin/reports')
@login_required
@role_required('admin')
def system_reports():
    total_borrows = BorrowRecord.query.count()
    overdue_borrows = BorrowRecord.query.filter(
        BorrowRecord.due_date < datetime.utcnow(), 
        BorrowRecord.status == 'borrowed'
    ).count()
    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(20).all()

    return render_template('system_reports.html',
                         total_borrows=total_borrows,
                         overdue_borrows=overdue_borrows,
                         recent_logs=recent_logs)

@app.route('/admin/settings', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def system_settings():
    site_name_setting = SystemSetting.query.filter_by(key='site_name').first()
    if not site_name_setting:
        site_name_setting = SystemSetting(key='site_name', value='SLMS')
        db.session.add(site_name_setting)
        db.session.commit()

    form = SettingsForm(site_name=site_name_setting.value)
    if form.validate_on_submit():
        site_name_setting.value = form.site_name.data  # This will be encrypted
        db.session.commit()
        
        create_audit_log(
            current_user.id,
            'System Settings Updated',
            'Site name setting updated',
            request.remote_addr
        )
        
        flash('Settings updated successfully.', 'success')
        return redirect(url_for('system_settings'))

    return render_template('system_settings.html', form=form)

@app.route('/books/search')
@login_required
def search_books():
    query = request.args.get('q', '')
    genre = request.args.get('genre', '')

    books_query = Book.query

    if query:
        books_query = books_query.filter(
            (Book.title.contains(query)) |
            (Book.author.contains(query)) |
            (Book.isbn.contains(query))
        )

    if genre:
        books_query = books_query.filter(Book.genre == genre)

    books = books_query.all()
    genres = db.session.query(Book.genre).distinct().all()

    return render_template('search_books.html', books=books, genres=genres, query=query, selected_genre=genre)

@app.route('/books/borrow/<int:book_id>')
@login_required
@role_required('student')
def borrow_book(book_id):
    book = Book.query.get_or_404(book_id)

    # Decrypt the location or any encrypted field used by the book
    try:
        location = book.location  # This will trigger decryption
    except Exception as e:
        flash(f"Error during decryption: {e}", 'error')
        return redirect(url_for('search_books'))

    if book.available_copies <= 0:
        flash('Book is not available for borrowing.', 'error')
        return redirect(url_for('search_books'))

    existing_borrow = BorrowRecord.query.filter_by(
        user_id=current_user.id,
        book_id=book_id,
        status='borrowed'
    ).first()

    if existing_borrow:
        flash('You have already borrowed this book.', 'error')
        return redirect(url_for('search_books'))

    due_date = datetime.utcnow() + timedelta(days=14)
    borrow_record = BorrowRecord(
        user_id=current_user.id,
        book_id=book_id,
        due_date=due_date
    )

    book.available_copies -= 1

    db.session.add(borrow_record)
    db.session.commit()

    create_audit_log(
        current_user.id,
        'Book Borrowed',
        f'User borrowed book: {book.title}',
        request.remote_addr
    )

    flash(f'Successfully borrowed "{book.title}". Due date: {due_date.strftime("%Y-%m-%d")}', 'success')
    return redirect(url_for('student_dashboard'))


@app.route('/books/return/<int:record_id>')
@login_required
@role_required('student')
def return_book(record_id):
    borrow_record = BorrowRecord.query.get_or_404(record_id)

    if borrow_record.user_id != current_user.id:
        flash('Unauthorized action.', 'error')
        return redirect(url_for('student_dashboard'))

    if datetime.utcnow() > borrow_record.due_date:
        days_overdue = (datetime.utcnow() - borrow_record.due_date).days
        borrow_record.fine_amount = days_overdue * 1.0

    borrow_record.return_date = datetime.utcnow()
    borrow_record.status = 'returned'

    book = Book.query.get(borrow_record.book_id)
    book.available_copies += 1

    db.session.commit()

    create_audit_log(
        current_user.id,
        'Book Returned',
        f'User returned book: {book.title}',
        request.remote_addr
    )

    if borrow_record.fine_amount > 0:
        flash(f'Book returned successfully. Fine: ${borrow_record.fine_amount:.2f}', 'warning')
    else:
        flash('Book returned successfully!', 'success')

    return redirect(url_for('student_dashboard'))

@app.route('/extend-session', methods=['POST'])
@login_required
def extend_session():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=30)

    create_audit_log(
        current_user.id,
        'Session Extended',
        f'User {current_user.username} extended session',
        request.remote_addr
    )

    return jsonify({'status': 'success', 'message': 'Session extended'})

@app.route('/api/security-log', methods=['POST'])
@login_required
def log_security_event():
    data = request.get_json()

    create_audit_log(
        current_user.id if current_user.is_authenticated else None,
        f"Security Event: {data.get('event', 'Unknown')}",
        data.get('details', ''),
        request.remote_addr
    )

    return jsonify({'status': 'logged'})

# ==================== ENCRYPTION MANAGEMENT ROUTES ====================

@app.route('/admin/encryption-status')
@login_required
@role_required('admin')
def encryption_status():
    """Display encryption status and statistics"""
    total_users = User.query.count()
    total_books = Book.query.count()
    total_logs = AuditLog.query.count()
    
    # Test encryption/decryption
    test_data = "Test encryption data"
    try:
        encrypted = aes_cipher.encrypt(test_data)
        decrypted = aes_cipher.decrypt(encrypted)
        encryption_working = (test_data == decrypted)
    except:
        encryption_working = False
    
    return render_template('encryption_status.html',
                         total_users=total_users,
                         total_books=total_books,
                         total_logs=total_logs,
                         encryption_working=encryption_working)

@app.route('/admin/migrate-encryption', methods=['POST'])
@login_required
@role_required('admin')
def migrate_encryption():
    """Migrate existing unencrypted data to encrypted format"""
    try:
        migrated_count = 0
        
        # Migrate users with unencrypted emails
        users = User.query.all()
        for user in users:
            # Check if email needs migration (simple heuristic)
            if user.email_encrypted and '@' in user.email_encrypted and len(user.email_encrypted) < 100:
                # Looks like unencrypted email, migrate it
                old_email = user.email_encrypted
                user.email = old_email  # This will encrypt it
                migrated_count += 1
        
        # Migrate books with unencrypted locations
        books = Book.query.all()
        for book in books:
            if book.location_encrypted and len(book.location_encrypted) < 100 and 'Section' in book.location_encrypted:
                # Looks like unencrypted location, migrate it
                old_location = book.location_encrypted
                book.location = old_location  # This will encrypt it
                migrated_count += 1
        
        db.session.commit()
        
        create_audit_log(
            current_user.id,
            'Data Migration',
            f'Migrated {migrated_count} records to encrypted format',
            request.remote_addr
        )
        
        flash(f'Data migration completed! Migrated {migrated_count} records.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Migration failed: {str(e)}', 'error')
    
    return redirect(url_for('encryption_status'))

# ==================== DATABASE INITIALIZATION ====================

def init_database():
    with app.app_context():
        db.create_all()

        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin_password = bcrypt.generate_password_hash('admin123').decode('utf-8')
            admin_user = User(
                username='admin',
                password_hash=admin_password,
                role='admin'
            )
            admin_user.email = 'admin@slms.com'  # This will be encrypted
            db.session.add(admin_user)

            librarian_password = bcrypt.generate_password_hash('librarian123').decode('utf-8')
            librarian_user = User(
                username='librarian',
                password_hash=librarian_password,
                role='librarian'
            )
            librarian_user.email = 'librarian@slms.com'  # This will be encrypted
            db.session.add(librarian_user)

            # Sample books with encrypted locations
            sample_books = [
                {
                    'title': 'Introduction to Cybersecurity',
                    'author': 'John Smith',
                    'isbn': '978-0123456789',
                    'genre': 'Technology',
                    'publication_year': 2023,
                    'total_copies': 3,
                    'available_copies': 3,
                    'location': 'Section A, Shelf 1'
                },
                {
                    'title': 'The Great Gatsby',
                    'author': 'F. Scott Fitzgerald',
                    'isbn': '978-0743273565',
                    'genre': 'Fiction',
                    'publication_year': 1925,
                    'total_copies': 2,
                    'available_copies': 2,
                    'location': 'Section B, Shelf 3'
                },
                {
                    'title': 'A Brief History of Time',
                    'author': 'Stephen Hawking',
                    'isbn': '978-0553380163',
                    'genre': 'Science',
                    'publication_year': 1988,
                    'total_copies': 4,
                    'available_copies': 4,
                    'location': 'Section C, Shelf 5'
                },
                {
                    'title': 'The Art of War',
                    'author': 'Sun Tzu',
                    'isbn': '978-1599869773',
                    'genre': 'History',
                    'publication_year': 2005,
                    'total_copies': 1,
                    'available_copies': 1,
                    'location': 'Section D, Shelf 2'
                },
                {
                    'title': 'The Diary of a Young Girl',
                    'author': 'Anne Frank',
                    'isbn': '978-0553296983',
                    'genre': 'Biography',
                    'publication_year': 1993,
                    'total_copies': 3,
                    'available_copies': 3,
                    'location': 'Section E, Shelf 4'
                },
                {
                    'title': 'Sherlock Holmes: The Complete Novels and Stories',
                    'author': 'Arthur Conan Doyle',
                    'isbn': '978-0553212419',
                    'genre': 'Mystery',
                    'publication_year': 1986,
                    'total_copies': 2,
                    'available_copies': 2,
                    'location': 'Section F, Shelf 6'
                },
                {
                    'title': 'Pride and Prejudice',
                    'author': 'Jane Austen',
                    'isbn': '978-1503290563',
                    'genre': 'Romance',
                    'publication_year': 1813,
                    'total_copies': 3,
                    'available_copies': 3,
                    'location': 'Section G, Shelf 7'
                },
                {
                    'title': "Harry Potter and the Sorcerer's Stone",
                    'author': 'J.K. Rowling',
                    'isbn': '978-0590353427',
                    'genre': 'Fantasy',
                    'publication_year': 1997,
                    'total_copies': 5,
                    'available_copies': 5,
                    'location': 'Section H, Shelf 8'
                },
                {
                    'title': 'The Da Vinci Code',
                    'author': 'Dan Brown',
                    'isbn': '978-0307474278',
                    'genre': 'Thriller',
                    'publication_year': 2003,
                    'total_copies': 4,
                    'available_copies': 4,
                    'location': 'Section I, Shelf 9'
                },
            ]

            for book_data in sample_books:
                location = book_data.pop('location')
                book = Book(**book_data, added_by=admin_user.id)
                book.location = location  # This will be encrypted
                db.session.add(book)

            db.session.commit()
            print("Database initialized with encrypted data!")
            print("Admin credentials: username='admin', password='admin123'")
            print("Librarian credentials: username='librarian', password='librarian123'")

if __name__ == '__main__':
    init_database()
    
    # SSL context for HTTPS
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.load_cert_chain(certfile='C:/ssl_certs/server.crt', keyfile='C:/ssl_certs/server.key')
        app.run(host='0.0.0.0', port=5000, ssl_context=context, debug=True)
    except FileNotFoundError:
        print("SSL certificates not found. Running without HTTPS...")
        app.run(host='0.0.0.0', port=5000, debug=True)
