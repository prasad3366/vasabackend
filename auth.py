from flask import Blueprint, request, jsonify
import pymysql
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import logging
from config import Config

# Logging configuration
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Create Blueprint
auth_bp = Blueprint('auth', __name__)

# -------------------------
# Database connection
# -------------------------
def get_db_connection():
    try:
        conn = pymysql.connect(
            host=Config.DB_HOST,
            user=Config.DB_USERNAME,
            password=Config.DB_PASSWORD,
            database=Config.DB_NAME,
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor
        )
        return conn
    except pymysql.Error as e:
        logger.error(f"Database connection failed: {e}")
        raise

# -------------------------
# Token Verification (RAW TOKEN ONLY)
# -------------------------
def verify_customer_token(request):
    """
    Accepts ONLY raw JWT token in Authorization header.
    Rejects 'Bearer <token>'.
    Returns (payload, error_response, status_code)
    """
    auth = request.headers.get("Authorization")
    if not auth:
        return None, jsonify({"error": "Missing token"}), 401

    if auth.lower().startswith("bearer "):
        return None, jsonify({"error": "Use raw token, not Bearer"}), 401

    token = auth.strip()

    try:
        payload = jwt.decode(token, Config.SECRET_KEY, algorithms=["HS256"])
        return payload, None, None
    except jwt.ExpiredSignatureError:
        return None, jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return None, jsonify({"error": "Invalid token"}), 401


# -------------------------
# Admin Signup
# -------------------------
@auth_bp.route('/admin/signup', methods=['POST'])
def admin_signup():
    try:
        data = request.get_json()
        logger.debug(f"Admin signup data: {data}")

        username = data.get('username')
        email = data.get('email')
        phone_number = data.get('phone_number')
        password = data.get('password')
        confirm_password = data.get('confirm_password')

        if not all([username, email, phone_number, password, confirm_password]):
            return jsonify({'error': 'All fields are required'}), 400

        if password != confirm_password:
            return jsonify({'error': 'Passwords do not match'}), 400

        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400

        if '@' not in email:
            return jsonify({'error': 'Invalid email format'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        password_hash = generate_password_hash(password)

        try:
            cursor.execute("""
                INSERT INTO users (username, email, phone_number, password_hash, role_id)
                VALUES (%s, %s, %s, %s, %s)
            """, (username, email, phone_number, password_hash, 1))
            conn.commit()
            logger.info(f"Admin created: {username}")
            return jsonify({'message': 'Admin registered successfully!'}), 201
        except pymysql.err.IntegrityError as e:
            msg = str(e)
            if 'email' in msg:
                return jsonify({'error': 'Email already exists'}), 400
            if 'phone_number' in msg:
                return jsonify({'error': 'Phone number already exists'}), 400
            if 'username' in msg:
                return jsonify({'error': 'Username already exists'}), 400
            return jsonify({'error': 'User already exists'}), 400
        finally:
            cursor.close()
            conn.close()
    except Exception as e:
        logger.error(f"Admin signup error: {e}")
        return jsonify({'error': 'Server error'}), 500


# -------------------------
# Customer Signup
# -------------------------
@auth_bp.route('/customer/signup', methods=['POST'])
def customer_signup():
    try:
        data = request.get_json()
        logger.debug(f"Customer signup data: {data}")

        username = data.get('username')
        email = data.get('email')
        phone_number = data.get('phone_number')
        password = data.get('password')
        confirm_password = data.get('confirm_password')

        if not all([username, email, phone_number, password, confirm_password]):
            return jsonify({'error': 'All fields are required'}), 400

        if password != confirm_password:
            return jsonify({'error': 'Passwords do not match'}), 400

        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400

        if '@' not in email:
            return jsonify({'error': 'Invalid email format'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        password_hash = generate_password_hash(password)

        try:
            cursor.execute("""
                INSERT INTO users (username, email, phone_number, password_hash, role_id)
                VALUES (%s, %s, %s, %s, %s)
            """, (username, email, phone_number, password_hash, 2))
            conn.commit()
            logger.info(f"Customer created: {username}")
            return jsonify({'message': 'Customer registered successfully!'}), 201
        except pymysql.err.IntegrityError as e:
            msg = str(e)
            if 'email' in msg:
                return jsonify({'error': 'Email already exists'}), 400
            if 'phone_number' in msg:
                return jsonify({'error': 'Phone number already exists'}), 400
            if 'username' in msg:
                return jsonify({'error': 'Username already exists'}), 400
            return jsonify({'error': 'User already exists'}), 400
        finally:
            cursor.close()
            conn.close()
    except Exception as e:
        logger.error(f"Customer signup error: {e}")
        return jsonify({'error': 'Server error'}), 500


# -------------------------
# Admin Login
# -------------------------
@auth_bp.route('/admin/login', methods=['POST'])
def admin_login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s AND role_id = 1", (username,))
        user = cursor.fetchone()

        if not user or not check_password_hash(user['password_hash'], password):
            cursor.close()
            conn.close()
            return jsonify({'error': 'Invalid username or password'}), 401

        token = jwt.encode({
            'user_id': user['id'],
            'username': user['username'],
            'role_id': 1,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, Config.SECRET_KEY, algorithm='HS256')

        cursor.close()
        conn.close()
        logger.info(f"Admin login: {username}")
        return jsonify({'message': 'Admin login successful', 'token': token}), 200

    except Exception as e:
        logger.error(f"Admin login error: {e}")
        return jsonify({'error': 'Server error'}), 500


# -------------------------
# Customer Login
# -------------------------
@auth_bp.route('/customer/login', methods=['POST'])
def customer_login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s AND role_id = 2", (username,))
        user = cursor.fetchone()

        if not user or not check_password_hash(user['password_hash'], password):
            cursor.close()
            conn.close()
            return jsonify({'error': 'Invalid username or password'}), 401

        token = jwt.encode({
            'user_id': user['id'],
            'username': user['username'],
            'role_id': 2,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, Config.SECRET_KEY, algorithm='HS256')

        cursor.close()
        conn.close()
        logger.info(f"Customer login: {username}")
        return jsonify({'message': 'Customer login successful', 'token': token}), 200

    except Exception as e:
        logger.error(f"Customer login error: {e}")
        return jsonify({'error': 'Server error'}), 500


# -------------------------
# Protected Dashboard (Uses verify_customer_token)
# -------------------------
@auth_bp.route('/dashboard', methods=['GET'])
def dashboard():
    payload, error_response, status_code = verify_customer_token(request)
    if error_response:
        return error_response, status_code

    role_id = payload['role_id']
    username = payload['username']

    if role_id == 1:
        return jsonify({'message': f'Welcome Admin {username}!'}), 200
    elif role_id == 2:
        return jsonify({'message': f'Welcome Customer {username}!'}), 200
    else:
        return jsonify({'error': 'Unknown role'}), 403


# =============================================
# 1. GET MY PROFILE - Only Own Data
# =============================================
@auth_bp.route('/profile', methods=['GET'])
def get_my_profile():
    payload, error_response, status_code = verify_customer_token(request)
    if error_response:
        return error_response, status_code

    user_id = payload['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT id, username, email, phone_number, role_id, created_at 
            FROM users WHERE id = %s
        """, (user_id,))
        user = cursor.fetchone()

        if not user:
            return jsonify({"error": "User not found"}), 404

        role_name = "Admin" if user['role_id'] == 1 else "Customer"

        return jsonify({
            "message": "Profile fetched successfully",
            "profile": {
                "id": user['id'],
                "username": user['username'],
                "email": user['email'],
                "phone_number": user['phone_number'],
                "role": role_name,
                "role_id": user['role_id'],
                "created_at": user['created_at'].strftime("%Y-%m-%d %H:%M:%S") if user['created_at'] else None
            }
        }), 200

    except Exception as e:
        logger.error(f"Get profile error: {e}")
        return jsonify({"error": "Server error"}), 500
    finally:
        cursor.close()
        conn.close()


# =============================================
# 2. UPDATE PROFILE - Email, Phone, Password
# =============================================
@auth_bp.route('/profile/update', methods=['PUT'])
def update_profile():
    payload, error_response, status_code = verify_customer_token(request)
    if error_response:
        return error_response, status_code

    user_id = payload['user_id']
    data = request.get_json()

    new_email = data.get('email')
    new_phone = data.get('phone_number')
    new_password = data.get('password')
    confirm_password = data.get('confirm_password')

    if not any([new_email, new_phone, new_password]):
        return jsonify({"error": "Provide at least one field to update"}), 400

    if new_password:
        if new_password != confirm_password:
            return jsonify({"error": "Passwords do not match"}), 400
        if len(new_password) < 6:
            return jsonify({"error": "Password too short"}), 400
        password_hash = generate_password_hash(new_password)
    else:
        password_hash = None

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        updates = []
        params = []

        if new_email:
            if '@' not in new_email:
                return jsonify({"error": "Invalid email"}), 400
            updates.append("email = %s")
            params.append(new_email)

        if new_phone:
            updates.append("phone_number = %s")
            params.append(new_phone)

        if password_hash:
            updates.append("password_hash = %s")
            params.append(password_hash)

        params.append(user_id)
        query = f"UPDATE users SET {', '.join(updates)} WHERE id = %s"

        cursor.execute(query, params)
        conn.commit()

        if cursor.rowcount == 0:
            return jsonify({"error": "Nothing updated"}), 400

        return jsonify({
            "message": "Profile updated successfully!",
            "updated": {"email": bool(new_email), "phone": bool(new_phone), "password": bool(new_password)}
        }), 200

    except pymysql.err.IntegrityError as e:
        if "email_unique" in str(e):
            return jsonify({"error": "Email already taken"}), 409
        if "phone_unique" in str(e):
            return jsonify({"error": "Phone number already taken"}), 409
        return jsonify({"error": "Update failed"}), 400

    except Exception as e:
        logger.error(f"Update error: {e}")
        return jsonify({"error": "Server error"}), 500
    finally:
        cursor.close()
        conn.close()