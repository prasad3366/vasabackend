# favorites.py
from flask import Blueprint, request, jsonify
import pymysql
from config import Config
import jwt
from functools import wraps
import logging

favorites_bp = Blueprint('favorites', __name__)
logger = logging.getLogger(__name__)

def get_db_connection():
    return pymysql.connect(
        host=Config.DB_HOST,
        user=Config.DB_USERNAME,
        password=Config.DB_PASSWORD,
        database=Config.DB_NAME,
        cursorclass=pymysql.cursors.DictCursor
    )

def verify_customer_token(request):
    token = request.headers.get('Authorization')
    if not token:
        return None, jsonify({'error': 'Token missing'}), 401
    if token.lower().startswith('bearer '):
        return None, jsonify({'error': 'Use raw token, not Bearer'}), 401
    try:
        data = jwt.decode(token.strip(), Config.SECRET_KEY, algorithms=['HS256'])
        if data.get('role_id') != 2:
            return None, jsonify({'error': 'Customer only'}), 403
        return data, None, None
    except jwt.ExpiredSignatureError:
        return None, jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return None, jsonify({'error': 'Invalid token'}), 401

def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        payload, err, code = verify_customer_token(request)
        if err: return err, code
        request.user_id = payload['user_id']
        return f(*args, **kwargs)
    return decorated


# 1. ADD MULTIPLE TO FAVORITES
@favorites_bp.route('/favorites', methods=['POST'])
@jwt_required
def add_to_favorites():
    user_id = request.user_id
    data = request.get_json() or {}
    perfume_ids = data.get('perfume_ids', [])

    if not perfume_ids:
        return jsonify({"error": "perfume_ids array required"}), 400

    try:
        perfume_ids = [int(pid) for pid in perfume_ids]
    except:
        return jsonify({"error": "All perfume_ids must be integers"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    added = []
    already = []
    errors = []

    try:
        for pid in perfume_ids:
            # Check perfume exists
            cursor.execute("SELECT id FROM perfumes WHERE id = %s AND available = 1", (pid,))
            if not cursor.fetchone():
                errors.append({"perfume_id": pid, "error": "Not found"})
                continue

            # Insert or ignore
            cursor.execute("""
                INSERT IGNORE INTO favorites (user_id, perfume_id)
                VALUES (%s, %s)
            """, (user_id, pid))

            if cursor.rowcount:
                added.append(pid)
            else:
                already.append(pid)

        conn.commit()

        return jsonify({
            "message": "Favorites updated",
            "added": added,
            "already_in_favorites": already,
            "errors": errors
        }), 200

    except Exception as e:
        conn.rollback()
        logger.error(f"Batch add favorites error (user {user_id}): {e}")
        return jsonify({"error": "DB error"}), 500
    finally:
        cursor.close()
        conn.close()


# 2. VIEW ALL FAVORITES
@favorites_bp.route('/favorites', methods=['GET'])
@jwt_required
def view_favorites():
    user_id = request.user_id
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT f.id, f.perfume_id, p.name, p.price, p.size, f.added_at
            FROM favorites f
            JOIN perfumes p ON f.perfume_id = p.id
            WHERE f.user_id = %s AND p.available = 1
            ORDER BY f.added_at DESC
        """, (user_id,))
        items = cursor.fetchall()

        base_url = request.host_url.rstrip('/')
        for item in items:
            item['photo_url'] = f"{base_url}/perfumes/photo/{item['perfume_id']}"

        return jsonify({"favorites": items}), 200

    except Exception as e:
        logger.error(f"View favorites error (user {user_id}): {e}")
        return jsonify({"error": "Failed to load favorites"}), 500
    finally:
        conn.close()


# 3. DELETE MULTIPLE FROM FAVORITES
@favorites_bp.route('/favorites', methods=['DELETE'])
@jwt_required
def remove_from_favorites():
    user_id = request.user_id
    data = request.get_json() or {}
    perfume_ids = data.get('perfume_ids', [])

    if not perfume_ids:
        return jsonify({"error": "perfume_ids array required"}), 400

    try:
        perfume_ids = [int(pid) for pid in perfume_ids]
    except:
        return jsonify({"error": "All perfume_ids must be integers"}), 400

    if not perfume_ids:
        return jsonify({"error": "No valid perfume_ids"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Use IN clause
        placeholders = ','.join(['%s'] * len(perfume_ids))
        sql = f"""
            DELETE FROM favorites 
            WHERE user_id = %s AND perfume_id IN ({placeholders})
        """
        cursor.execute(sql, [user_id] + perfume_ids)
        deleted_count = cursor.rowcount

        conn.commit()

        if deleted_count == 0:
            return jsonify({"message": "No items removed (not in favorites)"}), 200

        return jsonify({
            "message": f"Removed {deleted_count} item(s)",
            "removed_perfume_ids": perfume_ids[:deleted_count]
        }), 200

    except Exception as e:
        conn.rollback()
        logger.error(f"Batch delete favorites error (user {user_id}): {e}")
        return jsonify({"error": "DB error"}), 500
    finally:
        cursor.close()
        conn.close()