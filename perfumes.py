from flask import Blueprint, request, jsonify, send_file
import pymysql
import jwt
import io
import re
from werkzeug.utils import secure_filename
from config import Config
from datetime import datetime
import logging
from decimal import Decimal

perfumes_bp = Blueprint('perfumes', __name__)

# File upload configuration
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_db_connection():
    return pymysql.connect(
        host=Config.DB_HOST,
        user=Config.DB_USERNAME,
        password=Config.DB_PASSWORD,
        database=Config.DB_NAME,
        cursorclass=pymysql.cursors.DictCursor
    )

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_perfume_data(name, price_str, category, size, quantity_str=None, description=None, top_notes=None, heart_notes=None, base_notes=None):
    """Validate perfume data. Returns (is_valid, error_message)"""
    if not name or len(name.strip()) < 2:
        return False, "Name must be at least 2 characters long"
    
    try:
        price = float(price_str)
        if price <= 0:
            return False, "Price must be greater than 0"
        if price != float(f"{price:.2f}"):
            return False, "Price can have maximum 2 decimal places"
    except ValueError:
        return False, "Price must be a valid number"
    
    if category not in ['men', 'women', 'unisex']:
        return False, "Category must be 'men', 'women', or 'unisex'"
    
    if not size or not re.match(r'^\d+ml$', size):
        return False, "Size must be a valid format (e.g., '30ml', '50ml', '100ml')"
    
    if quantity_str is not None:
        try:
            quantity = int(quantity_str)
            if quantity < 0:
                return False, "Quantity cannot be negative"
        except ValueError:
            return False, "Quantity must be a valid number"
    
    if description and len(description) > 1000:
        return False, "Description too long (maximum 1000 characters)"
    
    if top_notes and len(top_notes) > 500:
        return False, "Top notes too long (maximum 500 characters)"
    
    if heart_notes and len(heart_notes) > 500:
        return False, "Heart notes too long (maximum 500 characters)"
    
    if base_notes and len(base_notes) > 500:
        return False, "Base notes too long (maximum 500 characters)"
    
    return True, None

def validate_cart_data(items):
    """Validate cart items data. Returns (is_valid, error_message)"""
    if not items:
        return False, "At least one item must be provided"
    
    for item in items:
        perfume_id = item.get('perfume_id')
        quantity_str = item.get('quantity')
        
        if not perfume_id:
            return False, "Perfume ID is required for all items"
        
        try:
            perfume_id = int(perfume_id)
            if perfume_id <= 0:
                return False, "Perfume ID must be a positive integer"
        except (ValueError, TypeError):
            return False, "Perfume ID must be a valid integer"
        
        try:
            quantity = int(quantity_str)
            if quantity <= 0:
                return False, "Quantity must be a positive integer"
        except (ValueError, TypeError):
            return False, "Quantity must be a valid integer"
    
    return True, None

def verify_admin_token(request):
    auth = request.headers.get("Authorization")
    if not auth or auth.lower().startswith("bearer "):
        return None, jsonify({"error": "Use raw token, not Bearer"}), 401
    try:
        payload = jwt.decode(auth.strip(), Config.SECRET_KEY, algorithms=["HS256"])
        if payload.get("role_id") != 1:
            return None, jsonify({"error": "Admin access required"}), 403
        return payload, None, None
    except jwt.ExpiredSignatureError:
        return None, jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return None, jsonify({"error": "Invalid token"}), 401

def verify_customer_token(request):
    auth = request.headers.get("Authorization")
    if not auth or auth.lower().startswith("bearer "):
        return None, jsonify({"error": "Use raw token, not Bearer"}), 401
    try:
        payload = jwt.decode(auth.strip(), Config.SECRET_KEY, algorithms=["HS256"])
        if payload.get("role_id") != 2:
            return None, jsonify({"error": "Customer access only"}), 403
        return payload, None, None
    except jwt.ExpiredSignatureError:
        return None, jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return None, jsonify({"error": "Invalid token"}), 401


@perfumes_bp.route('/admin/perfumes', methods=['POST'])
def add_perfume():
    payload, err, code = verify_admin_token(request)
    if err: return err, code

    name        = request.form.get('name', '').strip()
    price       = request.form.get('price')
    description = request.form.get('description', '').strip()
    category    = request.form.get('category')
    quantity    = request.form.get('quantity', '100')
    top_notes   = request.form.get('top_notes', '')
    heart_notes = request.form.get('heart_notes', '')
    base_notes  = request.form.get('base_notes', '')
    photo       = request.files.get('photo')

    sizes = request.form.getlist('size')

    if not name or not price or not category or not sizes:
        return jsonify({'error': 'Name, price, category, and size(s) required'}), 400

    if category not in ['men','women','unisex']:
        return jsonify({'error': 'Category must be men/women/unisex'}), 400

    valid_sizes = []
    for s in sizes:
        s = s.strip()
        if not re.match(r'^\d+ml$', s):
            return jsonify({'error': f"Invalid size: {s} → use 50ml"}), 400
        valid_sizes.append(s)

    photo_data = None
    if photo and photo.filename:
        if photo.filename.lower().split('.')[-1] not in ['jpg','jpeg','png']:
            return jsonify({'error': 'Only jpg/png'}), 400
        photo_data = photo.read()
        if len(photo_data) > 5*1024*1024:
            return jsonify({'error': 'Photo max 5MB'}), 400

    import json
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            try:
                cur.execute("""
                    INSERT INTO perfumes 
                    (name, price, description, quantity, available, photo, created_at, category, size,
                     top_notes, heart_notes, base_notes)
                    VALUES (%s, %s, %s, %s, 1, %s, NOW(), %s, %s, %s, %s, %s)
                """, (
                    name, price, description, quantity, photo_data,
                    category, json.dumps(valid_sizes),
                    top_notes, heart_notes, base_notes
                ))
            except Exception as e:
                logger.error(f"Insert error with description: {str(e)}")
                if 'description' in str(e).lower() or 'unknown column' in str(e).lower():
                    logger.warning("Description column may not exist, trying without it")
                    cur.execute("""
                        INSERT INTO perfumes 
                        (name, price, quantity, available, photo, created_at, category, size,
                         top_notes, heart_notes, base_notes)
                        VALUES (%s, %s, %s, 1, %s, NOW(), %s, %s, %s, %s, %s)
                    """, (
                        name, price, quantity, photo_data,
                        category, json.dumps(valid_sizes),
                        top_notes, heart_notes, base_notes
                    ))
                else:
                    raise
            
            pid = cur.lastrowid
        conn.commit()
        return jsonify({
            'message': 'Perfume added!',
            'id': pid,
            'sizes': valid_sizes
        }), 201
    except Exception as e:
        conn.rollback()
        logger.error(f"Error adding perfume: {str(e)}")
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()
        
@perfumes_bp.route('/admin/perfumes', methods=['GET'])
def get_perfumes_admin():
    _, err, code = verify_admin_token(request)
    if err: return err, code

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT id, name, description, price, quantity, available, created_at, updated_at, category, size, top_notes, heart_notes, base_notes
                FROM perfumes ORDER BY id DESC
            """)
            perfumes = cursor.fetchall()
    except Exception as e:
        logger.error(f"Error retrieving perfumes: {str(e)}")
        return jsonify({'error': 'Failed to retrieve perfumes'}), 500
    finally:
        conn.close()
    
    return jsonify({'perfumes': perfumes}), 200

@perfumes_bp.route('/admin/perfumes', methods=['PUT'])
def update_perfume():
    _, err, code = verify_admin_token(request)
    if err: return err, code

    perfume_id = request.form.get('id')
    if not perfume_id:
        return jsonify({'error': 'Perfume ID required'}), 400

    name = request.form.get('name')
    if name is not None:
        name = name.strip()
    description = request.form.get('description')
    price_str = request.form.get('price')
    quantity_str = request.form.get('quantity')
    category = request.form.get('category')
    size = request.form.get('size')
    top_notes = request.form.get('top_notes')
    heart_notes = request.form.get('heart_notes')
    base_notes = request.form.get('base_notes')
    photo = request.files.get('photo')

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT id, name, description, price, quantity, available, category, size, top_notes, heart_notes, base_notes
                FROM perfumes WHERE id = %s
            """, (perfume_id,))
            existing = cursor.fetchone()
            if not existing:
                return jsonify({'error': 'Perfume not found'}), 404

            # Prepare fields to update
            update_fields = []
            update_params = []

            # Validate and add fields only if provided
            if name is not None:
                temp_name = name
                is_valid, validation_error = validate_perfume_data(temp_name, str(existing['price']), existing['category'], existing['size'], None, None, None, None, None)
                if not is_valid:
                    return jsonify({'error': validation_error}), 400
                update_fields.append("name = %s")
                update_params.append(name)

            if description is not None:
                is_valid, validation_error = validate_perfume_data(existing['name'], str(existing['price']), existing['category'], existing['size'], None, description, None, None, None)
                if not is_valid:
                    return jsonify({'error': validation_error}), 400
                update_fields.append("description = %s")
                update_params.append(description)

            if price_str is not None:
                is_valid, validation_error = validate_perfume_data(existing['name'], price_str, existing['category'], existing['size'], None, None, None, None, None)
                if not is_valid:
                    return jsonify({'error': validation_error}), 400
                update_fields.append("price = %s")
                update_params.append(price_str)

            new_quantity = existing['quantity']
            if quantity_str is not None:
                is_valid, validation_error = validate_perfume_data(existing['name'], str(existing['price']), existing['category'], existing['size'], quantity_str, None, None, None, None)
                if not is_valid:
                    return jsonify({'error': validation_error}), 400
                new_quantity = int(quantity_str)
                update_fields.append("quantity = %s")
                update_params.append(new_quantity)

            if category is not None:
                is_valid, validation_error = validate_perfume_data(existing['name'], str(existing['price']), category, existing['size'], None, None, None, None, None)
                if not is_valid:
                    return jsonify({'error': validation_error}), 400
                update_fields.append("category = %s")
                update_params.append(category)

            if size is not None:
                is_valid, validation_error = validate_perfume_data(existing['name'], str(existing['price']), existing['category'], size, None, None, None, None, None)
                if not is_valid:
                    return jsonify({'error': validation_error}), 400
                update_fields.append("size = %s")
                update_params.append(size)

            if top_notes is not None:
                is_valid, validation_error = validate_perfume_data(existing['name'], str(existing['price']), existing['category'], existing['size'], None, None, top_notes, None, None)
                if not is_valid:
                    return jsonify({'error': validation_error}), 400
                update_fields.append("top_notes = %s")
                update_params.append(top_notes)

            if heart_notes is not None:
                is_valid, validation_error = validate_perfume_data(existing['name'], str(existing['price']), existing['category'], existing['size'], None, None, None, heart_notes, None)
                if not is_valid:
                    return jsonify({'error': validation_error}), 400
                update_fields.append("heart_notes = %s")
                update_params.append(heart_notes)

            if base_notes is not None:
                is_valid, validation_error = validate_perfume_data(existing['name'], str(existing['price']), existing['category'], existing['size'], None, None, None, None, base_notes)
                if not is_valid:
                    return jsonify({'error': validation_error}), 400
                update_fields.append("base_notes = %s")
                update_params.append(base_notes)

            photo_data = None
            if photo and photo.filename:
                if not allowed_file(photo.filename):
                    return jsonify({'error': 'Invalid file type'}), 400
                photo_data = photo.read()
                if len(photo_data) > MAX_FILE_SIZE:
                    return jsonify({'error': 'File too large'}), 400
                update_fields.append("photo = %s")
                update_params.append(photo_data)

            if not update_fields:
                return jsonify({'error': 'No fields provided to update'}), 400

            new_available = 1 if new_quantity > 0 else 0
            update_fields.append("available = %s")
            update_params.append(new_available)
            update_fields.append("updated_at = %s")
            update_params.append(datetime.now())

            update_params.append(perfume_id)

            sql = f"""
                UPDATE perfumes SET {', '.join(update_fields)} WHERE id = %s
            """
            cursor.execute(sql, update_params)

            if cursor.rowcount == 0:
                return jsonify({'error': 'No changes made'}), 400

        conn.commit()
        return jsonify({'message': 'Perfume updated successfully'}), 200
    except Exception as e:
        conn.rollback()
        logger.error(f"Error updating perfume: {str(e)}")
        return jsonify({'error': 'Database error'}), 500
    finally:
        conn.close()

@perfumes_bp.route('/admin/special-offers', methods=['POST'])
def add_special_offer():
    _, err, code = verify_admin_token(request)
    if err: return err, code

    perfume_id = request.form.get('id')
    discount_percentage = request.form.get('discount_percentage')
    end_date = request.form.get('end_date')

    if not perfume_id or not discount_percentage or not end_date:
        return jsonify({'error': 'Perfume ID, discount percentage, and end date are required'}), 400

    try:
        discount = float(discount_percentage)
        if discount <= 0 or discount >= 100:
            return jsonify({'error': 'Discount percentage must be between 0 and 100'}), 400
    except ValueError:
        return jsonify({'error': 'Invalid discount percentage'}), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Check if perfume exists
            cursor.execute("SELECT id FROM perfumes WHERE id = %s", (perfume_id,))
            if not cursor.fetchone():
                return jsonify({'error': 'Perfume not found'}), 404

            # Check if there's already an active discount
            cursor.execute("""
                SELECT id FROM discounts 
                WHERE perfume_id = %s AND end_date >= CURRENT_DATE()
            """, (perfume_id,))
            if cursor.fetchone():
                return jsonify({'error': 'Perfume already has an active special offer'}), 400

            # Add new discount
            cursor.execute("""
                INSERT INTO discounts (perfume_id, discount_percentage, start_date, end_date) 
                VALUES (%s, %s, CURRENT_DATE(), %s)
            """, (perfume_id, discount, end_date))
            
        conn.commit()
        return jsonify({'message': 'Special offer added successfully'}), 201
    except Exception as e:
        conn.rollback()
        logger.error(f"Error adding special offer: {str(e)}")
        return jsonify({'error': 'Database error'}), 500
    finally:
        conn.close()

@perfumes_bp.route('/admin/special-offers/<int:perfume_id>', methods=['PUT'])
def update_special_offer(perfume_id):
    _, err, code = verify_admin_token(request)
    if err: return err, code

    discount_percentage = request.form.get('discount_percentage')
    end_date = request.form.get('end_date')

    if not discount_percentage and not end_date:
        return jsonify({'error': 'Discount percentage or end date is required'}), 400

    if discount_percentage:
        try:
            discount = float(discount_percentage)
            if discount <= 0 or discount >= 100:
                return jsonify({'error': 'Discount percentage must be between 0 and 100'}), 400
        except ValueError:
            return jsonify({'error': 'Invalid discount percentage'}), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Check if discount exists and is active
            cursor.execute("""
                SELECT id FROM discounts 
                WHERE perfume_id = %s AND end_date >= CURRENT_DATE()
            """, (perfume_id,))
            if not cursor.fetchone():
                return jsonify({'error': 'No active special offer found for this perfume'}), 404

            # Update fields
            update_fields = []
            update_params = []
            
            if discount_percentage:
                update_fields.append("discount_percentage = %s")
                update_params.append(discount)
            if end_date:
                update_fields.append("end_date = %s")
                update_params.append(end_date)

            update_params.append(perfume_id)
            
            sql = f"""
                UPDATE discounts 
                SET {', '.join(update_fields)}
                WHERE perfume_id = %s AND end_date >= CURRENT_DATE()
            """
            cursor.execute(sql, update_params)
            
        conn.commit()
        return jsonify({'message': 'Special offer updated successfully'}), 200
    except Exception as e:
        conn.rollback()
        logger.error(f"Error updating special offer: {str(e)}")
        return jsonify({'error': 'Database error'}), 500
    finally:
        conn.close()

@perfumes_bp.route('/admin/special-offers/<int:perfume_id>', methods=['DELETE'])
def delete_special_offer(perfume_id):
    _, err, code = verify_admin_token(request)
    if err: return err, code

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Delete active discount
            cursor.execute("""
                DELETE FROM discounts 
                WHERE perfume_id = %s AND end_date >= CURRENT_DATE()
            """, (perfume_id,))
            
            if cursor.rowcount == 0:
                return jsonify({'error': 'No active special offer found for this perfume'}), 404
                
        conn.commit()
        return jsonify({'message': 'Special offer deleted successfully'}), 200
    except Exception as e:
        conn.rollback()
        logger.error(f"Error deleting special offer: {str(e)}")
        return jsonify({'error': 'Database error'}), 500
    finally:
        conn.close()

@perfumes_bp.route('/admin/perfumes/best-seller', methods=['PUT'])
def update_best_seller():
    _, err, code = verify_admin_token(request)
    if err: return err, code

    perfume_id = request.form.get('id')
    is_best_seller = request.form.get('is_best_seller', 'true').lower() == 'true'

    if not perfume_id:
        return jsonify({'error': 'Perfume ID required'}), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # First check if perfume exists
            cursor.execute("SELECT id FROM perfumes WHERE id = %s", (perfume_id,))
            if not cursor.fetchone():
                return jsonify({'error': 'Perfume not found'}), 404

            # Update the is_best_seller status
            cursor.execute("""
                UPDATE perfumes 
                SET is_best_seller = %s,
                    updated_at = %s
                WHERE id = %s
            """, (is_best_seller, datetime.now(), perfume_id))

            if cursor.rowcount == 0:
                return jsonify({'error': 'No changes made'}), 400

        conn.commit()
        return jsonify({
            'message': f"Perfume {'added to' if is_best_seller else 'removed from'} best sellers successfully",
            'perfume_id': perfume_id,
            'is_best_seller': is_best_seller
        }), 200
    except Exception as e:
        conn.rollback()
        logger.error(f"Error updating best seller status: {str(e)}")
        return jsonify({'error': 'Database error'}), 500
    finally:
        conn.close()

@perfumes_bp.route('/admin/perfumes', methods=['DELETE'])
def delete_perfume():
    _, err, code = verify_admin_token(request)
    if err: return err, code

    perfume_id = request.form.get('id')
    if not perfume_id:
        return jsonify({'error': 'Perfume ID required'}), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # First delete from order_items (child table)
            cursor.execute("DELETE FROM order_items WHERE perfume_id = %s", (perfume_id,))
            
            # Then delete the perfume (parent table)
            cursor.execute("DELETE FROM perfumes WHERE id = %s", (perfume_id,))
            rowcount = cursor.rowcount
        
        if rowcount == 0:
            return jsonify({'error': 'Perfume not found'}), 404
        
        conn.commit()
        return jsonify({'message': 'Perfume deleted successfully'}), 200
    except Exception as e:
        conn.rollback()
        logger.error(f"Error deleting perfume: {str(e)}")
        return jsonify({'error': 'Database error'}), 500
    finally:
        conn.close()

# PUBLIC ROUTES
@perfumes_bp.route('/perfumes/best-sellers', methods=['GET'])
def get_best_sellers():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Get perfumes marked as best sellers
            sql = """
                SELECT p.id, p.name, p.description, p.price, p.quantity, p.available, 
                       p.category, p.size, p.top_notes, p.heart_notes, p.base_notes
                FROM perfumes p
                WHERE p.available = 1
                AND p.is_best_seller = 1
                ORDER BY p.created_at DESC
                LIMIT 10
            """
            cursor.execute(sql)
            best_sellers = cursor.fetchall()
            
            # Add photo URLs and stock information
            base_url = request.host_url.rstrip('/')
            for perfume in best_sellers:
                perfume['photo_url'] = f"{base_url}/perfumes/photo/{perfume['id']}"
                perfume['in_stock'] = perfume['quantity'] > 0
                perfume['stock_level'] = 'low' if perfume['quantity'] <= 5 else 'available'
                
    except Exception as e:
        logger.error(f"Error retrieving best sellers: {str(e)}")
        return jsonify({'error': 'Failed to retrieve best sellers'}), 500
    finally:
        conn.close()
    
    return jsonify({'best_sellers': best_sellers}), 200

@perfumes_bp.route('/perfumes/new-arrivals', methods=['GET'])
def get_new_arrivals():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Get the most recently added perfumes (last 30 days)
            sql = """
                SELECT id, name, description, price, quantity, available, 
                       category, size, top_notes, heart_notes, base_notes, created_at
                FROM perfumes
                WHERE available = 1
                AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
                ORDER BY created_at DESC
                LIMIT 10
            """
            cursor.execute(sql)
            new_arrivals = cursor.fetchall()
            
            # Add photo URLs and stock information
            base_url = request.host_url.rstrip('/')
            for perfume in new_arrivals:
                perfume['photo_url'] = f"{base_url}/perfumes/photo/{perfume['id']}"
                perfume['in_stock'] = perfume['quantity'] > 0
                perfume['stock_level'] = 'low' if perfume['quantity'] <= 5 else 'available'
                
    except Exception as e:
        logger.error(f"Error retrieving new arrivals: {str(e)}")
        return jsonify({'error': 'Failed to retrieve new arrivals'}), 500
    finally:
        conn.close()
    
    return jsonify({'new_arrivals': new_arrivals}), 200

@perfumes_bp.route('/perfumes/special-offers', methods=['GET'])
def get_special_offers():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Get perfumes with special offers (assuming a discount field or special price)
            sql = """
                SELECT p.id, p.name, p.description, p.price, p.quantity, p.available, 
                       p.category, p.size, p.top_notes, p.heart_notes, p.base_notes,
                       d.discount_percentage, d.end_date
                FROM perfumes p
                JOIN discounts d ON p.id = d.perfume_id
                WHERE p.available = 1
                AND d.end_date >= CURRENT_DATE()
                ORDER BY d.discount_percentage DESC
            """
            cursor.execute(sql)
            special_offers = cursor.fetchall()
            
            # Add photo URLs, stock information, and calculate discounted prices
            base_url = request.host_url.rstrip('/')
            for perfume in special_offers:
                perfume['photo_url'] = f"{base_url}/perfumes/photo/{perfume['id']}"
                perfume['in_stock'] = perfume['quantity'] > 0
                perfume['stock_level'] = 'low' if perfume['quantity'] <= 5 else 'available'
                # Calculate discounted price
                original_price = float(perfume['price'])
                discount = float(perfume['discount_percentage'])
                perfume['original_price'] = original_price
                perfume['discounted_price'] = round(original_price * (1 - discount/100), 2)
                
    except Exception as e:
        logger.error(f"Error retrieving special offers: {str(e)}")
        return jsonify({'error': 'Failed to retrieve special offers'}), 500
    finally:
        conn.close()
    
    return jsonify({'special_offers': special_offers}), 200

@perfumes_bp.route('/perfumes', methods=['GET'])
def view_perfumes():
    min_price = request.args.get('min_price')
    max_price = request.args.get('max_price')
    in_stock_only = request.args.get('in_stock_only', 'true').lower() == 'true'

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            base_sql = """
                SELECT id, name, description, price, quantity, available, category, size, top_notes, heart_notes, base_notes 
                FROM perfumes WHERE available = 1
            """
            params = []
            
            if in_stock_only:
                base_sql += " AND quantity > 0"
            if min_price:
                base_sql += " AND price >= %s"
                params.append(float(min_price))
            if max_price:
                base_sql += " AND price <= %s"
                params.append(float(max_price))
            
            base_sql += " ORDER BY id DESC"
            cursor.execute(base_sql, params)
            perfumes = cursor.fetchall()
            
            base_url = request.host_url.rstrip('/')
            for perfume in perfumes:
                perfume['photo_url'] = f"{base_url}/perfumes/photo/{perfume['id']}"
                perfume['in_stock'] = perfume['quantity'] > 0
                perfume['stock_level'] = 'low' if perfume['quantity'] <= 5 else 'available'
                
    except Exception as e:
        logger.error(f"Error retrieving perfumes: {str(e)}")
        return jsonify({'error': 'Failed to retrieve perfumes'}), 500
    finally:
        conn.close()
    
    return jsonify({'perfumes': perfumes}), 200

@perfumes_bp.route('/perfumes/<int:perfume_id>', methods=['GET'])
def get_perfume_details(perfume_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT id, name, description, price, quantity, available, category, size, top_notes, heart_notes, base_notes 
                FROM perfumes WHERE id = %s
            """, (perfume_id,))
            perfume = cursor.fetchone()
            
            if perfume:
                base_url = request.host_url.rstrip('/')
                perfume['photo_url'] = f"{base_url}/perfumes/photo/{perfume['id']}"
                perfume['in_stock'] = perfume['quantity'] > 0 and perfume['available'] == 1
                perfume['stock_level'] = 'low' if perfume['quantity'] <= 5 else 'available'
    except Exception as e:
        logger.error(f"Error retrieving perfume: {str(e)}")
        return jsonify({'error': 'Failed to retrieve perfume'}), 500
    finally:
        conn.close()
    
    if not perfume:
        return jsonify({'error': 'Perfume not found'}), 404
    return jsonify({'perfume': perfume}), 200

@perfumes_bp.route('/perfumes/photo/<int:perfume_id>', methods=['GET'])
def get_photo(perfume_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT photo FROM perfumes WHERE id = %s", (perfume_id,))
            result = cursor.fetchone()
    finally:
        conn.close()

    if result and result.get('photo'):
        return send_file(io.BytesIO(result['photo']), mimetype='image/jpeg')
    return jsonify({'error': 'Photo not found'}), 404

# ==================== REVIEW ROUTES ====================

def validate_review_data(rating, comment=None):
    """Validate review data. Returns (is_valid, error_message)"""
    try:
        rating_int = int(rating)
        if rating_int < 1 or rating_int > 5:
            return False, "Rating must be between 1 and 5"
    except ValueError:
        return False, "Rating must be a valid number between 1 and 5"
    
    if comment and len(comment.strip()) > 500:
        return False, "Comment too long (maximum 500 characters)"
    
    if not comment or not comment.strip():
        return False, "Comment is required"
    
    return True, None

@perfumes_bp.route('/perfumes/<int:perfume_id>/reviews', methods=['POST'])
def add_review(perfume_id):
    customer_data, err, code = verify_customer_token(request)
    if err:
        return err, code

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Verify perfume exists
            cursor.execute("SELECT id FROM perfumes WHERE id = %s", (perfume_id,))
            if not cursor.fetchone():
                return jsonify({'error': 'Perfume not found'}), 404
            
            # Check if user already reviewed this perfume
            user_id = customer_data.get('user_id')
            cursor.execute(
                "SELECT id FROM reviews WHERE perfume_id = %s AND user_id = %s", 
                (perfume_id, user_id)
            )
            if cursor.fetchone():
                return jsonify({'error': 'You have already reviewed this perfume'}), 400

            # Get review data
            rating = request.form.get('rating')
            comment = request.form.get('comment', '').strip()

            # Validate review data
            is_valid, validation_error = validate_review_data(rating, comment)
            if not is_valid:
                return jsonify({'error': validation_error}), 400

            # Insert review
            sql = """
                INSERT INTO reviews (perfume_id, user_id, rating, comment, created_at) 
                VALUES (%s, %s, %s, %s, %s)
            """
            cursor.execute(sql, (perfume_id, user_id, int(rating), comment, datetime.now()))
            review_id = cursor.lastrowid
            
        conn.commit()
        logger.info(f"Review {review_id} added by user {user_id} for perfume {perfume_id}")
        return jsonify({
            'message': 'Review added successfully', 
            'review_id': review_id,
            'perfume_id': perfume_id
        }), 201
        
    except Exception as e:
        conn.rollback()
        logger.error(f"Error adding review: {str(e)}")
        return jsonify({'error': f'Database error: {str(e)}'}), 500
    finally:
        conn.close()

@perfumes_bp.route('/perfumes/<int:perfume_id>/reviews', methods=['GET'])
def get_reviews(perfume_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Verify perfume exists
            cursor.execute("SELECT id, name FROM perfumes WHERE id = %s", (perfume_id,))
            perfume = cursor.fetchone()
            if not perfume:
                return jsonify({'error': 'Perfume not found'}), 404
            
            # Get reviews with user info
            sql = """
                SELECT r.id, r.rating, r.comment, r.created_at, u.username as user_name, u.id as user_id
                FROM reviews r
                JOIN users u ON r.user_id = u.id
                WHERE r.perfume_id = %s
                ORDER BY r.created_at DESC
            """
            cursor.execute(sql, (perfume_id,))
            reviews = cursor.fetchall()
            
            # Calculate average rating
            if reviews:
                avg_rating = sum(r['rating'] for r in reviews) / len(reviews)
                perfume['average_rating'] = round(avg_rating, 1)
                perfume['total_reviews'] = len(reviews)
            else:
                perfume['average_rating'] = 0
                perfume['total_reviews'] = 0
                
    except Exception as e:
        logger.error(f"Error retrieving reviews: {str(e)}")
        return jsonify({'error': 'Failed to retrieve reviews'}), 500
    finally:
        conn.close()
    
    return jsonify({
        'perfume': perfume,
        'reviews': reviews
    }), 200

@perfumes_bp.route('/perfumes/<int:perfume_id>/reviews/<int:review_id>', methods=['DELETE'])
def delete_review(perfume_id, review_id):
    # Try admin first, then customer
    admin_data, admin_err, admin_code = verify_admin_token(request)
    if admin_err:
        # Admin auth failed, try customer auth
        customer_data, customer_err, customer_code = verify_customer_token(request)
        if customer_err:
            return customer_err, customer_code
        
        user_id = customer_data.get('user_id')
        is_admin = False
    else:
        is_admin = True
        user_id = None

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Get review details with ownership check
            cursor.execute(
                """
                SELECT r.user_id, u.username 
                FROM reviews r 
                JOIN users u ON r.user_id = u.id 
                WHERE r.id = %s AND r.perfume_id = %s
                """, 
                (review_id, perfume_id)
            )
            review = cursor.fetchone()
            
            if not review:
                return jsonify({'error': 'Review not found'}), 404
            
            # Permission check
            if is_admin:
                # Admin can delete any review
                pass
            elif review['user_id'] != user_id:
                return jsonify({'error': 'You can only delete your own reviews'}), 403
            
            # Delete review
            cursor.execute(
                "DELETE FROM reviews WHERE id = %s AND perfume_id = %s", 
                (review_id, perfume_id)
            )
            
            if cursor.rowcount == 0:
                return jsonify({'error': 'Review not found or already deleted'}), 404
        
        conn.commit()
        logger.info(f"Review {review_id} deleted by {'admin' if is_admin else f'user {user_id}'}")
        return jsonify({'message': 'Review deleted successfully'}), 200
        
    except Exception as e:
        conn.rollback()
        logger.error(f"Error deleting review {review_id}: {str(e)}")
        return jsonify({'error': f'Database error: {str(e)}'}), 500
    finally:
        conn.close()

@perfumes_bp.route('/admin/reviews', methods=['GET'])
def get_all_reviews_admin():
    _, err, code = verify_admin_token(request)
    if err:
        return err, code

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
                SELECT r.id, r.perfume_id, p.name as perfume_name, r.user_id, 
                       u.username as user_name, u.email, r.rating, r.comment, r.created_at
                FROM reviews r
                JOIN perfumes p ON r.perfume_id = p.id
                JOIN users u ON r.user_id = u.id
                ORDER BY r.created_at DESC
            """
            cursor.execute(sql)
            reviews = cursor.fetchall()
            
            # Group reviews by perfume for easier admin viewing
            grouped_reviews = {}
            for review in reviews:
                perfume_id = review['perfume_id']
                if perfume_id not in grouped_reviews:
                    grouped_reviews[perfume_id] = {
                        'perfume_name': review['perfume_name'],
                        'reviews': []
                    }
                grouped_reviews[perfume_id]['reviews'].append(review)
                
        logger.info(f"Retrieved {len(reviews)} reviews for admin")
    except Exception as e:
        logger.error(f"Error retrieving all reviews: {str(e)}")
        return jsonify({'error': 'Failed to retrieve reviews'}), 500
    finally:
        conn.close()
    
    return jsonify({
        'total_reviews': len(reviews),
        'reviews_by_perfume': grouped_reviews
    }), 200

@perfumes_bp.route('/admin/reviews/<int:review_id>', methods=['DELETE'])
def delete_review_admin(review_id):
    _, err, code = verify_admin_token(request)
    if err:
        return err, code

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Check if review exists and get details
            cursor.execute("""
                SELECT r.id, r.perfume_id, p.name as perfume_name, u.username
                FROM reviews r
                JOIN perfumes p ON r.perfume_id = p.id
                JOIN users u ON r.user_id = u.id
                WHERE r.id = %s
            """, (review_id,))
            review = cursor.fetchone()
            
            if not review:
                return jsonify({'error': 'Review not found'}), 404
            
            # Delete review
            cursor.execute("DELETE FROM reviews WHERE id = %s", (review_id,))
            
            if cursor.rowcount == 0:
                return jsonify({'error': 'Review not found or already deleted'}), 404
                
        conn.commit()
        logger.info(f"Admin deleted review {review_id} for {review['perfume_name']} by {review['username']}")
        return jsonify({
            'message': 'Review deleted successfully',
            'deleted_review': {
                'id': review_id,
                'perfume_name': review['perfume_name'],
                'deleted_by': review['username']
            }
        }), 200
    except Exception as e:
        conn.rollback()
        logger.error(f"Error deleting review {review_id}: {str(e)}")
        return jsonify({'error': f'Database error: {str(e)}'}), 500
    finally:
        conn.close()

@perfumes_bp.route('/users/<int:user_id>/reviews', methods=['GET'])
def get_user_reviews(user_id):
    customer_data, err, code = verify_customer_token(request)
    if err:
        return err, code
    
    # Only allow user to see their own reviews
    if customer_data.get('user_id') != user_id:
        return jsonify({'error': 'You can only view your own reviews'}), 403

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
                SELECT r.id, r.perfume_id, p.name as perfume_name, p.price,
                       r.rating, r.comment, r.created_at
                FROM reviews r
                JOIN perfumes p ON r.perfume_id = p.id
                WHERE r.user_id = %s
                ORDER BY r.created_at DESC
            """
            cursor.execute(sql, (user_id,))
            user_reviews = cursor.fetchall()
    except Exception as e:
        logger.error(f"Error retrieving user reviews: {str(e)}")
        return jsonify({'error': 'Failed to retrieve reviews'}), 500
    finally:
        conn.close()
    
    return jsonify({'reviews': user_reviews}), 200
# --------------------------------------------------------------
#  NEW PUBLIC ENDPOINT – show *all* reviews
# --------------------------------------------------------------
@perfumes_bp.route('/reviews', methods=['GET'])
def get_all_reviews():
    """
    Public endpoint – returns every review in the system.
    No authentication required.
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # 1. Grab every review + perfume + user info
            sql_reviews = """
                SELECT
                    r.id, r.rating, r.comment, r.created_at,
                    r.perfume_id, p.name AS perfume_name,
                    r.user_id, u.username AS user_name
                FROM reviews r
                JOIN perfumes p ON r.perfume_id = p.id
                JOIN users u ON r.user_id = u.id
                ORDER BY r.created_at DESC
            """
            cursor.execute(sql_reviews)
            all_reviews = cursor.fetchall()

            # 2. Build per-perfume aggregates (average rating, total count)
            sql_aggregates = """
                SELECT
                    p.id AS perfume_id,
                    p.name AS perfume_name,
                    COALESCE(AVG(r.rating), 0) AS avg_rating,
                    COUNT(r.id) AS total_reviews
                FROM perfumes p
                LEFT JOIN reviews r ON r.perfume_id = p.id
                GROUP BY p.id, p.name
                ORDER BY avg_rating DESC, p.name
            """
            cursor.execute(sql_aggregates)
            perfume_stats = cursor.fetchall()

            # 3. Global average (optional but handy)
            if all_reviews:
                global_avg = sum(r['rating'] for r in all_reviews) / len(all_reviews)
            else:
                global_avg = 0.0

    except Exception as e:
        logger.error(f"Error in get_all_reviews: {str(e)}")
        return jsonify({'error': 'Failed to retrieve reviews'}), 500
    finally:
        conn.close()

    return jsonify({
        'global_average_rating': round(global_avg, 2),
        'total_reviews': len(all_reviews),
        'perfume_statistics': [
            {
                'perfume_id': s['perfume_id'],
                'perfume_name': s['perfume_name'],
                'average_rating': round(s['avg_rating'], 2),
                'total_reviews': s['total_reviews']
            } for s in perfume_stats
        ],
        'reviews': [
            {
                'review_id': r['id'],
                'perfume_id': r['perfume_id'],
                'perfume_name': r['perfume_name'],
                'user_id': r['user_id'],
                'user_name': r['user_name'],
                'rating': r['rating'],
                'comment': r['comment'],
                'created_at': r['created_at'].isoformat() if r['created_at'] else None
            } for r in all_reviews
        ]
    }), 200