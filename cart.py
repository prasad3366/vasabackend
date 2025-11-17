# cart.py
from flask import Blueprint, request, jsonify
import pymysql
from config import Config
import jwt
from functools import wraps
from datetime import datetime
import logging

cart_bp = Blueprint('cart', __name__)
logger = logging.getLogger(__name__)

def get_db_connection():
    try:
        return pymysql.connect(
            host=Config.DB_HOST,
            user=Config.DB_USERNAME,
            password=Config.DB_PASSWORD,
            database=Config.DB_NAME,
            cursorclass=pymysql.cursors.DictCursor
        )
    except Exception as e:
        logger.error(f"DB Connection Failed: {e}")
        return None


# ==================== TOKEN VERIFICATION ====================
def verify_customer_token(request):
    token = request.headers.get('Authorization')
    if not token:
        return None, jsonify({'error': 'Token missing'}), 401
    if token.lower().startswith('bearer '):
        return None, jsonify({'error': 'Use raw token, not Bearer'}), 401
    try:
        data = jwt.decode(token.strip(), Config.SECRET_KEY, algorithms=['HS256'])
        if data.get('role_id') != 2:
            return None, jsonify({'error': 'Access denied — Customer only'}), 403
        return data, None, None
    except jwt.ExpiredSignatureError:
        return None, jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return None, jsonify({'error': 'Invalid token'}), 401


def verify_admin_token(request):
    token = request.headers.get('Authorization')
    if not token:
        return None, jsonify({'error': 'Token missing'}), 401
    if token.lower().startswith('bearer '):
        return None, jsonify({'error': 'Use raw token, not Bearer'}), 401
    try:
        payload = jwt.decode(token.strip(), Config.SECRET_KEY, algorithms=['HS256'])
        if payload.get('role_id') != 1:
            return None, jsonify({'error': 'Access denied – Admin only'}), 403
        return payload, None, None
    except jwt.ExpiredSignatureError:
        return None, jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return None, jsonify({'error': 'Invalid token'}), 401


def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        payload, err, code = verify_customer_token(request)
        if err:
            return err, code
        request.user_id = payload['user_id']
        request.username = payload.get('username')
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        payload, err_resp, code = verify_admin_token(request)
        if err_resp:
            return err_resp, code
        request.admin_id = payload['user_id']
        return f(*args, **kwargs)
    return wrapper


# ==================== HELPER: ATTACH ORDER ITEMS ====================
def attach_order_items(cursor, orders, base_url):
    for order in orders:
        cursor.execute("""
            SELECT 
                oi.perfume_id, p.name, oi.quantity,
                COALESCE(oi.size, p.size) AS size,
                oi.unit_price,
                (oi.quantity * oi.unit_price) AS subtotal
            FROM order_items oi
            JOIN perfumes p ON oi.perfume_id = p.id
            WHERE oi.order_id = %s
        """, (order['id'],))
        items = cursor.fetchall()
        for item in items:
            item['photo_url'] = f"{base_url}/perfumes/photo/{item['perfume_id']}"
        order['items'] = items
        order['grand_total'] = round(
            float(order.get('total_amount') or 0) +
            float(order.get('shipping_cost') or 0) +
            float(order.get('tax_amount') or 0), 2
        )


# ==================== CART ROUTES ====================
@cart_bp.route('/cart', methods=['POST'])
@jwt_required
def add_to_cart():
    user_id = request.user_id
    data = request.get_json(silent=True) or {}
    items = data.get('items', [])
    if not items:
        return jsonify({"error": "No items provided"}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Server error"}), 500

    cursor = conn.cursor()
    added = []
    errors = []

    try:
        for item in items:
            try:
                pid = int(item['perfume_id'])
                qty = int(item.get('quantity', 1))
                size = item.get('size')
            except (ValueError, TypeError):
                errors.append({"perfume_id": item.get('perfume_id'), "error": "Invalid data"})
                continue

            cursor.execute("SELECT quantity, size FROM perfumes WHERE id = %s AND available = 1", (pid,))
            perfume = cursor.fetchone()
            if not perfume:
                errors.append({"perfume_id": pid, "error": "Perfume not available"})
                continue

            stock = perfume['quantity']
            db_size = perfume['size']
            use_size = size if size else db_size

            cursor.execute(
                "SELECT quantity FROM carts WHERE user_id = %s AND perfume_id = %s AND COALESCE(size, '') = COALESCE(%s, '')",
                (user_id, pid, use_size)
            )
            current = cursor.fetchone()
            current_qty = current['quantity'] if current else 0
            new_total = current_qty + qty
            if new_total > stock:
                errors.append({"perfume_id": pid, "error": f"Only {stock} in stock (you have {current_qty})"})
                continue

            cursor.execute("""
                INSERT INTO carts (user_id, perfume_id, quantity, size)
                VALUES (%s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    quantity = VALUES(quantity),
                    size = COALESCE(VALUES(size), size)
            """, (user_id, pid, new_total, use_size))

            added.append({"perfume_id": pid, "total_in_cart": new_total, "size": use_size})

        conn.commit()

        if errors and not added:
            return jsonify({"errors": errors}), 400
        if errors:
            return jsonify({"message": "Partial success", "added": added, "errors": errors}), 207

        return jsonify({"message": "All added", "added": added}), 201

    except Exception as e:
        conn.rollback()
        logger.error(f"Add to cart error (user {user_id}): {e}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()
        conn.close()


@cart_bp.route('/cart', methods=['GET'])
@jwt_required
def view_cart():
    user_id = request.user_id
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Server error"}), 500

    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT c.id, c.perfume_id, p.name, p.price, c.quantity, COALESCE(c.size, p.size) AS size,
                   p.quantity AS stock, c.added_at
            FROM carts c
            JOIN perfumes p ON c.perfume_id = p.id
            WHERE c.user_id = %s
            ORDER BY c.added_at DESC
        """, (user_id,))
        items = cursor.fetchall()
        base_url = request.host_url.rstrip('/')

        for item in items:
            item['photo_url'] = f"{base_url}/perfumes/photo/{item['perfume_id']}"
            item['in_stock'] = item['stock'] >= item['quantity']

        return jsonify({"cart_items": items}), 200

    except Exception as e:
        logger.error(f"View cart error (user {user_id}): {e}")
        return jsonify({"error": "Failed to load cart"}), 500
    finally:
        cursor.close()
        conn.close()


@cart_bp.route('/cart/<int:perfume_id>', methods=['DELETE'])
@jwt_required
def remove_from_cart(perfume_id):
    user_id = request.user_id
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Server error"}), 500

    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM carts WHERE user_id = %s AND perfume_id = %s", (user_id, perfume_id))
        if cursor.rowcount == 0:
            return jsonify({"error": "Item not in your cart"}), 404

        conn.commit()
        return jsonify({"message": "Item removed"}), 200

    except Exception as e:
        conn.rollback()
        logger.error(f"Delete error (user {user_id}): {e}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()
        conn.close()


# ==================== CHECKOUT ====================
@cart_bp.route('/checkout', methods=['POST'])
@jwt_required
def checkout():
    user_id = request.user_id
    data = request.get_json(silent=True) or {}

    required = ['shipping', 'payment_method', 'items', 'totalPrice', 'tax', 'shippingCost']
    for field in required:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400

    shipping = data['shipping']
    payment_method = data['payment_method'].lower()
    items = data['items']
    card_details = data.get('card_details', {})

    if payment_method not in ['card', 'cod']:
        return jsonify({"error": "payment_method must be 'card' or 'cod'"}), 400

    if not items or not isinstance(items, list):
        return jsonify({"error": "Items must be a non-empty list"}), 400

    ship_keys = ['firstName', 'lastName', 'email', 'phone', 'address', 'city', 'state', 'zip']
    for key in ship_keys:
        if not shipping.get(key) or not str(shipping[key]).strip():
            return jsonify({"error": f"Shipping {key} is required and cannot be empty"}), 400

    if payment_method == 'card':
        card_keys = ['cardName', 'cardNumber', 'expiry', 'cvv']
        for key in card_keys:
            value = card_details.get(key)
            if not value or not str(value).strip():
                return jsonify({"error": f"Card {key} is required"}), 400
            if key == 'cardNumber' and (len(value.replace(' ', '')) < 13 or len(value.replace(' ', '')) > 19):
                return jsonify({"error": "Invalid card number"}), 400
            if key == 'cvv' and not (value.isdigit() and len(value) in [3, 4]):
                return jsonify({"error": "CVV must be 3 or 4 digits"}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Database unavailable"}), 500

    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO orders (
                user_id, total_amount, shipping_cost, tax_amount,
                shipping_first_name, shipping_last_name, shipping_email,
                shipping_phone, shipping_address, shipping_city,
                shipping_state, shipping_zip, payment_method, status
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            user_id,
            float(data['totalPrice']),
            float(data['shippingCost']),
            float(data['tax']),
            shipping['firstName'].strip(),
            shipping['lastName'].strip(),
            shipping['email'].strip().lower(),
            shipping['phone'].strip(),
            shipping['address'].strip(),
            shipping['city'].strip(),
            shipping['state'].strip(),
            shipping['zip'].strip(),
            payment_method,
            'pending'
        ))
        order_id = cursor.lastrowid

        for item in items:
            try:
                perfume_id = int(item['perfume_id'])
                quantity = int(item['quantity'])
                size = item.get('selectedSize') or None
                unit_price = float(item['price'])
            except (KeyError, ValueError, TypeError):
                conn.rollback()
                return jsonify({"error": "Invalid item data format"}), 400

            if quantity <= 0:
                return jsonify({"error": "Quantity must be positive"}), 400

            cursor.execute("SELECT quantity, name FROM perfumes WHERE id = %s AND available = 1", (perfume_id,))
            perfume = cursor.fetchone()
            if not perfume:
                conn.rollback()
                return jsonify({"error": f"Perfume ID {perfume_id} not found or unavailable"}), 404

            if perfume['quantity'] < quantity:
                conn.rollback()
                return jsonify({"error": f"Only {perfume['quantity']} left of {perfume['name']}"}), 400

            cursor.execute("""
                INSERT INTO order_items (order_id, perfume_id, quantity, size, unit_price)
                VALUES (%s, %s, %s, %s, %s)
            """, (order_id, perfume_id, quantity, size, unit_price))

            cursor.execute("UPDATE perfumes SET quantity = quantity - %s WHERE id = %s", (quantity, perfume_id))

        if payment_method == 'card':
            last4 = str(card_details['cardNumber']).replace(' ', '')[-4:]
            cursor.execute("""
                INSERT INTO payment_details 
                (order_id, payment_method, card_last4, card_holder_name, expiry)
                VALUES (%s, %s, %s, %s, %s)
            """, (order_id, 'card', last4, card_details['cardName'], card_details['expiry']))

        cursor.execute("DELETE FROM carts WHERE user_id = %s", (user_id,))

        final_status = 'paid' if payment_method == 'card' else 'cod_pending'
        cursor.execute("UPDATE orders SET status = %s WHERE id = %s", (final_status, order_id))

        conn.commit()

        return jsonify({
            "message": "Order placed successfully!",
            "order_id": order_id,
            "status": final_status,
            "payment_method": payment_method,
            "total": float(data['totalPrice']) + float(data['shippingCost']) + float(data['tax'])
        }), 201

    except Exception as e:
        conn.rollback()
        logger.error(f"Checkout failed (user {user_id}): {str(e)}")
        return jsonify({"error": "Order failed. Please try again later."}), 500
    finally:
        cursor.close()
        conn.close()


# ==================== USER ORDER ROUTES ====================
@cart_bp.route('/orders', methods=['GET'])
@jwt_required
def get_orders():
    user_id = request.user_id
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Server error"}), 500

    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT 
                id, total_amount, status, payment_method, created_at,
                shipping_first_name, shipping_last_name, shipping_city,
                shipping_address, shipping_zip, shipping_phone, shipping_email
            FROM orders 
            WHERE user_id = %s 
            ORDER BY created_at DESC
        """, (user_id,))
        orders = cursor.fetchall()

        base_url = request.host_url.rstrip('/')
        attach_order_items(cursor, orders, base_url)

        return jsonify({"orders": orders}), 200

    except Exception as e:
        logger.error(f"Get orders failed (user {user_id}): {e}")
        return jsonify({"error": "Failed to load orders"}), 500
    finally:
        cursor.close()
        conn.close()


@cart_bp.route('/recent-orders', methods=['GET'])
@jwt_required
def recent_orders():
    user_id = request.user_id
    limit = max(1, min(request.args.get('limit', 5, type=int), 20))

    conn = get_db_connection()
    if not conn:
        return jsonify({"recent_orders": [], "count": 0, "message": "Loading..."}), 200

    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT id, total_amount, shipping_cost, tax_amount, status, 
                   payment_method, created_at, shipping_city
            FROM orders 
            WHERE user_id = %s 
            ORDER BY created_at DESC 
            LIMIT %s
        """, (user_id, limit))

        orders = cursor.fetchall()
        if not orders:
            return jsonify({"recent_orders": [], "count": 0, "message": "No orders yet"}), 200

        result = []
        base_url = request.host_url.rstrip('/')

        for order in orders:
            order_id = order['id']
            cursor.execute("""
                SELECT p.name, oi.quantity, oi.unit_price, oi.perfume_id
                FROM order_items oi
                JOIN perfumes p ON oi.perfume_id = p.id
                WHERE oi.order_id = %s
            """, (order_id,))
            items = cursor.fetchall()

            order_data = {
                "order_id": order_id,
                "date": order['created_at'].strftime("%d %b %Y"),
                "time": order['created_at'].strftime("%I:%M %p"),
                "city": order['shipping_city'],
                "status": order['status'],
                "grand_total": round(float(order['total_amount']) + 
                                   float(order.get('shipping_cost') or 0) + 
                                   float(order.get('tax_amount') or 0), 2),
                "items": [
                    {
                        "name": item['name'],
                        "quantity": item['quantity'],
                        "photo": f"{base_url}/perfumes/photo/{item['perfume_id']}"
                    } for item in items
                ],
                "items_count": len(items)
            }
            result.append(order_data)

        return jsonify({
            "recent_orders": result,
            "count": len(result),
            "message": "Your latest orders"
        }), 200

    except Exception as e:
        logger.error(f"User {user_id} recent orders: {e}")
        return jsonify({"recent_orders": [], "count": 0, "message": "Try again"}), 200
    finally:
        cursor.close()
        conn.close()


# ==================== ADMIN: ALL ORDERS ====================

@cart_bp.route('/admin/orders', methods=['GET'])
@admin_required
def admin_all_orders():
    page = max(request.args.get('page', 1, int), 1)
    limit = min(request.args.get('limit', 20, int), 100)
    status_filter = request.args.get('status')
    start_date = request.args.get('start')  # Format: YYYY-MM-DD
    end_date = request.args.get('end')      # Format: YYYY-MM-DD
    offset = (page - 1) * limit

    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Database unavailable"}), 500

    cursor = conn.cursor()
    try:
        # Build WHERE clause with filters
        where_clauses = []
        params = []
        
        if status_filter:
            where_clauses.append("o.status = %s")
            params.append(status_filter)
        
        if start_date:
            try:
                start = datetime.strptime(start_date, '%Y-%m-%d')
                where_clauses.append("DATE(o.created_at) >= %s")
                params.append(start.date())
            except ValueError:
                pass
        
        if end_date:
            try:
                end = datetime.strptime(end_date, '%Y-%m-%d')
                where_clauses.append("DATE(o.created_at) <= %s")
                params.append(end.date())
            except ValueError:
                pass

        where_sql = " AND ".join(where_clauses)
        if where_sql:
            where_sql = " WHERE " + where_sql

        # Count total matching orders
        count_sql = f"SELECT COUNT(*) AS total FROM orders o{where_sql}"
        cursor.execute(count_sql, params)
        total = cursor.fetchone()['total']

        # Fetch filtered orders
        sql = f"""
            SELECT 
                o.id, o.user_id, u.username,
                o.total_amount, o.shipping_cost, o.tax_amount,
                o.status, o.payment_method, o.created_at,
                o.shipping_first_name, o.shipping_last_name,
                o.shipping_address, o.shipping_city,
                o.shipping_state, o.shipping_zip, o.shipping_phone, o.shipping_email
            FROM orders o
            JOIN users u ON o.user_id = u.id
            {where_sql}
            ORDER BY o.created_at DESC LIMIT %s OFFSET %s
        """
        fetch_params = params + [limit, offset]
        cursor.execute(sql, fetch_params)
        orders = cursor.fetchall()

        base_url = request.host_url.rstrip('/')
        attach_order_items(cursor, orders, base_url)

        meta = {
            "page": page,
            "limit": limit,
            "total": total,
            "pages": (total + limit - 1) // limit,
            "has_next": page * limit < total,
            "has_prev": page > 1
        }

        return jsonify({"orders": orders, "meta": meta}), 200

    except Exception as e:
        logger.error(f"Admin all-orders error (admin {request.admin_id}): {e}")
        return jsonify({"error": "Failed to load orders"}), 500
    finally:
        cursor.close()
        conn.close()