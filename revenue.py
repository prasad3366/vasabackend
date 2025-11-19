from flask import Blueprint, request, jsonify
import pymysql
from config import Config
import jwt
from functools import wraps
from datetime import datetime, timedelta
import logging

revenue_bp = Blueprint('revenue', __name__)
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


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        payload, err_resp, code = verify_admin_token(request)
        if err_resp:
            return err_resp, code
        request.admin_id = payload['user_id']
        return f(*args, **kwargs)
    return wrapper


# ==================== SALES REPORT ROUTE ====================
@revenue_bp.route('/admin/sales/report', methods=['GET'])
@admin_required
def sales_report():
    """
    Get sales report with metrics:
    - Total sales
    - Total orders
    - Average order value
    - Top perfumes
    - Daily sales breakdown
    """
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database unavailable"}), 500

        cursor = conn.cursor()

        # Get date range from query params (optional)
        days = request.args.get('days', 30, type=int)
        start_date = datetime.now() - timedelta(days=days)

        # Total sales and orders
        cursor.execute("""
            SELECT 
                COUNT(*) AS total_orders,
                SUM(total_amount) AS total_sales,
                SUM(shipping_cost) AS total_shipping,
                SUM(tax_amount) AS total_tax,
                AVG(total_amount) AS avg_order_value
            FROM orders 
            WHERE created_at >= %s AND status != 'cancelled'
        """, (start_date,))
        
        sales_summary = cursor.fetchone()

        # Orders by status
        cursor.execute("""
            SELECT status, COUNT(*) AS count
            FROM orders 
            WHERE created_at >= %s
            GROUP BY status
        """, (start_date,))
        
        orders_by_status = cursor.fetchall()

        # Top 10 best-selling perfumes
        cursor.execute("""
            SELECT 
                p.id,
                p.name,
                SUM(oi.quantity) AS total_quantity,
                SUM(oi.quantity * oi.unit_price) AS total_revenue,
                COUNT(DISTINCT oi.order_id) AS num_orders
            FROM order_items oi
            JOIN perfumes p ON oi.perfume_id = p.id
            JOIN orders o ON oi.order_id = o.id
            WHERE o.created_at >= %s AND o.status != 'cancelled'
            GROUP BY p.id, p.name
            ORDER BY total_revenue DESC
            LIMIT 10
        """, (start_date,))
        
        top_perfumes = cursor.fetchall()

        # Daily sales breakdown (last 30 days)
        cursor.execute("""
            SELECT 
                DATE(created_at) AS date,
                COUNT(*) AS orders,
                SUM(total_amount + COALESCE(shipping_cost, 0) + COALESCE(tax_amount, 0)) AS daily_revenue
            FROM orders 
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY) AND status != 'cancelled'
            GROUP BY DATE(created_at)
            ORDER BY date ASC
        """)
        
        daily_sales = cursor.fetchall()

        # Convert daily_sales to handle date serialization
        daily_sales_formatted = []
        for sale in daily_sales:
            daily_sales_formatted.append({
                'date': sale['date'].strftime("%Y-%m-%d") if sale['date'] else None,
                'orders': sale['orders'],
                'revenue': float(sale['daily_revenue'] or 0)
            })

        # Payment method breakdown
        cursor.execute("""
            SELECT 
                payment_method,
                COUNT(*) AS count,
                SUM(total_amount + COALESCE(shipping_cost, 0) + COALESCE(tax_amount, 0)) AS revenue
            FROM orders 
            WHERE created_at >= %s AND status != 'cancelled'
            GROUP BY payment_method
        """, (start_date,))
        
        payment_methods = cursor.fetchall()

        cursor.close()
        conn.close()

        return jsonify({
            "success": True,
            "summary": {
                "total_orders": sales_summary['total_orders'] or 0,
                "total_sales": float(sales_summary['total_sales'] or 0),
                "total_shipping": float(sales_summary['total_shipping'] or 0),
                "total_tax": float(sales_summary['total_tax'] or 0),
                "avg_order_value": float(sales_summary['avg_order_value'] or 0),
                "period_days": days
            },
            "orders_by_status": orders_by_status,
            "top_perfumes": top_perfumes,
            "daily_sales": daily_sales_formatted,
            "payment_methods": payment_methods,
            "timestamp": datetime.now().isoformat()
        }), 200

    except Exception as e:
        logger.error(f"Sales report error (admin {request.admin_id}): {e}")
        return jsonify({"error": f"Failed to generate sales report: {str(e)}"}), 500


# ==================== REVENUE BY PERFUME ====================
@revenue_bp.route('/admin/revenue/perfume/<int:perfume_id>', methods=['GET'])
@admin_required
def perfume_revenue(perfume_id):
    """
    Get revenue details for a specific perfume
    """
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database unavailable"}), 500

        cursor = conn.cursor()

        days = request.args.get('days', 30, type=int)
        start_date = datetime.now() - timedelta(days=days)

        # Get perfume info and revenue
        cursor.execute("""
            SELECT 
                p.id,
                p.name,
                p.price,
                SUM(oi.quantity) AS total_quantity_sold,
                COUNT(DISTINCT oi.order_id) AS total_orders,
                SUM(oi.quantity * oi.unit_price) AS total_revenue,
                AVG(oi.unit_price) AS avg_price_sold
            FROM perfumes p
            LEFT JOIN order_items oi ON p.id = oi.perfume_id
            LEFT JOIN orders o ON oi.order_id = o.id
            WHERE p.id = %s AND (o.created_at IS NULL OR (o.created_at >= %s AND o.status != 'cancelled'))
            GROUP BY p.id, p.name, p.price
        """, (perfume_id, start_date))
        
        perfume_data = cursor.fetchone()

        if not perfume_data:
            cursor.close()
            conn.close()
            return jsonify({"error": "Perfume not found"}), 404

        # Daily sales for this perfume
        cursor.execute("""
            SELECT 
                DATE(o.created_at) AS date,
                SUM(oi.quantity) AS quantity,
                SUM(oi.quantity * oi.unit_price) AS revenue
            FROM order_items oi
            JOIN orders o ON oi.order_id = o.id
            WHERE oi.perfume_id = %s AND o.created_at >= %s AND o.status != 'cancelled'
            GROUP BY DATE(o.created_at)
            ORDER BY date ASC
        """, (perfume_id, start_date))
        
        daily_data = cursor.fetchall()

        daily_formatted = []
        for day in daily_data:
            daily_formatted.append({
                'date': day['date'].strftime("%Y-%m-%d") if day['date'] else None,
                'quantity': day['quantity'],
                'revenue': float(day['revenue'] or 0)
            })

        cursor.close()
        conn.close()

        return jsonify({
            "success": True,
            "perfume": perfume_data,
            "daily_sales": daily_formatted,
            "period_days": days,
            "timestamp": datetime.now().isoformat()
        }), 200

    except Exception as e:
        logger.error(f"Perfume revenue error (admin {request.admin_id}): {e}")
        return jsonify({"error": f"Failed to get perfume revenue: {str(e)}"}), 500


# ==================== MONTHLY REVENUE SUMMARY ====================
@revenue_bp.route('/admin/revenue/monthly', methods=['GET'])
@admin_required
def monthly_revenue():
    """
    Get revenue breakdown by month (last 12 months)
    """
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database unavailable"}), 500

        cursor = conn.cursor()

        cursor.execute("""
            SELECT 
                DATE_FORMAT(created_at, '%Y-%m') AS month,
                COUNT(*) AS total_orders,
                SUM(total_amount + COALESCE(shipping_cost, 0) + COALESCE(tax_amount, 0)) AS total_revenue,
                AVG(total_amount) AS avg_order_value,
                SUM(CASE WHEN status = 'paid' THEN 1 ELSE 0 END) AS completed_orders,
                SUM(CASE WHEN status = 'cancelled' THEN 1 ELSE 0 END) AS cancelled_orders
            FROM orders 
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 12 MONTH)
            GROUP BY DATE_FORMAT(created_at, '%Y-%m')
            ORDER BY month DESC
        """)
        
        monthly_data = cursor.fetchall()

        cursor.close()
        conn.close()

        # Format data
        formatted_data = []
        for month in monthly_data:
            formatted_data.append({
                'month': month['month'],
                'total_orders': month['total_orders'],
                'total_revenue': float(month['total_revenue'] or 0),
                'avg_order_value': float(month['avg_order_value'] or 0),
                'completed_orders': month['completed_orders'],
                'cancelled_orders': month['cancelled_orders']
            })

        return jsonify({
            "success": True,
            "monthly_revenue": formatted_data,
            "timestamp": datetime.now().isoformat()
        }), 200

    except Exception as e:
        logger.error(f"Monthly revenue error (admin {request.admin_id}): {e}")
        return jsonify({"error": f"Failed to get monthly revenue: {str(e)}"}), 500