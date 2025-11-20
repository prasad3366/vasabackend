# main.py
from flask import Flask, send_from_directory
from auth import auth_bp
from perfumes import perfumes_bp
from cart import cart_bp
from favorites import favorites_bp   
from revenue import revenue_bp       # ← NEW: Favorites blueprint
from flask_cors import CORS
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__, static_folder='../frontend')

# Enable CORS for Vite frontend
CORS(app, resources={
    r"/*": {
        "origins": [
            "http://localhost:5173",
            "http://127.0.0.1:5173"
        ],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "expose_headers": ["Content-Type"],
        "supports_credentials": True
    }
})

# ========================================
# Register Blueprints – NO /api prefix
# ========================================
app.register_blueprint(auth_bp)          # → /login, /register
app.register_blueprint(perfumes_bp)      # → /perfumes, /perfumes/photo/1
app.register_blueprint(cart_bp)          # → /cart, /cart/5
app.register_blueprint(favorites_bp)  
app.register_blueprint(revenue_bp)   # → /favorites, /favorites/1

# ========================================
# Serve Frontend (Vite)
# ========================================
@app.route('/')
def serve_frontend():
    return send_from_directory('../frontend', 'index.html')

@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory('../frontend', filename)

# ========================================
if __name__ == '__main__':
    logger.info("Flask app running at http://127.0.0.1:5000")
    app.run(debug=True, host="127.0.0.1", port=5000)