import os
import random
import re
import threading
import logging
import json
from logging.handlers import RotatingFileHandler
from html import escape
from datetime import datetime, timedelta

import pymysql
from flask import Flask, jsonify, request
from flask_mail import Mail, Message
from werkzeug.security import check_password_hash, generate_password_hash
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# LOGGING SETUP
# Two directories:
#   logs/success/  — all successful API responses (2xx)
#   logs/error/    — all errors, exceptions, failed DB ops (4xx, 5xx)
# Each file rotates at 10 MB, keeps last 5 backups.
# ──────────────────────────────────────────────────────────────────────────────

SUCCESS_LOG_DIR = os.path.join(os.path.dirname(__file__), "logs", "success")
ERROR_LOG_DIR   = os.path.join(os.path.dirname(__file__), "logs", "error")

os.makedirs(SUCCESS_LOG_DIR, exist_ok=True)
os.makedirs(ERROR_LOG_DIR,   exist_ok=True)

def _make_logger(name: str, log_dir: str, level=logging.DEBUG) -> logging.Logger:
    """Create a rotating file logger that writes JSON lines."""
    logger = logging.getLogger(name)
    logger.setLevel(level)
    if not logger.handlers:
        handler = RotatingFileHandler(
            os.path.join(log_dir, f"{name}.log"),
            maxBytes=10 * 1024 * 1024,   # 10 MB per file
            backupCount=5,
            encoding="utf-8",
        )
        handler.setLevel(level)
        # Plain formatter — we build JSON manually so it's easy to parse
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
    return logger

success_logger = _make_logger("success", SUCCESS_LOG_DIR)
error_logger   = _make_logger("error",   ERROR_LOG_DIR)


def log_success(endpoint: str, method: str, status_code: int, message: str, extra: dict = None):
    """Write a JSON line to logs/success/success.log"""
    entry = {
        "timestamp":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "level":       "SUCCESS",
        "endpoint":    endpoint,
        "method":      method,
        "status_code": status_code,
        "message":     message,
    }
    if extra:
        entry.update(extra)
    success_logger.info(json.dumps(entry))


def log_error(endpoint: str, method: str, status_code: int, message: str, extra: dict = None, exc: Exception = None):
    """Write a JSON line to logs/error/error.log"""
    entry = {
        "timestamp":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "level":       "ERROR",
        "endpoint":    endpoint,
        "method":      method,
        "status_code": status_code,
        "message":     message,
    }
    if extra:
        entry.update(extra)
    if exc:
        entry["exception"] = str(exc)
        entry["exception_type"] = type(exc).__name__
    error_logger.error(json.dumps(entry))


def log_warning(endpoint: str, method: str, status_code: int, message: str, extra: dict = None):
    """Write a JSON line to logs/error/error.log with level WARNING (4xx)"""
    entry = {
        "timestamp":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "level":       "WARNING",
        "endpoint":    endpoint,
        "method":      method,
        "status_code": status_code,
        "message":     message,
    }
    if extra:
        entry.update(extra)
    error_logger.warning(json.dumps(entry))


# ──────────────────────────────────────────────────────────────────────────────
# REQUEST / RESPONSE HOOKS — auto-log every request
# ──────────────────────────────────────────────────────────────────────────────

@app.before_request
def handle_cors_preflight():
    if request.method == "OPTIONS":
        return "", 204


@app.after_request
def add_cors_and_log(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"

    # Skip logging for OPTIONS (preflight) and health check spam
    if request.method == "OPTIONS":
        return response

    status = response.status_code
    endpoint = request.path
    method   = request.method

    if 200 <= status < 300:
        log_success(endpoint, method, status, "Request completed successfully")
    elif 400 <= status < 500:
        log_warning(endpoint, method, status, f"Client error — {response.status}")
    elif status >= 500:
        log_error(endpoint, method, status, f"Server error — {response.status}")

    return response


# ──────────────────────────────────────────────────────────────────────────────
# DB CONFIG
# ──────────────────────────────────────────────────────────────────────────────

db_config = {
    "host":     os.getenv("DB_HOST", ""),
    "user":     os.getenv("DB_USER", ""),
    "password": os.getenv("DB_PASSWORD", ""),
    "database": os.getenv("DB_NAME", "cloud"),
}

app.config.update(
    MAIL_SERVER=os.getenv("MAIL_SERVER", "smtp.gmail.com"),
    MAIL_PORT=int(os.getenv("MAIL_PORT", "587")),
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.getenv("MAIL_USERNAME", ""),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD", ""),
)
mail = Mail(app)


def get_db_connection():
    try:
        conn = pymysql.connect(
            host=db_config["host"],
            user=db_config["user"],
            password=db_config["password"],
            database=db_config["database"],
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=False,
        )
        return conn
    except Exception as exc:
        log_error("DB_CONNECTION", "INTERNAL", 500, "Failed to connect to MySQL database", exc=exc)
        raise


# ──────────────────────────────────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def get_json_payload():
    return request.get_json(silent=True) or {}


def require_fields(data, fields):
    missing = [field for field in fields if not str(data.get(field, "")).strip()]
    if missing:
        log_warning(
            request.path, request.method, 400,
            "Missing required fields",
            extra={"missing_fields": missing},
        )
        return jsonify({"error": f"Missing required fields: {', '.join(missing)}"}), 400
    return None


def validate_password_strength(password):
    if len(password) < 8:
        return "Password must be at least 8 characters."
    if not re.search(r"[A-Z]", password):
        return "Password must include at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must include at least one lowercase letter."
    if not re.search(r"\d", password):
        return "Password must include at least one number."
    if not re.search(r"[^A-Za-z0-9]", password):
        return "Password must include at least one special character."
    return None


def serialize_cart_row(row):
    return {
        "id":                  row["id"],
        "product_id":          row["product_id"],
        "product_name":        row["product_name"],
        "product_image":       row["product_image"],
        "product_description": row["product_description"],
        "price":               float(row["price"]),
        "quantity":            row["quantity"],
        "subtotal":            float(row["price"]) * row["quantity"],
        "updated_at":          row["updated_at"].isoformat() if row["updated_at"] else None,
    }


def fetch_user_by_email(cursor, email):
    cursor.execute(
        """
        SELECT id, username, full_name, email, address, phone, otp_code, otp_expiry,
               last_login_otp_verified_at
        FROM users
        WHERE email = %s
        """,
        (email,),
    )
    return cursor.fetchone()


def should_require_daily_login_otp(user):
    last_verified = user.get("last_login_otp_verified_at")
    if not last_verified:
        return True
    return last_verified.date() != datetime.now().date()


def fetch_cart(cursor, user_id):
    cursor.execute(
        """
        SELECT id, product_id, product_name, product_image, product_description,
               price, quantity, updated_at
        FROM cart_items
        WHERE user_id = %s
        ORDER BY updated_at DESC, id DESC
        """,
        (user_id,),
    )
    rows  = cursor.fetchall()
    items = [serialize_cart_row(row) for row in rows]
    total = round(sum(item["subtotal"] for item in items), 2)
    return {"items": items, "total": total}


def serialize_payment_row(row):
    return {
        "id":                    row["id"],
        "order_id":              row["order_id"],
        "payment_type":          row["payment_type"],
        "payment_method":        row["payment_method"],
        "amount":                float(row["amount"]),
        "status":                row["status"],
        "transaction_reference": row["transaction_reference"],
        "notes":                 row["notes"],
        "created_at":            row["created_at"].isoformat() if row["created_at"] else None,
    }


def serialize_recharge_row(row):
    return {
        "id":                    row["id"],
        "mobile_number":         row["mobile_number"],
        "operator_name":         row["operator_name"],
        "plan_name":             row["plan_name"],
        "amount":                float(row["amount"]),
        "payment_method":        row["payment_method"],
        "status":                row["status"],
        "transaction_reference": row["transaction_reference"],
        "created_at":            row["created_at"].isoformat() if row["created_at"] else None,
    }


def serialize_service_activity_row(row):
    return {
        "id":            row["id"],
        "service_name":  row["service_name"],
        "service_path":  row["service_path"],
        "activity_type": row["activity_type"],
        "note":          row["note"],
        "created_at":    row["created_at"].isoformat() if row["created_at"] else None,
    }


def serialize_order_item(item):
    return {
        "product_id":    item["product_id"],
        "product_name":  item["product_name"],
        "product_image": item["product_image"],
        "price":         float(item["price"]),
        "quantity":      item["quantity"],
        "subtotal":      float(item["price"]) * item["quantity"],
    }


def normalize_order_item(item):
    price    = float(item.get("price") or 0)
    quantity = max(int(item.get("quantity") or 1), 1)
    return {
        "product_id":    str(item.get("product_id") or item.get("id") or "").strip() or "product",
        "product_name":  str(item.get("product_name") or item.get("name") or "Product").strip(),
        "product_image": str(item.get("product_image") or item.get("image") or "").strip() or None,
        "price":         price,
        "quantity":      quantity,
        "subtotal":      float(item.get("subtotal") or price * quantity),
    }


# ──────────────────────────────────────────────────────────────────────────────
# EMAIL HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def build_order_receipt(order_payload):
    items             = order_payload.get("items") or []
    total_quantity    = sum(int(item.get("quantity") or 0) for item in items)
    payment_method    = order_payload.get("payment_method") or "Not provided"
    payment_status    = order_payload.get("payment_status") or "Not provided"
    transaction_reference = order_payload.get("transaction_reference") or "Not provided"
    payment_notes     = order_payload.get("payment_notes") or "Not provided"
    shipping_phone    = order_payload.get("shipping_phone") or "Not provided"
    shipping_address  = order_payload.get("shipping_address") or "Not provided"

    item_lines = "\n".join(
        [
            (
                f"{index}. Product ID: {item.get('product_id') or 'Not provided'}\n"
                f"   Name: {item.get('product_name') or 'Product'}\n"
                f"   Image: {item.get('product_image') or 'Not provided'}\n"
                f"   Quantity: {int(item.get('quantity') or 0)}\n"
                f"   Unit Price: Rs. {float(item.get('price') or 0):.2f}\n"
                f"   Subtotal: Rs. {float(item.get('subtotal') or 0):.2f}"
            )
            for index, item in enumerate(items, start=1)
        ]
    ) or "No item details found."

    text_body = (
        f"Hello {order_payload['shipping_name']},\n\n"
        f"Your order #{order_payload['id']} has been placed successfully.\n\n"
        "Order Details\n"
        "-------------\n"
        f"Order ID: {order_payload['id']}\n"
        f"Order Date: {order_payload['created_at']}\n"
        f"Order Status: {order_payload['status']}\n\n"
        "Payment Details\n"
        "---------------\n"
        f"Payment Method: {payment_method}\n"
        f"Payment Status: {payment_status}\n"
        f"Transaction Reference: {transaction_reference}\n"
        f"Payment Notes: {payment_notes}\n\n"
        "Products Purchased\n"
        "------------------\n"
        f"{item_lines}\n\n"
        "Amount Summary\n"
        "--------------\n"
        f"Total Quantity: {total_quantity}\n"
        f"Total Paid: Rs. {float(order_payload['total_amount']):.2f}\n\n"
        "Thank you for shopping with Google Store."
    )

    html_lines = "".join(
        [
            (
                "<tr>"
                f"<td style='padding:8px;border-bottom:1px solid #e5e7eb;'>{escape(str(item.get('product_id') or ''))}</td>"
                f"<td style='padding:8px;border-bottom:1px solid #e5e7eb;'><strong>{escape(str(item.get('product_name') or 'Product'))}</strong></td>"
                f"<td style='padding:8px;border-bottom:1px solid #e5e7eb;text-align:center;'>{int(item.get('quantity') or 0)}</td>"
                f"<td style='padding:8px;border-bottom:1px solid #e5e7eb;text-align:right;'>Rs. {float(item.get('price') or 0):.2f}</td>"
                f"<td style='padding:8px;border-bottom:1px solid #e5e7eb;text-align:right;'>Rs. {float(item.get('subtotal') or 0):.2f}</td>"
                "</tr>"
            )
            for item in items
        ]
    ) or "<tr><td colspan='5'>No item details found.</td></tr>"

    escaped_address = escape(str(shipping_address)).replace("\n", "<br>")
    html_body = f"""
    <div style="font-family:Arial,sans-serif;max-width:760px;margin:0 auto;padding:24px;color:#202124;">
      <h2 style="color:#1a73e8;">Google Store Receipt</h2>
      <p>Your order <strong>#{order_payload['id']}</strong> has been placed successfully.</p>
      <div style="border:1px solid #e5e7eb;border-radius:10px;padding:14px;margin:16px 0;background:#f8fafc;">
        <h3>Customer Details</h3>
        <strong>Name:</strong> {escape(str(order_payload['shipping_name']))}<br>
        <strong>Email:</strong> {escape(str(order_payload['shipping_email']))}<br>
        <strong>Phone:</strong> {escape(str(shipping_phone))}<br>
        <strong>Address:</strong><br>{escaped_address}
      </div>
      <table style="width:100%;border-collapse:collapse;margin:20px 0;">
        <thead>
          <tr style="background:#f8f9fa;">
            <th style="padding:8px;text-align:left;">Product ID</th>
            <th style="padding:8px;text-align:left;">Product</th>
            <th style="padding:8px;text-align:center;">Qty</th>
            <th style="padding:8px;text-align:right;">Price</th>
            <th style="padding:8px;text-align:right;">Subtotal</th>
          </tr>
        </thead>
        <tbody>{html_lines}</tbody>
      </table>
      <div style="text-align:right;border-top:2px solid #e5e7eb;padding-top:12px;">
        <strong>Total Quantity:</strong> {total_quantity}<br>
        <strong>Total Paid:</strong> Rs. {float(order_payload['total_amount']):.2f}
      </div>
      <p>Thank you for shopping with Google Store.</p>
    </div>
    """
    return text_body, html_body


def send_order_receipt_email(order_payload):
    if not app.config["MAIL_USERNAME"]:
        raise RuntimeError("MAIL_USERNAME is not configured")
    if not app.config["MAIL_PASSWORD"]:
        raise RuntimeError("MAIL_PASSWORD is not configured")
    msg = Message(
        f"Google Store - Order #{order_payload['id']}",
        sender=app.config["MAIL_USERNAME"],
        recipients=[order_payload["shipping_email"]],
    )
    text_body, html_body = build_order_receipt(order_payload)
    msg.body = text_body
    msg.html = html_body
    mail.send(msg)


def send_order_receipt_email_async(order_payload):
    def worker():
        try:
            with app.app_context():
                send_order_receipt_email(order_payload)
            log_success(
                "/api/orders/email", "ASYNC", 200,
                "Order receipt email sent successfully",
                extra={"order_id": order_payload.get("id"), "to": order_payload.get("shipping_email")},
            )
        except Exception as exc:
            log_error(
                "/api/orders/email", "ASYNC", 500,
                "Order receipt email failed",
                extra={"order_id": order_payload.get("id"), "to": order_payload.get("shipping_email")},
                exc=exc,
            )
    threading.Thread(target=worker, daemon=True).start()


def build_recharge_receipt(recharge_payload):
    text_body = (
        f"Hello {recharge_payload['email']},\n\n"
        f"Your recharge #{recharge_payload['id']} has been saved successfully.\n\n"
        "Recharge Details\n"
        "----------------\n"
        f"Mobile Number: {recharge_payload['mobile_number']}\n"
        f"Operator: {recharge_payload['operator_name']}\n"
        f"Plan: {recharge_payload['plan_name'] or 'Custom plan'}\n"
        f"Amount Paid: Rs. {float(recharge_payload['amount']):.2f}\n"
        f"Payment Method: {recharge_payload['payment_method']}\n"
        f"Status: {recharge_payload['status']}\n"
        f"Transaction Reference: {recharge_payload['transaction_reference'] or 'Not provided'}\n"
        f"Date: {recharge_payload['created_at']}\n\n"
        "Thank you for using Google Pay."
    )
    html_body = f"""
    <div style="font-family:Arial,sans-serif;max-width:680px;margin:0 auto;padding:24px;color:#202124;">
      <h2 style="color:#1a73e8;">Google Pay Recharge Receipt</h2>
      <p>Your recharge <strong>#{recharge_payload['id']}</strong> has been saved successfully.</p>
      <table style="width:100%;border-collapse:collapse;margin:20px 0;">
        <tbody>
          <tr><td style="padding:8px;"><strong>Mobile Number</strong></td><td>{escape(str(recharge_payload['mobile_number']))}</td></tr>
          <tr><td style="padding:8px;"><strong>Operator</strong></td><td>{escape(str(recharge_payload['operator_name']))}</td></tr>
          <tr><td style="padding:8px;"><strong>Plan</strong></td><td>{escape(str(recharge_payload['plan_name'] or 'Custom plan'))}</td></tr>
          <tr><td style="padding:8px;"><strong>Amount Paid</strong></td><td>Rs. {float(recharge_payload['amount']):.2f}</td></tr>
          <tr><td style="padding:8px;"><strong>Payment Method</strong></td><td>{escape(str(recharge_payload['payment_method']))}</td></tr>
          <tr><td style="padding:8px;"><strong>Status</strong></td><td>{escape(str(recharge_payload['status']))}</td></tr>
          <tr><td style="padding:8px;"><strong>Transaction Ref</strong></td><td>{escape(str(recharge_payload['transaction_reference'] or 'Not provided'))}</td></tr>
          <tr><td style="padding:8px;"><strong>Date</strong></td><td>{escape(str(recharge_payload['created_at']))}</td></tr>
        </tbody>
      </table>
      <p>Thank you for using Google Pay.</p>
    </div>
    """
    return text_body, html_body


def send_recharge_receipt_email(recharge_payload):
    if not app.config["MAIL_USERNAME"] or not app.config["MAIL_PASSWORD"]:
        raise RuntimeError("MAIL credentials not configured.")
    msg = Message(
        f"Google Pay Recharge Receipt #{recharge_payload['id']}",
        sender=app.config["MAIL_USERNAME"],
        recipients=[recharge_payload["email"]],
    )
    text_body, html_body = build_recharge_receipt(recharge_payload)
    msg.body = text_body
    msg.html = html_body
    mail.send(msg)


def send_recharge_receipt_email_async(recharge_payload):
    def worker():
        try:
            with app.app_context():
                send_recharge_receipt_email(recharge_payload)
            log_success(
                "/api/recharges/email", "ASYNC", 200,
                "Recharge receipt email sent successfully",
                extra={"recharge_id": recharge_payload.get("id"), "to": recharge_payload.get("email")},
            )
        except Exception as exc:
            log_error(
                "/api/recharges/email", "ASYNC", 500,
                "Recharge receipt email failed",
                extra={"recharge_id": recharge_payload.get("id"), "to": recharge_payload.get("email")},
                exc=exc,
            )
    threading.Thread(target=worker, daemon=True).start()


# ──────────────────────────────────────────────────────────────────────────────
# TABLE HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def ensure_service_activity_table(cursor):
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS service_activity (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            service_name VARCHAR(100) NOT NULL,
            service_path VARCHAR(255) DEFAULT NULL,
            activity_type VARCHAR(50) NOT NULL DEFAULT 'open',
            note VARCHAR(255) DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            CONSTRAINT fk_service_activity_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """
    )


def ensure_order_tables(cursor):
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS orders (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            shipping_name VARCHAR(150) NOT NULL,
            shipping_email VARCHAR(150) NOT NULL,
            shipping_address TEXT NOT NULL,
            shipping_phone VARCHAR(20) DEFAULT NULL,
            total_amount DECIMAL(10, 2) NOT NULL,
            status VARCHAR(50) NOT NULL DEFAULT 'placed',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            CONSTRAINT fk_orders_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS order_items (
            id INT AUTO_INCREMENT PRIMARY KEY,
            order_id INT NOT NULL,
            product_id VARCHAR(100) NOT NULL,
            product_name VARCHAR(255) NOT NULL,
            product_image TEXT DEFAULT NULL,
            price DECIMAL(10, 2) NOT NULL,
            quantity INT NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT fk_order_items_order FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE
        )
        """
    )


# ──────────────────────────────────────────────────────────────────────────────
# ROUTES
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api", methods=["GET"])
@app.route("/api/", methods=["GET"])
def api_root():
    return jsonify({
        "message":   "API is running successfully",
        "status":    "healthy",
        "service":   "Google Store Backend",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }), 200


# ── SIGNUP ────────────────────────────────────────────────────────────────────

@app.route("/api/signup/request", methods=["POST"])
@app.route("/api/signup/request/", methods=["POST"])
def signup_request():
    data = get_json_payload()
    validation_error = require_fields(data, ["username", "email", "password"])
    if validation_error:
        return validation_error

    email     = data["email"].strip().lower()
    username  = data["username"].strip()
    full_name = data.get("full_name", username).strip() or username
    password  = data["password"].strip()

    password_error = validate_password_strength(password)
    if password_error:
        log_warning(request.path, request.method, 400, password_error, extra={"email": email})
        return jsonify({"error": password_error}), 400

    password_hash = generate_password_hash(password)
    otp    = str(random.randint(100000, 999999))
    expiry = datetime.now() + timedelta(minutes=10)

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id FROM users WHERE email = %s OR username = %s", (email, username))
            if cursor.fetchone():
                log_warning(request.path, request.method, 409, "Signup failed — user already exists", extra={"email": email})
                return jsonify({"error": "User already exists"}), 409

            cursor.execute(
                """
                INSERT INTO pending_signups (email, username, full_name, password_hash, otp_code, otp_expiry)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    username = VALUES(username), full_name = VALUES(full_name),
                    password_hash = VALUES(password_hash), otp_code = VALUES(otp_code), otp_expiry = VALUES(otp_expiry)
                """,
                (email, username, full_name, password_hash, otp, expiry),
            )
            conn.commit()

        msg = Message(
            "Google Store - Verify Registration",
            sender=app.config["MAIL_USERNAME"],
            recipients=[email],
        )
        msg.body = f"Hello {username}, your registration OTP is {otp}. It expires in 10 minutes."
        mail.send(msg)

        log_success(request.path, request.method, 200, "Signup OTP sent", extra={"email": email})
        return jsonify({"message": "OTP sent to email!"}), 200

    except Exception as exc:
        conn.rollback()
        log_error(request.path, request.method, 500, "Signup request failed", extra={"email": email}, exc=exc)
        return jsonify({"error": str(exc)}), 500
    finally:
        conn.close()


@app.route("/api/signup/verify", methods=["POST"])
@app.route("/api/signup/verify/", methods=["POST"])
def signup_verify():
    data = get_json_payload()
    validation_error = require_fields(data, ["email", "otp"])
    if validation_error:
        return validation_error

    email    = data["email"].strip().lower()
    user_otp = data["otp"].strip()

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM pending_signups WHERE email = %s", (email,))
            pending_user = cursor.fetchone()

            if not pending_user:
                log_warning(request.path, request.method, 404, "Signup verify — no pending signup found", extra={"email": email})
                return jsonify({"error": "Signup request not found"}), 404

            if pending_user["otp_code"] != user_otp or datetime.now() >= pending_user["otp_expiry"]:
                log_warning(request.path, request.method, 401, "Signup verify — invalid or expired OTP", extra={"email": email})
                return jsonify({"error": "Invalid or expired OTP"}), 401

            cursor.execute(
                "INSERT INTO users (username, full_name, email, password) VALUES (%s, %s, %s, %s)",
                (pending_user["username"], pending_user["full_name"], pending_user["email"], pending_user["password_hash"]),
            )
            cursor.execute("DELETE FROM pending_signups WHERE email = %s", (email,))
            conn.commit()

            log_success(request.path, request.method, 201, "Account created successfully", extra={"email": email, "username": pending_user["username"]})
            return jsonify({
                "message": "Account created successfully!",
                "user": {
                    "username":  pending_user["username"],
                    "full_name": pending_user["full_name"],
                    "email":     pending_user["email"],
                },
            }), 201

    except pymysql.MySQLError as exc:
        conn.rollback()
        log_error(request.path, request.method, 409, "Signup verify — DB error, user may already exist", extra={"email": email}, exc=exc)
        return jsonify({"error": "User already exists"}), 409
    finally:
        conn.close()


# ── LOGIN ─────────────────────────────────────────────────────────────────────

@app.route("/api/login/request", methods=["POST"])
@app.route("/api/login/request/", methods=["POST"])
def login_request():
    data = get_json_payload()
    validation_error = require_fields(data, ["email", "password"])
    if validation_error:
        return validation_error

    email    = data["email"].strip().lower()
    password = data["password"].strip()

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()

            if not user or not check_password_hash(user["password"], password):
                log_warning(request.path, request.method, 401, "Login failed — invalid credentials", extra={"email": email})
                return jsonify({"error": "Invalid credentials"}), 401

            if not should_require_daily_login_otp(user):
                cursor.execute("UPDATE users SET otp_code = NULL, otp_expiry = NULL WHERE email = %s", (email,))
                conn.commit()
                log_success(request.path, request.method, 200, "Login successful — OTP skipped (same day)", extra={"email": email})
                return jsonify({
                    "message":      "Login successful",
                    "otp_required": False,
                    "user": {
                        "id":        user["id"],
                        "username":  user["username"],
                        "full_name": user["full_name"],
                        "email":     user["email"],
                        "address":   user["address"],
                        "phone":     user["phone"],
                    },
                }), 200

            otp    = str(random.randint(100000, 999999))
            expiry = datetime.now() + timedelta(minutes=5)
            cursor.execute("UPDATE users SET otp_code = %s, otp_expiry = %s WHERE email = %s", (otp, expiry, email))
            conn.commit()

        msg = Message("Google Store - Login OTP", sender=app.config["MAIL_USERNAME"], recipients=[email])
        msg.body = f"Your login OTP is {otp}. It expires in 5 minutes."
        mail.send(msg)

        log_success(request.path, request.method, 200, "Login OTP sent", extra={"email": email})
        return jsonify({"message": "OTP sent to email", "otp_required": True}), 200

    except Exception as exc:
        conn.rollback()
        log_error(request.path, request.method, 500, "Login request failed", extra={"email": email}, exc=exc)
        return jsonify({"error": str(exc)}), 500
    finally:
        conn.close()


@app.route("/api/login/verify", methods=["POST"])
@app.route("/api/login/verify/", methods=["POST"])
def login_verify():
    data = get_json_payload()
    validation_error = require_fields(data, ["email", "otp"])
    if validation_error:
        return validation_error

    email    = data["email"].strip().lower()
    user_otp = data["otp"].strip()

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE email = %s AND otp_code = %s", (email, user_otp))
            user = cursor.fetchone()

            if not user or datetime.now() >= user["otp_expiry"]:
                log_warning(request.path, request.method, 401, "Login verify — invalid or expired OTP", extra={"email": email})
                return jsonify({"error": "Invalid or expired OTP"}), 401

            cursor.execute(
                "UPDATE users SET otp_code = NULL, otp_expiry = NULL, last_login_otp_verified_at = %s WHERE id = %s",
                (datetime.now(), user["id"]),
            )
            conn.commit()

            log_success(request.path, request.method, 200, "Login verified successfully", extra={"email": email, "user_id": user["id"]})
            return jsonify({
                "message": "Login successful",
                "user": {
                    "id":        user["id"],
                    "username":  user["username"],
                    "full_name": user["full_name"],
                    "email":     user["email"],
                    "address":   user["address"],
                    "phone":     user["phone"],
                },
            }), 200
    finally:
        conn.close()


# ── USER PROFILE ──────────────────────────────────────────────────────────────

@app.route("/api/users/<path:email>", methods=["GET"])
def get_user_profile(email):
    normalized_email = email.strip().lower()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            user = fetch_user_by_email(cursor, normalized_email)
            if not user:
                log_warning(request.path, request.method, 404, "User profile not found", extra={"email": normalized_email})
                return jsonify({"error": "User not found"}), 404
            log_success(request.path, request.method, 200, "User profile fetched", extra={"email": normalized_email})
            return jsonify({"user": {
                "id":        user["id"],
                "username":  user["username"],
                "full_name": user["full_name"],
                "email":     user["email"],
                "address":   user["address"],
                "phone":     user["phone"],
            }}), 200
    finally:
        conn.close()


@app.route("/api/users/<path:email>", methods=["PUT"])
def update_user_profile(email):
    data = get_json_payload()
    normalized_email = email.strip().lower()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            user = fetch_user_by_email(cursor, normalized_email)
            if not user:
                log_warning(request.path, request.method, 404, "Update profile — user not found", extra={"email": normalized_email})
                return jsonify({"error": "User not found"}), 404

            full_name = data.get("full_name", user["full_name"] or user["username"])
            address   = data.get("address", user["address"])
            phone     = data.get("phone", user["phone"])

            cursor.execute(
                "UPDATE users SET full_name = %s, address = %s, phone = %s WHERE id = %s",
                (full_name, address, phone, user["id"]),
            )
            conn.commit()
            log_success(request.path, request.method, 200, "User profile updated", extra={"email": normalized_email})
            return jsonify({"message": "Profile updated successfully"}), 200
    finally:
        conn.close()


# ── CART ──────────────────────────────────────────────────────────────────────

@app.route("/api/cart", methods=["GET"])
@app.route("/api/cart/", methods=["GET"])
def get_cart():
    email = request.args.get("email", "").strip().lower()
    if not email:
        log_warning(request.path, request.method, 400, "Get cart — email missing")
        return jsonify({"error": "Email is required"}), 400
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            user = fetch_user_by_email(cursor, email)
            if not user:
                log_warning(request.path, request.method, 404, "Get cart — user not found", extra={"email": email})
                return jsonify({"error": "User not found"}), 404
            log_success(request.path, request.method, 200, "Cart fetched", extra={"email": email})
            return jsonify(fetch_cart(cursor, user["id"])), 200
    finally:
        conn.close()


@app.route("/api/cart/items", methods=["POST"])
@app.route("/api/cart/items/", methods=["POST"])
def add_cart_item():
    data = get_json_payload()
    validation_error = require_fields(data, ["email", "product_id", "product_name", "price"])
    if validation_error:
        return validation_error

    email               = data["email"].strip().lower()
    quantity            = max(int(data.get("quantity", 1)), 1)
    product_id          = str(data["product_id"]).strip()
    product_name        = str(data["product_name"]).strip()
    product_image       = str(data.get("product_image", "")).strip() or None
    product_description = str(data.get("product_description", "")).strip() or None
    price               = float(data["price"])

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            user = fetch_user_by_email(cursor, email)
            if not user:
                log_warning(request.path, request.method, 404, "Add cart item — user not found", extra={"email": email})
                return jsonify({"error": "User not found"}), 404

            cursor.execute(
                """
                INSERT INTO cart_items
                    (user_id, product_id, product_name, product_image, product_description, price, quantity)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    product_name = VALUES(product_name), product_image = VALUES(product_image),
                    product_description = VALUES(product_description), price = VALUES(price),
                    quantity = quantity + VALUES(quantity)
                """,
                (user["id"], product_id, product_name, product_image, product_description, price, quantity),
            )
            conn.commit()
            log_success(request.path, request.method, 201, "Cart item added", extra={"email": email, "product_id": product_id})
            return jsonify({"message": "Item added to cart"}), 201
    finally:
        conn.close()


@app.route("/api/cart/items", methods=["PUT"])
@app.route("/api/cart/items/", methods=["PUT"])
def update_cart_item():
    data = get_json_payload()
    validation_error = require_fields(data, ["email", "product_id", "quantity"])
    if validation_error:
        return validation_error

    email      = data["email"].strip().lower()
    product_id = str(data["product_id"]).strip()
    quantity   = int(data["quantity"])

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            user = fetch_user_by_email(cursor, email)
            if not user:
                log_warning(request.path, request.method, 404, "Update cart — user not found", extra={"email": email})
                return jsonify({"error": "User not found"}), 404

            if quantity <= 0:
                cursor.execute("DELETE FROM cart_items WHERE user_id = %s AND product_id = %s", (user["id"], product_id))
            else:
                cursor.execute(
                    "UPDATE cart_items SET quantity = %s WHERE user_id = %s AND product_id = %s",
                    (quantity, user["id"], product_id),
                )
            conn.commit()
            log_success(request.path, request.method, 200, "Cart updated", extra={"email": email, "product_id": product_id, "quantity": quantity})
            return jsonify({"message": "Cart updated"}), 200
    finally:
        conn.close()


@app.route("/api/cart/items", methods=["DELETE"])
@app.route("/api/cart/items/", methods=["DELETE"])
def delete_cart_item():
    data       = get_json_payload()
    email      = str(data.get("email", "")).strip().lower()
    product_id = str(data.get("product_id", "")).strip()

    if not email or not product_id:
        log_warning(request.path, request.method, 400, "Delete cart item — email or product_id missing")
        return jsonify({"error": "Email and product_id are required"}), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            user = fetch_user_by_email(cursor, email)
            if not user:
                log_warning(request.path, request.method, 404, "Delete cart item — user not found", extra={"email": email})
                return jsonify({"error": "User not found"}), 404

            cursor.execute("DELETE FROM cart_items WHERE user_id = %s AND product_id = %s", (user["id"], product_id))
            conn.commit()
            log_success(request.path, request.method, 200, "Cart item removed", extra={"email": email, "product_id": product_id})
            return jsonify({"message": "Item removed from cart"}), 200
    finally:
        conn.close()


# ── ORDERS ────────────────────────────────────────────────────────────────────

@app.route("/api/orders", methods=["POST"])
@app.route("/api/orders/", methods=["POST"])
def create_order():
    data = get_json_payload()
    validation_error = require_fields(data, ["email", "shipping_name", "shipping_address"])
    if validation_error:
        return validation_error

    email             = data["email"].strip().lower()
    shipping_name     = data["shipping_name"].strip()
    shipping_address  = data["shipping_address"].strip()
    shipping_phone    = str(data.get("shipping_phone", "")).strip() or None
    status            = str(data.get("status", "placed")).strip() or "placed"
    payment_method    = str(data.get("payment_method", "")).strip() or None
    payment_status    = str(data.get("payment_status", "paid")).strip() or "paid"
    transaction_reference = str(data.get("transaction_reference", "")).strip() or None
    payment_notes     = str(data.get("payment_notes", "")).strip() or None

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            ensure_order_tables(cursor)
            user = fetch_user_by_email(cursor, email)
            if not user:
                log_warning(request.path, request.method, 404, "Create order — user not found", extra={"email": email})
                return jsonify({"error": "User not found"}), 404

            cart          = fetch_cart(cursor, user["id"])
            request_items = [normalize_order_item(item) for item in (data.get("items") or []) if isinstance(item, dict)]
            order_items   = cart["items"] or request_items
            order_total   = round(sum(float(item.get("subtotal") or (float(item.get("price") or 0) * int(item.get("quantity") or 1))) for item in order_items), 2)

            if not order_items:
                log_warning(request.path, request.method, 400, "Create order — cart is empty", extra={"email": email})
                return jsonify({"error": "Cart is empty"}), 400

            cursor.execute(
                "INSERT INTO orders (user_id, shipping_name, shipping_email, shipping_address, shipping_phone, total_amount, status) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (user["id"], shipping_name, email, shipping_address, shipping_phone, order_total, status),
            )
            order_id = cursor.lastrowid

            for item in order_items:
                cursor.execute(
                    "INSERT INTO order_items (order_id, product_id, product_name, product_image, price, quantity) VALUES (%s, %s, %s, %s, %s, %s)",
                    (order_id, item["product_id"], item["product_name"], item["product_image"], item["price"], item["quantity"]),
                )

            cursor.execute("DELETE FROM cart_items WHERE user_id = %s", (user["id"],))
            cursor.execute(
                "UPDATE users SET full_name = %s, address = %s, phone = COALESCE(%s, phone) WHERE id = %s",
                (shipping_name, shipping_address, shipping_phone, user["id"]),
            )

            if payment_method:
                cursor.execute(
                    "INSERT INTO payments (user_id, order_id, payment_type, payment_method, amount, status, transaction_reference, notes) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                    (user["id"], order_id, "order", payment_method, order_total, payment_status, transaction_reference, payment_notes),
                )

            receipt_created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            order_payload = {
                "id":                    order_id,
                "shipping_name":         shipping_name,
                "shipping_email":        email,
                "shipping_address":      shipping_address,
                "shipping_phone":        shipping_phone,
                "total_amount":          order_total,
                "status":                status,
                "payment_method":        payment_method,
                "payment_status":        payment_status,
                "transaction_reference": transaction_reference,
                "payment_notes":         payment_notes,
                "created_at":            receipt_created_at,
                "items":                 [serialize_order_item(item) for item in order_items],
            }
            conn.commit()

            email_queued = bool(app.config["MAIL_USERNAME"] and app.config["MAIL_PASSWORD"])
            if email_queued:
                send_order_receipt_email_async(order_payload)

            log_success(request.path, request.method, 201, "Order placed successfully",
                        extra={"email": email, "order_id": order_id, "total_amount": order_total})
            return jsonify({
                "message":      "Order placed successfully",
                "order_id":     order_id,
                "total_amount": order_total,
                "email_queued": email_queued,
                "order":        order_payload,
            }), 201

    except Exception as exc:
        conn.rollback()
        log_error(request.path, request.method, 500, "Create order failed", extra={"email": email}, exc=exc)
        return jsonify({"error": str(exc)}), 500
    finally:
        conn.close()


@app.route("/api/orders", methods=["GET"])
@app.route("/api/orders/", methods=["GET"])
def get_orders():
    email = request.args.get("email", "").strip().lower()
    if not email:
        log_warning(request.path, request.method, 400, "Get orders — email missing")
        return jsonify({"error": "Email is required"}), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            ensure_order_tables(cursor)
            user = fetch_user_by_email(cursor, email)
            if not user:
                log_warning(request.path, request.method, 404, "Get orders — user not found", extra={"email": email})
                return jsonify({"error": "User not found"}), 404

            cursor.execute(
                "SELECT id, shipping_name, shipping_email, shipping_address, shipping_phone, total_amount, status, created_at FROM orders WHERE user_id = %s ORDER BY created_at DESC, id DESC",
                (user["id"],),
            )
            orders = cursor.fetchall()
            for order in orders:
                cursor.execute(
                    "SELECT product_id, product_name, product_image, price, quantity FROM order_items WHERE order_id = %s ORDER BY id ASC",
                    (order["id"],),
                )
                items = cursor.fetchall()
                order["items"]        = [{"product_id": i["product_id"], "product_name": i["product_name"], "product_image": i["product_image"], "price": float(i["price"]), "quantity": i["quantity"], "subtotal": float(i["price"]) * i["quantity"]} for i in items]
                order["total_amount"] = float(order["total_amount"])
                order["created_at"]   = order["created_at"].isoformat() if order["created_at"] else None

            log_success(request.path, request.method, 200, "Orders fetched", extra={"email": email, "count": len(orders)})
            return jsonify({"orders": orders}), 200
    finally:
        conn.close()


# ── PAYMENTS ──────────────────────────────────────────────────────────────────

@app.route("/api/payments", methods=["POST"])
@app.route("/api/payments/", methods=["POST"])
def create_payment():
    data = get_json_payload()
    validation_error = require_fields(data, ["email", "payment_method", "amount"])
    if validation_error:
        return validation_error

    email                 = data["email"].strip().lower()
    payment_type          = str(data.get("payment_type", "payment")).strip() or "payment"
    payment_method        = data["payment_method"].strip()
    amount                = float(data["amount"])
    status                = str(data.get("status", "paid")).strip() or "paid"
    transaction_reference = str(data.get("transaction_reference", "")).strip() or None
    notes                 = str(data.get("notes", "")).strip() or None
    order_id              = data.get("order_id")

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            user = fetch_user_by_email(cursor, email)
            if not user:
                log_warning(request.path, request.method, 404, "Create payment — user not found", extra={"email": email})
                return jsonify({"error": "User not found"}), 404

            cursor.execute(
                "INSERT INTO payments (user_id, order_id, payment_type, payment_method, amount, status, transaction_reference, notes) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                (user["id"], order_id, payment_type, payment_method, amount, status, transaction_reference, notes),
            )
            conn.commit()
            log_success(request.path, request.method, 201, "Payment saved", extra={"email": email, "amount": amount, "method": payment_method})
            return jsonify({"message": "Payment saved successfully", "payment_id": cursor.lastrowid}), 201
    finally:
        conn.close()


@app.route("/api/payments", methods=["GET"])
@app.route("/api/payments/", methods=["GET"])
def get_payments():
    email = request.args.get("email", "").strip().lower()
    if not email:
        log_warning(request.path, request.method, 400, "Get payments — email missing")
        return jsonify({"error": "Email is required"}), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            user = fetch_user_by_email(cursor, email)
            if not user:
                log_warning(request.path, request.method, 404, "Get payments — user not found", extra={"email": email})
                return jsonify({"error": "User not found"}), 404

            cursor.execute(
                "SELECT id, order_id, payment_type, payment_method, amount, status, transaction_reference, notes, created_at FROM payments WHERE user_id = %s ORDER BY created_at DESC, id DESC",
                (user["id"],),
            )
            payments = [serialize_payment_row(row) for row in cursor.fetchall()]
            log_success(request.path, request.method, 200, "Payments fetched", extra={"email": email, "count": len(payments)})
            return jsonify({"payments": payments}), 200
    finally:
        conn.close()


# ── RECHARGES ─────────────────────────────────────────────────────────────────

@app.route("/api/recharges", methods=["POST"])
@app.route("/api/recharges/", methods=["POST"])
def create_recharge():
    data = get_json_payload()
    validation_error = require_fields(data, ["email", "mobile_number", "operator_name", "amount", "payment_method"])
    if validation_error:
        return validation_error

    email                 = data["email"].strip().lower()
    mobile_number         = str(data["mobile_number"]).strip()
    operator_name         = str(data["operator_name"]).strip()
    plan_name             = str(data.get("plan_name", "")).strip() or None
    amount                = float(data["amount"])
    payment_method        = str(data["payment_method"]).strip()
    status                = str(data.get("status", "success")).strip() or "success"
    transaction_reference = str(data.get("transaction_reference", "")).strip() or None

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            user = fetch_user_by_email(cursor, email)
            if not user:
                log_warning(request.path, request.method, 404, "Create recharge — user not found", extra={"email": email})
                return jsonify({"error": "User not found"}), 404

            cursor.execute(
                "INSERT INTO recharges (user_id, mobile_number, operator_name, plan_name, amount, payment_method, status, transaction_reference) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                (user["id"], mobile_number, operator_name, plan_name, amount, payment_method, status, transaction_reference),
            )
            recharge_id = cursor.lastrowid
            cursor.execute(
                "INSERT INTO payments (user_id, order_id, payment_type, payment_method, amount, status, transaction_reference, notes) VALUES (%s, NULL, %s, %s, %s, %s, %s, %s)",
                (user["id"], "recharge", payment_method, amount, status, transaction_reference, f"Recharge for {mobile_number} ({operator_name})"),
            )
            conn.commit()

            recharge_payload = {
                "id":                    recharge_id,
                "email":                 email,
                "mobile_number":         mobile_number,
                "operator_name":         operator_name,
                "plan_name":             plan_name,
                "amount":                amount,
                "payment_method":        payment_method,
                "status":                status,
                "transaction_reference": transaction_reference,
                "created_at":            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            email_queued = bool(app.config["MAIL_USERNAME"] and app.config["MAIL_PASSWORD"])
            if email_queued:
                send_recharge_receipt_email_async(recharge_payload)

            log_success(request.path, request.method, 201, "Recharge saved", extra={"email": email, "recharge_id": recharge_id, "amount": amount})
            return jsonify({
                "message":     "Recharge saved successfully",
                "recharge_id": recharge_id,
                "email_queued": email_queued,
                "recharge":    recharge_payload,
            }), 201
    finally:
        conn.close()


@app.route("/api/recharges", methods=["GET"])
@app.route("/api/recharges/", methods=["GET"])
def get_recharges():
    email = request.args.get("email", "").strip().lower()
    if not email:
        log_warning(request.path, request.method, 400, "Get recharges — email missing")
        return jsonify({"error": "Email is required"}), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            user = fetch_user_by_email(cursor, email)
            if not user:
                log_warning(request.path, request.method, 404, "Get recharges — user not found", extra={"email": email})
                return jsonify({"error": "User not found"}), 404

            cursor.execute(
                "SELECT id, mobile_number, operator_name, plan_name, amount, payment_method, status, transaction_reference, created_at FROM recharges WHERE user_id = %s ORDER BY created_at DESC, id DESC",
                (user["id"],),
            )
            recharges = [serialize_recharge_row(row) for row in cursor.fetchall()]
            log_success(request.path, request.method, 200, "Recharges fetched", extra={"email": email, "count": len(recharges)})
            return jsonify({"recharges": recharges}), 200
    finally:
        conn.close()


# ── SERVICE ACTIVITY ──────────────────────────────────────────────────────────

@app.route("/api/service-activity", methods=["POST"])
@app.route("/api/service-activity/", methods=["POST"])
def create_service_activity():
    data = get_json_payload()
    validation_error = require_fields(data, ["email", "service_name"])
    if validation_error:
        return validation_error

    email         = data["email"].strip().lower()
    service_name  = str(data["service_name"]).strip()
    service_path  = str(data.get("service_path", "")).strip() or None
    activity_type = str(data.get("activity_type", "open")).strip() or "open"
    note          = str(data.get("note", "")).strip() or None

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            ensure_service_activity_table(cursor)
            user = fetch_user_by_email(cursor, email)
            if not user:
                log_warning(request.path, request.method, 404, "Create service activity — user not found", extra={"email": email})
                return jsonify({"error": "User not found"}), 404

            cursor.execute(
                "INSERT INTO service_activity (user_id, service_name, service_path, activity_type, note) VALUES (%s, %s, %s, %s, %s)",
                (user["id"], service_name, service_path, activity_type, note),
            )
            conn.commit()
            log_success(request.path, request.method, 201, "Service activity saved", extra={"email": email, "service": service_name})
            return jsonify({"message": "Service activity saved", "activity_id": cursor.lastrowid}), 201
    finally:
        conn.close()


@app.route("/api/service-activity", methods=["GET"])
@app.route("/api/service-activity/", methods=["GET"])
def get_service_activity():
    email = request.args.get("email", "").strip().lower()
    if not email:
        log_warning(request.path, request.method, 400, "Get service activity — email missing")
        return jsonify({"error": "Email is required"}), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            ensure_service_activity_table(cursor)
            user = fetch_user_by_email(cursor, email)
            if not user:
                log_warning(request.path, request.method, 404, "Get service activity — user not found", extra={"email": email})
                return jsonify({"error": "User not found"}), 404

            cursor.execute(
                "SELECT id, service_name, service_path, activity_type, note, created_at FROM service_activity WHERE user_id = %s ORDER BY created_at DESC, id DESC",
                (user["id"],),
            )
            activities = [serialize_service_activity_row(row) for row in cursor.fetchall()]
            log_success(request.path, request.method, 200, "Service activities fetched", extra={"email": email, "count": len(activities)})
            return jsonify({"activities": activities}), 200
    finally:
        conn.close()


# ── HISTORY ───────────────────────────────────────────────────────────────────

@app.route("/api/history", methods=["GET"])
def get_user_history():
    email = request.args.get("email", "").strip().lower()
    if not email:
        log_warning(request.path, request.method, 400, "Get history — email missing")
        return jsonify({"error": "Email is required"}), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            ensure_order_tables(cursor)
            ensure_service_activity_table(cursor)
            user = fetch_user_by_email(cursor, email)
            if not user:
                log_warning(request.path, request.method, 404, "Get history — user not found", extra={"email": email})
                return jsonify({"error": "User not found"}), 404

            cursor.execute(
                "SELECT id, shipping_name, shipping_email, shipping_address, shipping_phone, total_amount, status, created_at FROM orders WHERE user_id = %s ORDER BY created_at DESC, id DESC",
                (user["id"],),
            )
            orders = cursor.fetchall()
            for order in orders:
                cursor.execute("SELECT product_id, product_name, product_image, price, quantity FROM order_items WHERE order_id = %s ORDER BY id ASC", (order["id"],))
                items = cursor.fetchall()
                order["items"]        = [{"product_id": i["product_id"], "product_name": i["product_name"], "product_image": i["product_image"], "price": float(i["price"]), "quantity": i["quantity"], "subtotal": float(i["price"]) * i["quantity"]} for i in items]
                order["total_amount"] = float(order["total_amount"])
                order["created_at"]   = order["created_at"].isoformat() if order["created_at"] else None

            cursor.execute("SELECT id, order_id, payment_type, payment_method, amount, status, transaction_reference, notes, created_at FROM payments WHERE user_id = %s ORDER BY created_at DESC, id DESC", (user["id"],))
            payments = [serialize_payment_row(row) for row in cursor.fetchall()]

            cursor.execute("SELECT id, mobile_number, operator_name, plan_name, amount, payment_method, status, transaction_reference, created_at FROM recharges WHERE user_id = %s ORDER BY created_at DESC, id DESC", (user["id"],))
            recharges = [serialize_recharge_row(row) for row in cursor.fetchall()]

            cursor.execute("SELECT id, service_name, service_path, activity_type, note, created_at FROM service_activity WHERE user_id = %s ORDER BY created_at DESC, id DESC", (user["id"],))
            service_activity = [serialize_service_activity_row(row) for row in cursor.fetchall()]

            log_success(request.path, request.method, 200, "Full history fetched", extra={"email": email})
            return jsonify({
                "orders":           orders,
                "payments":         payments,
                "recharges":        recharges,
                "service_activity": service_activity,
            }), 200
    finally:
        conn.close()


# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port  = int(os.getenv("PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    log_success("STARTUP", "SYSTEM", 200, f"Flask app starting on port {port}", extra={"debug": debug})
    app.run(host="0.0.0.0", port=port, debug=debug)
