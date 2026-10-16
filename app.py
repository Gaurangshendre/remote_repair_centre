"""Remote Repair Centre – Flask Application (Supabase backend)."""

import re
import uuid
import os

from dotenv import load_dotenv
from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from supabase import create_client, Client
from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------------------
# Load environment variables
# ---------------------------------------------------------------------------
load_dotenv()

# ---------------------------------------------------------------------------
# App & Supabase setup
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "rrc-secret-key-change-in-production")

SUPABASE_URL: str = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY: str = os.getenv("SUPABASE_KEY", "")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError(
        "Missing SUPABASE_URL or SUPABASE_KEY. "
        "Copy .env.example to .env and fill in your Supabase credentials."
    )

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _validate_registration(name, mobile, email, address, password):
    """Return a list of error strings (empty == valid)."""
    errors = []

    # Name: letters & spaces, 2-100 chars
    if not name or not re.fullmatch(r"[A-Za-z ]{2,100}", name):
        errors.append("Name must be 2-100 characters and contain only letters and spaces.")

    # Mobile: exactly 10 digits
    if not mobile or not re.fullmatch(r"\d{10}", mobile):
        errors.append("Mobile must be exactly 10 digits.")

    # Email: basic format check
    if not email or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        errors.append("Enter a valid email address.")

    # Address: 5-500 chars
    if not address or len(address.strip()) < 5 or len(address.strip()) > 500:
        errors.append("Address must be between 5 and 500 characters.")

    # Password: min 8 chars, at least 1 upper, 1 lower, 1 digit, 1 special
    if not password or len(password) < 8:
        errors.append("Password must be at least 8 characters.")
    elif not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter.")
    elif not re.search(r"[a-z]", password):
        errors.append("Password must contain at least one lowercase letter.")
    elif not re.search(r"\d", password):
        errors.append("Password must contain at least one digit.")
    elif not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        errors.append("Password must contain at least one special character.")

    return errors

# ---------------------------------------------------------------------------
# Routes – public pages
# ---------------------------------------------------------------------------

@app.route("/")
def home():
    """Landing page – redirect to login."""
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    """Customer self-registration."""
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        mobile = request.form.get("mobile", "").strip()
        email = request.form.get("email", "").strip().lower()
        address = request.form.get("address", "").strip()
        password = request.form.get("password", "")

        errors = _validate_registration(name, mobile, email, address, password)
        if errors:
            for err in errors:
                flash(err, "danger")
            return render_template(
                "register.html",
                name=name, mobile=mobile, email=email, address=address,
            )

        # Check for duplicate email
        existing = supabase.table("users").select("user_id").eq("email", email).execute()
        if existing.data:
            flash("An account with this email already exists.", "danger")
            return render_template(
                "register.html",
                name=name, mobile=mobile, email=email, address=address,
            )

        user_doc = {
            "user_id": str(uuid.uuid4()),
            "name": name,
            "mobile": mobile,
            "email": email,
            "address": address,
            "password_hash": generate_password_hash(password),
            "role": "customer",  # self-registration is always 'customer'
        }
        supabase.table("users").insert(user_doc).execute()
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Authenticate user and set session."""
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        result = supabase.table("users").select("*").eq("email", email).execute()
        user = result.data[0] if result.data else None

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["user_id"]
            session["role"] = user["role"]
            session["name"] = user["name"]
            flash(f"Welcome back, {user['name']}!", "success")
            return _redirect_by_role(user["role"])

        flash("Invalid email or password.", "danger")
        return render_template("login.html", email=email)

    return render_template("login.html")


@app.route("/logout")
def logout():
    """Clear session and redirect to login."""
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

# ---------------------------------------------------------------------------
# Dashboard stubs (role-specific)
# ---------------------------------------------------------------------------

@app.route("/customer/dashboard")
def customer_dashboard():
    if session.get("role") != "customer":
        flash("Access denied.", "danger")
        return redirect(url_for("login"))
    return render_template("customer_dashboard.html")


@app.route("/admin/dashboard")
def admin_dashboard():
    if session.get("role") != "admin":
        flash("Access denied.", "danger")
        return redirect(url_for("login"))
    return render_template("admin_dashboard.html")


@app.route("/delivery/dashboard")
def delivery_dashboard():
    if session.get("role") != "delivery":
        flash("Access denied.", "danger")
        return redirect(url_for("login"))
    return render_template("delivery_dashboard.html")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _redirect_by_role(role):
    """Return a redirect response to the correct dashboard for *role*."""
    if role == "admin":
        return redirect(url_for("admin_dashboard"))
    if role == "delivery":
        return redirect(url_for("delivery_dashboard"))
    return redirect(url_for("customer_dashboard"))


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)
