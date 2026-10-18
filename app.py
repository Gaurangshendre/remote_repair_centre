"""Remote Repair Centre – Flask Application (Supabase backend)."""

import hmac
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
ADMIN_REGISTRATION_CODE: str = os.getenv("ADMIN_REGISTRATION_CODE", "")

ROLE_PROFILE_FIELDS = {
    "customer": ("device_type", "contact_preference"),
    "delivery": ("vehicle_type", "vehicle_number", "service_area"),
    "shop": ("shop_name", "shop_category", "service_area"),
}

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError(
        "Missing SUPABASE_URL or SUPABASE_KEY. "
        "Copy .env.example to .env and fill in your Supabase credentials."
    )

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _validate_registration(name, mobile, email, address, password, role, profile_data, admin_code):
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

    if role not in {"customer", "delivery", "admin", "shop"}:
        errors.append("Select a valid account type.")
    elif role == "customer":
        if profile_data.get("device_type") not in {"smartphone", "laptop", "tablet", "other"}:
            errors.append("Select the device you use most for repairs.")
        if profile_data.get("contact_preference") not in {"email", "phone"}:
            errors.append("Select your preferred contact method.")
    elif role == "delivery":
        if profile_data.get("vehicle_type") not in {"motorbike", "scooter", "car", "van", "other"}:
            errors.append("Select a valid vehicle type.")
        if not re.fullmatch(r"[A-Za-z0-9 -]{5,20}", profile_data.get("vehicle_number", "")):
            errors.append("Enter a valid vehicle registration number.")
        if not re.fullmatch(r"[A-Za-z0-9 ,.'-]{2,100}", profile_data.get("service_area", "")):
            errors.append("Enter a service area between 2 and 100 characters.")
    elif role == "shop":
        if not re.fullmatch(r"[^<>]{2,100}", profile_data.get("shop_name", "")):
            errors.append("Shop name must be between 2 and 100 characters.")
        if profile_data.get("shop_category") not in {"phone_repair", "computer_repair", "electronics", "general_repair", "other"}:
            errors.append("Select a valid shop category.")
        if not re.fullmatch(r"[A-Za-z0-9 ,.'-]{2,100}", profile_data.get("service_area", "")):
            errors.append("Enter a service area between 2 and 100 characters.")
    elif role == "admin":
        if not ADMIN_REGISTRATION_CODE:
            errors.append("Admin registration is disabled until an invite code is configured.")
        elif not hmac.compare_digest(admin_code, ADMIN_REGISTRATION_CODE):
            errors.append("The admin invite code is invalid.")

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
    """Register a customer, delivery, admin, or shop account."""
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        mobile = request.form.get("mobile", "").strip()
        email = request.form.get("email", "").strip().lower()
        address = request.form.get("address", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "").strip()
        profile_data = {
            "device_type": request.form.get("device_type", "").strip(),
            "contact_preference": request.form.get("contact_preference", "").strip(),
            "vehicle_type": request.form.get("vehicle_type", "").strip(),
            "vehicle_number": request.form.get("vehicle_number", "").strip(),
            "shop_name": request.form.get("shop_name", "").strip(),
            "shop_category": request.form.get("shop_category", "").strip(),
            "service_area": request.form.get(
                "delivery_service_area" if role == "delivery" else "shop_service_area", ""
            ).strip(),
        }
        admin_code = request.form.get("admin_code", "")

        errors = _validate_registration(
            name, mobile, email, address, password, role, profile_data, admin_code
        )
        if errors:
            for err in errors:
                flash(err, "danger")
            return render_template(
                "register.html",
                name=name, mobile=mobile, email=email, address=address, role=role,
                profile_data=profile_data,
            )

        # Check for duplicate email
        existing = supabase.table("users").select("user_id").eq("email", email).execute()
        if existing.data:
            flash("An account with this email already exists.", "danger")
            return render_template(
                "register.html",
                name=name, mobile=mobile, email=email, address=address, role=role,
                profile_data=profile_data,
            )

        user_doc = {
            "user_id": str(uuid.uuid4()),
            "name": name,
            "mobile": mobile,
            "email": email,
            "address": address,
            "password_hash": generate_password_hash(password),
            "role": role,
            "profile_data": {
                key: profile_data[key]
                for key in ROLE_PROFILE_FIELDS.get(role, ())
            },
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


@app.route("/shop/dashboard")
def shop_dashboard():
    if session.get("role") != "shop":
        flash("Access denied.", "danger")
        return redirect(url_for("login"))
    return render_template("shop_dashboard.html")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _redirect_by_role(role):
    """Return a redirect response to the correct dashboard for *role*."""
    if role == "admin":
        return redirect(url_for("admin_dashboard"))
    if role == "delivery":
        return redirect(url_for("delivery_dashboard"))
    if role == "shop":
        return redirect(url_for("shop_dashboard"))
    if role == "customer":
        return redirect(url_for("customer_dashboard"))
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)
