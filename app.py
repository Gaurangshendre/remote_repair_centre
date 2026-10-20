"""Remote Repair Centre – Flask Application (Supabase backend)."""

import hmac
import os
import re
import uuid
from functools import wraps

from dotenv import load_dotenv
from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from supabase import create_client, Client
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

# ---------------------------------------------------------------------------
# Load environment variables
# ---------------------------------------------------------------------------
load_dotenv()

# ---------------------------------------------------------------------------
# App & Supabase setup
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "rrc-secret-key-change-in-production")

UPLOAD_FOLDER = os.path.join(app.root_path, "statics", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
ALLOWED_PHOTO_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}

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
# Access control & role helpers
# ---------------------------------------------------------------------------

REQUEST_STATUSES = [
    "Pickup Pending",
    "Pickup Assigned",
    "Picked Up",
    "Under Inspection",
    "Repair in Progress",
    "Repaired",
    "Out for Delivery",
    "Delivered",
    "Cancelled",
]


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


def login_required(view_func):
    """Ensure user is logged in before accessing the view."""
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapper


def role_required(*allowed_roles):
    """Ensure user is logged in and possesses one of the allowed roles."""
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            if not session.get("user_id"):
                flash("Please log in to continue.", "warning")
                return redirect(url_for("login"))
            user_role = session.get("role")
            if user_role not in allowed_roles:
                flash("Access denied. You do not have permission to access this page.", "danger")
                if user_role == "customer":
                    return redirect(url_for("customer_dashboard"))
                return _redirect_by_role(user_role)
            return view_func(*args, **kwargs)
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Dashboard routes (role-specific)
# ---------------------------------------------------------------------------

@app.route("/customer/dashboard")
@role_required("customer")
def customer_dashboard():
    recent_requests = []
    try:
        res = (
            supabase.table("requests")
            .select("*")
            .eq("user_id", session["user_id"])
            .order("created_at", desc=True)
            .execute()
        )
        recent_requests = res.data or []
    except Exception:
        recent_requests = []
    return render_template("customer_dashboard.html", recent_requests=recent_requests)


@app.route("/admin/dashboard")
@role_required("admin")
def admin_dashboard():
    total_requests = 0
    pending_requests = 0
    try:
        res = supabase.table("requests").select("status").execute()
        all_reqs = res.data or []
        total_requests = len(all_reqs)
        pending_requests = sum(1 for r in all_reqs if r.get("status") == "Pickup Pending")
    except Exception:
        pass
    return render_template(
        "admin_dashboard.html",
        total_requests=total_requests,
        pending_requests=pending_requests,
    )


@app.route("/delivery/dashboard")
@role_required("delivery")
def delivery_dashboard():
    return render_template("delivery_dashboard.html")


@app.route("/shop/dashboard")
@role_required("shop")
def shop_dashboard():
    return render_template("shop_dashboard.html")


# ---------------------------------------------------------------------------
# Customer Service Request routes
# ---------------------------------------------------------------------------

@app.route("/customer/requests/new", methods=["GET", "POST"])
@app.route("/requests/new", methods=["GET", "POST"])
@role_required("customer")
def new_request():
    """Create a new repair or resell request."""
    if request.method == "POST":
        company = request.form.get("company", "").strip()
        model = request.form.get("model", "").strip()
        request_type = request.form.get("request_type", "").strip()
        part = request.form.get("part", "").strip()
        issue_description = request.form.get("issue_description", "").strip()

        part_photo = request.files.get("part_photo")

        errors = []
        if not company or len(company) < 2 or len(company) > 100:
            errors.append("Company/brand name must be between 2 and 100 characters.")
        if not model or len(model) < 1 or len(model) > 100:
            errors.append("Model name must be between 1 and 100 characters.")
        if request_type not in ("Repair", "Resell"):
            errors.append("Request type must be either 'Repair' or 'Resell'.")
        if not part or len(part) < 2 or len(part) > 100:
            errors.append("Please select or specify the part to resell." if request_type == "Resell" else "Please select or specify the affected part.")
        if not issue_description or len(issue_description) < 10 or len(issue_description) > 2000:
            errors.append("Part description must be between 10 and 2000 characters." if request_type == "Resell" else "Issue description must be between 10 and 2000 characters.")

        if request_type == "Resell":
            if not part_photo or not part_photo.filename:
                errors.append("Please upload a photo of the part for validation.")
            else:
                ext = part_photo.filename.rsplit(".", 1)[-1].lower() if "." in part_photo.filename else ""
                if ext not in ALLOWED_PHOTO_EXTENSIONS:
                    errors.append("Photo must be a valid image format (PNG, JPG, JPEG, or WEBP).")
        elif part_photo and part_photo.filename:
            ext = part_photo.filename.rsplit(".", 1)[-1].lower() if "." in part_photo.filename else ""
            if ext not in ALLOWED_PHOTO_EXTENSIONS:
                errors.append("Photo must be a valid image format (PNG, JPG, JPEG, or WEBP).")

        if errors:
            for err in errors:
                flash(err, "danger")
            return render_template(
                "new_request.html",
                company=company,
                model=model,
                request_type=request_type,
                part=part,
                issue_description=issue_description,
            )

        photo_url = None
        if part_photo and part_photo.filename:
            safe_name = f"{uuid.uuid4().hex[:12]}_{secure_filename(part_photo.filename)}"
            save_path = os.path.join(app.config["UPLOAD_FOLDER"], safe_name)
            part_photo.save(save_path)
            photo_url = f"/uploads/{safe_name}"

        final_description = (
            f"{issue_description}\n\n[Photo: {photo_url}]" if photo_url else issue_description
        )

        new_req_id = str(uuid.uuid4())
        req_doc = {
            "request_id": new_req_id,
            "user_id": session["user_id"],
            "company": company,
            "model": model,
            "request_type": request_type,
            "part": part,
            "issue_description": final_description,
            "status": "Pickup Pending",
            "delivery_boy_id": None,
        }

        try:
            supabase.table("requests").insert(req_doc).execute()
            flash("Service request submitted successfully! Status: Pickup Pending.", "success")
            return redirect(url_for("my_requests"))
        except Exception as e:
            flash(
                f"Error submitting request: {e}. Please ensure the 'requests' table has been created in your Supabase database using supabase_schema.sql.",
                "danger",
            )
            return render_template(
                "new_request.html",
                company=company,
                model=model,
                request_type=request_type,
                part=part,
                issue_description=issue_description,
            )

    return render_template("new_request.html", request_type="Repair")


@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    """Serve uploaded photos."""
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


@app.route("/customer/requests")
@app.route("/my-requests")
@role_required("customer")
def my_requests():
    """List only the logged-in customer's requests with their statuses."""
    requests_list = []
    delivery_map = {}
    try:
        res = (
            supabase.table("requests")
            .select("*")
            .eq("user_id", session["user_id"])
            .order("created_at", desc=True)
            .execute()
        )
        requests_list = res.data or []

        # Fetch delivery boys details for any assigned requests
        assigned_ids = list({r["delivery_boy_id"] for r in requests_list if r.get("delivery_boy_id")})
        if assigned_ids:
            db_res = (
                supabase.table("users")
                .select("user_id, name, mobile")
                .in_("user_id", assigned_ids)
                .execute()
            )
            delivery_map = {u["user_id"]: u for u in (db_res.data or [])}
    except Exception as e:
        flash(
            f"Could not load requests: {e}. Please ensure the 'requests' table is created in Supabase.",
            "warning",
        )

    return render_template(
        "my_requests.html",
        requests=requests_list,
        delivery_map=delivery_map,
    )


# ---------------------------------------------------------------------------
# Admin Management routes
# ---------------------------------------------------------------------------

@app.route("/admin/requests")
@role_required("admin")
def admin_requests():
    """List all requests with dropdowns to assign a delivery boy and update status."""
    status_filter = request.args.get("status", "").strip()
    requests_list = []
    delivery_boys = []
    user_map = {}

    try:
        # Fetch requests
        query = supabase.table("requests").select("*")
        if status_filter:
            query = query.eq("status", status_filter)
        res = query.order("created_at", desc=True).execute()
        requests_list = res.data or []

        # Fetch delivery boys
        db_res = (
            supabase.table("users")
            .select("user_id, name, mobile")
            .eq("role", "delivery")
            .execute()
        )
        delivery_boys = db_res.data or []

        # Fetch customer info for addresses and contacts
        user_ids = list({r["user_id"] for r in requests_list if r.get("user_id")})
        if user_ids:
            u_res = (
                supabase.table("users")
                .select("user_id, name, mobile, address, email")
                .in_("user_id", user_ids)
                .execute()
            )
            user_map = {u["user_id"]: u for u in (u_res.data or [])}
    except Exception as e:
        flash(
            f"Could not load requests: {e}. Please ensure the 'requests' table is created in Supabase.",
            "warning",
        )

    return render_template(
        "admin_requests.html",
        requests=requests_list,
        delivery_boys=delivery_boys,
        user_map=user_map,
        all_statuses=REQUEST_STATUSES,
        current_status=status_filter,
    )


@app.route("/admin/requests/<request_id>/update", methods=["POST"])
@role_required("admin")
def admin_update_request(request_id):
    """Update assigned delivery boy and/or status for a request."""
    delivery_boy_id = request.form.get("delivery_boy_id", "").strip() or None
    new_status = request.form.get("status", "").strip()

    updates = {}
    if new_status:
        if new_status not in REQUEST_STATUSES:
            flash(f"Invalid status '{new_status}'.", "danger")
            return redirect(url_for("admin_requests"))
        updates["status"] = new_status

    if delivery_boy_id:
        db_check = (
            supabase.table("users")
            .select("user_id")
            .eq("user_id", delivery_boy_id)
            .eq("role", "delivery")
            .execute()
        )
        if not db_check.data:
            flash("Selected delivery person not found.", "danger")
            return redirect(url_for("admin_requests"))
        updates["delivery_boy_id"] = delivery_boy_id
    else:
        updates["delivery_boy_id"] = None

    try:
        supabase.table("requests").update(updates).eq("request_id", request_id).execute()
        flash(f"Request #{request_id[:8].upper()} updated successfully.", "success")
    except Exception as e:
        flash(f"Failed to update request: {e}", "danger")

    return redirect(url_for("admin_requests"))


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)

