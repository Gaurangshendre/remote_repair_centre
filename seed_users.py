"""Seed the Supabase users table with 1 admin + 2 delivery boys for testing.

Run once:  python seed_users.py
"""

import os
import uuid

from dotenv import load_dotenv
from supabase import create_client
from werkzeug.security import generate_password_hash

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("Set SUPABASE_URL and SUPABASE_KEY in your .env file.")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

SEED_USERS = [
    {
        "user_id": str(uuid.uuid4()),
        "name": "Admin User",
        "mobile": "9000000001",
        "email": "admin@rrc.com",
        "address": "RRC Head Office, Main Street",
        "password_hash": generate_password_hash("Admin@123"),
        "role": "admin",
    },
    {
        "user_id": str(uuid.uuid4()),
        "name": "Delivery Boy One",
        "mobile": "9000000002",
        "email": "delivery1@rrc.com",
        "address": "Delivery Hub A, North Zone",
        "password_hash": generate_password_hash("Deliver@123"),
        "role": "delivery",
    },
    {
        "user_id": str(uuid.uuid4()),
        "name": "Delivery Boy Two",
        "mobile": "9000000003",
        "email": "delivery2@rrc.com",
        "address": "Delivery Hub B, South Zone",
        "password_hash": generate_password_hash("Deliver@456"),
        "role": "delivery",
    },
]


def seed():
    for user in SEED_USERS:
        # Check if user already exists
        existing = (
            supabase.table("users")
            .select("user_id")
            .eq("email", user["email"])
            .execute()
        )
        if existing.data:
            print(f"  Skipped (already exists): {user['email']}")
        else:
            supabase.table("users").insert(user).execute()
            print(f"  Inserted: {user['email']}  role={user['role']}")


if __name__ == "__main__":
    seed()
    print("\nDone. Seed users ready for testing.")
