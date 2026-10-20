-- =============================================================
-- Run this SQL in your Supabase Dashboard → SQL Editor
-- =============================================================

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id     UUID            NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    name        VARCHAR(100)    NOT NULL,
    mobile      VARCHAR(10)     NOT NULL,
    email       VARCHAR(255)    NOT NULL UNIQUE,
    address     VARCHAR(500)    NOT NULL,
    password_hash TEXT          NOT NULL,
    role        VARCHAR(20)     NOT NULL DEFAULT 'customer'
                CHECK (role IN ('customer', 'admin', 'delivery', 'shop')),
    profile_data JSONB          NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ     NOT NULL DEFAULT now()
);

-- Index for fast login lookups
CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);

ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_data JSONB NOT NULL DEFAULT '{}'::jsonb;

-- Update the allowed roles when upgrading an existing database.
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE users ADD CONSTRAINT users_role_check
    CHECK (role IN ('customer', 'admin', 'delivery', 'shop'));

-- =============================================================
-- Row Level Security (RLS)
-- =============================================================
-- Disable RLS so the service-role key (or anon key with no
-- policies) can freely read/write during development.
-- Tighten this before going to production!
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- Allow all operations for the anon/service-role key
CREATE POLICY "Allow all for service role" ON users
    FOR ALL
    USING (true)
    WITH CHECK (true);

-- =============================================================
-- Requests table
-- =============================================================
CREATE TABLE IF NOT EXISTS requests (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY,
    request_id          UUID            NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID            NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    company             VARCHAR(100)    NOT NULL,
    model               VARCHAR(100)    NOT NULL,
    request_type        VARCHAR(20)     NOT NULL CHECK (request_type IN ('Repair', 'Resell')),
    part                VARCHAR(100)    NOT NULL,
    issue_description   TEXT            NOT NULL,
    status              VARCHAR(50)     NOT NULL DEFAULT 'Pickup Pending',
    delivery_boy_id     UUID            REFERENCES users(user_id) ON DELETE SET NULL,
    photo_url           VARCHAR(500),
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT now()
);

-- Optional migration for existing requests table:
-- ALTER TABLE requests ADD COLUMN IF NOT EXISTS photo_url VARCHAR(500);

-- Index for fast queries by user, status, and delivery person
CREATE INDEX IF NOT EXISTS idx_requests_user_id ON requests (user_id);
CREATE INDEX IF NOT EXISTS idx_requests_status ON requests (status);
CREATE INDEX IF NOT EXISTS idx_requests_delivery_boy ON requests (delivery_boy_id);
CREATE INDEX IF NOT EXISTS idx_requests_created_at ON requests (created_at DESC);

-- Row Level Security (RLS) for requests
ALTER TABLE requests ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow all for service role on requests" ON requests
    FOR ALL
    USING (true)
    WITH CHECK (true);


