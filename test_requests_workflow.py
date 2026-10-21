"""Test suite for requests table schema, validation, new request, my requests, admin requests, and access control."""

import io
import unittest
from unittest.mock import MagicMock, patch
import uuid

import app as flask_app


class TestRequestsWorkflow(unittest.TestCase):
    def setUp(self):
        self.app = flask_app.app
        self.app.config["TESTING"] = True
        self.app.config["WTF_CSRF_ENABLED"] = False
        self.client = self.app.test_client()

    # ------------------------------------------------------------------------
    # 6. Access Control Tests
    # ------------------------------------------------------------------------
    def test_unauthenticated_redirects_to_login(self):
        """No login -> redirect to login."""
        protected_routes = [
            "/customer/dashboard",
            "/customer/requests",
            "/customer/requests/new",
            "/admin/dashboard",
            "/admin/requests",
        ]
        for route in protected_routes:
            with self.subTest(route=route):
                resp = self.client.get(route, follow_redirects=False)
                self.assertEqual(resp.status_code, 302)
                self.assertIn("/login", resp.headers["Location"])

    def test_customer_accessing_admin_page_denied(self):
        """Customer opening an admin page -> access denied."""
        with self.client.session_transaction() as sess:
            sess["user_id"] = str(uuid.uuid4())
            sess["role"] = "customer"
            sess["name"] = "Test Customer"

        admin_routes = ["/admin/dashboard", "/admin/requests"]
        for route in admin_routes:
            with self.subTest(route=route):
                resp = self.client.get(route, follow_redirects=True)
                self.assertEqual(resp.status_code, 200)
                html = resp.get_data(as_text=True)
                self.assertIn("Access denied", html)
                # redirected back to customer dashboard
                self.assertIn("Your repair activity", html)

    def test_admin_accessing_admin_page_allowed(self):
        """Admin opening admin pages -> permitted."""
        with self.client.session_transaction() as sess:
            sess["user_id"] = str(uuid.uuid4())
            sess["role"] = "admin"
            sess["name"] = "Admin User"

        with patch.object(flask_app.supabase, "table") as mock_table:
            mock_table.return_value.select.return_value.execute.return_value.data = []
            mock_table.return_value.select.return_value.eq.return_value.execute.return_value.data = []
            mock_table.return_value.select.return_value.order.return_value.execute.return_value.data = []

            resp = self.client.get("/admin/requests")
            self.assertEqual(resp.status_code, 200)
            html = resp.get_data(as_text=True)
            self.assertIn("Service Requests Management", html)

    # ------------------------------------------------------------------------
    # 2 & 3. New Request Page & Validation
    # ------------------------------------------------------------------------
    def test_new_request_page_renders_fields(self):
        """New Request page contains company, model, request_type, part, issue_description."""
        with self.client.session_transaction() as sess:
            sess["user_id"] = str(uuid.uuid4())
            sess["role"] = "customer"
            sess["name"] = "Test Customer"

        resp = self.client.get("/customer/requests/new")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn('name="company"', html)
        self.assertIn('name="model"', html)
        self.assertIn('name="request_type"', html)
        self.assertIn('name="part"', html)
        self.assertIn('name="issue_description"', html)
        self.assertIn("Repair", html)
        self.assertIn("Resell", html)

    def test_new_request_validation_errors(self):
        """Backend validates invalid or empty fields."""
        with self.client.session_transaction() as sess:
            sess["user_id"] = str(uuid.uuid4())
            sess["role"] = "customer"
            sess["name"] = "Test Customer"

        # Missing all fields
        resp = self.client.post("/customer/requests/new", data={
            "company": "",
            "model": "",
            "request_type": "InvalidType",
            "part": "",
            "issue_description": "short",
        }, follow_redirects=True)

        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("Company/brand name must be between 2 and 100 characters.", html)
        self.assertIn("Model name must be between 1 and 100 characters.", html)
        self.assertIn("Request type must be either &#39;Repair&#39; or &#39;Resell&#39;.", html)
        self.assertIn("Please select or specify the affected part.", html)
        self.assertIn("Issue description must be between 10 and 2000 characters.", html)

    def test_resell_request_labels_and_validation(self):
        """Resell request displays 'Part Description' and validates resell specific messages and photo requirement."""
        with self.client.session_transaction() as sess:
            sess["user_id"] = str(uuid.uuid4())
            sess["role"] = "customer"
            sess["name"] = "Test Customer"

        # Missing part, description, and photo for Resell
        resp = self.client.post("/customer/requests/new", data={
            "company": "Samsung",
            "model": "Galaxy S22",
            "request_type": "Resell",
            "part": "",
            "issue_description": "short",
        }, follow_redirects=True)

        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("Please select or specify the part to resell.", html)
        self.assertIn("Part description must be between 10 and 2000 characters.", html)
        self.assertIn("Please upload a photo of the part for validation.", html)
        self.assertIn("Part Description", html)
        self.assertIn("Part / Component to Resell", html)

        # Invalid photo extension
        resp_invalid = self.client.post("/customer/requests/new", data={
            "company": "Samsung",
            "model": "Galaxy S22",
            "request_type": "Resell",
            "part": "Screen / Display",
            "issue_description": "Original working AMOLED display with no scratches.",
            "part_photo": (io.BytesIO(b"fake-pdf-content"), "screen.pdf"),
        }, content_type="multipart/form-data", follow_redirects=True)

        self.assertEqual(resp_invalid.status_code, 200)
        html_invalid = resp_invalid.get_data(as_text=True)
        self.assertIn("Photo must be a valid image format (PNG, JPG, JPEG, or WEBP).", html_invalid)

    def test_resell_request_saves_with_uploaded_photo(self):
        """Valid Resell request saves with photo reference and 'Pickup Pending'."""
        user_uuid = str(uuid.uuid4())
        with self.client.session_transaction() as sess:
            sess["user_id"] = user_uuid
            sess["role"] = "customer"
            sess["name"] = "Test Customer"

        inserted_docs = []

        def mock_insert(doc):
            inserted_docs.append(doc)
            mock_res = MagicMock()
            mock_res.execute.return_value = MagicMock(data=[doc])
            return mock_res

        with patch.object(flask_app.supabase, "table") as mock_table:
            mock_table.return_value.insert.side_effect = mock_insert
            mock_table.return_value.select.return_value.eq.return_value.order.return_value.execute.return_value.data = []

            resp = self.client.post("/customer/requests/new", data={
                "company": "Apple",
                "model": "iPhone 13",
                "request_type": "Resell",
                "part": "Battery",
                "issue_description": "Original OEM battery with 88% battery health in great condition.",
                "part_photo": (io.BytesIO(b"test-image-binary-data"), "battery_health.jpg"),
            }, content_type="multipart/form-data", follow_redirects=True)

            self.assertEqual(resp.status_code, 200)
            self.assertEqual(len(inserted_docs), 1)
            saved = inserted_docs[0]
            self.assertEqual(saved["user_id"], user_uuid)
            self.assertEqual(saved["request_type"], "Resell")
            self.assertEqual(saved["part"], "Battery")
            self.assertIn("[Photo: /uploads/", saved["issue_description"])

    def test_new_request_saves_with_default_status_and_user_id(self):
        """Valid submission saves with 'Pickup Pending' and logged-in user_id."""
        user_uuid = str(uuid.uuid4())
        with self.client.session_transaction() as sess:
            sess["user_id"] = user_uuid
            sess["role"] = "customer"
            sess["name"] = "Test Customer"

        inserted_docs = []

        def mock_insert(doc):
            inserted_docs.append(doc)
            mock_res = MagicMock()
            mock_res.execute.return_value = MagicMock(data=[doc])
            return mock_res

        with patch.object(flask_app.supabase, "table") as mock_table:
            # Mock table("requests").insert(...)
            mock_table.return_value.insert.side_effect = mock_insert
            # Mock table("requests").select(...)... for subsequent redirect to my_requests
            mock_table.return_value.select.return_value.eq.return_value.order.return_value.execute.return_value.data = []

            resp = self.client.post("/customer/requests/new", data={
                "company": "Apple",
                "model": "iPhone 14 Pro",
                "request_type": "Repair",
                "part": "Screen / Display",
                "issue_description": "The screen has vertical green lines and does not respond to touch.",
            }, follow_redirects=True)

            self.assertEqual(resp.status_code, 200)
            self.assertEqual(len(inserted_docs), 1)
            saved = inserted_docs[0]
            self.assertEqual(saved["user_id"], user_uuid)
            self.assertEqual(saved["company"], "Apple")
            self.assertEqual(saved["model"], "iPhone 14 Pro")
            self.assertEqual(saved["request_type"], "Repair")
            self.assertEqual(saved["part"], "Screen / Display")
            self.assertEqual(saved["issue_description"], "The screen has vertical green lines and does not respond to touch.")
            self.assertEqual(saved["status"], "Pickup Pending")
            self.assertIsNone(saved["delivery_boy_id"])

    # ------------------------------------------------------------------------
    # 4. My Requests Page
    # ------------------------------------------------------------------------
    def test_my_requests_shows_only_customer_requests(self):
        """My Requests page displays customer's requests and their statuses."""
        user_uuid = str(uuid.uuid4())
        with self.client.session_transaction() as sess:
            sess["user_id"] = user_uuid
            sess["role"] = "customer"
            sess["name"] = "Alice Customer"

        mock_requests = [
            {
                "request_id": str(uuid.uuid4()),
                "user_id": user_uuid,
                "company": "Samsung",
                "model": "Galaxy S23",
                "request_type": "Repair",
                "part": "Battery",
                "issue_description": "Battery drains within 2 hours of full charge.",
                "status": "Pickup Pending",
                "delivery_boy_id": None,
                "created_at": "2026-10-19T08:00:00Z",
            }
        ]

        with patch.object(flask_app.supabase, "table") as mock_table:
            # Query filters by eq("user_id", user_uuid)
            mock_table.return_value.select.return_value.eq.return_value.order.return_value.execute.return_value.data = mock_requests

            resp = self.client.get("/customer/requests")
            self.assertEqual(resp.status_code, 200)
            html = resp.get_data(as_text=True)
            self.assertIn("Samsung", html)
            self.assertIn("Galaxy S23", html)
            self.assertIn("Battery", html)
            self.assertIn("Pickup Pending", html)
            # Verify estimated pickup date trigger and modal
            self.assertIn("pickup-estimate-trigger", html)
            self.assertIn("pickupEstimateModal", html)

    def test_pickup_pending_shows_estimated_pickup_date_5_to_7_days(self):
        """Clicking pickup pending status column shows estimated date of pickup (after 5-7 days)."""
        from app import calculate_pickup_estimate

        # Unit test helper: 5 to 7 days calculation
        est = calculate_pickup_estimate("2026-10-10T10:00:00Z")
        self.assertEqual(est["start"], "15 Oct 2026")
        self.assertEqual(est["end"], "17 Oct 2026")
        self.assertEqual(est["range_text"], "Oct 15 – Oct 17, 2026")

        # Integration test with my_requests page
        user_uuid = str(uuid.uuid4())
        req_id = str(uuid.uuid4())
        with self.client.session_transaction() as sess:
            sess["user_id"] = user_uuid
            sess["role"] = "customer"
            sess["name"] = "Alice Customer"

        mock_requests = [
            {
                "request_id": req_id,
                "user_id": user_uuid,
                "company": "OnePlus",
                "model": "11R",
                "request_type": "Repair",
                "part": "Screen / Display",
                "issue_description": "Touch is flickering.",
                "status": "Pickup Pending",
                "delivery_boy_id": None,
                "created_at": "2026-10-10T10:00:00Z",
            }
        ]

        with patch.object(flask_app.supabase, "table") as mock_table:
            mock_table.return_value.select.return_value.eq.return_value.order.return_value.execute.return_value.data = mock_requests

            resp = self.client.get("/my-requests")
            self.assertEqual(resp.status_code, 200)
            html = resp.get_data(as_text=True)

            # Check that pickup pending status column has interactive trigger and data attributes
            self.assertIn("pickup-estimate-trigger", html)
            self.assertIn("status-cell-clickable", html)
            self.assertIn("data-estimate-range=\"Oct 15 – Oct 17, 2026\"", html)
            self.assertIn("pickupEstimateModal", html)
            self.assertIn("Estimated Pickup Schedule", html)
            self.assertIn("5 to 7 days", html)


    # ------------------------------------------------------------------------
    # 5. Admin Page - List, Delivery Boy & Status Dropdowns
    # ------------------------------------------------------------------------
    def test_admin_requests_lists_and_updates(self):
        """Admin page lists requests with delivery boy and status dropdowns."""
        admin_uuid = str(uuid.uuid4())
        delivery_uuid = str(uuid.uuid4())
        cust_uuid = str(uuid.uuid4())

        with self.client.session_transaction() as sess:
            sess["user_id"] = admin_uuid
            sess["role"] = "admin"
            sess["name"] = "Admin Chief"

        req_id = str(uuid.uuid4())
        mock_reqs = [
            {
                "request_id": req_id,
                "user_id": cust_uuid,
                "company": "Dell",
                "model": "XPS 15",
                "request_type": "Repair",
                "part": "Motherboard / Logic Board",
                "issue_description": "Device does not turn on after BIOS update.",
                "status": "Pickup Pending",
                "delivery_boy_id": None,
                "created_at": "2026-10-19T08:30:00Z",
            }
        ]
        mock_delivery_boys = [
            {"user_id": delivery_uuid, "name": "Speedy Courier", "mobile": "9876543210"}
        ]
        mock_customers = [
            {"user_id": cust_uuid, "name": "John Customer", "mobile": "9123456789", "address": "123 Green Way", "email": "john@cust.com"}
        ]

        with patch.object(flask_app.supabase, "table") as mock_table:
            def table_side_effect(name):
                t = MagicMock()
                if name == "requests":
                    t.select.return_value.order.return_value.execute.return_value.data = mock_reqs
                elif name == "users":
                    t.select.return_value.eq.return_value.execute.return_value.data = mock_delivery_boys
                    t.select.return_value.in_.return_value.execute.return_value.data = mock_customers
                return t

            mock_table.side_effect = table_side_effect

            resp = self.client.get("/admin/requests")
            self.assertEqual(resp.status_code, 200)
            html = resp.get_data(as_text=True)
            self.assertIn("Dell", html)
            self.assertIn("XPS 15", html)
            self.assertIn("Speedy Courier", html)
            self.assertIn('name="delivery_boy_id"', html)
            self.assertIn('name="status"', html)

        # Test POST update to assign delivery boy and change status
        updated_calls = []

        with patch.object(flask_app.supabase, "table") as mock_table:
            def update_table_side_effect(name):
                t = MagicMock()
                if name == "users":
                    # Check delivery boy exists
                    t.select.return_value.eq.return_value.eq.return_value.execute.return_value.data = [{"user_id": delivery_uuid}]
                elif name == "requests":
                    def mock_update(payload):
                        updated_calls.append(payload)
                        mock_eq = MagicMock()
                        mock_eq.execute.return_value = MagicMock(data=[payload])
                        return MagicMock(eq=MagicMock(return_value=mock_eq))
                    t.update.side_effect = mock_update
                return t

            mock_table.side_effect = update_table_side_effect

            update_resp = self.client.post(f"/admin/requests/{req_id}/update", data={
                "delivery_boy_id": delivery_uuid,
                "status": "Repair in Progress",
            }, follow_redirects=True)

            self.assertEqual(update_resp.status_code, 200)
            self.assertEqual(len(updated_calls), 1)
            self.assertEqual(updated_calls[0]["status"], "Repair in Progress")
            self.assertEqual(updated_calls[0]["delivery_boy_id"], delivery_uuid)


if __name__ == "__main__":
    unittest.main()
