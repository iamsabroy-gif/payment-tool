"""ISO-8583 Lab backend API tests (cookie-based auth)."""
import os
import uuid
import time
import pytest
import requests

BASE_URL = os.environ["REACT_APP_BACKEND_URL"].rstrip("/") if os.environ.get("REACT_APP_BACKEND_URL") else "https://financial-lab.preview.emergentagent.com"
ADMIN_EMAIL = "admin@iso8583.dev"
ADMIN_PASSWORD = "admin12345"


# ---------------------------------------------------------------- fixtures
@pytest.fixture(scope="session")
def admin_session():
    s = requests.Session()
    r = s.post(f"{BASE_URL}/api/auth/login",
               json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
               timeout=30)
    assert r.status_code == 200, f"admin login failed: {r.status_code} {r.text}"
    assert s.cookies.get("access_token"), "access_token cookie missing"
    return s


@pytest.fixture(scope="session")
def free_user():
    """Create a fresh free-tier user."""
    email = f"TEST_{uuid.uuid4().hex[:8]}@example.com"
    pwd = "Password123!"
    s = requests.Session()
    r = s.post(f"{BASE_URL}/api/auth/register",
               json={"email": email, "password": pwd, "name": "Free User"},
               timeout=30)
    assert r.status_code == 200, r.text
    return {"session": s, "email": email, "password": pwd, "user": r.json()}


# ---------------------------------------------------------------- auth
class TestAuth:
    def test_register_new_user(self):
        email = f"TEST_{uuid.uuid4().hex[:8]}@example.com"
        s = requests.Session()
        r = s.post(f"{BASE_URL}/api/auth/register",
                   json={"email": email, "password": "Password123!"})
        assert r.status_code == 200
        body = r.json()
        assert body["email"] == email.lower()
        assert body["plan"] == "free"
        assert s.cookies.get("access_token")
        assert s.cookies.get("refresh_token")

    def test_login_admin(self, admin_session):
        r = admin_session.get(f"{BASE_URL}/api/auth/me")
        assert r.status_code == 200
        body = r.json()
        assert body["email"] == ADMIN_EMAIL
        assert body["plan"] == "pro"
        assert "password_hash" not in body

    def test_login_invalid_password(self):
        r = requests.post(f"{BASE_URL}/api/auth/login",
                          json={"email": ADMIN_EMAIL, "password": "wrong-pass-123"})
        assert r.status_code == 401

    def test_me_unauthenticated(self):
        r = requests.get(f"{BASE_URL}/api/auth/me")
        assert r.status_code == 401


# ---------------------------------------------------------------- specs
class TestSpecs:
    def test_list_specs(self, admin_session):
        r = admin_session.get(f"{BASE_URL}/api/specs")
        assert r.status_code == 200
        ids = [x["network_id"] for x in r.json()]
        assert {"visa", "mastercard", "amex"}.issubset(set(ids))

    def test_visa_fields(self, admin_session):
        r = admin_session.get(f"{BASE_URL}/api/specs/visa/fields")
        assert r.status_code == 200
        body = r.json()
        assert body["network_id"] == "visa"
        nums = [f["field"] for f in body["fields"]]
        for f in (2, 3, 4, 11, 41, 49):
            assert f in nums

    def test_unknown_network(self, admin_session):
        r = admin_session.get(f"{BASE_URL}/api/specs/foo/fields")
        assert r.status_code == 404


# ---------------------------------------------------------------- iso preview/send
SAMPLE_DE = {
    "2": "4111111111111111",
    "3": "000000",
    "4": "000000010000",
    "11": "123456",
    "41": "TERM0001",
    "49": "840",
}


class TestIsoFlow:
    def test_preview_0200(self, admin_session):
        r = admin_session.post(f"{BASE_URL}/api/iso/preview",
                               json={"mti": "0200", "network_id": "visa", "data_elements": SAMPLE_DE})
        assert r.status_code == 200, r.text
        body = r.json()
        assert "raw_hex" in body and len(body["raw_hex"]) > 0
        assert body["parsed"]["mti"] == "0200"
        assert sorted(body["parsed"]["active_fields"]) == [2, 3, 4, 11, 41, 49]

    def test_preview_invalid_mti(self, admin_session):
        r = admin_session.post(f"{BASE_URL}/api/iso/preview",
                               json={"mti": "xx", "network_id": "visa", "data_elements": SAMPLE_DE})
        assert r.status_code == 400

    def test_send_creates_two_logs(self, admin_session):
        r = admin_session.post(f"{BASE_URL}/api/iso/send",
                               json={"mti": "0200", "network_id": "visa", "data_elements": SAMPLE_DE})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["outbound"]["direction"] == "outbound"
        assert body["inbound"]["direction"] == "inbound"
        assert body["outbound"]["status_code"] == body["response_code"]
        assert body["inbound"]["related_id"] == body["outbound"]["id"]
        assert body["response_code"] in {"00", "05", "12", "14", "51", "61"}
        # GET log to verify persistence
        log_id = body["outbound"]["id"]
        g = admin_session.get(f"{BASE_URL}/api/logs/{log_id}")
        assert g.status_code == 200
        assert g.json()["id"] == log_id

    def test_logs_list_and_filter(self, admin_session):
        r = admin_session.get(f"{BASE_URL}/api/logs?limit=20")
        assert r.status_code == 200
        body = r.json()
        assert "items" in body and "total" in body
        # filter
        r2 = admin_session.get(f"{BASE_URL}/api/logs?direction=inbound&limit=5")
        assert r2.status_code == 200
        for it in r2.json()["items"]:
            assert it["direction"] == "inbound"


# ---------------------------------------------------------------- templates
class TestTemplates:
    def test_create_list_delete(self, admin_session):
        payload = {
            "name": f"TEST_tpl_{uuid.uuid4().hex[:6]}",
            "network_id": "visa",
            "mti": "0200",
            "data_elements": SAMPLE_DE,
            "description": "test",
        }
        r = admin_session.post(f"{BASE_URL}/api/templates", json=payload)
        assert r.status_code == 200, r.text
        tid = r.json()["id"]
        # list
        r2 = admin_session.get(f"{BASE_URL}/api/templates")
        assert r2.status_code == 200
        assert any(t["id"] == tid for t in r2.json())
        # delete
        r3 = admin_session.delete(f"{BASE_URL}/api/templates/{tid}")
        assert r3.status_code == 200
        # gone
        r4 = admin_session.delete(f"{BASE_URL}/api/templates/{tid}")
        assert r4.status_code == 404


# ---------------------------------------------------------------- stats
class TestStats:
    def test_stats_shape(self, admin_session):
        r = admin_session.get(f"{BASE_URL}/api/stats")
        assert r.status_code == 200
        body = r.json()
        for key in ("total", "outbound", "inbound", "success", "failed",
                    "volume_by_day", "recent", "response_code_breakdown",
                    "plan", "log_limit"):
            assert key in body
        assert body["plan"] == "pro"
        assert body["log_limit"] is None  # pro = unlimited


# ---------------------------------------------------------------- billing
class TestBilling:
    def test_checkout_creates_session(self, admin_session):
        r = admin_session.post(f"{BASE_URL}/api/billing/checkout",
                               json={"origin_url": BASE_URL})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["url"].startswith("http")
        assert body["session_id"]
        # Poll status with the freshly created session
        sid = body["session_id"]
        time.sleep(2)
        s = admin_session.get(f"{BASE_URL}/api/billing/status/{sid}")
        # emergent test stripe key may not be queryable; tolerate 502 but flag
        assert s.status_code in (200, 502), s.text
        if s.status_code == 200:
            sb = s.json()
            assert "payment_status" in sb
            assert "status" in sb


# ---------------------------------------------------------------- free quota
class TestFreeQuota:
    def test_free_user_log_limit(self, free_user):
        s = free_user["session"]
        # send 51 transactions; the 51st should 402
        last_status = None
        for i in range(52):
            r = s.post(f"{BASE_URL}/api/iso/send",
                       json={"mti": "0200", "network_id": "visa", "data_elements": SAMPLE_DE})
            last_status = r.status_code
            if r.status_code == 402:
                break
        assert last_status == 402, f"Expected 402 quota error, got {last_status}"

    def test_stats_free_plan(self, free_user):
        s = free_user["session"]
        r = s.get(f"{BASE_URL}/api/stats")
        assert r.status_code == 200
        body = r.json()
        assert body["plan"] == "free"
        assert body["log_limit"] == 50
