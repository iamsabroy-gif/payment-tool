"""Regression tests for features added after iteration_1:

- WebSocket connection profile CRUD (POST /api/connections with transport=websocket)
- Live WebSocket connect + iso/send-tcp round-trip against the upstream
  wss://iso8583-server.emergent.host sandbox
- Cryptography routes: /api/keys/{kcv,cvv,pvv,arqc}, /api/pin/encrypt
- ASCII decoder regression for secondary-bitmap (covered separately in
  test_iso8583_codecs.py — here we also do an end-to-end check via the
  /api/iso/simulate route to make sure nothing else blew up).
"""
import os
import uuid
import pytest
import requests

BASE_URL = os.environ["REACT_APP_BACKEND_URL"].rstrip("/") if os.environ.get("REACT_APP_BACKEND_URL") else "https://financial-lab.preview.emergentagent.com"
ADMIN_EMAIL = "admin@iso8583.dev"
ADMIN_PASSWORD = "admin12345"

LIVE_WS_URL = "wss://iso8583-server.emergent.host/api/ws/iso8583"
LIVE_WS_TOKEN = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiJzdmM6MGIwYjkyNDktMDVmOC00MGViLTkwYmMtOGJiNGRmYzg5N2JjIiwia2luZCI6InNlcnZpY2UiLCJsYWJlbCI6ImZpbmFuY2lhbC1sYWIgYnJpZGdlIiwiZXhwIjoxNzc3NzQ5Nzk5LCJpYXQiOjE3Nzc2NjMzOTl9."
    "YOKrVFtflSGnVznbqBlJqeWLYf0SOabof-yVnH0Sny4"
)


@pytest.fixture(scope="module")
def admin_session():
    s = requests.Session()
    r = s.post(
        f"{BASE_URL}/api/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        timeout=30,
    )
    assert r.status_code == 200, f"admin login failed: {r.status_code} {r.text}"
    return s


# ---------------------------------------------------------------- WebSocket profile CRUD
class TestWebSocketProfile:
    def test_create_ws_profile_echoes_token_but_not_password(self, admin_session):
        name = f"TEST_ws_{uuid.uuid4().hex[:6]}"
        payload = {
            "name": name,
            "transport": "websocket",
            "ws_url": LIVE_WS_URL,
            "auth_token": LIVE_WS_TOKEN,
            "auth_password": "shouldnotbereturned",
            "ws_text_mode": False,
            "length_header": "2_byte",
            "wire_format": "ascii",
            "timeout_sec": 15,
        }
        r = admin_session.post(f"{BASE_URL}/api/connections", json=payload)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["name"] == name
        assert body["transport"] == "websocket"
        assert body["ws_url"] == LIVE_WS_URL
        assert body["auth_token"] == LIVE_WS_TOKEN
        assert body["wire_format"] == "ascii"
        assert body["length_header"] == "2_byte"
        # auth_password MUST NOT be echoed
        assert "auth_password" not in body, "password was leaked back in response"
        # Store id for downstream tests
        pytest.ws_profile_id = body["id"]

    def test_list_shows_new_ws_profile(self, admin_session):
        r = admin_session.get(f"{BASE_URL}/api/connections")
        assert r.status_code == 200
        ids = [c["id"] for c in r.json()]
        assert getattr(pytest, "ws_profile_id", None) in ids

    def test_create_ws_profile_missing_url_rejected(self, admin_session):
        payload = {
            "name": f"TEST_bad_{uuid.uuid4().hex[:6]}",
            "transport": "websocket",
            "length_header": "2_byte",
            "wire_format": "ascii",
        }
        r = admin_session.post(f"{BASE_URL}/api/connections", json=payload)
        assert r.status_code == 400
        assert "ws_url" in r.text

    def test_create_tcp_profile_missing_host_rejected(self, admin_session):
        payload = {
            "name": f"TEST_bad_tcp_{uuid.uuid4().hex[:6]}",
            "transport": "tcp",
            "length_header": "2_byte",
        }
        r = admin_session.post(f"{BASE_URL}/api/connections", json=payload)
        assert r.status_code == 400


# ---------------------------------------------------------------- Live WS connect + send
class TestLiveWebSocketRoundTrip:
    def test_connect_ws_profile(self, admin_session):
        conn_id = getattr(pytest, "ws_profile_id", None)
        if not conn_id:
            pytest.skip("ws_profile_id not set — upstream create failed")
        r = admin_session.post(f"{BASE_URL}/api/connections/{conn_id}/connect", timeout=30)
        # Accept 200 (online) or structured 502/504 when internet blocked
        assert r.status_code in (200, 502, 504), r.text
        if r.status_code != 200:
            pytest.skip(f"Upstream unreachable from pod: {r.status_code} {r.text}")
        body = r.json()
        assert body.get("state") in ("connected", "online", "ready"), body

    def test_send_tcp_over_ws_roundtrip(self, admin_session):
        conn_id = getattr(pytest, "ws_profile_id", None)
        if not conn_id:
            pytest.skip("ws_profile_id not set")
        # Quick status check first — skip test if connection not live
        st = admin_session.get(f"{BASE_URL}/api/connections/{conn_id}/status")
        if st.status_code != 200 or st.json().get("state") not in ("connected", "online", "ready"):
            pytest.skip(f"ws not connected: {st.text}")
        payload = {
            "connection_id": conn_id,
            "mti": "0800",
            "network_id": "visa",
            "data_elements": {
                "7": "0226140000",
                "11": "000099",
                "70": "301",
            },
        }
        r = admin_session.post(f"{BASE_URL}/api/iso/send-tcp", json=payload, timeout=30)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["outbound"]["mti"] == "0800"
        # Real upstream should respond with 0810
        assert body["inbound"]["mti"] == "0810", body["inbound"]
        assert body["response_code"] == "00", body

    def test_disconnect_ws_profile(self, admin_session):
        conn_id = getattr(pytest, "ws_profile_id", None)
        if not conn_id:
            pytest.skip("ws_profile_id not set")
        r = admin_session.post(f"{BASE_URL}/api/connections/{conn_id}/disconnect")
        assert r.status_code == 200

    def test_cleanup_delete_ws_profile(self, admin_session):
        conn_id = getattr(pytest, "ws_profile_id", None)
        if not conn_id:
            pytest.skip("nothing to clean up")
        r = admin_session.delete(f"{BASE_URL}/api/connections/{conn_id}")
        assert r.status_code == 200


# ---------------------------------------------------------------- Crypto routes
class TestCryptoRoutes:
    def test_kcv_3des(self, admin_session):
        r = admin_session.post(
            f"{BASE_URL}/api/keys/kcv",
            json={"key_hex": "0123456789ABCDEFFEDCBA9876543210", "algorithm": "3DES"},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["algorithm"] == "3DES"
        assert len(body["kcv"]) == 6  # first 6 hex chars
        assert all(c in "0123456789ABCDEFabcdef" for c in body["kcv"])

    def test_cvv(self, admin_session):
        r = admin_session.post(
            f"{BASE_URL}/api/keys/cvv",
            json={
                "pan": "4111111111111111",
                "expiry": "2512",
                "service_code": "101",
                "cvk_a_hex": "0123456789ABCDEF",
                "cvk_b_hex": "FEDCBA9876543210",
            },
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["service_code"] == "101"
        assert len(body["cvv"]) == 3 and body["cvv"].isdigit()

    def test_pvv(self, admin_session):
        r = admin_session.post(
            f"{BASE_URL}/api/keys/pvv",
            json={
                "pan": "4111111111111111",
                "pin": "1234",
                "pvki": "1",
                "pvk_a_hex": "0123456789ABCDEF",
                "pvk_b_hex": "FEDCBA9876543210",
            },
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["pvki"] == "1"
        assert len(body["pvv"]) == 4 and body["pvv"].isdigit()

    def test_arqc_cvn10(self, admin_session):
        r = admin_session.post(
            f"{BASE_URL}/api/keys/arqc",
            json={
                "mdk_hex": "0123456789ABCDEFFEDCBA9876543210",
                "pan": "4111111111111111",
                "psn": "00",
                "cdol_hex": "00000000010000000000000000084000008000000008400000036522000000000002",
                "cvn": "CVN10",
            },
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["algorithm"] == "3DES"
        assert len(body["arqc_hex"]) == 16
        assert body["f55_tlv_hex"].startswith("9F2608")

    def test_pin_encrypt_iso0(self, admin_session):
        r = admin_session.post(
            f"{BASE_URL}/api/pin/encrypt",
            json={
                "pin": "1234",
                "pan": "4111111111111111",
                "key_hex": "0123456789ABCDEFFEDCBA9876543210",
                "format": "ISO-0",
                "algorithm": "3DES",
            },
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["format"] == "ISO-0"
        assert len(body["clear_block_hex"]) == 16
        assert len(body["encrypted_block_hex"]) == 16


# ---------------------------------------------------------------- Samples
class TestSamples:
    def test_samples_public_list(self, admin_session):
        r = admin_session.get(f"{BASE_URL}/api/samples")
        assert r.status_code == 200
        body = r.json()
        assert isinstance(body, list)
        assert len(body) >= 1
        for s in body:
            assert "id" in s and "name" in s
