"""Regression tests for Phase A/B — user-defined ISO-8583 specs.

Covers:
- POST /api/user-specs (CRUD + reserved-id rejection + duplicate)
- POST /api/user-specs/import (CSV + JSON payload)
- GET /api/user-specs (list)
- GET /api/user-specs/template (CSV template, public)
- PUT /api/user-specs/{id} (update + network_id immutable)
- DELETE /api/user-specs/{id} (and unregister)
- GET /api/specs (built-in + custom)
- GET /api/specs/{nid}/fields and /mandatory for user specs
- POST /api/iso/preview using user spec (with mandatory validation)
- POST /api/iso/send writing logs against a user spec
"""
import os
import uuid
import pytest
import requests

BASE_URL = (
    os.environ["REACT_APP_BACKEND_URL"].rstrip("/")
    if os.environ.get("REACT_APP_BACKEND_URL")
    else "https://financial-lab.preview.emergentagent.com"
)
ADMIN_EMAIL = "admin@iso8583.dev"
ADMIN_PASSWORD = "admin12345"


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


def _slug():
    return f"testspec{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------- public template
class TestTemplate:
    def test_template_is_public_csv(self):
        # No auth — purposely public
        r = requests.get(f"{BASE_URL}/api/user-specs/template", timeout=30)
        assert r.status_code == 200, r.text
        assert "text/csv" in r.headers.get("content-type", "")
        first_line = r.text.splitlines()[0].strip()
        # Must contain at minimum these columns
        for col in ["field", "name", "format", "length_type"]:
            assert col in first_line, f"missing {col} in CSV header: {first_line}"


# ---------------------------------------------------------------- CRUD
class TestUserSpecCRUD:
    def test_create_user_spec_minimal(self, admin_session):
        slug = _slug()
        body = {
            "network_id": slug,
            "name": "TEST_SpecCRUD",
            "description": "user spec for CRUD test",
            "fields": {
                "2": {"name": "PAN", "format": "n", "length_type": "LLVAR", "max_length": 19},
                "4": {"name": "Amount", "format": "n", "length_type": "fixed", "max_length": 12},
                "11": {"name": "STAN", "format": "n", "length_type": "fixed", "max_length": 6},
            },
            "mandatory_per_mti": {"0200": [2, 4, 11]},
        }
        r = admin_session.post(f"{BASE_URL}/api/user-specs", json=body)
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["network_id"] == f"user:{slug}"
        assert data["name"] == "TEST_SpecCRUD"
        assert data["mandatory_per_mti"]["0200"] == [2, 4, 11]
        assert "id" in data
        pytest.spec_id = data["id"]
        pytest.spec_nid = data["network_id"]
        pytest.spec_slug = slug

    def test_reserved_network_id_rejected(self, admin_session):
        for reserved in ["visa", "mastercard", "amex", "rupay"]:
            r = admin_session.post(
                f"{BASE_URL}/api/user-specs",
                json={"network_id": reserved, "name": "x"},
            )
            assert r.status_code == 400, f"{reserved}: {r.status_code} {r.text}"
            assert "reserved" in r.text.lower()

    def test_duplicate_network_id_returns_409(self, admin_session):
        slug = pytest.spec_slug
        r = admin_session.post(
            f"{BASE_URL}/api/user-specs",
            json={"network_id": slug, "name": "dup"},
        )
        assert r.status_code == 409, r.text

    def test_list_returns_owned_spec(self, admin_session):
        r = admin_session.get(f"{BASE_URL}/api/user-specs")
        assert r.status_code == 200
        ids = [s["id"] for s in r.json()]
        assert pytest.spec_id in ids

    def test_specs_endpoint_includes_builtin_and_custom(self, admin_session):
        r = admin_session.get(f"{BASE_URL}/api/specs")
        assert r.status_code == 200
        rows = r.json()
        nids = {row["network_id"]: row for row in rows}
        # Built-ins present
        for b in ["visa", "mastercard", "amex", "rupay"]:
            assert b in nids, f"missing built-in {b}: {list(nids.keys())}"
            assert nids[b]["builtin"] is True
        # Custom present + flagged builtin=False
        assert pytest.spec_nid in nids
        assert nids[pytest.spec_nid]["builtin"] is False

    def test_user_spec_fields_endpoint(self, admin_session):
        r = admin_session.get(f"{BASE_URL}/api/specs/{pytest.spec_nid}/fields")
        assert r.status_code == 200
        body = r.json()
        assert body["network_id"] == pytest.spec_nid
        # fields catalog returns list-of-dicts shape
        nums = {f["field"] for f in body["fields"]}
        assert 2 in nums and 4 in nums and 11 in nums

    def test_user_spec_mandatory_endpoint(self, admin_session):
        r = admin_session.get(f"{BASE_URL}/api/specs/{pytest.spec_nid}/mandatory")
        assert r.status_code == 200
        body = r.json()
        assert body["mandatory_per_mti"].get("0200") == [2, 4, 11]

    def test_update_user_spec(self, admin_session):
        slug = pytest.spec_slug
        update_body = {
            "network_id": slug,
            "name": "TEST_SpecCRUD_renamed",
            "description": "updated",
            "fields": {
                "2": {"name": "PAN", "format": "n", "length_type": "LLVAR", "max_length": 19},
                "4": {"name": "Amount", "format": "n", "length_type": "fixed", "max_length": 12},
                "11": {"name": "STAN", "format": "n", "length_type": "fixed", "max_length": 6},
                "41": {"name": "TID", "format": "ans", "length_type": "fixed", "max_length": 8},
            },
            "mandatory_per_mti": {"0200": [2, 4, 11, 41]},
        }
        r = admin_session.put(f"{BASE_URL}/api/user-specs/{pytest.spec_id}", json=update_body)
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["name"] == "TEST_SpecCRUD_renamed"
        assert 41 in data["mandatory_per_mti"]["0200"]

        # GET to confirm persistence
        r2 = admin_session.get(f"{BASE_URL}/api/specs/{pytest.spec_nid}/mandatory")
        assert r2.json()["mandatory_per_mti"]["0200"] == [2, 4, 11, 41]

    def test_update_with_changed_network_id_rejected(self, admin_session):
        body = {
            "network_id": _slug(),  # different
            "name": "won't-stick",
        }
        r = admin_session.put(f"{BASE_URL}/api/user-specs/{pytest.spec_id}", json=body)
        assert r.status_code == 400
        assert "network_id" in r.text.lower()


# ---------------------------------------------------------------- import
class TestUserSpecImport:
    def test_import_csv_creates_spec(self, admin_session):
        slug = _slug()
        csv_text = (
            "field,name,format,length_type,max_length,encoding,length_encoding\n"
            "2,PAN,n,LLVAR,19,ascii,ascii\n"
            "4,Amount,n,fixed,12,ascii,ascii\n"
            "11,STAN,n,fixed,6,ascii,ascii\n"
        )
        r = admin_session.post(
            f"{BASE_URL}/api/user-specs/import",
            json={
                "network_id": slug,
                "name": "TEST_csv_import",
                "csv_text": csv_text,
                "mandatory_per_mti": {"0200": [2, 4, 11]},
            },
        )
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["network_id"] == f"user:{slug}"
        pytest.csv_spec_id = data["id"]
        pytest.csv_spec_nid = data["network_id"]

    def test_import_csv_missing_header_column(self, admin_session):
        bad_csv = (
            "field,name,format,max_length\n"  # missing length_type
            "2,PAN,n,19\n"
        )
        r = admin_session.post(
            f"{BASE_URL}/api/user-specs/import",
            json={"network_id": _slug(), "name": "bad", "csv_text": bad_csv},
        )
        assert r.status_code == 400, r.text
        assert "csv header missing column" in r.text.lower()

    def test_import_payload_json(self, admin_session):
        slug = _slug()
        payload = {
            "fields": {
                "2": {"name": "PAN", "format": "n", "length_type": "LLVAR", "max_length": 19},
                "4": {"name": "Amount", "format": "n", "length_type": "fixed", "max_length": 12},
                "11": {"name": "STAN", "format": "n", "length_type": "fixed", "max_length": 6},
            },
            "mandatory_per_mti": {"0200": [2, 4, 11]},
        }
        r = admin_session.post(
            f"{BASE_URL}/api/user-specs/import",
            json={
                "network_id": slug,
                "name": "TEST_json_import",
                "payload": payload,
            },
        )
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["network_id"] == f"user:{slug}"
        pytest.json_spec_id = data["id"]
        pytest.json_spec_nid = data["network_id"]

    def test_import_no_body_rejected(self, admin_session):
        r = admin_session.post(
            f"{BASE_URL}/api/user-specs/import",
            json={"network_id": _slug(), "name": "empty"},
        )
        assert r.status_code == 400


# ---------------------------------------------------------------- iso flows on user spec
class TestIsoFlowsOnUserSpec:
    def test_preview_with_user_spec_round_trip(self, admin_session):
        body = {
            "mti": "0200",
            "network_id": pytest.spec_nid,  # from CRUD test
            "data_elements": {
                "2": "4111111111111111",
                "3": "000000",
                "4": "000000010000",
                "7": "0226140000",
                "11": "000123",
                "41": "TERM0001",
                "49": "356",
            },
            "validate": True,
        }
        r = admin_session.post(f"{BASE_URL}/api/iso/preview", json=body)
        assert r.status_code == 200, r.text
        data = r.json()
        # Preview returns {raw_hex, raw_base64, parsed:{mti,fields:[...],...}, validation_errors}
        assert "raw_hex" in data and len(data["raw_hex"]) > 0
        parsed = data.get("parsed") or {}
        assert parsed.get("mti") == "0200"
        # Round-trip: amount field 4 should encode/decode back to original
        f4 = next((f for f in parsed.get("fields", []) if f.get("field") == 4), None)
        assert f4 is not None, f"field 4 missing in parsed: {parsed}"
        assert f4["value"] == "000000010000"

    def test_preview_missing_mandatory_flags_validation_errors(self, admin_session):
        body = {
            "mti": "0200",
            "network_id": pytest.spec_nid,
            "data_elements": {
                # intentionally missing 4 / 11 / 41 (all mandatory after update)
                "2": "4111111111111111",
            },
            "validate": True,
        }
        r = admin_session.post(f"{BASE_URL}/api/iso/preview", json=body)
        # Should still 200 (preview), but validation_errors must mention mandatory
        assert r.status_code == 200, r.text
        body_json = r.json()
        errors = body_json.get("validation_errors") or []
        joined = " ".join(str(e).lower() for e in errors)
        assert "mandatory" in joined, f"expected 'mandatory' in errors: {errors}"

    def test_send_with_user_spec_writes_logs(self, admin_session):
        # Use a fresh STAN to avoid collisions
        stan = f"{uuid.uuid4().int % 1_000_000:06d}"
        body = {
            "mti": "0200",
            "network_id": pytest.spec_nid,
            "data_elements": {
                "2": "4111111111111111",
                "3": "000000",
                "4": "000000010000",
                "7": "0226140000",
                "11": stan,
                "41": "TERM0001",
                "49": "356",
            },
            "target": "simulator",
        }
        r = admin_session.post(f"{BASE_URL}/api/iso/send", json=body)
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["outbound"]["mti"] == "0200"
        assert data["inbound"]["mti"] in ("0210", "0230"), data["inbound"]
        # Response code must be 2 chars
        rc = data.get("response_code") or data["inbound"].get("data_elements", {}).get("39")
        assert rc and len(rc) == 2

        # Confirm logs exist for this STAN/network
        r2 = admin_session.get(f"{BASE_URL}/api/logs?network_id={pytest.spec_nid}")
        assert r2.status_code == 200
        items = r2.json().get("items", [])

        def _stan_of(it):
            parsed = it.get("parsed") or {}
            for f in parsed.get("fields", []) or []:
                if f.get("field") == 11:
                    return f.get("value")
            return None

        assert any(_stan_of(it) == stan for it in items), (
            f"outbound log with STAN {stan} not found among {len(items)} items"
        )


# ---------------------------------------------------------------- delete + cleanup
class TestUserSpecDelete:
    def test_delete_unregisters_spec(self, admin_session):
        # Delete the CRUD spec last (used by iso flows above)
        r = admin_session.delete(f"{BASE_URL}/api/user-specs/{pytest.spec_id}")
        assert r.status_code == 200, r.text

        # /api/specs should no longer list it
        r2 = admin_session.get(f"{BASE_URL}/api/specs")
        nids = {row["network_id"] for row in r2.json()}
        assert pytest.spec_nid not in nids

        # /api/specs/{nid}/fields → 404
        r3 = admin_session.get(f"{BASE_URL}/api/specs/{pytest.spec_nid}/fields")
        assert r3.status_code == 404

    def test_cleanup_csv_and_json_specs(self, admin_session):
        for sid in (getattr(pytest, "csv_spec_id", None), getattr(pytest, "json_spec_id", None)):
            if sid:
                admin_session.delete(f"{BASE_URL}/api/user-specs/{sid}")
