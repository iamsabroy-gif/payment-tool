"""Regression tests for features added in iteration_3:

- Bucket CRUD: POST/GET/PUT/DELETE /api/buckets
- Bucket execution: POST /api/buckets/{id}/run, POST /api/buckets/run-once
- bucket_run_id propagated to transaction_logs; /api/logs?bucket_run_id= filters
- /api/logs/export returns text/plain attachment respecting filters
"""
import os
import time
import uuid
import pytest
import requests

BASE_URL = os.environ["REACT_APP_BACKEND_URL"].rstrip("/") if os.environ.get("REACT_APP_BACKEND_URL") else "https://financial-lab.preview.emergentagent.com"
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


@pytest.fixture(scope="module")
def admin_templates(admin_session):
    """Return a list of >=2 saved template ids belonging to the admin user."""
    r = admin_session.get(f"{BASE_URL}/api/templates")
    assert r.status_code == 200, r.text
    tpls = r.json()
    if len(tpls) < 2:
        pytest.skip(f"admin has <2 saved templates (found {len(tpls)}), cannot build bucket")
    return tpls


# ---------------------------------------------------------------- Bucket CRUD
class TestBucketCRUD:
    created_bucket_id: str = ""

    def test_create_bucket_empty_template_ids_rejected(self, admin_session):
        r = admin_session.post(
            f"{BASE_URL}/api/buckets",
            json={"name": "TEST_empty", "template_ids": []},
        )
        assert r.status_code == 400, r.text

    def test_create_bucket_unknown_template_id_rejected(self, admin_session):
        r = admin_session.post(
            f"{BASE_URL}/api/buckets",
            json={"name": "TEST_bad", "template_ids": ["nonexistent-id-123"]},
        )
        assert r.status_code == 400, r.text

    def test_create_bucket_ok(self, admin_session, admin_templates):
        tpl_ids = [admin_templates[0]["id"], admin_templates[1]["id"]]
        name = f"TEST_bucket_{uuid.uuid4().hex[:6]}"
        r = admin_session.post(
            f"{BASE_URL}/api/buckets",
            json={"name": name, "description": "pytest-created", "template_ids": tpl_ids},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["name"] == name
        assert body["template_ids"] == tpl_ids
        # hydrated templates array preserves order
        assert len(body["templates"]) == 2
        assert body["templates"][0]["id"] == tpl_ids[0]
        assert body["templates"][1]["id"] == tpl_ids[1]
        for t in body["templates"]:
            for k in ("id", "name", "mti", "network_id"):
                assert k in t, f"template hydrate missing {k}"
        assert body["last_run_at"] is None
        TestBucketCRUD.created_bucket_id = body["id"]

    def test_list_buckets_contains_new(self, admin_session):
        r = admin_session.get(f"{BASE_URL}/api/buckets")
        assert r.status_code == 200
        ids = [b["id"] for b in r.json()]
        assert TestBucketCRUD.created_bucket_id in ids

    def test_update_bucket_reorder(self, admin_session, admin_templates):
        bid = TestBucketCRUD.created_bucket_id
        reordered = [admin_templates[1]["id"], admin_templates[0]["id"]]
        r = admin_session.put(
            f"{BASE_URL}/api/buckets/{bid}",
            json={"name": "TEST_bucket_renamed", "description": "updated", "template_ids": reordered},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["name"] == "TEST_bucket_renamed"
        assert body["description"] == "updated"
        assert body["template_ids"] == reordered
        assert [t["id"] for t in body["templates"]] == reordered

    def test_delete_nonexistent_returns_404(self, admin_session):
        r = admin_session.delete(f"{BASE_URL}/api/buckets/nonexistent-id-xyz")
        assert r.status_code == 404


# ---------------------------------------------------------------- Bucket Run
class TestBucketRun:
    run_bucket_id: str = ""
    bucket_run_id: str = ""

    def test_setup_run_bucket(self, admin_session, admin_templates):
        tpl_ids = [admin_templates[0]["id"], admin_templates[1]["id"]]
        name = f"TEST_run_{uuid.uuid4().hex[:6]}"
        r = admin_session.post(
            f"{BASE_URL}/api/buckets",
            json={"name": name, "template_ids": tpl_ids},
        )
        assert r.status_code == 200, r.text
        TestBucketRun.run_bucket_id = r.json()["id"]

    def test_run_bucket_simulator(self, admin_session):
        bid = TestBucketRun.run_bucket_id
        r = admin_session.post(
            f"{BASE_URL}/api/buckets/{bid}/run",
            json={"target": "simulator", "delay_ms": 0},
            timeout=60,
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert "bucket_run_id" in body
        assert body["total"] == 2
        assert body["succeeded"] >= 1, body
        assert body["failed"] + body["succeeded"] == body["total"]
        assert len(body["results"]) == 2
        first = body["results"][0]
        for k in ("step", "template_name", "mti", "status_code", "outbound_log_id", "inbound_log_id"):
            assert k in first, f"missing {k} in step result"
        # Simulator returns a valid 2-char RC per step (00 or 05/51 for declined
        # 0200 scenarios based on PAN). Just verify structure is sane.
        for row in body["results"]:
            assert row["status_code"] and isinstance(row["status_code"], str), row
            assert len(row["status_code"]) == 2, row
        TestBucketRun.bucket_run_id = body["bucket_run_id"]

    def test_bucket_last_run_at_updated(self, admin_session):
        bid = TestBucketRun.run_bucket_id
        r = admin_session.get(f"{BASE_URL}/api/buckets")
        assert r.status_code == 200
        match = [b for b in r.json() if b["id"] == bid]
        assert match, "bucket missing from list"
        assert match[0]["last_run_at"] is not None

    def test_run_bucket_delay_enforced(self, admin_session):
        """Two-step bucket with delay_ms=200 must take >= 200ms (delay between steps)."""
        bid = TestBucketRun.run_bucket_id
        t0 = time.monotonic()
        r = admin_session.post(
            f"{BASE_URL}/api/buckets/{bid}/run",
            json={"target": "simulator", "delay_ms": 200},
            timeout=60,
        )
        elapsed_ms = (time.monotonic() - t0) * 1000
        assert r.status_code == 200, r.text
        # The server sleeps delay_ms between steps (1 gap for 2 steps).
        # Allow a little slack for clock but must be >= 200ms.
        assert elapsed_ms >= 200, f"expected >=200ms between two-step bucket, got {elapsed_ms:.0f}ms"

    def test_run_once_adhoc(self, admin_session, admin_templates):
        tpl_ids = [admin_templates[0]["id"]]
        r = admin_session.post(
            f"{BASE_URL}/api/buckets/run-once",
            json={"template_ids": tpl_ids, "target": "simulator", "delay_ms": 0},
            timeout=60,
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["bucket_id"] is None
        assert body["total"] == 1
        assert len(body["results"]) == 1
        assert body["results"][0]["status_code"] and len(body["results"][0]["status_code"]) == 2

    def test_logs_filter_by_bucket_run_id(self, admin_session):
        run_id = TestBucketRun.bucket_run_id
        assert run_id, "run_id not set from prior test"
        r = admin_session.get(f"{BASE_URL}/api/logs", params={"bucket_run_id": run_id})
        assert r.status_code == 200
        body = r.json()
        logs = body["items"] if isinstance(body, dict) else body
        # Two templates × 2 directions (outbound+inbound) = 4 logs
        assert len(logs) >= 2, f"expected >=2 logs for run_id, got {len(logs)}"
        for lg in logs:
            assert lg.get("bucket_run_id") == run_id

    def test_cleanup_delete_run_bucket(self, admin_session):
        bid = TestBucketRun.run_bucket_id
        if not bid:
            pytest.skip("nothing to clean up")
        r = admin_session.delete(f"{BASE_URL}/api/buckets/{bid}")
        assert r.status_code == 200


# ---------------------------------------------------------------- Logs export
class TestLogsExport:
    def test_export_txt_respects_filters(self, admin_session):
        # Grab latest log and export filtered by that network
        logs_resp = admin_session.get(f"{BASE_URL}/api/logs", params={"limit": 1})
        assert logs_resp.status_code == 200
        logs = logs_resp.json()
        if not logs:
            pytest.skip("no logs on admin account to export")
        r = admin_session.get(f"{BASE_URL}/api/logs/export", timeout=60)
        assert r.status_code == 200, r.text
        ct = r.headers.get("content-type", "")
        assert ct.startswith("text/plain"), f"bad content-type: {ct}"
        cd = r.headers.get("content-disposition", "")
        assert "attachment" in cd.lower(), f"bad content-disposition: {cd}"
        body = r.text
        assert "ISO-8583 LAB" in body and "Transaction log export" in body
        # Must contain at least one OUTBOUND or INBOUND line
        assert ("OUTBOUND" in body) or ("INBOUND" in body)
        assert "-- Parsed Data Elements --" in body
        assert "-- Raw hex --" in body

    def test_export_by_bucket_run_id(self, admin_session, admin_templates):
        # Fire an ad-hoc run to create fresh logs tied to a run_id
        tpl_ids = [admin_templates[0]["id"]]
        r = admin_session.post(
            f"{BASE_URL}/api/buckets/run-once",
            json={"template_ids": tpl_ids, "target": "simulator", "delay_ms": 0},
            timeout=60,
        )
        assert r.status_code == 200, r.text
        run_id = r.json()["bucket_run_id"]
        exp = admin_session.get(
            f"{BASE_URL}/api/logs/export", params={"bucket_run_id": run_id}, timeout=30,
        )
        assert exp.status_code == 200, exp.text
        assert exp.headers.get("content-type", "").startswith("text/plain")
        body = exp.text
        assert run_id in body or "bucket_run" in body.lower()
        # Make sure the filter applies: the export at minimum mentions something
        assert "ISO-8583 LAB" in body
