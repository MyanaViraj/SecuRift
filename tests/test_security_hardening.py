import os
import io
import tempfile
import pytest
from app import create_app
from config import Config, TestingConfig
from models import db
from models.models import User, Rule, PCAPAnalysis
from analyzer.pcap_analyzer import validate_pcap_file_structure


@pytest.fixture
def app():
    app = create_app(TestingConfig)
    with app.app_context():
        db.create_all()
        # Seed an admin and an analyst user
        admin = User(username="admin_user", role="Administrator")
        admin.set_password("admin_pass123")
        analyst = User(username="analyst_user", role="Analyst")
        analyst.set_password("analyst_pass123")
        db.session.add_all([admin, analyst])
        db.session.commit()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def test_secret_key_configuration():
    """Verify secret key is configured and not empty or default insecure."""
    key = Config.SECRET_KEY
    assert key is not None
    assert len(key) >= 32


def test_open_redirect_prevention(client):
    """Verify login blocks external redirects (e.g. //evil.com or http://evil.com)."""
    # 1. Unsafe external domain redirect attempt
    resp = client.post("/login?next=http://evil.com/malicious", data={
        "username": "admin_user",
        "password": "admin_pass123"
    }, follow_redirects=False)

    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/dashboard") or "evil.com" not in resp.headers["Location"]
    client.get("/logout")

    # 2. Protocol-relative redirect attempt
    resp2 = client.post("/login?next=//attacker.com", data={
        "username": "admin_user",
        "password": "admin_pass123"
    }, follow_redirects=False)

    assert resp2.status_code == 302
    assert "attacker.com" not in resp2.headers["Location"]
    client.get("/logout")

    # 3. Legitimate internal redirect attempt
    resp3 = client.post("/login?next=/rules", data={
        "username": "admin_user",
        "password": "admin_pass123"
    }, follow_redirects=False)

    assert resp3.status_code == 302
    assert resp3.headers["Location"].endswith("/rules")
    client.get("/logout")


def test_csrf_protection_enabled_on_production_config():
    """Verify CSRF protection is enabled on base Config."""
    assert Config.WTF_CSRF_ENABLED is True


def test_csrf_blocks_unauthorized_post():
    """Create an app instance with CSRF enabled and verify POST without token returns 400 Bad Request."""
    class CsrfTestingConfig(TestingConfig):
        WTF_CSRF_ENABLED = True

    csrf_app = create_app(CsrfTestingConfig)
    with csrf_app.app_context():
        db.create_all()
        admin = User(username="csrf_admin", role="Administrator")
        admin.set_password("password123")
        db.session.add(admin)
        db.session.commit()

        csrf_client = csrf_app.test_client()
        # Attempt to POST to login without CSRF token
        resp = csrf_client.post("/login", data={
            "username": "csrf_admin",
            "password": "password123"
        })
        # Should be rejected with 400 Bad Request (CSRF token missing)
        assert resp.status_code == 400
        assert b"CSRF" in resp.data or resp.status_code == 400


def test_role_based_authorization_delete_protection(client, app):
    """Verify that regular Analysts cannot delete rules (requires Administrator)."""
    with app.app_context():
        rule = Rule(
            sid=1000099,
            rule_text='alert tcp any any -> any 80 (msg:"Critical Rule"; sid:1000099;)',
            message="Critical Rule",
            severity="Critical"
        )
        db.session.add(rule)
        db.session.commit()
        rule_id = rule.id

    # 1. Login as Analyst
    client.post("/login", data={"username": "analyst_user", "password": "analyst_pass123"})

    # Attempt to delete rule as Analyst
    resp = client.post(f"/rules/delete/{rule_id}")
    assert resp.status_code == 403  # Forbidden

    # Verify rule was NOT deleted
    with app.app_context():
        assert db.session.get(Rule, rule_id) is not None

    # 2. Logout Analyst and Login as Administrator
    client.get("/logout")
    client.post("/login", data={"username": "admin_user", "password": "admin_pass123"})

    # Attempt to delete rule as Administrator
    resp_admin = client.post(f"/rules/delete/{rule_id}")
    assert resp_admin.status_code in [200, 302]

    # Verify rule IS deleted
    with app.app_context():
        assert db.session.get(Rule, rule_id) is None


def test_pcap_file_magic_header_validation():
    """Verify PCAP magic bytes validation rejects non-PCAP and zero-byte files."""
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        f.write(b"")  # 0 bytes
        f.flush()
        f_name = f.name

    try:
        valid, msg = validate_pcap_file_structure(f_name)
        assert valid is False
        assert "empty" in msg.lower()
    finally:
        if os.path.exists(f_name):
            os.remove(f_name)

    # Valid microsecond PCAP magic number (\xd4\xc3\xb2\xa1)
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        f.write(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
        f.flush()
        f_name2 = f.name

    try:
        valid2, msg2 = validate_pcap_file_structure(f_name2)
        assert valid2 is True
        assert msg2 is None
    finally:
        if os.path.exists(f_name2):
            os.remove(f_name2)


def test_upload_filename_collision_and_path_traversal(client, app):
    """Verify uploads use unique stored filenames and sanitize directory traversal attempts."""
    client.post("/login", data={"username": "admin_user", "password": "admin_pass123"})

    valid_pcap_bytes = b"\xd4\xc3\xb2\xa1" + b"\x00" * 30

    # 1. First upload with name "capture.pcap"
    data1 = {
        "pcap_file": (io.BytesIO(valid_pcap_bytes), "capture.pcap")
    }
    resp1 = client.post("/baseline/upload", data=data1, content_type="multipart/form-data")
    assert resp1.status_code in [200, 302]

    # 2. Second upload with the exact same filename "capture.pcap"
    data2 = {
        "pcap_file": (io.BytesIO(valid_pcap_bytes), "capture.pcap")
    }
    resp2 = client.post("/baseline/upload", data=data2, content_type="multipart/form-data")
    assert resp2.status_code in [200, 302]

    # Check database records
    with app.app_context():
        records = PCAPAnalysis.query.filter_by(filename="capture.pcap").all()
        assert len(records) >= 2
        # Verify stored_filenames are unique
        stored_names = [r.stored_filename for r in records if r.stored_filename]
        assert len(set(stored_names)) == len(stored_names)

    # 3. Path traversal attack attempt in filename
    data_traversal = {
        "pcap_file": (io.BytesIO(valid_pcap_bytes), "../../../etc/passwd.pcap")
    }
    resp3 = client.post("/baseline/upload", data=data_traversal, content_type="multipart/form-data")
    assert resp3.status_code in [200, 302]

    with app.app_context():
        traversal_rec = PCAPAnalysis.query.filter(PCAPAnalysis.filename.like("%passwd.pcap%")).first()
        if traversal_rec:
            # Must not contain directory traversal markers
            assert ".." not in traversal_rec.filename
            assert ".." not in (traversal_rec.stored_filename or "")
