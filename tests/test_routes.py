import pytest
from app import create_app
from config import TestingConfig
from models import db
from models.models import User, Rule, TestCase


@pytest.fixture
def client():
    app = create_app(TestingConfig)
    with app.app_context():
        db.create_all()

        # Seed admin user
        admin = User(username="admin", role="Lead Security Architect")
        admin.set_password("admin123")
        db.session.add(admin)

        # Seed a rule
        rule = Rule(
            sid=1000001,
            rule_text='alert tcp any any -> any 80 (msg:"HTTP Probe"; sid:1000001; rev:1;)',
            action="alert",
            protocol="tcp",
            message="HTTP Probe",
            severity="Medium",
            enabled=True
        )
        db.session.add(rule)

        # Seed a test case
        tc = TestCase(
            test_id="TC-1001",
            name="Route Test Case",
            expected_detection="Alert",
            actual_detection="Alert",
            status="PASS"
        )
        db.session.add(tc)

        db.session.commit()

        with app.test_client() as client:
            yield client

        db.session.remove()
        db.drop_all()


def test_login_page_renders(client):
    response = client.get("/login")
    assert response.status_code == 200
    assert b"SecuRift" in response.data
    assert b"admin123" in response.data


def test_unauthenticated_redirect(client):
    response = client.get("/dashboard")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_login_success(client):
    response = client.post("/login", data={
        "username": "admin",
        "password": "admin123"
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"Security Operations Dashboard" in response.data


def test_login_failure(client):
    response = client.post("/login", data={
        "username": "admin",
        "password": "wrongpassword"
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"Invalid authentication credentials" in response.data


def test_authenticated_route_access(client):
    # Log in first
    client.post("/login", data={"username": "admin", "password": "admin123"})

    endpoints = [
        "/dashboard",
        "/baseline",
        "/test-cases",
        "/rules",
        "/rules/create",
        "/validation",
        "/false-positives",
        "/performance",
        "/detection-logic",
        "/coverage",
        "/severity",
        "/mitre",
        "/snort",
        "/reports"
    ]

    for ep in endpoints:
        resp = client.get(ep)
        assert resp.status_code == 200, f"Endpoint {ep} failed with {resp.status_code}"


def test_csv_exports(client):
    client.post("/login", data={"username": "admin", "password": "admin123"})

    # Rules export
    r_resp = client.get("/rules/export")
    assert r_resp.status_code == 200
    assert "text/plain" in r_resp.content_type
    assert b"SecuRift Defensive Snort Detection Rules" in r_resp.data

    # Coverage matrix CSV
    c_resp = client.get("/coverage/export-csv")
    assert c_resp.status_code == 200
    assert "text/csv" in c_resp.content_type
    assert b"Detection Name" in c_resp.data


def test_pdf_report_generation(client):
    client.post("/login", data={"username": "admin", "password": "admin123"})

    # Report 1: Custom Snort Rules PDF
    r1 = client.get("/reports/generate-rules-pdf")
    assert r1.status_code == 200
    assert "application/pdf" in r1.content_type

    # Report 2: Coverage Matrix PDF
    r2 = client.get("/reports/generate-coverage-pdf")
    assert r2.status_code == 200
    assert "application/pdf" in r2.content_type

    # Report 3: Performance PDF
    r3 = client.get("/reports/generate-performance-pdf")
    assert r3.status_code == 200
    assert "application/pdf" in r3.content_type
