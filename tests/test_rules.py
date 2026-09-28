import pytest
from app import create_app
from config import TestingConfig
from models import db
from models.models import Rule
from analyzer.rule_validator import validate_snort_rule, parse_snort_rule_text


@pytest.fixture
def app_ctx():
    app = create_app(TestingConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


def test_valid_snort_rule_syntax():
    rule = 'alert tcp any any -> 192.168.1.1 80 (msg:"Test Rule"; sid:1000010; rev:1;)'
    res = validate_snort_rule(rule)
    assert res["is_valid"] is True
    assert len(res["errors"]) == 0
    assert res["parsed"]["sid"] == 1000010
    assert res["parsed"]["message"] == "Test Rule"
    assert res["parsed"]["action"] == "alert"
    assert res["parsed"]["protocol"] == "tcp"


def test_invalid_snort_rule_missing_action():
    rule = 'any any -> 192.168.1.1 80 (msg:"Malformed"; sid:1000011;)'
    res = validate_snort_rule(rule)
    assert res["is_valid"] is False
    assert any("Invalid rule action" in err or "Rule header requires" in err for err in res["errors"])


def test_invalid_snort_rule_missing_parentheses():
    rule = 'alert tcp any any -> any any msg:"No parens"; sid:1000012;'
    res = validate_snort_rule(rule)
    assert res["is_valid"] is False
    assert any("Missing parentheses" in err for err in res["errors"])


def test_invalid_snort_rule_missing_sid():
    rule = 'alert tcp any any -> any 80 (msg:"Missing SID"; rev:1;)'
    res = validate_snort_rule(rule)
    assert res["is_valid"] is False
    assert any("sid" in err.lower() for err in res["errors"])


def test_invalid_snort_rule_missing_msg():
    rule = 'alert tcp any any -> any 80 (sid:1000013; rev:1;)'
    res = validate_snort_rule(rule)
    assert res["is_valid"] is False
    assert any("msg" in err.lower() for err in res["errors"])


def test_snort_rule_db_crud(app_ctx):
    # Create
    rule = Rule(
        sid=1000050,
        rule_text='alert tcp any any -> any 80 (msg:"CRUD Test Rule"; sid:1000050; rev:1;)',
        action="alert",
        protocol="tcp",
        message="CRUD Test Rule",
        severity="High",
        enabled=True
    )
    db.session.add(rule)
    db.session.commit()

    saved = Rule.query.filter_by(sid=1000050).first()
    assert saved is not None
    assert saved.message == "CRUD Test Rule"
    assert saved.enabled is True

    # Update / Toggle
    saved.enabled = False
    saved.severity = "Critical"
    db.session.commit()

    updated = Rule.query.filter_by(sid=1000050).first()
    assert updated.enabled is False
    assert updated.severity == "Critical"

    # Delete
    db.session.delete(updated)
    db.session.commit()

    deleted = Rule.query.filter_by(sid=1000050).first()
    assert deleted is None
