import json
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from . import db, login_manager


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


class User(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    # Roles: Analyst, Reviewer, Administrator
    role = db.Column(db.String(50), default="Analyst")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_admin(self):
        return self.role == "Administrator"

    def is_reviewer(self):
        return self.role in ("Reviewer", "Administrator")

    def is_analyst(self):
        return self.role in ("Analyst", "Reviewer", "Administrator")

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"


class Rule(db.Model):
    __tablename__ = "rules"

    id = db.Column(db.Integer, primary_key=True)
    sid = db.Column(db.Integer, unique=True, nullable=False, index=True)
    rule_text = db.Column(db.Text, nullable=False)
    action = db.Column(db.String(20), default="alert")
    protocol = db.Column(db.String(20), default="tcp")
    source_ip = db.Column(db.String(100), default="any")
    source_port = db.Column(db.String(100), default="any")
    direction = db.Column(db.String(10), default="->")
    destination_ip = db.Column(db.String(100), default="any")
    destination_port = db.Column(db.String(100), default="any")
    message = db.Column(db.String(255), nullable=False)
    revision = db.Column(db.Integer, default=1)
    classification = db.Column(db.String(100), default="attempted-admin")
    severity = db.Column(db.String(20), default="Medium")  # Low, Medium, High, Critical
    enabled = db.Column(db.Boolean, default=True)
    purpose = db.Column(db.Text, nullable=True)
    trigger_condition = db.Column(db.Text, nullable=True)
    expected_behavior = db.Column(db.Text, nullable=True)
    mitre_technique = db.Column(db.String(100), nullable=True)
    data_source = db.Column(db.String(50), default="REAL")  # REAL, DEMO
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    test_cases = db.relationship("TestCase", backref="rule", cascade="all, delete-orphan", lazy=True)
    test_executions = db.relationship("TestExecution", backref="rule", lazy=True)
    evaluations = db.relationship("DetectionEvaluation", backref="rule", lazy=True)
    mitre_mappings = db.relationship("MitreMapping", backref="rule", cascade="all, delete-orphan", lazy=True)
    performance_records = db.relationship("PerformanceMeasurement", backref="rule", cascade="all, delete-orphan", lazy=True)
    validation_results = db.relationship("ValidationResult", backref="rule", cascade="all, delete-orphan", lazy=True)

    def __repr__(self):
        return f"<Rule SID:{self.sid} - {self.message[:30]}>"


class PCAPAnalysis(db.Model):
    __tablename__ = "pcap_analyses"

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)           # Display / original name
    stored_filename = db.Column(db.String(255), nullable=True)    # Unique on-disk filename
    original_filename = db.Column(db.String(255), nullable=True)  # Clean original upload name
    total_packets = db.Column(db.Integer, default=0)
    source_ips = db.Column(db.Text, default="[]")                 # JSON string
    destination_ips = db.Column(db.Text, default="[]")            # JSON string
    source_ports = db.Column(db.Text, default="[]")               # JSON string
    destination_ports = db.Column(db.Text, default="[]")          # JSON string
    protocols = db.Column(db.Text, default="{}")                  # JSON string
    tcp_packets = db.Column(db.Integer, default=0)
    udp_packets = db.Column(db.Integer, default=0)
    dns_packets = db.Column(db.Integer, default=0)
    http_packets = db.Column(db.Integer, default=0)
    https_packets = db.Column(db.Integer, default=0)
    packet_frequency = db.Column(db.Text, default="[]")           # JSON string
    analysis_time = db.Column(db.Float, default=0.0)
    data_source = db.Column(db.String(50), default="REAL")        # REAL, DEMO
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    snort_executions = db.relationship("SnortExecution", backref="pcap_analysis", lazy=True)
    test_executions = db.relationship("TestExecution", backref="pcap_analysis", lazy=True)
    alerts = db.relationship("Alert", backref="pcap_analysis", lazy=True)

    def get_protocols(self):
        try:
            return json.loads(self.protocols or "{}")
        except Exception:
            return {}

    def get_source_ips(self):
        try:
            return json.loads(self.source_ips or "[]")
        except Exception:
            return []

    def get_destination_ips(self):
        try:
            return json.loads(self.destination_ips or "[]")
        except Exception:
            return []

    def get_ports(self):
        try:
            return {
                "source": json.loads(self.source_ports or "[]"),
                "dest": json.loads(self.destination_ports or "[]")
            }
        except Exception:
            return {"source": [], "dest": []}

    def get_packet_frequency(self):
        try:
            return json.loads(self.packet_frequency or "[]")
        except Exception:
            return []


class SnortExecution(db.Model):
    """Tracks every actual or demonstration Snort IDS invocation with auditable artifacts."""
    __tablename__ = "snort_executions"

    id = db.Column(db.Integer, primary_key=True)
    pcap_analysis_id = db.Column(db.Integer, db.ForeignKey("pcap_analyses.id", ondelete="SET NULL"), nullable=True)
    rule_set = db.Column(db.Text, nullable=True)               # Description or SID list
    command_summary = db.Column(db.Text, nullable=True)        # Safe summary of command args
    snort_version = db.Column(db.String(100), default="N/A")
    started_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = db.Column(db.DateTime, nullable=True)
    processing_time = db.Column(db.Float, default=0.0)         # Exact elapsed seconds
    packets_processed = db.Column(db.Integer, default=0)
    alerts_generated = db.Column(db.Integer, default=0)
    exit_code = db.Column(db.Integer, default=0)
    status = db.Column(db.String(50), default="SUCCESS")       # SUCCESS, FAILED, TIMEOUT, NOT_INSTALLED
    stdout = db.Column(db.Text, nullable=True)
    stderr = db.Column(db.Text, nullable=True)
    # Execution type must be REAL_SNORT or DEMO_SIMULATION
    execution_type = db.Column(db.String(50), default="REAL_SNORT")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    alerts = db.relationship("Alert", backref="snort_execution", lazy=True)
    test_executions = db.relationship("TestExecution", backref="snort_execution", lazy=True)
    performance_records = db.relationship("PerformanceMeasurement", backref="snort_execution", lazy=True)

    def __repr__(self):
        return f"<SnortExecution #{self.id} [{self.execution_type}] - {self.alerts_generated} alerts in {self.processing_time}s>"


class TestCase(db.Model):
    __tablename__ = "test_cases"
    __test__ = False

    id = db.Column(db.Integer, primary_key=True)
    test_id = db.Column(db.String(50), unique=True, nullable=False, index=True)
    name = db.Column(db.String(150), nullable=False)
    category = db.Column(db.String(100), default="Network Inspection")
    description = db.Column(db.Text, nullable=True)
    pcap_file = db.Column(db.String(255), nullable=True)
    pcap_analysis_id = db.Column(db.Integer, db.ForeignKey("pcap_analyses.id", ondelete="SET NULL"), nullable=True)
    expected_detection = db.Column(db.String(50), default="Alert")  # "Alert", "No Alert"
    actual_detection = db.Column(db.String(50), default="Untested") # "Alert", "No Alert", "Untested"
    rule_id = db.Column(db.Integer, db.ForeignKey("rules.id", ondelete="SET NULL"), nullable=True)
    severity = db.Column(db.String(20), default="Medium")
    status = db.Column(db.String(50), default="PENDING")            # PASS, FAIL, NOT DETECTED, UNEXPECTED ALERT, PENDING
    data_source = db.Column(db.String(50), default="REAL")          # REAL, DEMO
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    executions = db.relationship("TestExecution", backref="test_case", cascade="all, delete-orphan", lazy=True)
    validation_results = db.relationship("ValidationResult", backref="test_case", cascade="all, delete-orphan", lazy=True)

    def __repr__(self):
        return f"<TestCase {self.test_id}: {self.name}>"


class TestExecution(db.Model):
    """Tracks specific execution of a test case against an explicit PCAP and Snort run."""
    __tablename__ = "test_executions"
    __test__ = False

    id = db.Column(db.Integer, primary_key=True)
    test_case_id = db.Column(db.Integer, db.ForeignKey("test_cases.id", ondelete="CASCADE"), nullable=False)
    pcap_analysis_id = db.Column(db.Integer, db.ForeignKey("pcap_analyses.id", ondelete="SET NULL"), nullable=True)
    snort_execution_id = db.Column(db.Integer, db.ForeignKey("snort_executions.id", ondelete="SET NULL"), nullable=True)
    rule_id = db.Column(db.Integer, db.ForeignKey("rules.id", ondelete="SET NULL"), nullable=True)
    expected_result = db.Column(db.String(50), nullable=False)      # Alert, No Alert
    actual_result = db.Column(db.String(50), nullable=False)        # Alert, No Alert
    status = db.Column(db.String(50), nullable=False)               # PASS, FAIL, NOT DETECTED, UNEXPECTED ALERT
    evidence = db.Column(db.Text, nullable=True)
    execution_type = db.Column(db.String(50), default="REAL_SNORT") # REAL_SNORT, DEMO_SIMULATION, LOG_ANALYSIS
    started_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationship to single cohesive evaluation
    evaluation = db.relationship("DetectionEvaluation", backref="test_execution", uselist=False, cascade="all, delete-orphan")


class DetectionEvaluation(db.Model):
    """Unified evaluation model producing the single coherent confusion matrix (TP, FP, TN, FN, UNKNOWN)."""
    __tablename__ = "detection_evaluations"

    id = db.Column(db.Integer, primary_key=True)
    test_execution_id = db.Column(db.Integer, db.ForeignKey("test_executions.id", ondelete="CASCADE"), nullable=True)
    rule_id = db.Column(db.Integer, db.ForeignKey("rules.id", ondelete="SET NULL"), nullable=True)
    expected_detection = db.Column(db.String(50), nullable=False)   # Alert, No Alert
    actual_detection = db.Column(db.String(50), nullable=False)     # Alert, No Alert
    classification = db.Column(db.String(20), nullable=False)       # TP, FP, TN, FN, UNKNOWN
    evidence = db.Column(db.Text, nullable=True)
    reviewed_by = db.Column(db.String(100), default="Automated Validator")
    data_source = db.Column(db.String(50), default="REAL")          # REAL, IMPORTED, DEMO
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<DetectionEvaluation #{self.id} [{self.classification}] - {self.expected_detection}->{self.actual_detection}>"


class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)
    snort_execution_id = db.Column(db.Integer, db.ForeignKey("snort_executions.id", ondelete="SET NULL"), nullable=True)
    pcap_analysis_id = db.Column(db.Integer, db.ForeignKey("pcap_analyses.id", ondelete="SET NULL"), nullable=True)
    test_execution_id = db.Column(db.Integer, db.ForeignKey("test_executions.id", ondelete="SET NULL"), nullable=True)

    timestamp = db.Column(db.String(100), nullable=True)
    sid = db.Column(db.Integer, nullable=False, index=True)
    message = db.Column(db.String(255), nullable=False)
    protocol = db.Column(db.String(20), default="TCP")
    source_ip = db.Column(db.String(100), default="0.0.0.0")
    source_port = db.Column(db.String(50), default="0")
    destination_ip = db.Column(db.String(100), default="0.0.0.0")
    destination_port = db.Column(db.String(50), default="0")
    classification = db.Column(db.String(150), default="Potentially Bad Traffic")
    severity = db.Column(db.String(20), default="Medium")           # Low, Medium, High, Critical
    raw_alert = db.Column(db.Text, nullable=True)
    pcap_file = db.Column(db.String(255), nullable=True)
    source_type = db.Column(db.String(50), default="REAL_SNORT")    # REAL_SNORT, IMPORTED_SNORT_LOG, DEMO
    data_source = db.Column(db.String(50), default="REAL_SNORT")    # REAL_SNORT, IMPORTED_SNORT_LOG, DEMO
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    fp_records = db.relationship("FalsePositiveRecord", backref="alert", cascade="all, delete-orphan", lazy=True)

    @property
    def classification_state(self):
        """Returns True Positive, False Positive, or Unknown based strictly on explicit review."""
        if self.fp_records:
            return self.fp_records[-1].classification
        return "Unknown"


class ValidationResult(db.Model):
    __tablename__ = "validation_results"

    id = db.Column(db.Integer, primary_key=True)
    test_case_id = db.Column(db.Integer, db.ForeignKey("test_cases.id", ondelete="CASCADE"), nullable=True)
    test_execution_id = db.Column(db.Integer, db.ForeignKey("test_executions.id", ondelete="SET NULL"), nullable=True)
    rule_id = db.Column(db.Integer, db.ForeignKey("rules.id", ondelete="CASCADE"), nullable=True)
    expected_result = db.Column(db.String(50), nullable=False)      # Alert, No Alert
    actual_result = db.Column(db.String(50), nullable=False)        # Alert, No Alert
    status = db.Column(db.String(50), nullable=False)               # PASS, FAIL, NOT DETECTED, UNEXPECTED ALERT
    evidence = db.Column(db.Text, nullable=True)
    data_source = db.Column(db.String(50), default="REAL")          # REAL, DEMO
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class FalsePositiveRecord(db.Model):
    __tablename__ = "false_positive_records"

    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.Integer, db.ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False)
    classification = db.Column(db.String(50), default="Unknown")    # True Positive, False Positive, Unknown
    notes = db.Column(db.Text, nullable=True)
    reviewed_by = db.Column(db.String(100), default="Analyst")
    reviewed_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class PerformanceMeasurement(db.Model):
    __tablename__ = "performance_measurements"

    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.Integer, db.ForeignKey("rules.id", ondelete="CASCADE"), nullable=False)
    snort_execution_id = db.Column(db.Integer, db.ForeignKey("snort_executions.id", ondelete="SET NULL"), nullable=True)
    pcap_analysis_id = db.Column(db.Integer, db.ForeignKey("pcap_analyses.id", ondelete="SET NULL"), nullable=True)
    packets_processed = db.Column(db.Integer, default=0)
    alerts_generated = db.Column(db.Integer, default=0)
    processing_time = db.Column(db.Float, default=0.0)              # seconds
    alerts_per_1000_packets = db.Column(db.Float, default=0.0)
    detection_rate = db.Column(db.Float, nullable=True)             # Only set from actual DetectionEvaluation, else None
    throughput = db.Column(db.Float, default=0.0)                   # packets/sec
    snort_version = db.Column(db.String(100), default="N/A")
    status = db.Column(db.String(50), default="Optimal")            # Optimal, Warning, Resource-Heavy
    measurement_type = db.Column(db.String(50), default="REAL_SNORT")  # REAL_SNORT, DEMO_SIMULATION, IMPORTED
    data_source = db.Column(db.String(50), default="REAL")          # REAL, DEMO
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class MitreMapping(db.Model):
    __tablename__ = "mitre_mappings"

    id = db.Column(db.Integer, primary_key=True)
    technique_id = db.Column(db.String(50), nullable=False, index=True)
    technique_name = db.Column(db.String(150), nullable=False)
    tactic = db.Column(db.String(100), default="Discovery")
    rule_id = db.Column(db.Integer, db.ForeignKey("rules.id", ondelete="CASCADE"), nullable=False)
    detection_logic = db.Column(db.Text, nullable=False)
    evidence = db.Column(db.Text, nullable=True)
    severity = db.Column(db.String(20), default="Medium")
    validation_status = db.Column(db.String(50), default="Validated")  # Validated, Candidate, Under Review
    data_source = db.Column(db.String(50), default="REAL")             # REAL, DEMO
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class Report(db.Model):
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    report_type = db.Column(db.String(100), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    file_format = db.Column(db.String(10), default="PDF")           # PDF, CSV
    file_path = db.Column(db.String(255), nullable=False)
    data_source = db.Column(db.String(50), default="REAL")          # REAL, DEMO, MIXED
    snort_version = db.Column(db.String(100), default="N/A")
    sample_size = db.Column(db.Integer, default=0)
    generated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
