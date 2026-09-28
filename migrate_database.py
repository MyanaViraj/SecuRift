"""
SecuRift Safe Database Migration Script
Backs up SQLite database, adds missing columns and new entities, and preserves existing data.
"""
import os
import shutil
import sqlite3
from datetime import datetime

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.db")
BACKUP_PATH = os.path.join(BASE_DIR, f"database_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db")


def run_migration():
    if not os.path.exists(DB_PATH):
        print(f"[*] No existing database found at {DB_PATH}. It will be created on application startup.")
        return

    print(f"[*] Backing up existing database to: {BACKUP_PATH}")
    shutil.copy2(DB_PATH, BACKUP_PATH)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    def add_column_if_missing(table, column, col_type, default=None):
        cursor.execute(f"PRAGMA table_info({table});")
        cols = [info[1] for info in cursor.fetchall()]
        if column not in cols:
            default_clause = f" DEFAULT {default}" if default is not None else ""
            sql = f"ALTER TABLE {table} ADD COLUMN {column} {col_type}{default_clause};"
            print(f"    -> Adding column {table}.{column} ({col_type})...")
            cursor.execute(sql)

    print("[*] Checking and migrating existing tables...")

    # 1. PCAP Analyses
    add_column_if_missing("pcap_analyses", "stored_filename", "VARCHAR(255)")
    add_column_if_missing("pcap_analyses", "original_filename", "VARCHAR(255)")
    add_column_if_missing("pcap_analyses", "data_source", "VARCHAR(50)", "'REAL'")

    # Populate stored_filename and original_filename if empty
    cursor.execute("UPDATE pcap_analyses SET stored_filename = filename WHERE stored_filename IS NULL;")
    cursor.execute("UPDATE pcap_analyses SET original_filename = filename WHERE original_filename IS NULL;")

    # 2. Rules
    add_column_if_missing("rules", "data_source", "VARCHAR(50)", "'REAL'")

    # 3. Test Cases
    add_column_if_missing("test_cases", "pcap_analysis_id", "INTEGER")
    add_column_if_missing("test_cases", "data_source", "VARCHAR(50)", "'REAL'")

    # 4. Alerts
    add_column_if_missing("alerts", "snort_execution_id", "INTEGER")
    add_column_if_missing("alerts", "pcap_analysis_id", "INTEGER")
    add_column_if_missing("alerts", "test_execution_id", "INTEGER")
    add_column_if_missing("alerts", "data_source", "VARCHAR(50)", "'REAL_SNORT'")

    # 5. Validation Results
    add_column_if_missing("validation_results", "test_execution_id", "INTEGER")
    add_column_if_missing("validation_results", "data_source", "VARCHAR(50)", "'REAL'")

    # 6. False Positive Records
    add_column_if_missing("false_positive_records", "reviewed_by", "VARCHAR(100)", "'Analyst'")

    # 7. Performance Measurements
    add_column_if_missing("performance_measurements", "snort_execution_id", "INTEGER")
    add_column_if_missing("performance_measurements", "pcap_analysis_id", "INTEGER")
    add_column_if_missing("performance_measurements", "throughput", "FLOAT", "0.0")
    add_column_if_missing("performance_measurements", "snort_version", "VARCHAR(100)", "'N/A'")
    add_column_if_missing("performance_measurements", "data_source", "VARCHAR(50)", "'REAL'")

    # 8. MITRE Mappings
    add_column_if_missing("mitre_mappings", "data_source", "VARCHAR(50)", "'REAL'")

    # 9. Reports
    add_column_if_missing("reports", "data_source", "VARCHAR(50)", "'REAL'")
    add_column_if_missing("reports", "snort_version", "VARCHAR(100)", "'N/A'")
    add_column_if_missing("reports", "sample_size", "INTEGER", "0")

    # 10. New Tables: snort_executions, test_executions, detection_evaluations
    print("[*] Creating new tables if missing...")
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS snort_executions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pcap_analysis_id INTEGER,
        rule_set TEXT,
        command_summary TEXT,
        snort_version VARCHAR(100),
        started_at DATETIME,
        completed_at DATETIME,
        processing_time FLOAT DEFAULT 0.0,
        packets_processed INTEGER DEFAULT 0,
        alerts_generated INTEGER DEFAULT 0,
        exit_code INTEGER DEFAULT 0,
        status VARCHAR(50) DEFAULT 'SUCCESS',
        stdout TEXT,
        stderr TEXT,
        execution_type VARCHAR(50) DEFAULT 'REAL_SNORT',
        created_at DATETIME,
        FOREIGN KEY (pcap_analysis_id) REFERENCES pcap_analyses(id) ON DELETE SET NULL
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS test_executions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        test_case_id INTEGER NOT NULL,
        pcap_analysis_id INTEGER,
        snort_execution_id INTEGER,
        rule_id INTEGER,
        expected_result VARCHAR(50) NOT NULL,
        actual_result VARCHAR(50) NOT NULL,
        status VARCHAR(50) NOT NULL,
        evidence TEXT,
        execution_type VARCHAR(50) DEFAULT 'REAL_SNORT',
        started_at DATETIME,
        completed_at DATETIME,
        created_at DATETIME,
        FOREIGN KEY (test_case_id) REFERENCES test_cases(id) ON DELETE CASCADE,
        FOREIGN KEY (pcap_analysis_id) REFERENCES pcap_analyses(id) ON DELETE SET NULL,
        FOREIGN KEY (snort_execution_id) REFERENCES snort_executions(id) ON DELETE SET NULL,
        FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE SET NULL
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS detection_evaluations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        test_execution_id INTEGER,
        rule_id INTEGER,
        expected_detection VARCHAR(50) NOT NULL,
        actual_detection VARCHAR(50) NOT NULL,
        classification VARCHAR(20) NOT NULL,
        evidence TEXT,
        reviewed_by VARCHAR(100) DEFAULT 'Automated Validator',
        data_source VARCHAR(50) DEFAULT 'REAL',
        created_at DATETIME,
        FOREIGN KEY (test_execution_id) REFERENCES test_executions(id) ON DELETE CASCADE,
        FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE SET NULL
    );
    """)

    conn.commit()
    conn.close()
    print("[+] Migration completed successfully with data preservation!")


if __name__ == "__main__":
    run_migration()
