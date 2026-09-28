import os
import shutil
import subprocess
import tempfile
import time


def check_snort_installed():
    """
    Detect if the Snort binary is installed and executable in PATH.
    Returns dict with path and version, or None if absent.
    """
    path = shutil.which("snort")
    if not path:
        return None
    try:
        proc = subprocess.run(
            [path, "-V"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False
        )
        # Parse version line
        version_line = "Snort (Unknown Version)"
        output = proc.stdout or proc.stderr
        for line in output.splitlines():
            if "Version" in line or "Snort" in line:
                version_line = line.strip()
                break
        return {"path": path, "version": version_line}
    except Exception as e:
        return {"path": path, "version": f"Available ({str(e)})"}


def run_snort_on_pcap(pcap_path, rules_text=None, snort_conf_path=None):
    """
    Runs Snort against a given PCAP file using safe subprocess execution.
    Returns a dict with execution results, alerts, or friendly fallback messages.
    """
    snort_info = check_snort_installed()
    if not snort_info:
        return {
            "success": False,
            "snort_available": False,
            "error": "Snort executable not detected. You can still import existing Snort alerts."
        }

    snort_bin = snort_info["path"]
    if not os.path.exists(pcap_path):
        return {"success": False, "snort_available": True, "error": f"PCAP not found: {pcap_path}"}

    start_time = time.time()
    temp_dir = tempfile.mkdtemp(prefix="securift_snort_")
    alert_file = os.path.join(temp_dir, "alert")
    rules_file = os.path.join(temp_dir, "custom.rules")
    conf_file = snort_conf_path or os.path.join(temp_dir, "snort.conf")

    try:
        # If rules text is provided, write to custom.rules
        if rules_text:
            with open(rules_file, "w") as f:
                f.write(rules_text)

        # Create minimal snort.conf if none provided
        if not snort_conf_path or not os.path.exists(snort_conf_path):
            with open(conf_file, "w") as f:
                f.write(
                    "# Auto-generated SecuRift Snort Configuration\n"
                    "ipvar HOME_NET any\n"
                    "ipvar EXTERNAL_NET any\n"
                    f"include {rules_file}\n"
                )

        # Build safe subprocess arguments
        cmd = [
            snort_bin,
            "-q",
            "-r", pcap_path,
            "-c", conf_file,
            "-A", "fast",
            "-l", temp_dir,
            "-k", "none"
        ]

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            check=False
        )

        elapsed = round(time.time() - start_time, 4)

        # Read generated alert file if created
        alerts_content = ""
        possible_alert_paths = [
            alert_file,
            os.path.join(temp_dir, "alert.fast"),
            os.path.join(temp_dir, "snort.alert.fast"),
        ]
        for p in possible_alert_paths:
            if os.path.exists(p):
                with open(p, "r", errors="ignore") as f:
                    alerts_content = f.read()
                break

        return {
            "success": True,
            "snort_available": True,
            "execution_time": elapsed,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "alerts_raw": alerts_content,
            "return_code": proc.returncode
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "snort_available": True,
            "error": "Snort execution timed out after 30 seconds."
        }
    except Exception as e:
        return {
            "success": False,
            "snort_available": True,
            "error": f"Error running Snort: {str(e)}"
        }
    finally:
        # Clean up temporary directory
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass
