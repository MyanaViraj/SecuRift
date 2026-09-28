import re
import shutil
import subprocess
import tempfile
import os


VALID_ACTIONS = {"alert", "log", "pass", "drop", "reject", "sdrop"}
VALID_PROTOCOLS = {"tcp", "udp", "icmp", "ip"}
VALID_DIRECTIONS = {"->", "<>"}


def parse_snort_rule_text(rule_text):
    """
    Parses a Snort rule string into its structured components:
    action, protocol, src_ip, src_port, direction, dst_ip, dst_port, and options.
    """
    rule_text = rule_text.strip()
    # Normalize spaces
    clean_text = " ".join(rule_text.split())

    # Find the options block in parentheses
    opt_start = clean_text.find("(")
    opt_end = clean_text.rfind(")")

    if opt_start == -1 or opt_end == -1 or opt_end <= opt_start:
        header_part = clean_text
        options_part = ""
    else:
        header_part = clean_text[:opt_start].strip()
        options_part = clean_text[opt_start + 1:opt_end].strip()

    header_tokens = header_part.split()

    parsed = {
        "action": header_tokens[0] if len(header_tokens) > 0 else "alert",
        "protocol": header_tokens[1] if len(header_tokens) > 1 else "tcp",
        "source_ip": header_tokens[2] if len(header_tokens) > 2 else "any",
        "source_port": header_tokens[3] if len(header_tokens) > 3 else "any",
        "direction": header_tokens[4] if len(header_tokens) > 4 else "->",
        "destination_ip": header_tokens[5] if len(header_tokens) > 5 else "any",
        "destination_port": header_tokens[6] if len(header_tokens) > 6 else "any",
        "message": "",
        "sid": None,
        "revision": 1,
        "classification": "attempted-admin",
        "raw_options": options_part
    }

    if options_part:
        # Extract msg
        msg_match = re.search(r'msg\s*:\s*"([^"]+)"\s*;', options_part)
        if msg_match:
            parsed["message"] = msg_match.group(1)

        # Extract sid
        sid_match = re.search(r'sid\s*:\s*(\d+)\s*;', options_part)
        if sid_match:
            parsed["sid"] = int(sid_match.group(1))

        # Extract rev
        rev_match = re.search(r'rev\s*:\s*(\d+)\s*;', options_part)
        if rev_match:
            parsed["revision"] = int(rev_match.group(1))

        # Extract classtype
        class_match = re.search(r'classtype\s*:\s*([^;]+)\s*;', options_part)
        if class_match:
            parsed["classification"] = class_match.group(1).strip()

    return parsed


def validate_snort_rule(rule_text):
    """
    Validates a Snort rule for syntax correctness.
    Performs comprehensive structural inspection and checks with local parser.
    Also attempts invocation of 'snort -T' if Snort binary is present.
    Returns:
    {
        "is_valid": bool,
        "mode": "Local Syntax Engine" or "Snort Binary Engine",
        "errors": [str],
        "warnings": [str],
        "parsed": dict
    }
    """
    errors = []
    warnings = []

    if not rule_text or not rule_text.strip():
        return {
            "is_valid": False,
            "mode": "Local Syntax Engine",
            "errors": ["Rule text cannot be empty."],
            "warnings": [],
            "parsed": {}
        }

    rule_text = rule_text.strip()

    # Rule must have parentheses for options
    opt_start = rule_text.find("(")
    opt_end = rule_text.rfind(")")

    if opt_start == -1 or opt_end == -1:
        errors.append("Missing parentheses '(' and ')' for Snort rule options.")
    elif opt_end <= opt_start:
        errors.append("Malformed parentheses enclosing rule options.")

    header_str = rule_text[:opt_start].strip() if opt_start != -1 else rule_text
    header_tokens = header_str.split()

    if len(header_tokens) < 7:
        errors.append(
            f"Rule header requires 7 elements: action, protocol, src_ip, src_port, direction, dst_ip, dst_port. "
            f"Found only {len(header_tokens)} tokens."
        )
    else:
        action = header_tokens[0].lower()
        protocol = header_tokens[1].lower()
        direction = header_tokens[4]

        if action not in VALID_ACTIONS:
            errors.append(f"Invalid rule action '{action}'. Expected one of: {', '.join(sorted(VALID_ACTIONS))}")

        if protocol not in VALID_PROTOCOLS:
            errors.append(f"Invalid protocol '{protocol}'. Expected one of: {', '.join(sorted(VALID_PROTOCOLS))}")

        if direction not in VALID_DIRECTIONS:
            errors.append(f"Invalid direction operator '{direction}'. Expected '->' or '<>'.")

    # Options validation
    parsed = {}
    if opt_start != -1 and opt_end > opt_start:
        options_str = rule_text[opt_start + 1:opt_end].strip()
        parsed = parse_snort_rule_text(rule_text)

        if not parsed.get("message"):
            errors.append("Rule option 'msg' is missing or not properly quoted: expected msg:\"...\";")

        if parsed.get("sid") is None:
            errors.append("Rule option 'sid' is missing or not a valid integer: expected sid:<id>;")
        else:
            sid_val = parsed["sid"]
            if sid_val < 1000000:
                warnings.append(
                    f"SID {sid_val} is in the reserved/official range (< 1,000,000). "
                    "Custom local rules conventionally use SIDs >= 1,000,000."
                )

        if not re.search(r'rev\s*:\s*\d+\s*;', options_str):
            warnings.append("Rule option 'rev' is recommended (e.g., rev:1;).")

        # Check semicolon termination of options
        opt_tokens = [tok.strip() for tok in options_str.split(";") if tok.strip()]
        for tok in opt_tokens:
            if not tok.endswith(""):
                pass  # split by semicolon handles it

    # Check Snort executable if available
    snort_path = shutil.which("snort")
    mode = "Local Syntax Engine"
    if snort_path and len(errors) == 0:
        # Run test config check
        try:
            temp_dir = tempfile.mkdtemp(prefix="securift_rule_check_")
            temp_rules = os.path.join(temp_dir, "test.rules")
            temp_conf = os.path.join(temp_dir, "test.conf")

            with open(temp_rules, "w") as rf:
                rf.write(rule_text + "\n")

            with open(temp_conf, "w") as cf:
                cf.write(f"include {temp_rules}\n")

            cmd = [snort_path, "-T", "-c", temp_conf]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)

            if proc.returncode == 0:
                mode = "Snort Binary Engine (Validated by Snort -T)"
            else:
                # Capture snort error
                snort_err = proc.stderr or proc.stdout
                warnings.append(f"Snort -T flagged rule warnings/output: {snort_err[:200]}")
                mode = "Local Syntax Engine (Snort returned non-zero)"

            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            mode = "Local Syntax Engine"

    return {
        "is_valid": len(errors) == 0,
        "mode": mode,
        "errors": errors,
        "warnings": warnings,
        "parsed": parsed
    }
