import re

def detect_hardcoded_passwords(code):
    patterns = [
        r"password\s*=\s*['\"].+['\"]",
        r"passwd\s*=\s*['\"].+['\"]",
        r"secret\s*=\s*['\"].+['\"]"
    ]
    for p in patterns:
        if re.search(p, code, re.IGNORECASE):
            return True
    return False


def detect_command_injection(code):
    patterns = [
        r"os\.system\(.+\+.+\)",
        r"subprocess\.Popen\(.+\+.+\)",
        r"subprocess\.call\(.+\+.+\)"
    ]
    for p in patterns:
        if re.search(p, code):
            return True
    return False


def detect_unsafe_deserialization(code):
    patterns = [
        r"pickle\.load\(",
        r"pickle\.loads\("
    ]
    for p in patterns:
        if re.search(p, code):
            return True
    return False


def detect_weak_crypto(code):
    patterns = [
        r"hashlib\.md5\(",
        r"hashlib\.sha1\("
    ]
    for p in patterns:
        if re.search(p, code):
            return True
    return False


def detect_eval_usage(code):
    return "eval(" in code


def detect_shell_usage(code):
    return "shell=True" in code


def detect_unvalidated_input(code):
    # input() sin validación
    if "input(" in code:
        return True
    return False


def run_heuristics(code):
    findings = []

    if detect_hardcoded_passwords(code):
        findings.append("hardcoded_password")

    if detect_command_injection(code):
        findings.append("command_injection")

    if detect_unsafe_deserialization(code):
        findings.append("unsafe_deserialization")

    if detect_weak_crypto(code):
        findings.append("weak_crypto")

    if detect_eval_usage(code):
        findings.append("eval_usage")

    if detect_shell_usage(code):
        findings.append("shell_injection")

    if detect_unvalidated_input(code):
        findings.append("unvalidated_input")

    return findings
