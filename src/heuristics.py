import re
import ast

# ================================================================
# VULNERABILITY DEFINITIONS (severity, pattern, description)
# ================================================================

HARD_CODED_SECRET_PATTERNS = [
    r"(secret|token|api[_-]?key|password|pwd|passphrase)[\"'\s:=]+\w+",
    r"secret[_-]?key\s*=\s*['\"].+['\"]"
]

SQLI_SINKS = ["execute", "executemany"]

DANGEROUS_OS_CALLS = [
    r"os\.system",
    r"os\.popen",
    r"subprocess\.Popen",
    r"subprocess\.call",
    r"subprocess\.run",
]

PATH_TRAVERSAL_SINKS = [
    "open",
    "os.remove",
    "os.rmdir",
    "os.unlink",
]

USER_INPUT_SOURCES = [
    "request.args.get",
    "request.form.get",
    "request.json.get",
    "input(",
]

# ================================================================
# AST VISITOR FOR TAINT TRACKING
# ================================================================

class TaintTracker(ast.NodeVisitor):
    """
    Tracks variables that originate from user input (tainted vars).
    """

    def __init__(self):
        self.tainted_vars = set()

    def visit_Assign(self, node):
        # Detect tainted assignment
        if isinstance(node.value, ast.Call):
            if hasattr(node.value.func, "attr"):
                call_name = f"{getattr(node.value.func, 'value', None)}.{node.value.func.attr}"
            else:
                call_name = ""

            # Check known input sources
            if any(source in ast.unparse(node.value) for source in USER_INPUT_SOURCES):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_vars.add(target.id)

        # Propagate taint: A = B
        if isinstance(node.value, ast.Name):
            if node.value.id in self.tainted_vars:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_vars.add(target.id)

        self.generic_visit(node)

# ================================================================
#         HEURISTIC CHECK FUNCTIONS
# ================================================================

def detect_hardcoded_secrets(code):
    findings = []
    for pattern in HARD_CODED_SECRET_PATTERNS:
        if re.search(pattern, code, re.IGNORECASE):
            findings.append({
                "name": "hardcoded_secret",
                "severity": "HIGH",
                "detail": f"Secret o token hardcodeado detectado: {pattern}"
            })
    return findings


def detect_sql_injection(tree, tainted_vars):
    findings = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if hasattr(node.func, 'attr') and node.func.attr in SQLI_SINKS:
                # 1. Parameter is a Name
                if node.args:
                    arg = node.args[0]

                    # case: execute(query)
                    if isinstance(arg, ast.Name):
                        if arg.id in tainted_vars:
                            findings.append({
                                "name": "sql_injection",
                                "severity": "CRITICAL",
                                "detail": f"Variable '{arg.id}' controlada por usuario usada en SQL execution."
                            })

                    # case: execute("SELECT..." + user_input)
                    if isinstance(arg, ast.BinOp):
                        if contains_tainted(arg, tainted_vars):
                            findings.append({
                                "name": "sql_injection",
                                "severity": "CRITICAL",
                                "detail": "Concatenación peligrosa detectada dentro de execute()"
                            })

                    # case: execute(f"...{user_input}...")
                    if isinstance(arg, ast.JoinedStr):
                        if contains_tainted(arg, tainted_vars):
                            findings.append({
                                "name": "sql_injection",
                                "severity": "CRITICAL",
                                "detail": "F-string peligrosa en ejecución SQL"
                            })

    return findings


def detect_command_injection(tree, tainted_vars):
    findings = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call_src = ast.unparse(node.func)

            if any(danger in call_src for danger in DANGEROUS_OS_CALLS):
                # Detect tainted arguments
                for arg in node.args:
                    if contains_tainted(arg, tainted_vars):
                        findings.append({
                            "name": "command_injection",
                            "severity": "CRITICAL",
                            "detail": f"Llamada peligrosa: {call_src} recibe datos del usuario"
                        })

    return findings


def detect_path_traversal(tree, tainted_vars):
    findings = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = ast.unparse(node.func)

            if any(sink in func for sink in PATH_TRAVERSAL_SINKS):
                if node.args:
                    arg = node.args[0]
                    if contains_tainted(arg, tainted_vars):
                        findings.append({
                            "name": "path_traversal",
                            "severity": "HIGH",
                            "detail": f"Llamada a {func} con path controlado por usuario"
                        })

    return findings


def detect_debug_mode(code):
    if "app.run(" in code and "debug=True" in code:
        return [{
            "name": "debug_mode_enabled",
            "severity": "MEDIUM",
            "detail": "Modo debug habilitado en producción."
        }]
    return []


def detect_xss(code):
    # Simple reflected XSS heuristic (string interpolation in HTML-like response)
    if re.search(r"return\s+f?['\"].*{.*}.*['\"]", code):
        return [{
            "name": "xss_reflected",
            "severity": "MEDIUM",
            "detail": "Salida dinámica no sanitizada enviada al cliente."
        }]
    return []


# ================================================================
# UTILITY: Check if node contains tainted variable
# ================================================================

def contains_tainted(node, tainted_vars):
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and n.id in tainted_vars:
            return True
    return False


# ================================================================
# MAIN ENTRYPOINT
# ================================================================

def run_heuristics(code):
    findings = []

    # AST parse
    try:
        tree = ast.parse(code)
    except:
        return [{"name": "syntax_error", "severity": "LOW", "detail": "No se pudo analizar el AST"}]

    # Taint tracking
    tracker = TaintTracker()
    tracker.visit(tree)
    tainted = tracker.tainted_vars

    # ---- Heuristic Calls ----
    findings.extend(detect_hardcoded_secrets(code))
    findings.extend(detect_debug_mode(code))
    findings.extend(detect_xss(code))
    findings.extend(detect_sql_injection(tree, tainted))
    findings.extend(detect_command_injection(tree, tainted))
    findings.extend(detect_path_traversal(tree, tainted))

    return findings
