import os
import ast
import re
import pandas as pd
import numpy as np
from pathlib import Path
from tqdm import tqdm
from radon.complexity import cc_visit
from radon.metrics import mi_visit
import json

# ---------------------------------------------------------
# CONFIGURACIÓN
# ---------------------------------------------------------
INPUT_CSV = "data/cvefixes/raw/CVEfixes.csv"  # Ajusta esta ruta de ser necesario
OUTPUT_DIR = Path("data/cvefixes/processed")
OUTPUT_CSV = OUTPUT_DIR / "dataset_features_labeled.csv"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

print("=" * 70)
print("PROCESAMIENTO DE DATASET KAGGLE - CÓDIGO VULNERABLE")
print("=" * 70)


# ================================================================
# VULNERABILITY DETECTION (from heuristics.py)
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


class TaintTracker(ast.NodeVisitor):
    """Tracks variables that originate from user input (tainted vars)."""

    def __init__(self):
        self.tainted_vars = set()

    def visit_Assign(self, node):
        if isinstance(node.value, ast.Call):
            if any(source in ast.unparse(node.value) for source in USER_INPUT_SOURCES):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_vars.add(target.id)

        if isinstance(node.value, ast.Name):
            if node.value.id in self.tainted_vars:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_vars.add(target.id)

        self.generic_visit(node)


def contains_tainted(node, tainted_vars):
    """Check if node contains tainted variable"""
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and n.id in tainted_vars:
            return True
    return False


def detect_hardcoded_secrets(code):
    findings = []
    for pattern in HARD_CODED_SECRET_PATTERNS:
        if re.search(pattern, code, re.IGNORECASE):
            findings.append({
                "name": "hardcoded_secret",
                "severity": "HIGH"
            })
    return findings


def detect_sql_injection(tree, tainted_vars):
    findings = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if hasattr(node.func, 'attr') and node.func.attr in SQLI_SINKS:
                if node.args:
                    arg = node.args[0]
                    if isinstance(arg, ast.Name) and arg.id in tainted_vars:
                        findings.append({"name": "sql_injection", "severity": "CRITICAL"})
                    elif isinstance(arg, ast.BinOp) and contains_tainted(arg, tainted_vars):
                        findings.append({"name": "sql_injection", "severity": "CRITICAL"})
                    elif isinstance(arg, ast.JoinedStr) and contains_tainted(arg, tainted_vars):
                        findings.append({"name": "sql_injection", "severity": "CRITICAL"})
    return findings


def detect_command_injection(tree, tainted_vars):
    findings = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call_src = ast.unparse(node.func)
            if any(danger in call_src for danger in DANGEROUS_OS_CALLS):
                for arg in node.args:
                    if contains_tainted(arg, tainted_vars):
                        findings.append({"name": "command_injection", "severity": "CRITICAL"})
    return findings


def detect_path_traversal(tree, tainted_vars):
    findings = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = ast.unparse(node.func)
            if any(sink in func for sink in PATH_TRAVERSAL_SINKS):
                if node.args and contains_tainted(node.args[0], tainted_vars):
                    findings.append({"name": "path_traversal", "severity": "HIGH"})
    return findings


def detect_debug_mode(code):
    if "app.run(" in code and "debug=True" in code:
        return [{"name": "debug_mode_enabled", "severity": "MEDIUM"}]
    return []


def detect_xss(code):
    if re.search(r"return\s+f?['\"].*{.*}.*['\"]", code):
        return [{"name": "xss_reflected", "severity": "MEDIUM"}]
    return []


def run_heuristics(code, tree, tainted_vars):
    """Run all heuristic checks"""
    findings = []
    findings.extend(detect_hardcoded_secrets(code))
    findings.extend(detect_debug_mode(code))
    findings.extend(detect_xss(code))
    findings.extend(detect_sql_injection(tree, tainted_vars))
    findings.extend(detect_command_injection(tree, tainted_vars))
    findings.extend(detect_path_traversal(tree, tainted_vars))
    return findings


# ---------------------------------------------------------
# CLASE: Extracción de métricas AST
# ---------------------------------------------------------
class ASTMetrics(ast.NodeVisitor):
    def __init__(self):
        self.functions = 0
        self.classes = 0
        self.imports = 0
        self.nodes = 0
        self.control_structures = 0
        self.max_depth = 0
        self.current_depth = 0

    def visit_FunctionDef(self, node):
        self.functions += 1
        self.current_depth += 1
        self.max_depth = max(self.max_depth, self.current_depth)
        self.generic_visit(node)
        self.current_depth -= 1

    def visit_ClassDef(self, node):
        self.classes += 1
        self.current_depth += 1
        self.max_depth = max(self.max_depth, self.current_depth)
        self.generic_visit(node)
        self.current_depth -= 1

    def visit_Import(self, node):
        self.imports += 1

    def visit_ImportFrom(self, node):
        self.imports += 1

    def generic_visit(self, node):
        self.nodes += 1
        
        if isinstance(node, (ast.If, ast.For, ast.While, ast.Try, ast.With)):
            self.control_structures += 1
        
        self.current_depth += 1
        self.max_depth = max(self.max_depth, self.current_depth)
        super().generic_visit(node)
        self.current_depth -= 1


# ---------------------------------------------------------
# DETECCIÓN DE PATRONES ADICIONALES
# ---------------------------------------------------------
def detect_additional_patterns(code):
    """Detecta patrones adicionales no cubiertos por heuristics.py"""
    patterns = {
        # Deserialización insegura
        'pickle_usage': r'pickle\.(load|loads)\s*\(',
        'yaml_unsafe_load': r'yaml\.load\s*\(',
        'marshal_usage': r'marshal\.loads?\s*\(',
        
        # Criptografía débil
        'weak_hash': r'hashlib\.(md5|sha1)\s*\(',
        'des_crypto': r'DES\.(new|MODE)',
        
        # Evaluación dinámica
        'eval_usage': r'\beval\s*\(',
        'exec_usage': r'\bexec\s*\(',
        'compile_usage': r'\bcompile\s*\(',
        
        # Shell injection
        'shell_true': r'shell\s*=\s*True',
        
        # Random inseguro para crypto
        'weak_random': r'random\.(random|randint|choice)',
        
        # XML parsing inseguro
        'xml_unsafe': r'(etree\.fromstring|parseString|xml\.dom)',
    }
    
    detected = {}
    for name, pattern in patterns.items():
        detected[name] = 1 if re.search(pattern, code, re.IGNORECASE) else 0
    
    return detected


# ---------------------------------------------------------
# DETECCIÓN DE SANITIZACIÓN
# ---------------------------------------------------------
def detect_sanitization(code):
    """Detecta presencia de sanitización o validación"""
    patterns = {
        'has_validation': r'(validate|check|verify|sanitize|escape|clean)',
        'has_try_except': r'try\s*:',
        'has_isinstance': r'isinstance\s*\(',
        'has_assert': r'assert\s+',
        'has_raise': r'raise\s+',
        'parameterized_query': r'(execute|cursor\.execute)\s*\([^)]*\?|%s[^)]*\)',
        'html_escape': r'(escape|html\.escape|cgi\.escape)',
    }
    
    detected = {}
    for name, pattern in patterns.items():
        detected[name] = 1 if re.search(pattern, code, re.IGNORECASE) else 0
    
    return detected


# ---------------------------------------------------------
# EXTRACCIÓN COMPLETA DE FEATURES
# ---------------------------------------------------------
def extract_all_features(code):
    """Extrae todas las features necesarias para el modelo"""
    
    # 1. Métricas básicas
    lines = code.splitlines()
    loc = len(lines)
    comments = sum(1 for line in lines if line.strip().startswith("#"))
    blank_lines = sum(1 for line in lines if not line.strip())
    code_lines = loc - comments - blank_lines
    
    # 2. Parsing AST
    try:
        tree = ast.parse(code)
        ast_valid = True
    except:
        return None
    
    # 3. Métricas AST
    visitor = ASTMetrics()
    visitor.visit(tree)
    
    # 4. Taint tracking
    tracker = TaintTracker()
    tracker.visit(tree)
    tainted_vars = tracker.tainted_vars
    
    # 5. Heurísticas de vulnerabilidad
    vuln_findings = run_heuristics(code, tree, tainted_vars)
    
    # Contar vulnerabilidades por severidad
    critical_count = sum(1 for f in vuln_findings if f['severity'] == 'CRITICAL')
    high_count = sum(1 for f in vuln_findings if f['severity'] == 'HIGH')
    medium_count = sum(1 for f in vuln_findings if f['severity'] == 'MEDIUM')
    low_count = sum(1 for f in vuln_findings if f['severity'] == 'LOW')
    
    # Contar vulnerabilidades por tipo
    vuln_types = {}
    for finding in vuln_findings:
        vuln_name = finding['name']
        vuln_types[f'vuln_{vuln_name}'] = vuln_types.get(f'vuln_{vuln_name}', 0) + 1
    
    # 6. Complejidad ciclomática
    try:
        cc = sum([block.complexity for block in cc_visit(code)])
    except:
        cc = 0
    
    # 7. Maintainability Index
    try:
        mi = mi_visit(code, True)
    except:
        mi = 0
    
    # 8. Patrones adicionales
    additional = detect_additional_patterns(code)
    
    # 9. Sanitización
    sanitization = detect_sanitization(code)
    
    # 10. Features adicionales
    size_bytes = len(code.encode('utf-8'))
    avg_line_length = size_bytes / loc if loc > 0 else 0
    
    # Contar tokens simples
    tokens = re.findall(r'\b\w+\b', code)
    unique_tokens = len(set(tokens))
    total_tokens = len(tokens)
    
    # Combinar todas las features
    features = {
        # Métricas básicas (para compatibilidad con tu predict_risk)
        'loc': loc,
        'comments': comments,
        'functions': visitor.functions,
        'classes': visitor.classes,
        'imports': visitor.imports,
        'ast_nodes': visitor.nodes,
        'control_structures': visitor.control_structures,
        'cyclomatic_complexity': cc,
        'maintainability_index': mi,
        'size_bytes': size_bytes,
        
        # Métricas adicionales
        'code_lines': code_lines,
        'blank_lines': blank_lines,
        'avg_line_length': avg_line_length,
        'ast_depth': visitor.max_depth,
        
        # Tokens
        'total_tokens': total_tokens,
        'unique_tokens': unique_tokens,
        'token_diversity': unique_tokens / total_tokens if total_tokens > 0 else 0,
        
        # Taint tracking
        'tainted_vars_count': len(tainted_vars),
        'has_tainted_vars': 1 if len(tainted_vars) > 0 else 0,
        
        # Vulnerabilidades por severidad
        'vuln_critical_count': critical_count,
        'vuln_high_count': high_count,
        'vuln_medium_count': medium_count,
        'vuln_low_count': low_count,
        'total_vulnerabilities': len(vuln_findings),
        'has_vulnerabilities': 1 if len(vuln_findings) > 0 else 0,
    }
    
    # Agregar conteo de cada tipo de vulnerabilidad específico
    all_vuln_types = [
        'sql_injection', 'command_injection', 'path_traversal',
        'hardcoded_secret', 'debug_mode_enabled', 'xss_reflected'
    ]
    for vtype in all_vuln_types:
        features[f'vuln_{vtype}'] = vuln_types.get(f'vuln_{vtype}', 0)
    
    # Agregar patrones adicionales
    features.update(additional)
    
    # Agregar sanitización
    features.update(sanitization)
    
    return features


# ---------------------------------------------------------
# FUNCIÓN PRINCIPAL DE PROCESAMIENTO
# ---------------------------------------------------------
def process_dataset():
    print(f"\n Cargando dataset desde: {INPUT_CSV}")
    
    # Cargar dataset
    try:
        df = pd.read_csv(INPUT_CSV, low_memory=False)
        print(f" Dataset cargado: {len(df):,} registros")
    except Exception as e:
        print(f" Error al cargar dataset: {e}")
        return
    
    # Explorar columnas
    print(f"\n Columnas encontradas: {df.columns.tolist()}")
    
    # Verificar etiquetas de seguridad
    if 'safety' in df.columns:
        print(f"\n Distribución de etiquetas 'safety':")
        safety_counts = df['safety'].value_counts()
        print(safety_counts)
        
        unique_values = df['safety'].unique()
        print(f"\nValores únicos en 'safety': {unique_values}")
        
    else:
        print(" No se encontró columna 'safety'")
        return
    
    # Filtrar solo Python (si hay columna language)
    if 'language' in df.columns:
        print(f"\n Filtrando solo código Python...")
        df_python = df[df['language'] == 'py'].copy()
        print(f" Registros Python: {len(df_python):,}")
    else:
        df_python = df.copy()
        print(" No hay columna 'language', procesando todo el dataset")
    
    # Limpiar datos nulos
    df_python = df_python.dropna(subset=['code', 'safety'])
    print(f" Después de limpiar nulos: {len(df_python):,} registros")
    
    # Normalizar etiquetas a 0 (seguro) y 1 (vulnerable)
    print(f"\n Normalizando etiquetas...")
    
    def normalize_label(label):
        label_str = str(label).lower().strip()
        
        safe_values = ['safe', 'secure', '0', 'false', 'no', 'clean']
        unsafe_values = ['unsafe', 'vulnerable', 'insecure', '1', 'true', 'yes']
        
        if any(sv in label_str for sv in safe_values):
            return 0
        elif any(uv in label_str for uv in unsafe_values):
            return 1
        else:
            return None
    
    df_python['label'] = df_python['safety'].apply(normalize_label)
    df_python = df_python.dropna(subset=['label'])
    df_python['label'] = df_python['label'].astype(int)
    
    print(f" Etiquetas normalizadas:")
    print(f"   Seguro (0): {(df_python['label'] == 0).sum():,}")
    print(f"   Vulnerable (1): {(df_python['label'] == 1).sum():,}")
    
    # Extraer features
    print(f"\n Extrayendo features del código...")
    
    results = []
    failed = 0
    
    for idx, row in tqdm(df_python.iterrows(), total=len(df_python), desc="Procesando"):
        code = row['code']
        
        features = extract_all_features(code)
        
        if features is not None:
            features['label'] = row['label']
            features['original_safety'] = row['safety']
            results.append(features)
        else:
            failed += 1
    
    print(f"\n Features extraídas: {len(results):,}")
    print(f" Archivos fallidos (no parseables): {failed:,}")
    
    # Crear DataFrame final
    df_final = pd.DataFrame(results)
    
    # Guardar dataset procesado
    df_final.to_csv(OUTPUT_CSV, index=False)
    print(f"\n Dataset guardado en: {OUTPUT_CSV}")
    
    # Estadísticas finales
    print(f"\n{'='*70}")
    print(f" ESTADÍSTICAS FINALES")
    print(f"{'='*70}")
    print(f"Total de registros: {len(df_final):,}")
    print(f"Total de features: {len(df_final.columns) - 2}")
    print(f"\nDistribución final:")
    print(df_final['label'].value_counts())
    
    # Correlación entre vulnerabilidades detectadas y label
    if 'total_vulnerabilities' in df_final.columns:
        print(f"\n Correlación vulnerabilidades vs label:")
        correlation = df_final[['total_vulnerabilities', 'label']].corr()
        print(correlation)
    
    print(f"\n Features principales extraídas:")
    feature_cols = [col for col in df_final.columns if col not in ['label', 'original_safety']]
    
    print(f"\n Features básicas (compatibles con predict_risk):")
    basic_features = ['loc', 'comments', 'functions', 'classes', 'imports', 
                     'ast_nodes', 'control_structures', 'cyclomatic_complexity',
                     'maintainability_index', 'size_bytes']
    for feat in basic_features:
        print(f"  ✓ {feat}")
    
    print(f"\n Features de vulnerabilidad:")
    vuln_features = [col for col in feature_cols if 'vuln_' in col or 'tainted' in col]
    for feat in vuln_features[:10]:
        print(f"  ✓ {feat}")
    
    print(f"\n Features de sanitización:")
    sanit_features = [col for col in feature_cols if 'has_' in col or 'parameterized' in col]
    for feat in sanit_features[:5]:
        print(f"  ✓ {feat}")
    
    # Guardar información del procesamiento
    info = {
        'total_records': len(df_final),
        'total_features': len(feature_cols),
        'basic_features': basic_features,
        'vulnerability_features': vuln_features,
        'sanitization_features': sanit_features,
        'label_distribution': df_final['label'].value_counts().to_dict(),
        'failed_parsing': failed,
        'output_file': str(OUTPUT_CSV)
    }
    
    info_path = OUTPUT_DIR / "processing_info.json"
    with open(info_path, 'w') as f:
        json.dump(info, f, indent=2)
    
    print(f"\n Información guardada en: {info_path}")
    
    return df_final


# ---------------------------------------------------------
# EJECUCIÓN
# ---------------------------------------------------------
if __name__ == "__main__":
    df_result = process_dataset()
    
    if df_result is not None:
        print(f"\n{'='*70}")
        print(f" PROCESAMIENTO COMPLETADO !!!")
        print(f"{'='*70}")
        print(f"\nSiguiente paso:")
        print(f"   Entrenar modelo con: {OUTPUT_CSV}")
        print(f"   El modelo tendrá {len(df_result.columns) - 2} features")
        print(f"   Compatible con tu función predict_risk() existente")