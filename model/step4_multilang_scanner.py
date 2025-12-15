import os
import joblib
import re
import json
import sys
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin

# ---------------------------------------------------------
# 1. CLASE NECESARIA PARA JOBLIB (No borrar)
# ---------------------------------------------------------
class RiskKeywordCounter(BaseEstimator, TransformerMixin):
    def __init__(self, keywords=[]):
        self.keywords = keywords
    def fit(self, X, y=None): return self
    def transform(self, X):
        features = []
        for text in X:
            if not isinstance(text, str):
                features.append([0] * (len(self.keywords) + 1))
                continue
            text_lower = text.lower()
            row = [text_lower.count(k.lower()) for k in self.keywords]
            row.append(len(text) / 1000.0) 
            features.append(row)
        return np.array(features)

# ---------------------------------------------------------
# 2. CONFIGURACIÓN DEL ROUTER
# ---------------------------------------------------------
MODEL_DIR = "model/models"
REPORT_FILE = "multilang_security_report.json"

# Mapeo: Extensión -> {Modelo, Lenguaje}
LANG_MAP = {
    ".py":  "python",
    ".java": "java",
    ".c":   "c_cpp",
    ".cpp": "c_cpp",
    ".h":   "c_cpp",
    ".js":   "javascript",
    ".ts":   "javascript",
    ".jsx":  "javascript"
}

# ---------------------------------------------------------
# 3. BASE DE DATOS DE REGLAS (HEURÍSTICAS)
# ---------------------------------------------------------
RULES_DB = {
    "python": [
        {"id": "cmd_injection", "sev": "CRITICAL", "pat": r'(os\.system|subprocess\.call).*(\+|%|format)'},
        {"id": "hardcoded_pass", "sev": "HIGH", "pat": r'(password|secret)\s*=\s*["\'].+["\']'},
        {"id": "deserialize", "sev": "HIGH", "pat": r'pickle\.load'}
    ],
    "java": [
        {"id": "cmd_injection", "sev": "CRITICAL", "pat": r'Runtime\.getRuntime\(\)\.exec\(.*(\+|%s)'},
        {"id": "sql_injection", "sev": "CRITICAL", "pat": r'(executeQuery|prepareStatement)\s*\(.*(\+|%s)'},
        {"id": "hardcoded_pass", "sev": "HIGH", "pat": r'String\s+(password|secret)\s*=\s*".+"'},
        {"id": "unsafe_deserialize", "sev": "HIGH", "pat": r'readObject\(\)'}
    ],
    "c_cpp": [
        {"id": "buffer_overflow", "sev": "CRITICAL", "pat": r'(strcpy|strcat|gets|sprintf)\s*\('},
        {"id": "cmd_injection", "sev": "CRITICAL", "pat": r'system\s*\(.*(\+|%s)'},
        {"id": "format_string", "sev": "HIGH", "pat": r'printf\s*\([^,]+\)'}
    ],
    "javascript": [
        {"id": "dom_xss", "sev": "CRITICAL", "pat": r'(innerHTML|outerHTML|document\.write)\s*='},
        {"id": "eval_injection", "sev": "CRITICAL", "pat": r'(eval|setTimeout|setInterval)\s*\('},
        {"id": "cmd_injection", "sev": "CRITICAL", "pat": r'(child_process|exec|spawn).*(\+|%|`|\$\{)'},
        {"id": "prototype_pollution", "sev": "HIGH", "pat": r'__proto__|prototype'},
        {"id": "xss_react", "sev": "HIGH", "pat": r'dangerouslySetInnerHTML'}
    ]
}

# ---------------------------------------------------------
# 4. FUNCIONES DEL ESCÁNER
# ---------------------------------------------------------
def clean_code(text):
    if not isinstance(text, str): return ""
    text = re.sub(r'#.*|//.*|/\*[\s\S]*?\*/', '', text)
    text = text.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')
    text = re.sub(r'[^A-Za-z0-9\s\(\)\[\]\{\}\.\_\=\-\"\'\+\%\*\,<>\&]', '', text)
    return text

def scan_file(filepath, lang):
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        raw_code = f.read()

    # A. Cargar Modelo Específico
    model_name = f"best_model_{lang}.pkl"
    # Ajuste especial para python si usaste el nombre 'hybrid' antes
    if lang == 'python' and not os.path.exists(os.path.join(MODEL_DIR, model_name)):
        model_name = "best_model_hybrid.pkl" 
        
    model_path = os.path.join(MODEL_DIR, model_name)
    
    ml_prob = 0.0
    ml_msg = "Model Not Found"

    if os.path.exists(model_path):
        try:
            pipeline = joblib.load(model_path)
            clean = clean_code(raw_code)
            ml_prob = pipeline.predict_proba([clean])[0][1]
            ml_msg = "OK"
        except Exception as e:
            ml_msg = f"Error: {str(e)}"
    
    # B. Análisis Estático (Reglas específicas del lenguaje)
    findings = []
    lines = raw_code.split('\n')
    rules = RULES_DB.get(lang, [])

    for i, line in enumerate(lines):
        line_clean = line.strip()
        if not line_clean or line_clean.startswith(('/', '*', '#')): continue
        
        for r in rules:
            if re.search(r["pat"], line, re.IGNORECASE):
                findings.append({
                    "type": r["id"],
                    "severity": r["sev"],
                    "line": i + 1,
                    "snippet": line_clean[:80]
                })

    if lang == "javascript":
        # Buscamos la palabra 'var' completa (\bvar\b) para no confundir con 'variable'
        var_matches = re.findall(r'\bvar\s+', raw_code)
        var_count = len(var_matches)
        
        # Lógica de penalización
        if var_count > 3:
            # Por defecto es MEDIUM
            severity = "MEDIUM"
            # Si abusa mucho (>10), subimos a HIGH (código legado/peligroso)
            if var_count > 10: 
                severity = "HIGH" 
            
            findings.append({
                "type": "deprecated_syntax_var",
                "severity": severity,
                "line": 1, # Lo marcamos al inicio del archivo
                "snippet": f"GLOBAL CHECK: Se detectaron {var_count - 1} usos de 'var'. Use 'let' o 'const' para seguridad de alcance."
            })

    # C. Veredicto Híbrido
    max_severity = 0
    sev_map = {"CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.5, "LOW": 0.2}
    
    for f in findings:
        s = sev_map.get(f["severity"], 0)
        if s > max_severity: max_severity = s
    
    final_score = max(ml_prob, max_severity)
    
    if final_score > 0.8: verdict = "CRITICAL"
    elif final_score > 0.6: verdict = "HIGH"
    elif final_score > 0.4: verdict = "MEDIUM"
    else: verdict = "SAFE"

    return {
        "language": lang,
        "verdict": verdict,
        "score": round(final_score, 4),
        "ml_prob": round(ml_prob, 4),
        "findings": findings
    }

# ---------------------------------------------------------
# 5. EJECUCIÓN PRINCIPAL
# ---------------------------------------------------------
def run_multilang_scan():
    print(f"--- ESCÁNER DE SEGURIDAD MULTILENGUAJE ---")
    full_report = {}

    folder = sys.argv[1] if len(sys.argv) > 1 else "src"
    files = os.listdir(folder)
    
    for filename in files:
        ext = os.path.splitext(filename)[1].lower()
        if ext in LANG_MAP:
            lang = LANG_MAP[ext]
            path = os.path.join(folder, filename)
            
            print(f"Analizando {filename} ({lang})...")
            result = scan_file(path, lang)
            
            full_report[filename] = result
            print(f" -> Resultado: {result['verdict']} (Score: {result['score']})")

    with open(REPORT_FILE, "w") as f:
        json.dump(full_report, f, indent=4)
    print(f"\nReporte generado: {REPORT_FILE}")

if __name__ == "__main__":
    run_multilang_scan()