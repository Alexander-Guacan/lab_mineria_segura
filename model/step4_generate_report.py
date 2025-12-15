import os
import joblib
import re
import json
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin

# --- CLASE REQUERIDA PARA CARGAR EL MODELO ---
class RiskKeywordCounter(BaseEstimator, TransformerMixin):
    def __init__(self):
        self.risk_words = [
            'exec', 'eval', 'os.system', 'subprocess', 'shell=True', 
            'pickle.load', 'yaml.load', 'input', 'raw_input', 
            'cursor.execute', 'md5', 'sha1', 'tmp', 'password', 'token',
            'admin', 'debug=True'
        ]
    def fit(self, X, y=None): return self
    def transform(self, X):
        features = []
        for text in X:
            if not isinstance(text, str):
                features.append([0] * (len(self.risk_words) + 1))
                continue
            row = [text.count(word) for word in self.risk_words]
            row.append(len(text) / 1000.0) 
            features.append(row)
        return np.array(features)

MODEL_PATH = "model/models/best_model_hybrid.pkl"
TEST_DIR = "tests" 
REPORT_FILE = "final_security_report.json"

# --- MOTOR DE REGLAS (Scanner) ---
class VulnerabilityScanner:
    def __init__(self):
        self.rules = [
            {"id": "hardcoded_secret", "severity": "HIGH", "pattern": r'(password|secret|api_key|token|auth)\s*=\s*["\'][A-Za-z0-9@#$%^&+=]{8,}["\']', "desc": "Credencial hardcodeada."},
            {"id": "sql_injection", "severity": "CRITICAL", "pattern": r'(execute|execute_script)\s*\(\s*["\'].*["\']\s*(\+|%).*', "desc": "Inyección SQL (concatenación)."},
            {"id": "command_injection", "severity": "CRITICAL", "pattern": r'(os\.system|subprocess\.call|popen)\s*\(.*(\+|%|format).*', "desc": "Inyección de Comandos (concatenación)."},
            {"id": "insecure_deserialization", "severity": "HIGH", "pattern": r'pickle\.(load|loads)', "desc": "Deserialización insegura (Pickle)."},
            {"id": "dangerous_eval", "severity": "CRITICAL", "pattern": r'(eval|exec)\s*\(', "desc": "Uso peligroso de eval/exec."},
            {"id": "weak_hashing", "severity": "MEDIUM", "pattern": r'hashlib\.(md5|sha1)', "desc": "Hashing débil (MD5/SHA1)."},
            {"id": "debug_mode", "severity": "LOW", "pattern": r'debug\s*=\s*True', "desc": "Debug mode habilitado."}
        ]

    def scan_lines(self, code):
        findings = []
        lines = code.split('\n')
        for i, line in enumerate(lines):
            line_clean = line.strip()
            if not line_clean or line_clean.startswith('#'): continue
            for rule in self.rules:
                if re.search(rule["pattern"], line, re.IGNORECASE):
                    findings.append({
                        "name": rule["id"],
                        "severity": rule["severity"],
                        "line": i + 1,
                        "detail": rule["desc"],
                        "code_snippet": line_clean[:100]
                    })
        return findings

# --- LIMPIEZA ---
def clean_code_ml(text):
    if not isinstance(text, str): return ""
    text = re.sub(r'#.*', '', text)
    text = text.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')
    text = re.sub(r'[^A-Za-z0-9\s\(\)\[\]\{\}\.\_\=\-\"\'\+\%\*\,]', '', text)
    return text

# --- GENERADOR ---
def generate_report():
    print("--- GENERANDO REPORTE HÍBRIDO ---")
    
    if not os.path.exists(MODEL_PATH):
        print("Error: Modelo no encontrado.")
        return

    pipeline = joblib.load(MODEL_PATH)
    scanner = VulnerabilityScanner()
    full_report = {}

    files = [f for f in os.listdir(TEST_DIR) if f.endswith(".py")]
    
    for filename in files:
        filepath = os.path.join(TEST_DIR, filename)
        with open(filepath, 'r', encoding='utf-8') as f:
            raw_code = f.read()

        # 1. Obtener Probabilidad ML
        clean_text = clean_code_ml(raw_code)
        # Random Forest devuelve prob de clase 0 y 1. Tomamos clase 1.
        ml_prob = pipeline.predict_proba([clean_text])[0][1]

        # 2. Obtener Hallazgos Heurísticos
        heuristics = scanner.scan_lines(raw_code)
        
        # 3. LÓGICA DE VEREDICTO FINAL (Aquí está la corrección)
        severity_weights = {"CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.5, "LOW": 0.2}
        max_heuristic_severity = 0.0
        
        for h in heuristics:
            w = severity_weights.get(h["severity"], 0)
            if w > max_heuristic_severity:
                max_heuristic_severity = w

        # El veredicto final es el MÁXIMO riesgo detectado, sea por ML o por Reglas.
        # Si el ML dice 0.4 (Safe) pero hay un SQL Injection (1.0), el resultado es 1.0 (Critical)
        final_risk_score = max(ml_prob, max_heuristic_severity)
        
        if final_risk_score > 0.8:
            verdict = "CRITICAL"
        elif final_risk_score > 0.6:
            verdict = "HIGH"
        elif final_risk_score > 0.4:
            verdict = "MEDIUM"
        else:
            verdict = "SAFE"

        full_report[filename] = {
            "final_verdict": verdict,
            "risk_score": round(final_risk_score, 4),
            "ml_probability": round(ml_prob, 4),
            "findings_count": len(heuristics),
            "heuristics": heuristics
        }
        
        print(f"{filename:<25} | Verdict: {verdict:<10} | Score: {final_risk_score:.2f} (ML: {ml_prob:.2f})")

    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        json.dump(full_report, f, indent=4)
    print(f"\nReporte guardado en: {REPORT_FILE}")

if __name__ == "__main__":
    generate_report()