import os
import joblib
import re

# CONFIGURACIÓN
MODEL_PATH = "models/best_model_svm.pkl"
TARGET_FILES = [
    os.path.join("..", "tests", "test_high_risk.py"),
    os.path.join("..", "tests", "test_low_risk.py"),
    os.path.join("..", "tests", "test_simple.py"),
    os.path.join("..", "tests", "vulnerable_code.py")
]

# --- 1. LIMPIEZA (Debe coincidir con el entrenamiento del SVM) ---
# Nota: El SVM se entrenó quitando símbolos extraños, así que aquí hacemos lo mismo.
def clean_code(text):
    if not isinstance(text, str): return ""
    text = re.sub(r'#.*', '', text)
    text = text.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')
    # Limpieza estricta (alfanuméricos)
    text = re.sub(r'[^A-Za-z0-9\s\(\)\[\]\{\}\.\_\=\-\"\']', '', text)
    return text

# --- 2. LÓGICA HÍBRIDA (ML + HEURÍSTICA) ---
def analyze_hybrid():
    if not os.path.exists(MODEL_PATH):
        print("Error: No se encuentra el modelo.")
        return

    print(f"Cargando modelo SVM desde {MODEL_PATH}...")
    pipeline = joblib.load(MODEL_PATH)
    
    print("\n" + "="*100)
    print(f"{'ARCHIVO':<25} | {'ESTADO FINAL':<15} | {'PROB. IA':<10} | {'RAZÓN'}")
    print("="*100)

    for filepath in TARGET_FILES:
        if not os.path.exists(filepath):
            print(f"{filepath:<25} | NO ENCONTRADO")
            continue

        with open(filepath, "r", encoding="utf-8") as f:
            raw_code = f.read()

        # 1. Predicción del Modelo (IA)
        clean_text = clean_code(raw_code)
        probs = pipeline.predict_proba([clean_text])[0]
        prob_vuln = probs[1]

        # 2. Análisis Estático (Reglas de Respaldo)
        # Palabras que son INNEGABLEMENTE peligrosas en scripts simples
        danger_patterns = ['exec(', 'eval(', 'os.system', 'subprocess.call', 'pickle.load', 'shell=True']
        found_dangers = [p for p in danger_patterns if p in raw_code] # Buscamos en raw_code para ver símbolos
        
        # 3. Decisión Híbrida
        # Si la IA está segura (>65%), le creemos a la IA.
        # Si la IA duda (40-65%), miramos si hay patrones peligrosos obvios.
        
        estado = "❓ INDEFINIDO"
        razon = ""

        if prob_vuln > 0.65:
            estado = "🔴 CRÍTICO"
            razon = "Modelo IA detectó alta probabilidad."
        elif prob_vuln < 0.40 and not found_dangers:
            estado = "🟢 SEGURO"
            razon = "Modelo IA confía en que es seguro."
        else:
            # ZONA DE DUDA (Donde cayeron tus archivos)
            if found_dangers:
                estado = "🟠 ALERTA (Reglas)"
                razon = f"IA indecisa ({prob_vuln:.2%}), pero se detectó: {', '.join(found_dangers)}"
            elif prob_vuln > 0.50:
                 estado = "🟡 SOSPECHOSO"
                 razon = f"IA levemente inclinada a riesgo ({prob_vuln:.2%})."
            else:
                 estado = "🟢 SEGURO (Bajo Riesgo)"
                 razon = f"IA indecisa ({prob_vuln:.2%}) y sin patrones críticos obvios."

        filename = os.path.basename(filepath)
        print(f"{filename:<25} | {estado:<15} | {prob_vuln:.2%}    | {razon}")

    print("="*100)

if __name__ == "__main__":
    analyze_hybrid()