import os
import joblib
import re

# ---------------------------------------------------------
# CONFIGURACIÓN DE RUTAS
# ---------------------------------------------------------
# Asumimos que este script corre en 'src', por lo que 'models' está aquí mismo
MODEL_PATH = "models/best_model_svm.pkl"

# Lista de archivos específicos que quieres evaluar (Rutas Relativas)
# Usamos os.path.join para evitar problemas con las barras (\ o /)
TARGET_FILES = [
    os.path.join("..", "tests", "test_high_risk.py"),
    os.path.join("..", "tests", "test_low_risk.py"),
    os.path.join("..", "tests", "vulnerable_code.py")
]

# ---------------------------------------------------------
# FUNCIÓN DE LIMPIEZA (Debe ser idéntica al entrenamiento)
# ---------------------------------------------------------
def clean_code(text):
    if not isinstance(text, str): return ""
    text = re.sub(r'#.*', '', text)
    text = text.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')
    # AQUI ESTA EL CAMBIO: Agregamos \+\%\*\, al final del regex
    text = re.sub(r'[^A-Za-z0-9\s\(\)\[\]\{\}\.\_\=\-\"\'\+\%\*\,]', '', text)
    return text

# ---------------------------------------------------------
# PROCESO DE EVALUACIÓN
# ---------------------------------------------------------
def analyze_specific_files():
    # 1. Cargar Modelo
    if not os.path.exists(MODEL_PATH):
        print(f"ERROR CRÍTICO: No encuentro el modelo en '{MODEL_PATH}'")
        print("Asegúrate de ejecutar este script desde la carpeta 'src' donde creaste 'models'.")
        return

    print(f"Cargando modelo desde: {MODEL_PATH} ...")
    try:
        pipeline = joblib.load(MODEL_PATH)
    except Exception as e:
        print(f"Error cargando el modelo: {e}")
        return

    print("\n" + "="*80)
    print(f"{'ARCHIVO':<35} | {'PREDICCIÓN':<12} | {'CONF.':<8} | {'TÉRMINOS CLAVE'}")
    print("="*80)

    # 2. Iterar sobre la lista de archivos solicitada
    for filepath in TARGET_FILES:
        # Verificar si el archivo realmente existe en la ruta dada
        if not os.path.exists(filepath):
            print(f"{filepath:<35} | ❌ NO ENCONTRADO (Revisa la ruta)")
            continue
            
        try:
            # Leer contenido
            with open(filepath, "r", encoding="utf-8") as f:
                raw_code = f.read()
            
            # Limpiar (Preprocesamiento)
            clean_text = clean_code(raw_code)
            
            # Si el archivo está vacío después de limpiar
            if not clean_text.strip():
                print(f"{os.path.basename(filepath):<35} | ⚠️ VACÍO/SIN CÓDIGO VÁLIDO")
                continue

            # Predecir
            # Nota: predict espera una lista/iterable, por eso los corchetes []
            pred = pipeline.predict([clean_text])[0]
            prob = pipeline.predict_proba([clean_text])[0]
            
            # Interpretar resultados
            label = "VULNERABLE 🔴" if pred == 1 else "SEGURO 🟢"
            confidence = prob[1] if pred == 1 else prob[0]
            
            # Análisis visual de triggers (Solo para referencia, no es exacto al 100% como el modelo)
            # Buscamos qué palabras "peligrosas" o "seguras" están presentes
            sospechosos = ['exec', 'eval', 'os.system', 'subprocess', 'shell', 'pickle', 
                           'cursor.execute', 'raw_input', 'admin', 'md5', '404', 'cmd']
            seguros = ['logging', 'secrets', 'hash', 'def', 'class', 'return']
            
            if pred == 1:
                triggers = [w for w in sospechosos if w in clean_text.lower()]
            else:
                triggers = [w for w in seguros if w in clean_text.lower()]

            triggers_str = ", ".join(triggers[:4]) # Mostrar máx 4 palabras

            # Imprimir fila
            filename_only = os.path.basename(filepath)
            print(f"{filename_only:<35} | {label:<12} | {confidence:.2%}   | {triggers_str}")

        except Exception as e:
            print(f"{os.path.basename(filepath):<35} | ERROR PROCESANDO: {str(e)}")

    print("="*80)

if __name__ == "__main__":
    analyze_specific_files()