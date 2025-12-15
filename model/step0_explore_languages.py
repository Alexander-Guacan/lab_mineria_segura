import pandas as pd
import os

# RUTAS DE TUS DATASETS
CVE_FIXES = "data/cvefixes/raw/CVEFixes.csv"
KAGGLE_FIX = "data/kaggle_fix/vulnerability_fix_dataset.csv"

def analyze_languages():
    print("--- FASE 1: AUDITORÍA DE LENGUAJES DISPONIBLES ---")
    
    # 1. Analizar CVEFixes (Este tiene columna 'language' explícita)
    if os.path.exists(CVE_FIXES):
        print(f"\nCargando {CVE_FIXES}...")
        df1 = pd.read_csv(CVE_FIXES)
        
        # A veces la columna se llama 'lang' o 'language'
        lang_col = 'language' if 'language' in df1.columns else 'lang'
        
        if lang_col in df1.columns:
            print("Distribución de lenguajes en CVEFixes:")
            print(df1[lang_col].value_counts().head(10))
        else:
            print("⚠️ No encontré columna de lenguaje en CVEFixes.")
    else:
        print(f"⚠️ No encontrado: {CVE_FIXES}")

    # 2. Analizar Kaggle Vulnerability Fix (Este suele ser mixto sin etiqueta)
    # Vamos a intentar inferir el lenguaje por extensión o contenido
    if os.path.exists(KAGGLE_FIX):
        print(f"\nCargando {KAGGLE_FIX}...")
        try:
            df2 = pd.read_csv(KAGGLE_FIX)
            print(f"Total filas en Kaggle: {len(df2)}")
            
            # Muestreo rápido para ver qué hay
            # Buscamos extensiones en nombres de archivo si existen, o palabras clave
            print("Analizando muestra de contenido para adivinar lenguajes...")
            
            detected_langs = []
            
            # Tomamos una muestra para no tardar años
            sample = df2.head(2000) 
            
            # Intentamos adivinar basándonos en columnas comunes
            code_col = 'vulnerable_code' if 'vulnerable_code' in df2.columns else 'code'
            
            for code in sample[code_col].astype(str):
                if "#include" in code or "int main(" in code:
                    detected_langs.append("c/cpp")
                elif "import java" in code or "public class" in code:
                    detected_langs.append("java")
                elif "def " in code and "import " in code:
                    detected_langs.append("python")
                elif "<?php" in code:
                    detected_langs.append("php")
                else:
                    detected_langs.append("unknown")

            from collections import Counter
            print("Estimación de lenguajes en Kaggle (Muestra de 2000):")
            print(Counter(detected_langs))
            
        except Exception as e:
            print(f"Error leyendo Kaggle dataset: {e}")

if __name__ == "__main__":
    analyze_languages()