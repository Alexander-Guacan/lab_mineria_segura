import pandas as pd
import os
import re
from tqdm import tqdm

# RUTAS
INPUT_CVE = "data/cvefixes/raw/CVEFixes.csv"
INPUT_KAGGLE = "data/kaggle_fix/vulnerability_fix_dataset.csv"
OUTPUT_DIR = "data/partitioned"

os.makedirs(OUTPUT_DIR, exist_ok=True)

# Detectar lenguaje basado en contenido (para el dataset de Kaggle que no tiene etiqueta)
def detect_language(code):
    if not isinstance(code, str): return "unknown"
    code = code.lower()
    
    # Patrones fuertes
    if "public class" in code or "system.out.println" in code or "import java." in code:
        return "java"
    if "#include <" in code or "int main(" in code or "void *" in code:
        return "c_cpp"
    if "<?php" in code or "$_" in code:
        return "php"
    if "def " in code and ("import " in code or "print(" in code):
        return "python"
    
    return "unknown"

def partition_data():
    print("--- FASE 2: PARTICIONAMIENTO DE DATOS POR LENGUAJE ---")
    
    datasets = {
        "python": [],
        "java": [],
        "c_cpp": [],
        "php": []
    }

    # 1. PROCESAR CVEFIXES (Tiene etiquetas confiables)
    if os.path.exists(INPUT_CVE):
        print(f"Procesando {INPUT_CVE}...")
        df_cve = pd.read_csv(INPUT_CVE)
        # Normalizar nombres de columnas si es necesario
        lang_col = 'language' if 'language' in df_cve.columns else 'lang'
        
        for _, row in tqdm(df_cve.iterrows(), total=len(df_cve)):
            lang = str(row[lang_col]).lower()
            code = row['code']
            label = 1 if row['safety'] == 'vulnerable' else 0
            
            if pd.isna(code): continue

            # Mapeo de etiquetas CVE a nuestros grupos
            if lang == 'py':
                datasets["python"].append({"code": code, "target": label})
            elif lang in ['c', 'cpp', 'h', 'hpp']:
                datasets["c_cpp"].append({"code": code, "target": label})
            elif lang == 'java':
                datasets["java"].append({"code": code, "target": label})
            elif lang == 'php':
                datasets["php"].append({"code": code, "target": label})

    # 2. PROCESAR KAGGLE (Inferir etiquetas)
    if os.path.exists(INPUT_KAGGLE):
        print(f"Procesando {INPUT_KAGGLE}...")
        df_kag = pd.read_csv(INPUT_KAGGLE)
        
        # Ajustar nombres de columnas según tu CSV de Kaggle
        # Asumimos que tiene 'vulnerable_code' y 'fixed_code' o similar
        # Si el CSV tiene una sola columna 'code' y 'label', ajusta aquí.
        # Basado en datasets típicos de Kaggle de este tipo:
        vuln_col = 'vulnerable_code' if 'vulnerable_code' in df_kag.columns else 'code'
        safe_col = 'fixed_code' if 'fixed_code' in df_kag.columns else None

        for _, row in tqdm(df_kag.iterrows(), total=len(df_kag)):
            # Procesar código vulnerable
            code_v = row[vuln_col]
            lang_v = detect_language(code_v)
            if lang_v in datasets:
                datasets[lang_v].append({"code": code_v, "target": 1})
            
            # Procesar código seguro (si existe la columna)
            if safe_col and not pd.isna(row[safe_col]):
                code_s = row[safe_col]
                # Asumimos mismo lenguaje que el vulnerable
                if lang_v in datasets:
                     datasets[lang_v].append({"code": code_s, "target": 0})

    # 3. GUARDAR DATASETS LIMPIOS
    print("\nGuardando particiones...")
    for lang, data in datasets.items():
        if data:
            df_out = pd.DataFrame(data)
            # Eliminar duplicados exactos para limpiar ruido
            df_out = df_out.drop_duplicates(subset=['code'])
            
            out_path = os.path.join(OUTPUT_DIR, f"dataset_{lang}.csv")
            df_out.to_csv(out_path, index=False)
            
            print(f" -> {lang.upper()}: {len(df_out)} muestras guardadas en {out_path}")
            print(f"    (Vuln: {df_out['target'].sum()} | Safe: {len(df_out) - df_out['target'].sum()})")
        else:
            print(f" -> {lang.upper()}: No se encontraron datos suficientes.")

if __name__ == "__main__":
    partition_data()