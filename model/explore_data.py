import pandas as pd
import os

# Ajusta esta ruta a donde tengas tus archivos descomprimidos de Kaggle
# En CVEFixes usualmente los archivos clave son 'Method.csv' (código) y 'CWE.csv' (tipos de vulns)
# O a veces viene un dataset unificado. Asumiremos que estás buscando un archivo principal.
INPUT_CSV = "data/cvefixes/raw/CVEFixes.csv" # <--- CAMBIA ESTO si tu archivo tiene otro nombre

def explore_data():
    if not os.path.exists(INPUT_CSV):
        print(f"Error: No encuentro el archivo en {INPUT_CSV}")
        return

    print(f"--- Cargando {INPUT_CSV} para exploración (Fase SAMPLE del SEMMA) ---")
    
    # Leemos solo las primeras filas para no saturar memoria aún
    df = pd.read_csv(INPUT_CSV, nrows=5)
    
    print("\n1. Columnas disponibles:")
    print(df.columns.tolist())
    
    print("\n2. Vista previa de datos:")
    print(df.head())
    
    # Verificamos si hay una columna obvia de código y etiquetas
    possible_code_cols = [c for c in df.columns if "code" in c.lower() or "snippet" in c.lower() or "method" in c.lower()]
    print(f"\n3. Posibles columnas de código detectadas: {possible_code_cols}")

if __name__ == "__main__":
    explore_data()