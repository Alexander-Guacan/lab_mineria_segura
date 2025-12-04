import os
import pandas as pd
import requests
import zipfile
from pathlib import Path
import tqdm
import json


# ---------------------------------------------------------
# CONFIGURACIÓN
# ---------------------------------------------------------
DATA_DIR = Path("data/cvefixes")
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"

# Crear directorios
DATA_DIR.mkdir(parents=True, exist_ok=True)
RAW_DIR.mkdir(exist_ok=True)
PROCESSED_DIR.mkdir(exist_ok=True)

# URLs del dataset CVEFixes (GitHub oficial)
CVEFIXES_REPO = "https://github.com/secureIT-project/CVEfixes"
DATASET_URL = "https://zenodo.org/record/7029359/files/CVEfixes.csv"
# Descarga Manual alternativa
KAGGLE_URL = "https://www.kaggle.com/datasets/girish17019/cvefixes-vulnerable-and-fixed-code"

print("=" * 60)
print("DESCARGA DE DATASET CVEFixes")
print("=" * 60)


# ---------------------------------------------------------
# FUNCIÓN: Descargar archivo con barra de progreso
# ---------------------------------------------------------
def download_file(url, destination):
    """Descarga un archivo mostrando progreso"""
    print(f"\n Descargando desde: {url}")
    
    response = requests.get(url, stream=True)
    total_size = int(response.headers.get('content-length', 0))
    
    with open(destination, 'wb') as file, tqdm(
        desc=destination.name,
        total=total_size,
        unit='iB',
        unit_scale=True,
        unit_divisor=1024,
    ) as bar:
        for data in response.iter_content(chunk_size=1024):
            size = file.write(data)
            bar.update(size)
    
    print(f" Descargado: {destination}")


# ---------------------------------------------------------
# FUNCIÓN: Explorar dataset
# ---------------------------------------------------------
def explore_dataset(csv_path):
    """Analiza el dataset descargado"""
    print(f"\n Explorando dataset: {csv_path.name}")
    
    df = pd.read_csv(csv_path, low_memory=False)
    
    print(f"\n{'='*60}")
    print(f"INFORMACIÓN GENERAL")
    print(f"{'='*60}")
    print(f"Total de registros: {len(df):,}")
    print(f"Columnas: {len(df.columns)}")
    print(f"\nPrimeras columnas:")
    print(df.columns.tolist()[:15])
    
    # Verificar si hay columna de lenguaje
    if 'programming_language' in df.columns:
        print(f"\n{'='*60}")
        print(f"DISTRIBUCIÓN POR LENGUAJE")
        print(f"{'='*60}")
        lang_counts = df['programming_language'].value_counts()
        print(lang_counts.head(10))
        
        python_count = lang_counts.get('Python', 0) + lang_counts.get('python', 0)
        print(f"\n Registros de Python: {python_count:,}")
    
    # Verificar columnas relacionadas con código
    code_columns = [col for col in df.columns if 'code' in col.lower() or 'file' in col.lower()]
    print(f"\n{'='*60}")
    print(f"COLUMNAS RELACIONADAS CON CÓDIGO")
    print(f"{'='*60}")
    for col in code_columns:
        print(f"  - {col}")
    
    # Guardar información del dataset
    info_path = PROCESSED_DIR / "dataset_info.json"
    info = {
        "total_records": len(df),
        "columns": df.columns.tolist(),
        "languages": df['programming_language'].value_counts().to_dict() if 'programming_language' in df.columns else {},
        "code_columns": code_columns
    }
    
    with open(info_path, 'w') as f:
        json.dump(info, f, indent=2)
    
    print(f"\n Información guardada en: {info_path}")
    
    return df


# ---------------------------------------------------------
# FUNCIÓN: Filtrar registros de Python
# ---------------------------------------------------------
def filter_python_records(df):
    """Filtra solo registros de Python con código"""
    print(f"\n Filtrando registros de Python...")
    
    # Filtrar por lenguaje Python
    if 'programming_language' in df.columns:
        df_python = df[
            (df['programming_language'].str.lower() == 'python') |
            (df['programming_language'] == 'Python')
        ].copy()
    else:
        # Si no hay columna de lenguaje, filtrar por extensión de archivo
        if 'file_name' in df.columns:
            df_python = df[df['file_name'].str.endswith('.py', na=False)].copy()
        else:
            print(" No se pudo determinar el lenguaje")
            return None
    
    print(f" Registros Python encontrados: {len(df_python):,}")
    
    # Verificar que hay columnas de código
    has_code = any(col in df.columns for col in ['func_before', 'func_after', 'code_before', 'code_after'])
    
    if not has_code:
        print(" No se encontraron columnas con código fuente")
        return None
    
    # Guardar dataset filtrado
    output_path = PROCESSED_DIR / "cvefixes_python.csv"
    df_python.to_csv(output_path, index=False)
    print(f" Dataset Python guardado en: {output_path}")
    
    return df_python


# ---------------------------------------------------------
# PROCESO PRINCIPAL
# ---------------------------------------------------------
def main():
    csv_path = RAW_DIR / "CVEfixes.csv"
    
    # Paso 1: Descargar dataset si no existe
    if not csv_path.exists():
        print("\n Dataset no encontrado. Descargando...")
        try:
            download_file(DATASET_URL, csv_path)
        except Exception as e:
            print(f"\n Error al descargar: {e}")
            print("\n Alternativa: Descarga manualmente desde:")
            print(f"   {DATASET_URL}")
            print(f"   Y guárdalo en: {csv_path}")
            return
    else:
        print(f"\n Dataset ya existe en: {csv_path}")
    
    # Paso 2: Explorar dataset
    try:
        df = explore_dataset(csv_path)
    except Exception as e:
        print(f"\n Error al explorar dataset: {e}")
        return
    
    # Paso 3: Filtrar Python
    try:
        df_python = filter_python_records(df)
        
        if df_python is not None and len(df_python) > 0:
            print(f"\n{'='*60}")
            print(f" DATASET PYTHON LISTO")
            print(f"{'='*60}")
            print(f"Registros totales: {len(df_python):,}")
            print(f"Ubicación: {PROCESSED_DIR / 'cvefixes_python.csv'}")
            
            # Mostrar muestra
            print(f"\n Muestra de registros:")
            print(df_python.head(3))
            
    except Exception as e:
        print(f"\n Error al filtrar Python: {e}")
        return
    
    print(f"\n{'='*60}")
    print(f" PROCESO COMPLETADO")
    print(f"{'='*60}")
    print(f"\nSiguientes pasos:")
    print(f"1. Revisa el archivo: {PROCESSED_DIR / 'dataset_info.json'}")
    print(f"2. Examina los datos filtrados: {PROCESSED_DIR / 'cvefixes_python.csv'}")
    print(f"3. Prepárate para extraer features del código vulnerable/seguro")


if __name__ == "__main__":
    main()