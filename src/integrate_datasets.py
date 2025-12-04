import pandas as pd
import numpy as np
from pathlib import Path

# ---------------------------------------------------------
# CONFIGURACIÓN
# ---------------------------------------------------------
KAGGLE_DATASET = "data/processed/dataset_features_labeled.csv"  # Dataset real con labels
SYNTHETIC_DATASET = "data/meta/dataset_features.csv"  # Dataset de repos públicos
OUTPUT_DATASET = "data/meta/dataset_integrated.csv"

OUTPUT_DIR = Path("data/meta")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

print("=" * 70)
print("INTEGRACIÓN DE DATASETS")
print("=" * 70)

# ---------------------------------------------------------
# 1. CARGAR DATASETS
# ---------------------------------------------------------
print("\n Cargando datasets...")

# Dataset de Kaggle (con labels reales)
try:
    df_kaggle = pd.read_csv(KAGGLE_DATASET)
    print(f" Dataset Kaggle cargado: {len(df_kaggle):,} registros")
    print(f"   Columnas: {len(df_kaggle.columns)}")
except Exception as e:
    print(f" Error al cargar dataset Kaggle: {e}")
    df_kaggle = None

# Dataset sintético (de repos públicos)
try:
    df_synthetic = pd.read_csv(SYNTHETIC_DATASET)
    print(f" Dataset sintético cargado: {len(df_synthetic):,} registros")
    print(f"   Columnas: {len(df_synthetic.columns)}")
except Exception as e:
    print(f" No se pudo cargar dataset sintético: {e}")
    df_synthetic = None


# ---------------------------------------------------------
# 2. IDENTIFICAR FEATURES COMUNES
# ---------------------------------------------------------
print(f"\n{'='*70}")
print("ANÁLISIS DE FEATURES COMUNES")
print(f"{'='*70}")

# Features básicas que DEBEN estar en ambos
BASIC_FEATURES = [
    "loc",
    "comments",
    "functions",
    "classes",
    "imports",
    "ast_nodes",
    "control_structures",
    "cyclomatic_complexity",
    "maintainability_index",
    "size_bytes"
]

if df_kaggle is not None:
    kaggle_features = set(df_kaggle.columns)
    print(f"\n Features en dataset Kaggle: {len(kaggle_features)}")
    
    # Verificar features básicas
    missing_basic = [f for f in BASIC_FEATURES if f not in kaggle_features]
    if missing_basic:
        print(f" Features básicas faltantes en Kaggle: {missing_basic}")
    else:
        print(f" Todas las features básicas presentes")
    
    # Features adicionales (vulnerabilidades, etc.)
    extra_features = kaggle_features - set(BASIC_FEATURES) - {'label', 'original_safety'}
    print(f" Features adicionales en Kaggle: {len(extra_features)}")
    print(f"   Ejemplos: {list(extra_features)[:5]}")

if df_synthetic is not None:
    synthetic_features = set(df_synthetic.columns)
    print(f"\n Features en dataset sintético: {len(synthetic_features)}")
    
    missing_basic_synth = [f for f in BASIC_FEATURES if f not in synthetic_features]
    if missing_basic_synth:
        print(f" Features básicas faltantes en sintético: {missing_basic_synth}")


# ---------------------------------------------------------
# 3. PREPARAR DATASET SINTÉTICO
# ---------------------------------------------------------
print(f"\n{'='*70}")
print("PREPARANDO DATASET SINTÉTICO")
print(f"{'='*70}")

if df_synthetic is not None:
    # Crear etiquetas sintéticas basadas en heurísticas mejoradas
    print("\n Generando etiquetas sintéticas...")
    
    # Heurística más sofisticada para etiquetas
    df_synthetic["label"] = (
        (df_synthetic["cyclomatic_complexity"] > 15) |
        (df_synthetic["maintainability_index"] < 50) |
        ((df_synthetic["ast_nodes"] > 1000) & (df_synthetic["functions"] > 20))
    ).astype(int)
    
    print(f"   Distribución de labels sintéticas:")
    print(df_synthetic["label"].value_counts())
    
    # Agregar columna de origen
    df_synthetic["data_source"] = "synthetic"
    
    # Rellenar features faltantes con 0 (para features de vulnerabilidad que no tiene)
    if df_kaggle is not None:
        for col in kaggle_features:
            if col not in df_synthetic.columns and col not in ['label', 'original_safety', 'data_source']:
                df_synthetic[col] = 0
    
    print(f" Dataset sintético preparado: {len(df_synthetic):,} registros")


# ---------------------------------------------------------
# 4. PREPARAR DATASET KAGGLE
# ---------------------------------------------------------
print(f"\n{'='*70}")
print("PREPARANDO DATASET KAGGLE")
print(f"{'='*70}")

if df_kaggle is not None:
    # Agregar columna de origen
    df_kaggle["data_source"] = "kaggle_real"
    
    print(f"   Distribución de labels reales:")
    print(df_kaggle["label"].value_counts())
    
    # Rellenar features faltantes con valores predeterminados
    if df_synthetic is not None:
        for col in synthetic_features:
            if col not in df_kaggle.columns and col not in ['label', 'data_source', 'repo', 'file_path']:
                df_kaggle[col] = 0
    
    print(f" Dataset Kaggle preparado: {len(df_kaggle):,} registros")


# ---------------------------------------------------------
# 5. COMBINAR DATASETS
# ---------------------------------------------------------
print(f"\n{'='*70}")
print("COMBINANDO DATASETS")
print(f"{'='*70}")

# Identificar columnas comunes (excluyendo metadatos)
exclude_cols = ['repo', 'file_path', 'original_safety']

if df_kaggle is not None and df_synthetic is not None:
    # Obtener columnas comunes (excluyendo label y data_source)
    kaggle_features = set(df_kaggle.columns) - {'label', 'data_source'} - set(exclude_cols)
    synthetic_features = set(df_synthetic.columns) - {'label', 'data_source'} - set(exclude_cols)
    common_cols = list(kaggle_features & synthetic_features)
    
    print(f"\n Columnas comunes encontradas: {len(common_cols)}")
    
    # Seleccionar solo columnas comunes + label + data_source
    select_cols_kaggle = common_cols + ['label', 'data_source']
    select_cols_synthetic = common_cols + ['label', 'data_source']
    
    df_kaggle_selected = df_kaggle[select_cols_kaggle].copy()
    df_synthetic_selected = df_synthetic[select_cols_synthetic].copy()
    
    # Combinar
    df_combined = pd.concat([df_kaggle_selected, df_synthetic_selected], ignore_index=True)
    
    print(f"\n Datasets combinados exitosamente")
    print(f"   Total de registros: {len(df_combined):,}")
    print(f"   Total de features: {len(df_combined.columns) - 2}")  # -2 por label y data_source
    
    print(f"\n Distribución por origen:")
    print(df_combined["data_source"].value_counts())
    
    print(f"\n Distribución de labels combinada:")
    print(df_combined["label"].value_counts())
    
    # Verificar balanceo
    safe_count = (df_combined["label"] == 0).sum()
    vuln_count = (df_combined["label"] == 1).sum()
    balance_ratio = min(safe_count, vuln_count) / max(safe_count, vuln_count)
    
    print(f"\n Ratio de balanceo: {balance_ratio:.2%}")
    
    if balance_ratio < 0.5:
        print(f" Dataset desbalanceado. Aplicando balanceo...")
        
        # Undersampling de la clase mayoritaria
        df_safe = df_combined[df_combined["label"] == 0]
        df_vuln = df_combined[df_combined["label"] == 1]
        
        if len(df_safe) > len(df_vuln):
            df_safe_balanced = df_safe.sample(n=len(df_vuln), random_state=42)
            df_combined = pd.concat([df_safe_balanced, df_vuln], ignore_index=True)
        else:
            df_vuln_balanced = df_vuln.sample(n=len(df_safe), random_state=42)
            df_combined = pd.concat([df_safe, df_vuln_balanced], ignore_index=True)
        
        print(f" Dataset balanceado: {len(df_combined):,} registros")
        print(f"   Nuevo ratio: 50/50")
    
    # Shuffle
    df_combined = df_combined.sample(frac=1, random_state=42).reset_index(drop=True)
    
elif df_kaggle is not None:
    print("\n Solo dataset Kaggle disponible")
    df_combined = df_kaggle.copy()
    
elif df_synthetic is not None:
    print("\n Solo dataset sintético disponible")
    df_combined = df_synthetic.copy()
    
else:
    print("\n No hay datasets disponibles")
    exit(1)


# ---------------------------------------------------------
# 6. ANÁLISIS DE CALIDAD
# ---------------------------------------------------------
print(f"\n{'='*70}")
print("ANÁLISIS DE CALIDAD DEL DATASET INTEGRADO")
print(f"{'='*70}")

# Verificar valores nulos
null_counts = df_combined.isnull().sum()
null_features = null_counts[null_counts > 0]

if len(null_features) > 0:
    print(f"\n Features con valores nulos:")
    for feat, count in null_features.items():
        print(f"   {feat}: {count} ({count/len(df_combined)*100:.1f}%)")
    
    # Rellenar nulos con 0 o media según el caso
    print(f"\n Rellenando valores nulos...")
    for feat in null_features.index:
        if feat in BASIC_FEATURES:
            df_combined[feat].fillna(df_combined[feat].median(), inplace=True)
        else:
            df_combined[feat].fillna(0, inplace=True)
    
    print(f" Valores nulos rellenados")
else:
    print(f"\n No hay valores nulos")

# Estadísticas descriptivas de features clave
print(f"\n Estadísticas de features clave:")
key_features = ['cyclomatic_complexity', 'maintainability_index', 'ast_nodes', 'loc']
print(df_combined[key_features].describe())


# ---------------------------------------------------------
# 7. GUARDAR DATASET INTEGRADO
# ---------------------------------------------------------
output_path = Path(OUTPUT_DATASET)
df_combined.to_csv(output_path, index=False)

print(f"\n{'='*70}")
print(f" DATASET INTEGRADO GUARDADO")
print(f"{'='*70}")
print(f"Ruta: {output_path}")
print(f"Total registros: {len(df_combined):,}")
print(f"Total features: {len(df_combined.columns) - 2}")
print(f"\nDistribución final:")
print(df_combined['label'].value_counts())

# Guardar metadata
metadata = {
    "total_records": len(df_combined),
    "total_features": len(df_combined.columns) - 2,
    "label_distribution": df_combined['label'].value_counts().to_dict(),
    "data_sources": df_combined['data_source'].value_counts().to_dict() if 'data_source' in df_combined.columns else {},
    "features_list": [col for col in df_combined.columns if col not in ['label', 'data_source']],
    "basic_features": BASIC_FEATURES,
    "output_file": str(output_path)
}

import json
metadata_path = OUTPUT_DIR / "dataset_integrated_info.json"
with open(metadata_path, 'w') as f:
    json.dump(metadata, f, indent=2)

print(f"\n Metadata guardada en: {metadata_path}")

print(f"\n{'='*70}")
print(f" INTEGRACIÓN COMPLETADA")
print(f"{'='*70}")
print(f"\nSiguiente paso:")
print(f"   Entrenar modelo con: {output_path}")
print(f"   Objetivo: Alcanzar 82% accuracy con validación cruzada")