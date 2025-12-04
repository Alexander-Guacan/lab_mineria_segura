import pandas as pd

# Ajusta la ruta a tu CSV
CSV_PATH = "data/cvefixes/raw/CVEfixes.csv"

print("=" * 70)
print("DIAGNÓSTICO DEL DATASET")
print("=" * 70)

# Cargar dataset
df = pd.read_csv(CSV_PATH, low_memory=False)

print(f"\n✅ Dataset cargado: {len(df):,} registros")
print(f"📊 Columnas: {df.columns.tolist()}")

# Analizar columna 'language'
print(f"\n{'='*70}")
print("ANÁLISIS DE LA COLUMNA 'language'")
print(f"{'='*70}")

if 'language' in df.columns:
    # Ver valores únicos
    unique_langs = df['language'].unique()
    print(f"\n🔍 Valores únicos encontrados ({len(unique_langs)}):")
    for lang in unique_langs[:20]:  # Mostrar primeros 20
        count = (df['language'] == lang).sum()
        print(f"  - '{lang}' → {count:,} registros")
    
    if len(unique_langs) > 20:
        print(f"  ... y {len(unique_langs) - 20} más")
    
    # Distribución completa
    print(f"\n📊 Distribución completa:")
    print(df['language'].value_counts())
    
    # Buscar variantes de Python
    print(f"\n🐍 Buscando variantes de 'python':")
    python_variants = df[df['language'].str.contains('python', case=False, na=False)]
    print(f"   Registros que contienen 'python': {len(python_variants):,}")
    
    if len(python_variants) > 0:
        print(f"   Valores exactos:")
        print(python_variants['language'].value_counts())
else:
    print("⚠️ No existe columna 'language'")
    print("\n💡 El dataset podría ser mono-lenguaje (solo Python)")
    print("    Procesaremos todos los registros como Python")

# Analizar columna 'safety'
print(f"\n{'='*70}")
print("ANÁLISIS DE LA COLUMNA 'safety'")
print(f"{'='*70}")

if 'safety' in df.columns:
    print(f"\n🔍 Valores únicos:")
    print(df['safety'].value_counts())
    
    print(f"\n📋 Valores exactos:")
    for val in df['safety'].unique():
        print(f"  - '{val}' (tipo: {type(val).__name__})")
else:
    print("⚠️ No existe columna 'safety'")

# Analizar columna 'code'
print(f"\n{'='*70}")
print("ANÁLISIS DE LA COLUMNA 'code'")
print(f"{'='*70}")

if 'code' in df.columns:
    print(f"\n📏 Longitud del código:")
    df['code_length'] = df['code'].str.len()
    print(df['code_length'].describe())
    
    print(f"\n📄 Muestra de código (primeros 200 caracteres del primer registro):")
    print("-" * 70)
    print(df['code'].iloc[0][:200])
    print("-" * 70)
else:
    print("⚠️ No existe columna 'code'")

print(f"\n{'='*70}")
print("RECOMENDACIONES")
print(f"{'='*70}")

if 'language' not in df.columns:
    print("\n✅ Acción recomendada:")
    print("   El dataset no tiene columna 'language'")
    print("   → Procesar TODOS los registros como Python")
    print("   → Eliminar el filtro de lenguaje en el script")
elif len(python_variants) == 0:
    print("\n✅ Acción recomendada:")
    print("   No hay registros con 'python' en la columna 'language'")
    print("   → Verificar si todos los códigos son Python de todas formas")
    print("   → Procesar todos los registros sin filtro de lenguaje")
else:
    print("\n✅ Acción recomendada:")
    print(f"   Hay {len(python_variants):,} registros de Python")
    print("   → Ajustar el filtro para usar el valor exacto encontrado")